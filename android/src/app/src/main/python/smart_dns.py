"""Selective service DNS policy. Own-IP mode uses ordinary verified DoH only.

Provider's published HTTPS bootstrap: https://www.comss.ru/page.php?id=7315
No fallback to the ordinary resolver for an AI domain: it would silently undo
the profile. AAAA and HTTPS/SVCB answers are suppressed for selected names so
supported clients use IPv4 TCP rather than a direct IPv6/QUIC/ECH hint.
"""
import asyncio
import struct
import time
from collections import OrderedDict
from doh import Resolver,cache_records
from user_rules import DomainRules
from dns_profiles import selected_profile, providers
from service_routing import ServiceRouter
from service_catalog import service_for_host,DEFINITIONS

COMSS=(('Comss','dns.comss.one','212.109.195.93'),
       ('Comss','dns.comss.one','83.220.169.155'),
       ('Comss','dns.comss.one','195.133.25.16'))

def question(payload):
    if not 12<=len(payload)<=4096:raise ValueError('Invalid DNS query')
    _,flags,qd,an,ns,_=struct.unpack('!6H',payload[:12])
    if flags&0xf800 or qd!=1 or an or ns:raise ValueError('Unsupported DNS query')
    labels=[];offset=12
    while True:
        size=payload[offset];offset+=1
        if not size:break
        if size>63 or offset+size>=len(payload):raise ValueError('Invalid DNS label')
        label=payload[offset:offset+size].decode('ascii');offset+=size
        if not all(c.isalnum() or c in '-_' for c in label):raise ValueError('Invalid DNS label')
        labels.append(label)
        if offset-12>254:raise ValueError('Long DNS name')
    kind,cls=struct.unpack('!HH',payload[offset:offset+4])
    return '.'.join(labels).lower(),kind,cls,offset+4


def failure_response(payload):
    """Return SERVFAIL promptly instead of making every app wait for DNS timeout."""
    try:
        _, _, _, end = question(payload)
        flags = 0x8082 | (struct.unpack('!H', payload[2:4])[0] & 0x0100)
        return payload[:2] + struct.pack('!5H', flags, 1, 0, 0, 0) + payload[12:end]
    except (ValueError, IndexError, UnicodeError, struct.error):
        return None


class SmartDNS:
    def __init__(self,port=None,normal=None,smart=None,rules=None,own_ip=False,protected=None,profile='comss',directory=None,service_dns=None,network_key=''):
        self.rules=rules or DomainRules()
        self.own_ip=bool(own_ip)
        self.protected=protected or (lambda host:False)
        self.preferences=OrderedDict()
        self.normal=normal or Resolver(port)
        # Do not even create the relay-provider transport in own-IP mode.
        self.smart=None if self.own_ip else smart or Resolver(None,providers=providers(selected_profile(profile,directory)))
        self.routing=None if self.own_ip or not service_dns else ServiceRouter(profile,service_dns,directory,network_key)
        self.smart_pool={profile or 'comss':self.smart} if self.smart else {}
        self.directory=directory
        self.default_profile=profile or 'comss'
        self.stats={'smart_dns_ok':0,'smart_dns_failed':0,'smart_dns_suppressed':0,'secure_dns_suppressed':0}
    @property
    def provider(self):return self.normal.provider
    async def query(self,payload):
        try:host,kind,cls,end=question(payload)
        except (ValueError,IndexError,UnicodeError,struct.error):return None
        geo = self.rules.is_geo(host)
        protected = not self.rules.is_direct(host) and self.protected(host)
        if cls==1 and (geo and kind in (28,64,65) or protected and kind in (64,65)):
            flags=0x8080 | (struct.unpack('!H',payload[2:4])[0]&0x0100)
            self.stats['smart_dns_suppressed' if geo else 'secure_dns_suppressed']+=1
            return payload[:2]+struct.pack('!5H',flags,1,0,0,0)+payload[12:end]
        if not geo:
            answer=await self.normal.query(payload)
            self.rules.remember(host,payload,answer,protected=protected)
            return answer
        answer=await self.smart_for(host).query(payload)
        if answer and self.routing and self.routing.selection['services'].get(service_for_host(host))=='auto':
            wire=bytearray(answer)
            for offset,ttl in cache_records(payload,answer):struct.pack_into('!I',wire,offset,min(30,ttl))
            answer=bytes(wire)
        self.rules.remember(host,payload,answer,protected=protected)
        if not self.own_ip:self.stats['smart_dns_ok' if answer else 'smart_dns_failed']+=1
        return answer
    async def resolve(self,host):
        selected=self.smart_for(host)
        address=await selected.resolve(host)
        if selected is not self.normal:self.stats['smart_dns_ok' if address else 'smart_dns_failed']+=1
        return address
    def invalidate(self,host):
        self.preferences.pop(host,None)
        selected=self.smart_for(host)
        selected.invalidate(host)
    def candidates(self,host,first):
        selected=self.smart_for(host)
        candidates=list(dict.fromkeys([first,*getattr(selected,'last_addresses',{}).get(host,())])) if first else []
        preferred=self.preferred(host) if selected is not self.normal else None
        if preferred in candidates:
            candidates.remove(preferred)
            candidates.insert(0,preferred)
        return candidates
    def preferred(self,host):
        value=self.preferences.get(host)
        if value and value[1]>time.monotonic():return value[0]
        self.preferences.pop(host,None)
        return None
    def prefer(self,host,address,ttl=120):
        if self.own_ip or not self.rules.is_geo(host) or address not in self.smart_for(host).last_addresses.get(host,()):
            return False
        self.preferences[host]=(address,time.monotonic()+min(120,max(0,ttl)))
        self.preferences.move_to_end(host)
        while len(self.preferences)>64:self.preferences.popitem(last=False)
        return True
    async def close(self):
        self.preferences.clear()
        await asyncio.gather(self.normal.close(),*(r.close() for r in set(self.smart_pool.values())))

    def smart_for(self,host):
        if self.own_ip or not self.rules.is_geo(host):return self.normal
        if not self.routing:return self.smart
        identifier=self.routing.profile(host)
        if identifier not in self.smart_pool:
            self.smart_pool[identifier]=Resolver(None,providers=providers(selected_profile(identifier,self.directory)))
        return self.smart_pool[identifier]

    async def recover_routes(self):
        if not self.routing:return set()
        before={key:value['profile'] for key,value in self.routing.routes.items()}
        await self.routing.recover()
        changed={key for key,value in self.routing.routes.items() if value['profile']!=before[key]}
        for host in list(self.preferences):
            if service_for_host(host) in changed:self.preferences.pop(host,None)
        return changed

    def route_status(self):
        if self.routing:return self.routing.snapshot()
        return [dict(service=s['id'],name=s['name'],mode='own_ip' if self.own_ip else 'default',
                     profile='public-doh' if self.own_ip else self.default_profile,changes=0,state='') for s in DEFINITIONS]
