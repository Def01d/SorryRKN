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
from doh import Resolver
from user_rules import DomainRules

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
    def __init__(self,port=None,normal=None,smart=None,rules=None,own_ip=False,protected=None):
        self.rules=rules or DomainRules()
        self.own_ip=bool(own_ip)
        self.protected=protected or (lambda host:False)
        self.preferences=OrderedDict()
        self.normal=normal or Resolver(port)
        # Do not even create the relay-provider transport in own-IP mode.
        self.smart=None if self.own_ip else smart or Resolver(None,providers=COMSS)
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
        answer=await (self.normal if self.own_ip else self.smart).query(payload)
        self.rules.remember(host,payload,answer,protected=protected)
        if not self.own_ip:self.stats['smart_dns_ok' if answer else 'smart_dns_failed']+=1
        return answer
    async def resolve(self,host):
        selected=self.smart if not self.own_ip and self.rules.is_geo(host) else self.normal
        address=await selected.resolve(host)
        if selected is self.smart:self.stats['smart_dns_ok' if address else 'smart_dns_failed']+=1
        return address
    def invalidate(self,host):
        self.preferences.pop(host,None)
        selected=self.smart if not self.own_ip and self.rules.is_geo(host) else self.normal
        selected.invalidate(host)
    def candidates(self,host,first):
        selected=self.smart if not self.own_ip and self.rules.is_geo(host) else self.normal
        candidates=list(dict.fromkeys([first,*getattr(selected,'last_addresses',{}).get(host,())])) if first else []
        preferred=self.preferred(host) if selected is self.smart else None
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
        if self.own_ip or not self.rules.is_geo(host) or address not in self.smart.last_addresses.get(host,()):
            return False
        self.preferences[host]=(address,time.monotonic()+min(120,max(0,ttl)))
        self.preferences.move_to_end(host)
        while len(self.preferences)>64:self.preferences.popitem(last=False)
        return True
    async def close(self):
        self.preferences.clear()
        await asyncio.gather(self.normal.close(),*([self.smart.close()] if self.smart else []))
