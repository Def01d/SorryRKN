"""User-owned domain rules, independent from downloaded strategy snapshots."""
import ipaddress
import re
import struct
import time
from urllib.parse import urlsplit
from extra_sites import AI_HOSTS,matches

MAX_DOMAINS=256
MAX_TEXT=32768

def parse_domains(text):
    if not isinstance(text,str) or len(text)>MAX_TEXT:raise ValueError('Список слишком длинный')
    result=[]
    for line in text.splitlines():
        value=line.strip()
        if not value:continue
        if value.startswith('*.'):value=value[2:]
        if any(c.isspace() for c in value) or '\\' in value:raise ValueError('Неверный домен: '+value[:80])
        try:
            u=urlsplit(value if '://' in value else '//'+value)
            if u.scheme and u.scheme.lower() not in ('http','https'):raise ValueError()
            if u.username is not None or u.password is not None or not u.hostname:raise ValueError()
            if u.port is not None and not 1<=u.port<=65535:raise ValueError()
            host=u.hostname.rstrip('.').encode('idna').decode('ascii').lower()
            try:ipaddress.ip_address(host)
            except ValueError:pass
            else:raise ValueError()
            if len(host)>253 or '.' not in host or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in host.split('.')):raise ValueError()
        except (ValueError,UnicodeError):raise ValueError('Неверный домен: '+value[:80]) from None
        if host not in result:result.append(host)
        if len(result)>MAX_DOMAINS:raise ValueError('Не больше 256 доменов в каждом списке')
    if len('\n'.join(result))>MAX_TEXT:raise ValueError('Список доменов после преобразования слишком длинный')
    return result

class DomainRules:
    def __init__(self,geo=(),direct=(),builtins=True):
        self.geo=tuple(parse_domains('\n'.join(geo)))
        self.direct=tuple(parse_domains('\n'.join(direct)))
        self.builtins=builtins
        self.addresses={}
    def is_direct(self,host):return matches(host,self.direct)
    def is_geo(self,host):
        return not self.is_direct(host) and (matches(host,self.geo) or self.builtins and matches(host,AI_HOSTS))
    def direct_address(self,address):
        try:address=str(ipaddress.ip_address(address))
        except ValueError:return self.is_direct(address)
        expires=self.addresses.get(address,0)
        if expires>time.monotonic():return True
        self.addresses.pop(address,None)
        return False
    def remember(self,host,query,answer):
        if not self.is_direct(host) or not answer:return
        # Remember bounded A/AAAA answers for UDP, where TLS/HTTP names do not exist.
        def skip(offset):
            for _ in range(128):
                if offset>=len(answer):raise ValueError()
                n=answer[offset];offset+=1
                if n==0:return offset
                if n&0xc0==0xc0:
                    if offset>=len(answer):raise ValueError()
                    return offset+1
                if n>63 or offset+n>len(answer):raise ValueError()
                offset+=n
            raise ValueError()
        try:
            if len(answer)<12 or answer[:2]!=query[:2] or answer[2]&128==0 or answer[3]&15:return
            if struct.unpack('!H',answer[4:6])[0]!=1:return
            offset=skip(12)+4
            for _ in range(min(struct.unpack('!H',answer[6:8])[0],256)):
                offset=skip(offset)
                kind,cls,ttl,size=struct.unpack('!HHIH',answer[offset:offset+10]);offset+=10
                if offset+size>len(answer):return
                if cls==1 and (kind==1 and size==4 or kind==28 and size==16):
                    address=str(ipaddress.ip_address(answer[offset:offset+size]))
                    if len(self.addresses)>=2048:self.addresses={k:v for k,v in self.addresses.items() if v>time.monotonic()}
                    if len(self.addresses)<2048:self.addresses[address]=time.monotonic()+min(ttl,300)
                offset+=size
        except (ValueError,IndexError,struct.error):return
