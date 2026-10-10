"""User-owned domain rules, independent from downloaded strategy snapshots."""
import ipaddress
import re
import struct
import time
from urllib.parse import urlsplit
from extra_sites import AI_HOSTS,matches
from doh import dns_message, valid_answer, answer_names

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
        self.protected_addresses={}
    def is_direct(self,host):return matches(host,self.direct)
    def is_geo(self,host):
        return not self.is_direct(host) and (matches(host,self.geo) or self.builtins and matches(host,AI_HOSTS))
    def direct_address(self,address):
        return self._known_address(address,self.addresses,self.is_direct)
    def protected_address(self,address):
        return not self.direct_address(address) and self._known_address(address,self.protected_addresses,lambda host:False)
    @staticmethod
    def _known_address(address,addresses,hostname_rule):
        try:address=str(ipaddress.ip_address(address))
        except ValueError:return hostname_rule(address)
        expires=addresses.get(address,0)
        if expires>time.monotonic():return True
        addresses.pop(address,None)
        return False
    def remember(self,host,query,answer,protected=False):
        direct=self.is_direct(host)
        if not (direct or protected) or not answer:return
        # Remember bounded A/AAAA answers for UDP, where TLS/HTTP names do not exist.
        try:
            if not valid_answer(query,answer) or answer[3]&15:return
            _,_,(name,_,_),records=dns_message(answer)
            if name.decode('ascii')!=host.lower().rstrip('.'):return
            names=answer_names(answer,name,records)
            addresses=self.addresses if direct else self.protected_addresses
            now=time.monotonic()
            for is_answer,owner,kind,cls,_,ttl,offset,size in records[:256]:
                if is_answer and owner in names and cls==1 and (kind==1 and size==4 or kind==28 and size==16):
                    address=str(ipaddress.ip_address(answer[offset:offset+size]))
                    if len(addresses)>=2048:
                        for key,expires in list(addresses.items()):
                            if expires<=now:addresses.pop(key,None)
                    if len(addresses)<2048:addresses[address]=now+min(ttl,300)
        except (ValueError,IndexError,struct.error,UnicodeError):return
