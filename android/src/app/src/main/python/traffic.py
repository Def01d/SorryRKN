"""Bounded first-request inspection for routing. TLS stays encrypted end to end."""
import asyncio
import re
from pathlib import Path
from extra_sites import AI_HOSTS,INSTAGRAM_HOSTS,matches
from user_rules import DomainRules

MAX_INITIAL=65536
YOUTUBE_HOSTS=('youtube.com','youtube-nocookie.com','googlevideo.com','ytimg.com','youtu.be','youtubekids.com',
               'youtube.googleapis.com','youtubei.googleapis.com','youtubeembeddedplayer.googleapis.com',
               'yt3.ggpht.com','yt4.ggpht.com','yt3.googleusercontent.com','jnn-pa.googleapis.com',
               'wide-youtube.l.google.com','youtube-ui.l.google.com','ytimg.l.google.com','yt-video-upload.l.google.com')
_host=re.compile(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$')

def tls_name(data):
    handshake=bytearray(); offset=0
    while offset+5<=len(data):
        if data[offset]!=22 or data[offset+1]!=3: return None
        size=int.from_bytes(data[offset+3:offset+5],'big')
        if offset+5+size>len(data): return None
        handshake.extend(data[offset+5:offset+5+size]);offset+=5+size
        if len(handshake)>=4:
            total=4+int.from_bytes(handshake[1:4],'big')
            if total>MAX_INITIAL or handshake[0]!=1:return None
            if len(handshake)>=total:break
    try:
        if len(handshake)<4 or len(handshake)<total:return None
        body=handshake[4:total];p=34
        p+=1+body[p]
        p+=2+int.from_bytes(body[p:p+2],'big')
        p+=1+body[p]
        end=p+2+int.from_bytes(body[p:p+2],'big');p+=2
        if end>len(body):return None
        while p+4<=end:
            kind=int.from_bytes(body[p:p+2],'big');size=int.from_bytes(body[p+2:p+4],'big');p+=4
            if p+size>end:return None
            if kind==0:
                ext=body[p:p+size];q=2
                if len(ext)<2 or int.from_bytes(ext[:2],'big')!=len(ext)-2:return None
                while q+3<=len(ext):
                    name_type=ext[q];n=int.from_bytes(ext[q+1:q+3],'big');q+=3
                    if q+n>len(ext):return None
                    if name_type==0:
                        host=bytes(ext[q:q+n]).decode('ascii').lower().rstrip('.')
                        return host if _host.fullmatch(host) and all(0<len(x)<=63 for x in host.split('.')) else None
                    q+=n
            p+=size
    except (IndexError,ValueError,UnboundLocalError):pass
    return None

def request_name(data):
    if data[:1]==b'\x16':return tls_name(data)
    if data.startswith((b'GET ',b'POST ',b'HEAD ',b'PUT ',b'CONNECT ',b'OPTIONS ',b'DELETE ')):
        for line in data.split(b'\r\n')[1:]:
            if line.lower().startswith(b'host:'):
                try:host=line[5:].strip().decode('ascii').split(':')[0].lower().rstrip('.')
                except UnicodeError:return None
                return host if _host.fullmatch(host) else None
    return None

async def read_initial(reader):
    data=bytearray(await asyncio.wait_for(reader.read(16384),60))
    if not data:return b'',None
    # A modern ClientHello can span multiple TUN packets/TLS records. Read
    # complete records before handing it to a socket-based native engine.
    try:
        async with asyncio.timeout(2):
            if data[:1]==b'\x16':
                offset=0;handshake=bytearray()
                while len(data)<=MAX_INITIAL:
                    while len(data)<offset+5:
                        chunk=await reader.read(offset+5-len(data))
                        if not chunk:return bytes(data),request_name(data)
                        data.extend(chunk)
                    if data[offset]!=22 or data[offset+1]!=3:break
                    size=int.from_bytes(data[offset+3:offset+5],'big');end=offset+5+size
                    if size>16384 or end>MAX_INITIAL:break
                    while len(data)<end:
                        chunk=await reader.read(end-len(data))
                        if not chunk:return bytes(data),request_name(data)
                        data.extend(chunk)
                    handshake.extend(data[offset+5:end]);offset=end
                    if len(handshake)>=4 and len(handshake)>=4+int.from_bytes(handshake[1:4],'big'):break
            elif data.startswith((b'GET ',b'POST ',b'HEAD ',b'PUT ',b'OPTIONS ')):
                while b'\r\n\r\n' not in data and len(data)<16384:
                    chunk=await reader.read(16384-len(data))
                    if not chunk:break
                    data.extend(chunk)
    except asyncio.TimeoutError:pass # Preserve every byte even for partial/malformed messages.
    return bytes(data),request_name(data)

class Routes:
    inspect_ports={80,443,8080,8443}
    def __init__(self,directory,ports):
        self.ports=ports
        self.own_ip=bool(ports.get('own_ip'))
        self.rules=DomainRules(ports.get('geo_domains',()),ports.get('direct_domains',()),
                               bool(ports.get('builtin_extras',ports.get('smart_dns') or ports.get('ai'))))
        self.hosts=Path(directory,'hosts.txt').read_text().splitlines()
        self.excluded=Path(directory,'exclude.txt').read_text().splitlines()
    @staticmethod
    def matches(host,pattern):
        return host==pattern[1:] if pattern.startswith('^') else host==pattern or host.endswith('.'+pattern)
    def group(self,host):
        if not host or self.rules.is_direct(host) or any(self.matches(host,p) for p in self.excluded):return 'direct'
        if self.rules.is_geo(host) and (self.ports.get('ai') if self.own_ip else self.ports.get('smart_dns')):return 'ai'
        if self.ports.get('instagram') and matches(host,INSTAGRAM_HOSTS):return 'instagram'
        if not any(self.matches(host,p) for p in self.hosts):return 'direct'
        if self.ports.get('discord') and ('discord' in host or host=='dis.gd'):return 'discord'
        if self.ports.get('youtube') and any(self.matches(host,p) for p in YOUTUBE_HOSTS):return 'youtube'
        # Shared CDN/ECH cover names also serve unrelated websites. Applying a
        # YouTube strategy to every Cloudflare/CloudFront connection is unsafe.
        return 'direct'
    def port(self,group):return self.ports.get(group,self.ports.get('youtube'))
