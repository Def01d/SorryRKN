import asyncio
import contextlib
import json
import socket
import struct
import subprocess
from pathlib import Path
import httpx
import pytest
from doh import Resolver,valid_answer,ipv4_answers
from smart_dns import SmartDNS,COMSS,question
from traffic import Routes
from gateway import Gateway,encode_address,read_address
from extra_sites import AI_HOSTS,matches
import bridge_data as data

ROOT=Path(__file__).resolve().parents[1]

def query(host,kind=1):
    return struct.pack('!6H',42,0x0100,1,0,0,0)+b''.join(bytes([len(s)])+s.encode() for s in host.split('.'))+b'\0'+struct.pack('!HH',kind,1)

def answer(payload):
    return payload[:2]+struct.pack('!5H',0x8180,1,1,0,0)+payload[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,120,4)+socket.inet_aton('93.184.216.34')

class FakeDNS:
    provider='fake'
    def __init__(self,working=True):self.calls=[];self.closed=False;self.working=working
    async def query(self,payload):self.calls.append(question(payload)[0]);return answer(payload) if self.working else None
    async def resolve(self,host):self.calls.append(host);return '93.184.216.34' if self.working else None
    async def close(self):self.closed=True

@pytest.mark.asyncio
async def test_smart_dns_is_selective_and_does_not_fall_back_to_direct_ai():
    normal,smart=FakeDNS(),FakeDNS();resolver=SmartDNS(normal=normal,smart=smart)
    try:
        for host in ('chatgpt.com','api.openai.com','claude.ai','gemini.google.com'):
            result=await resolver.query(query(host));assert valid_answer(query(host),result)
        for host in ('youtube.com','discord.com','instagram.com','accounts.google.com','evilchatgpt.com'):
            assert await resolver.query(query(host))
        assert len(smart.calls)==4 and len(normal.calls)==5
        smart.working=False
        assert await resolver.resolve('chatgpt.com') is None
        assert await resolver.query(query('claude.ai')) is None
        assert len(normal.calls)==5
        assert resolver.stats['smart_dns_failed']==2
    finally:await resolver.close()
    assert normal.closed and smart.closed

@pytest.mark.asyncio
@pytest.mark.parametrize('kind',[28,64,65])
async def test_ai_ipv6_and_https_hints_are_suppressed_without_suppressing_other_sites(kind):
    normal,smart=FakeDNS(),FakeDNS();resolver=SmartDNS(normal=normal,smart=smart)
    try:
        payload=query('gemini.google.com',kind);response=await resolver.query(payload)
        assert valid_answer(payload,response) and struct.unpack('!H',response[6:8])[0]==0
        assert question(response[:2]+b'\x01\0'+response[4:])[0]=='gemini.google.com'
        assert not smart.calls and not normal.calls
        assert await resolver.query(query('www.youtube.com',kind))
        assert normal.calls==['www.youtube.com']
    finally:await resolver.close()

@pytest.mark.asyncio
@pytest.mark.parametrize('payload',[b'',b'x'*5000,query('chatgpt.com')[:14],query('chatgpt.com')[:12]+b'\xc0\x0c\0\x01\0\x01',
                                  struct.pack('!6H',42,0x8100,1,0,0,0)+query('chatgpt.com')[12:]])
async def test_malformed_dns_is_not_forwarded(payload):
    normal,smart=FakeDNS(),FakeDNS();resolver=SmartDNS(normal=normal,smart=smart)
    try:assert await resolver.query(payload) is None and not normal.calls and not smart.calls
    finally:await resolver.close()

@pytest.mark.asyncio
async def test_comss_bootstrap_ip_retains_tls_name_and_dns_wire_format():
    requests=[]
    async def handle(request):
        requests.append(request)
        assert request.url.host=='195.133.25.16' and request.url.path=='/dns-query'
        assert request.headers['host']=='dns.comss.one'
        assert request.extensions['sni_hostname']=='dns.comss.one'
        assert request.headers['content-type']=='application/dns-message'
        return httpx.Response(200,content=answer(await request.aread()))
    resolver=Resolver(None,httpx.MockTransport(handle),providers=COMSS)
    try:
        assert await resolver.resolve('chatgpt.com')=='93.184.216.34'
        assert resolver.provider=='Comss' and len(requests)==1
    finally:await resolver.close()

def setup_routes(directory):
    (directory/'hosts.txt').write_text('youtube.com\ndiscord.com\ncloudflare-ech.com\n')
    (directory/'exclude.txt').write_text('skip.instagram.com\n')

def test_extra_service_routes_preserve_boundaries_and_work_without_youtube_dpi(tmp_path):
    setup_routes(tmp_path)
    routes=Routes(tmp_path,{'youtube':1080,'discord':1083,'smart_dns':True,'instagram':1084})
    cases={'chatgpt.com':'ai','api.openai.com':'ai','claude.ai':'ai','gemini.google.com':'ai','i.instagram.com':'instagram',
           'scontent.cdninstagram.com':'instagram','evilinstagram.com':'direct','evilchatgpt.com':'direct',
           'accounts.google.com':'direct','cloudflare-ech.com':'direct','skip.instagram.com':'direct',
           'proactivebackend-pa.googleapis.com':'ai','www.facebook.com':'instagram',
           'www.youtube.com':'youtube','gateway.discord.com':'discord'}
    for host,group in cases.items():assert routes.group(host)==group
    disabled=Routes(tmp_path,{'youtube':1080,'discord':1083})
    assert disabled.group('chatgpt.com')==disabled.group('instagram.com')=='direct'
    extras_only=Routes(tmp_path,{'smart_dns':True,'instagram':1084})
    assert extras_only.group('www.youtube.com')==extras_only.group('discord.com')=='direct'
    assert matches('CHATGPT.COM.',AI_HOSTS) and not matches('chatgpt.com.example',AI_HOSTS)

@pytest.mark.asyncio
async def test_real_instagram_byedpi_route_and_ai_dns_failure_never_use_original_address(tmp_path):
    setup_routes(tmp_path)
    (tmp_path/'bundled-data.json').write_bytes((ROOT/'app/src/main/assets/bundled-data.json').read_bytes())
    options=json.loads(data.instagram_args('bye-disorder',tmp_path))
    assert options[-1]=='--auto=none' and options.count('--auto=torst,ssl_err')==10
    assert all('bye-instagram-hosts.txt' in x for x in options if x.startswith('--hosts='))
    hosts=(tmp_path/'bye-instagram-hosts.txt').read_text().splitlines()
    assert 'instagram.com' in hosts and 'youtube.com' not in hosts
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));native_port=sock.getsockname()[1]
    native=subprocess.Popen([str(ROOT/'build/test-byedpi'),'--ip','127.0.0.1',f'--port={native_port}',*options],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    accepted=[]
    async def echo(reader,writer):
        try:
            request=await reader.readuntil(b'\r\n\r\n');accepted.append(request)
            writer.write(request);await writer.drain()
        finally:writer.close()
    server=await asyncio.start_server(echo,'127.0.0.1',0);port=server.sockets[0].getsockname()[1]
    original=set(Routes.inspect_ports);Routes.inspect_ports.add(port)
    gateway=Gateway(port=0,directory=tmp_path,routes={'smart_dns':True,'instagram':native_port})
    try:
        for _ in range(100):
            try:
                _,writer=await asyncio.open_connection('127.0.0.1',native_port);writer.close();await writer.wait_closed();break
            except OSError:await asyncio.sleep(.01)
        else:pytest.fail('Instagram native proxy did not start')
        await gateway.start()
        async def resolve(host):return None if host=='chatgpt.com' else '127.0.0.1'
        gateway.resolver.resolve=resolve
        async def connect(host):
            reader,writer=await asyncio.open_connection('127.0.0.1',gateway.port)
            writer.write(b'\x05\x01\0');await writer.drain();assert await reader.readexactly(2)==b'\x05\0'
            writer.write(b'\x05\x01\0'+encode_address('127.0.0.1',port));await writer.drain()
            assert await reader.readexactly(3)==b'\x05\0\0';await read_address(reader)
            request=f'GET / HTTP/1.1\r\nHost: {host}\r\n\r\n'.encode();writer.write(request);await writer.drain()
            return reader,writer,request
        for host in ('instagram.com','claude.ai'):
            reader,writer,request=await connect(host)
            assert await asyncio.wait_for(reader.readexactly(len(request)),3)==request
            writer.close();await writer.wait_closed()
        reader,writer,_=await connect('chatgpt.com')
        assert await asyncio.wait_for(reader.read(),1)==b''
        writer.close();await writer.wait_closed()
        assert len(accepted)==2 and gateway.stats['ai_tcp']==gateway.stats['instagram_tcp']==1
        assert gateway.stats['connect_failed']==1
    finally:
        await gateway.close();server.close();await server.wait_closed();Routes.inspect_ports=original
        native.terminate();native.wait(timeout=3)
