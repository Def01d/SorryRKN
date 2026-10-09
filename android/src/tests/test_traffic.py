import asyncio
import contextlib
import json
import socket
import ssl
import subprocess
from pathlib import Path
import httpx
import pytest
from traffic import read_initial,request_name,Routes
from gateway import Gateway,encode_address,read_address

ROOT=Path(__file__).resolve().parents[1]

def hello(host='www.youtube.com',large=False):
    ctx=ssl.create_default_context()
    if large:ctx.set_alpn_protocols(['x'*100+str(i) for i in range(90)])
    incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO()
    tls=ctx.wrap_bio(incoming,outgoing,server_side=False,server_hostname=host)
    with contextlib.suppress(ssl.SSLWantReadError):tls.do_handshake()
    return outgoing.read()

@pytest.mark.asyncio
@pytest.mark.parametrize('large',[False,True])
async def test_fragmented_clienthello_preserves_all_bytes_and_sni(large):
    payload=hello(large=large);reader=asyncio.StreamReader()
    task=asyncio.create_task(read_initial(reader))
    for offset in range(0,len(payload),137):
        reader.feed_data(payload[offset:offset+137]);await asyncio.sleep(0)
    reader.feed_eof();collected,host=await task
    assert collected==payload and host=='www.youtube.com'
    if large:assert len(payload)>8000

@pytest.mark.asyncio
async def test_multirecord_clienthello_and_incomplete_data_preserved():
    payload=hello(); body=payload[5:];cut=83
    divided=payload[:3]+cut.to_bytes(2,'big')+body[:cut]+payload[:3]+(len(body)-cut).to_bytes(2,'big')+body[cut:]
    assert request_name(divided)=='www.youtube.com'
    for data in (divided,payload[:15],b'\x16\x03\x03\xff\xffraw',b'raw bytes'):
        reader=asyncio.StreamReader();reader.feed_data(data);reader.feed_eof()
        got,_=await read_initial(reader);assert got==data

def test_domain_filter_exact_excluded_and_service_routing(tmp_path):
    (tmp_path/'hosts.txt').write_text('youtube.com\ndiscord.com\n^dns.google\ncloudflare-ech.com\ncloudfront.net\n')
    (tmp_path/'exclude.txt').write_text('skip.youtube.com\n')
    routes=Routes(tmp_path,{'youtube':1080,'discord':1083})
    for host,wanted in [('www.youtube.com','youtube'),('cdn.discord.com','discord'),('evil-youtube.com','direct'),
                        ('skip.youtube.com','direct'),('x.skip.youtube.com','direct'),('dns.google','direct'),('x.dns.google','direct'),
                        ('cloudflare-ech.com','direct'),('example.cloudfront.net','direct'),(None,'direct')]:
        assert routes.group(host)==wanted
    assert routes.port('discord')==1083
    assert request_name(b'GET / HTTP/1.1\r\nHost: WWW.YOUTUBE.COM:443\r\n\r\n')=='www.youtube.com'

@pytest.mark.asyncio
async def test_direct_server_first_and_ipv6_translation_and_service_ports(tmp_path):
    (tmp_path/'hosts.txt').write_text('youtube.com\ndiscord.com\n')
    (tmp_path/'exclude.txt').write_text('skip.youtube.com\n')
    processes=[]; ports={}; original_ports=set(Routes.inspect_ports)
    for group,binary,args in [('youtube','test-tpws',['--socks','--bind-addr=127.0.0.1','--split-pos=1,midsld','--tlsrec=sni']),
                              ('discord','test-byedpi',['--ip','127.0.0.1','--disorder','1'])]:
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        native=subprocess.Popen([str(ROOT/'build'/binary),f'--port={port}',*args],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        processes.append(native);ports[group]=port
        for _ in range(100):
            try:
                _,writer=await asyncio.open_connection('127.0.0.1',port);writer.close();await writer.wait_closed();break
            except OSError:await asyncio.sleep(.01)
        else:pytest.fail('Native proxy startup failed')
    received=[]
    async def echo(reader,writer):
        data=await reader.readuntil(b'\r\n\r\n');received.append(data);writer.write(data);await writer.drain();writer.close()
    async def banner(reader,writer):
        writer.write(b'SERVER FIRST\n');await writer.drain();await reader.read();writer.close()
    server=await asyncio.start_server(echo,'127.0.0.1',0);target_port=server.sockets[0].getsockname()[1]
    server_first=await asyncio.start_server(banner,'127.0.0.1',0);banner_port=server_first.sockets[0].getsockname()[1]
    Routes.inspect_ports.add(target_port)
    gateway=Gateway(port=0,directory=tmp_path,routes=ports);await gateway.start()
    async def resolve(host):return '127.0.0.1'
    gateway.resolver.resolve=resolve
    async def connect(host,port):
        reader,writer=await asyncio.open_connection('127.0.0.1',gateway.port)
        writer.write(b'\x05\x01\0');await writer.drain();assert await reader.readexactly(2)==b'\x05\0'
        writer.write(b'\x05\x01\0'+encode_address(host,port));await writer.drain();assert await reader.readexactly(3)==b'\x05\0\0'
        await read_address(reader);return reader,writer
    try:
        r,w=await connect('127.0.0.1',banner_port)
        assert await asyncio.wait_for(r.readline(),.5)==b'SERVER FIRST\n';w.close();await w.wait_closed()
        # HTTP is deliberately echoed here: routing and byte preservation are
        # checked with two actual native engines, not a mocked SOCKS interface.
        for host in ('www.youtube.com','discord.com','normal.example.test'):
            request=f'GET / HTTP/1.1\r\nHost: {host}\r\n\r\n'.encode()
            # The original IPv6 address is unreachable; the known DNS A answer
            # must be used instead, while the application bytes stay identical.
            r,w=await connect('2001:db8::1',target_port);w.write(request);await w.drain()
            assert await asyncio.wait_for(r.readexactly(len(request)),3)==request;w.close();await w.wait_closed()
        assert gateway.stats['youtube_tcp']==1 and gateway.stats['discord_tcp']==1
        assert gateway.stats['direct_tcp']==2 and gateway.stats['ipv6_tcp']==3
        assert gateway.stats['tcp_failed']==0
    finally:
        await gateway.close();server.close();server_first.close();await server.wait_closed();await server_first.wait_closed()
        Routes.inspect_ports=original_ports
        for p in processes:p.terminate();p.wait(timeout=3)
