import asyncio
import base64
import contextlib
import datetime
import hashlib
import json
import socket
import ssl
import subprocess
from pathlib import Path
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from discord_gateway import check_gateway,hello,GUID
import strategy_probe as probe

ROOT=Path(__file__).resolve().parents[1]
HELLO=b'{"op":10,"d":{"heartbeat_interval":41250}}'

class Control:
    running=True
    def keepRunning(self):return self.running

class Writer:
    def __init__(self):self.data=[]
    def write(self,data):self.data.append(data)
    async def drain(self):pass

def frame(payload,opcode=1,fin=True):
    return bytes([(128 if fin else 0)|opcode,len(payload)])+payload

@pytest.mark.asyncio
async def test_fragmented_hello_and_ping_respond_with_masked_pong():
    reader=asyncio.StreamReader();writer=Writer()
    reader.feed_data(frame(b'ping',9)+frame(HELLO[:17],fin=False)+frame(HELLO[17:],0));reader.feed_eof()
    assert await hello(reader,writer)
    pong=writer.data[0];assert pong[0]==0x8a and pong[1]==0x84
    assert bytes(pong[6+i]^pong[2+i%4] for i in range(4))==b'ping'

@pytest.mark.asyncio
@pytest.mark.parametrize('data',[frame(b'[]'),frame(b'{"op":0,"d":{}}'),frame(b'{"op":10,"d":{"heartbeat_interval":true}}'),
                                 frame(b'',8),b'\x81\xff'+(2**40).to_bytes(8,'big'),b'\xc1\x01x',frame(b'{}',0)])
async def test_invalid_hello_or_frame_never_passes(data):
    reader=asyncio.StreamReader();reader.feed_data(data);reader.feed_eof()
    with pytest.raises((ValueError,asyncio.IncompleteReadError)):await hello(reader,Writer())

@pytest.mark.asyncio
async def test_api_success_does_not_hide_gateway_failure_or_disable_youtube():
    async def gateway(*args):return {'name':'Gateway','ok':False,'stage':'WebSocket Hello','error':'TimeoutError'}
    def http(request):
        if request.url.host=='www.youtube.com':return httpx.Response(204)
        if request.url.host=='cdn.discordapp.com':return httpx.Response(200,content=b'\x89PNG\r\n\x1a\n'+b'test',headers={'content-type':'image/png'})
        return httpx.Response(200,json={'url':'wss://gateway.discord.gg'})
    result=await probe.probe_async(1082,Control(),httpx.MockTransport(http),full_discord=True,gateway_check=gateway)
    assert result['passed']==1 and result['targets'][0]['ok']
    discord=result['targets'][1];assert discord['api_ok'] and discord['cdn_ok'] and not discord['gateway_ok']
    assert discord['stage']=='WebSocket Hello' and len(discord['parts'])==3
    async def working(*args):return {'name':'Gateway','ok':True,'stage':'WebSocket Hello','error':''}
    assert (await probe.probe_async(1082,Control(),httpx.MockTransport(http),full_discord=True,gateway_check=working))['complete']

@pytest.mark.asyncio
async def test_cdn_block_page_does_not_pass_even_with_working_gateway():
    async def gateway(*args):return {'name':'Gateway','ok':True,'stage':'WebSocket Hello','error':''}
    def http(request):
        if request.url.host=='www.youtube.com':return httpx.Response(204)
        if request.url.host=='cdn.discordapp.com':return httpx.Response(200,text='Access denied')
        return httpx.Response(200,json={'url':'wss://gateway.discord.gg'})
    result=await probe.probe_async(1082,Control(),httpx.MockTransport(http),full_discord=True,gateway_check=gateway)
    assert not result['targets'][1]['cdn_ok'] and result['targets'][1]['gateway_ok']

@pytest.mark.asyncio
async def test_hung_gateway_keeps_completed_api_and_cdn_diagnostics():
    closed=[]
    async def gateway(*args):
        try:await asyncio.Future()
        finally:closed.append(True)
    def http(request):
        if request.url.host=='www.youtube.com':return httpx.Response(204)
        if request.url.host=='cdn.discordapp.com':return httpx.Response(200,content=b'\x89PNG\r\n\x1a\n',headers={'content-type':'image/png'})
        return httpx.Response(200,json={'url':'wss://gateway.discord.gg'})
    result=await probe.probe_async(1082,Control(),httpx.MockTransport(http),timeout=.05,full_discord=True,gateway_check=gateway)
    assert result['targets'][1]['api_ok'] and result['targets'][1]['cdn_ok'] and closed==[True]

@pytest.mark.asyncio
async def test_missing_gateway_dns_preserves_verified_youtube(monkeypatch):
    class DNS:
        provider='Cloudflare'
        def __init__(self,port):pass
        async def resolve(self,host):return None if host=='gateway.discord.gg' else '8.8.4.4'
        async def close(self):pass
    def http(request):
        host=request.headers['host']
        if host=='www.youtube.com':return httpx.Response(204)
        if host=='cdn.discordapp.com':return httpx.Response(200,content=b'\x89PNG\r\n\x1a\n',headers={'content-type':'image/png'})
        return httpx.Response(200,json={'url':'wss://gateway.discord.gg'})
    monkeypatch.setattr(probe,'Resolver',DNS)
    monkeypatch.setattr(httpx,'AsyncHTTPTransport',lambda **kwargs:httpx.MockTransport(http))
    result=await probe.probe_async(1082,Control(),full_discord=True)
    assert result['passed']==1 and result['targets'][0]['ok']
    assert result['targets'][1]['parts'][1]['stage']=='DNS'


@pytest.mark.asyncio
async def test_probe_without_bootstrap_resolves_gateway_via_socks():
    destinations=[]
    async def gateway(port,address,verify,timeout):
        destinations.append((port,address))
        return {'name':'Gateway','ok':True,'stage':'WebSocket Hello','error':''}
    def http(request):
        if request.url.host=='www.youtube.com':return httpx.Response(204)
        if request.url.host=='cdn.discordapp.com':
            return httpx.Response(200,content=b'\x89PNG\r\n\x1a\n',headers={'content-type':'image/png'})
        return httpx.Response(200,json={'url':'wss://gateway.discord.gg'})
    result=await probe.probe_async(1082,Control(),httpx.MockTransport(http),
                                  bootstrap=False,full_discord=True,gateway_check=gateway)
    assert result['complete'] and destinations==[(1082,'gateway.discord.gg')]

@pytest.mark.asyncio
async def test_real_verified_wss_hello_through_both_native_engines(tmp_path):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'gateway.discord.gg')]);now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1))
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('gateway.discord.gg')]),False).sign(key,hashes.SHA256()))
    certfile=tmp_path/'cert.pem';keyfile=tmp_path/'key.pem'
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM));keyfile.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    server_ssl=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server_ssl.load_cert_chain(certfile,keyfile)
    client_ssl=ssl.create_default_context(cafile=str(certfile));mode=['good'];sni=[]
    server_ssl.set_servername_callback(lambda sock,host,ctx:sni.append(host))
    async def serve(reader,writer):
        try:
            request=await reader.readuntil(b'\r\n\r\n')
            assert b'Authorization:' not in request and b'Cookie:' not in request
            key=next(line.split(b':',1)[1].strip() for line in request.split(b'\r\n') if line.lower().startswith(b'sec-websocket-key:'))
            accept=base64.b64encode(hashlib.sha1(key+GUID.encode()).digest()) if mode[0]!='bad-accept' else b'wrong'
            writer.write(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+b'\r\n\r\n')
            writer.write(frame(HELLO if mode[0]!='bad-hello' else b'{"op":0}'));await writer.drain();await reader.read()
        except (OSError,asyncio.IncompleteReadError):pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):await writer.wait_closed()
    server=await asyncio.start_server(serve,'127.0.0.1',0,ssl=server_ssl);target=server.sockets[0].getsockname()[1]
    async with server:
        for binary,options in [('test-tpws',['--socks','--bind-addr=127.0.0.1','--tlsrec=sni','--split-pos=1,midsld']),
                               ('test-byedpi',['--ip','127.0.0.1','--disorder','1'])]:
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            native=subprocess.Popen([str(ROOT/'build'/binary),f'--port={port}',*options],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    try:
                        _,w=await asyncio.open_connection('127.0.0.1',port);w.close();await w.wait_closed();break
                    except OSError:await asyncio.sleep(.01)
                for scenario in ('good','bad-accept','bad-hello'):
                    mode[0]=scenario
                    result=await check_gateway(port,'127.0.0.1',client_ssl,target_port=target)
                    assert result['ok']==(scenario=='good'),result
                mode[0]='good'
                assert not (await check_gateway(port,'127.0.0.1',target_port=target))['ok']
            finally:native.terminate();native.wait(timeout=3)
    assert sni and all(host=='gateway.discord.gg' for host in sni)
