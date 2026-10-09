"""DNS fallback, cancellation, wire parsing, and TLS identity after IP pinning."""
import asyncio
import contextlib
import datetime
import ssl
import struct
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from doh import Resolver, PinnedTransport, valid_answer, ipv4_answers
import strategy_probe

QUERY=struct.pack('!6H',0x1234,0x0100,1,0,0,0)+b'\x03www\x07youtube\x03com\0\0\x01\0\x01'

def answer(query=QUERY,flags=0x8180):
    return query[:2]+struct.pack('!5H',flags,1,1,0,0)+query[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+b'\x08\x08\x04\x04'

@pytest.mark.parametrize('flags',[0x0100,0x8380,0x8182,0x8185])
def test_invalid_dns_flags(flags):
    assert not valid_answer(QUERY,answer(flags=flags))

def test_dns_names_ids_lengths_and_public_addresses():
    good=answer()
    assert valid_answer(QUERY,good)
    assert ipv4_answers(QUERY,good)==['8.8.4.4']
    assert not valid_answer(QUERY,b'\0\0'+good[2:])
    assert not ipv4_answers(QUERY,good[:-1])
    assert not ipv4_answers(QUERY,good[:-4]+b'\x7f\0\0\x01')
    assert not ipv4_answers(QUERY,good[:12]+b'\xc0\x0c'+good[14:]) # pointer loop
    other=bytearray(good); other[13:16]=b'bad'
    assert not ipv4_answers(QUERY,other)

@pytest.mark.asyncio
async def test_blocked_google_races_fallback_and_closes_loser():
    calls=[]; cancelled=[]
    async def handle(request):
        host=request.headers['host']; calls.append(host)
        assert request.url.host in ('8.8.8.8','1.1.1.1','9.9.9.9')
        assert request.extensions['sni_hostname']==host
        if host=='dns.google': return httpx.Response(503)
        if host=='dns.quad9.net':
            try: await asyncio.Future()
            finally: cancelled.append(host)
        return httpx.Response(200,content=answer(request.content))
    resolver=Resolver(1080,httpx.MockTransport(handle))
    try:
        assert await asyncio.wait_for(resolver.query(QUERY),.5)==answer()
        assert resolver.provider=='Cloudflare'
        assert cancelled==['dns.quad9.net']
        calls.clear()
        assert await resolver.resolve('www.youtube.com')=='8.8.4.4'
        assert calls==[]  # Positive TTL cache also serves resolve() with a new ID.
    finally: await resolver.close()

@pytest.mark.asyncio
async def test_preferred_failure_uses_other_provider():
    async def handle(request):
        return httpx.Response(502) if request.url.host=='1.1.1.1' else httpx.Response(200,content=answer(request.content))
    resolver=Resolver(1080,httpx.MockTransport(handle)); resolver.preferred=('Cloudflare','cloudflare-dns.com','1.1.1.1')
    try:
        assert await resolver.query(QUERY)==answer()
        assert resolver.provider in ('Google','Quad9')
    finally: await resolver.close()

@pytest.mark.asyncio
async def test_servfail_and_wrong_id_do_not_count_as_success():
    async def handle(request):
        if request.url.host=='1.1.1.1': return httpx.Response(200,content=b'\0\0'+answer()[2:])
        return httpx.Response(200,content=answer(flags=0x8182))
    resolver=Resolver(1080,httpx.MockTransport(handle))
    try:
        assert await resolver.query(QUERY) is None
        assert resolver.provider==''
    finally: await resolver.close()

@pytest.mark.asyncio
async def test_cancellation_releases_all_dns_requests():
    entered=[]; exited=[]
    async def handle(request):
        entered.append(request.url.host)
        try: await asyncio.Future()
        finally: exited.append(request.url.host)
    resolver=Resolver(1080,httpx.MockTransport(handle))
    task=asyncio.create_task(resolver.query(QUERY))
    await asyncio.sleep(.05); task.cancel()
    with pytest.raises(asyncio.CancelledError): await task
    assert len(entered)==3 and sorted(entered)==sorted(exited)
    await resolver.close()

@pytest.mark.asyncio
async def test_pinned_ip_preserves_verified_hostname_host_and_sni(tmp_path):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'dns.google')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
          .not_valid_after(now+datetime.timedelta(days=1)).add_extension(
              x509.SubjectAlternativeName([x509.DNSName('dns.google')]),False).sign(key,hashes.SHA256()))
    certfile=tmp_path/'cert.pem'; keyfile=tmp_path/'key.pem'
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    server_ssl=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server_ssl.load_cert_chain(certfile,keyfile)
    client_ssl=ssl.create_default_context(cafile=str(certfile)); names=[]; headers=[]
    server_ssl.set_servername_callback(lambda sock,hostname,ctx:names.append(hostname))
    async def serve(reader,writer):
        try:
            headers.append(await reader.readuntil(b'\r\n\r\n'))
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'); await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(OSError): await writer.wait_closed()
    server=await asyncio.start_server(serve,'127.0.0.1',0,ssl=server_ssl); port=server.sockets[0].getsockname()[1]
    async with server:
        for host,verify,success in [('dns.google',client_ssl,True),('wrong.invalid',client_ssl,False),('dns.google',True,False)]:
            transport=PinnedTransport(httpx.AsyncHTTPTransport(verify=verify,trust_env=False),{host:'127.0.0.1'})
            async with httpx.AsyncClient(transport=transport,trust_env=False) as client:
                if success: assert (await client.get(f'https://{host}:{port}/dns-query')).text=='OK'
                else:
                    with pytest.raises(httpx.ConnectError): await client.get(f'https://{host}:{port}/dns-query')
    assert names[0]=='dns.google'
    assert f'Host: dns.google:{port}'.encode() in headers[0]

@pytest.mark.asyncio
async def test_strategy_probe_uses_doh_ips_and_original_tls_names(monkeypatch):
    names=[]; requests=[]; closed=[]
    class DNS:
        provider='Cloudflare'
        def __init__(self,port): assert port==1082
        async def resolve(self,host): names.append(host); return '8.8.4.4'
        async def close(self): closed.append(True)
    async def handle(request):
        requests.append(request)
        assert request.url.host=='8.8.4.4'
        assert request.extensions['sni_hostname']==request.headers['host']
        return httpx.Response(204) if request.headers['host']=='www.youtube.com' else httpx.Response(200,json={'url':'wss://gateway.discord.gg'})
    class Control:
        def keepRunning(self): return True
    monkeypatch.setattr(strategy_probe,'Resolver',DNS)
    monkeypatch.setattr(httpx,'AsyncHTTPTransport',lambda **kwargs:httpx.MockTransport(handle))
    result=await strategy_probe.probe_async(1082,Control())
    assert result['complete'] and result['dns']['ok']
    assert result['dns']['provider']=='Cloudflare'
    assert result['dns']['resolved']==result['dns']['total']==2
    assert set(names)=={'www.youtube.com','discord.com'}
    assert len(requests)==2 and closed==[True]

@pytest.mark.asyncio
async def test_cancel_selection_during_dns_cleans_up(monkeypatch):
    exits=[]; closed=[]
    class DNS:
        provider=''
        def __init__(self,port): pass
        async def resolve(self,host):
            try: await asyncio.Future()
            finally: exits.append(host)
        async def close(self): closed.append(True)
    class Control:
        running=True
        def keepRunning(self): return self.running
    monkeypatch.setattr(strategy_probe,'Resolver',DNS)
    control=Control(); task=asyncio.create_task(strategy_probe.probe_async(1082,control))
    await asyncio.sleep(.06); control.running=False
    with pytest.raises(asyncio.CancelledError): await asyncio.wait_for(task,.5)
    assert len(exits)==2 and closed==[True]
