"""Alternate ChatGPT DNS addresses, real verified TLS, and no request replay."""
import asyncio,contextlib,datetime,ipaddress,ssl,struct
from pathlib import Path
import httpx,pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from gateway import Gateway
from geo_route import GeoRoutes,GeoRouteError,client_hello_only
from smart_dns import SmartDNS,COMSS
from doh import Resolver
from traffic import Routes
from test_extra_sites import query,setup_routes,answer
from test_traffic import hello

@pytest.fixture
def tls(tmp_path):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'chatgpt.com')]);now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
        .not_valid_after(now+datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('chatgpt.com')]),False).sign(key,hashes.SHA256()))
    cp=tmp_path/'cert.pem';kp=tmp_path/'key.pem';cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server.load_cert_chain(cp,kp)
    return server,ssl.create_default_context(cafile=str(cp))

@contextlib.asynccontextmanager
async def chatgpt_gateway(tmp_path,monkeypatch,tls,mode='silent'):
    setup_routes(tmp_path);requests=[];hellos=[];names=[];tasks=set()
    tls[0].set_servername_callback(lambda sock,name,ctx:names.append(name))
    async def good(reader,writer):
        task=asyncio.current_task();tasks.add(task)
        try:
            request=await reader.readuntil(b'\r\n\r\n');requests.append(request)
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nworking');await writer.drain()
        except (OSError,asyncio.IncompleteReadError):pass
        finally:writer.close();await writer.wait_closed();tasks.discard(task)
    second=await asyncio.start_server(good,'127.0.0.1',0,ssl=tls[0]);port=second.sockets[0].getsockname()[1]
    async def bad(reader,writer):
        task=asyncio.current_task();tasks.add(task)
        try:
            hellos.append(await reader.read(16384))
            if mode=='alert':writer.write(b'\x15\x03\x03\0\x02\x02\x50');await writer.drain()
            await reader.read()
        finally:writer.close();await writer.wait_closed();tasks.discard(task)
    first=await asyncio.start_server(bad,'127.0.0.2',port)if mode!='refused' else None
    monkeypatch.setattr(Routes,'inspect_ports',Routes.inspect_ports|{port})
    monkeypatch.setattr('gateway.TLS_FIRST_REPLY_TIMEOUT',.08)
    gateway=Gateway(port=0,directory=tmp_path,routes={'smart_dns':True});await gateway.start()
    invalidated=[]
    async def resolve(name):return '127.0.0.2'
    gateway.resolver.resolve=resolve;gateway.resolver.candidates=lambda host,first:[first,'127.0.0.1']
    gateway.resolver.invalidate=invalidated.append
    try:yield gateway,port,requests,hellos,names,invalidated
    finally:
        await gateway.close();second.close();await second.wait_closed()
        if first:first.close();await first.wait_closed()
        await asyncio.gather(*list(tasks),return_exceptions=True)

@pytest.mark.asyncio
@pytest.mark.parametrize('mode',['silent','alert','refused'])
async def test_second_dns_endpoint_serves_verified_chatgpt_and_failed_address_is_deprioritized(tmp_path,monkeypatch,tls,mode):
    async with chatgpt_gateway(tmp_path,monkeypatch,tls,mode)as (gw,port,requests,hellos,names,invalidated):
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(proxy=f'socks5://127.0.0.1:{gw.port}',verify=tls[1],trust_env=False),trust_env=False)as client:
            for _ in range(2):assert (await client.get(f'https://chatgpt.com:{port}/test')).text=='working'
        assert len(requests)==2 and all(b'GET /test HTTP/1.1' in r for r in requests)
        assert names==['chatgpt.com','chatgpt.com']
        assert len(hellos)==(0 if mode=='refused' else 1)
        assert all(client_hello_only(h) for h in hellos)
        assert gw.stats['geo_attempts']==3 and gw.stats['geo_retries']==1 and gw.stats['geo_failures']==1
        assert gw.stats['ai_tcp']==2 and not invalidated

@pytest.mark.asyncio
async def test_production_fallback_finishes_before_five_second_client_timeout(tmp_path,monkeypatch,tls):
    async with chatgpt_gateway(tmp_path,monkeypatch,tls,'silent')as (gw,port,*rest):
        monkeypatch.setattr('gateway.TLS_FIRST_REPLY_TIMEOUT',10.0)
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(proxy=f'socks5://127.0.0.1:{gw.port}',verify=tls[1],trust_env=False),timeout=5,trust_env=False)as client:
            assert (await client.get(f'https://chatgpt.com:{port}/test')).text=='working'
        assert gw.stats['geo_retries']==1

@pytest.mark.asyncio
async def test_dns_fallback_does_not_weaken_real_certificate_verification(tmp_path,monkeypatch,tls):
    async with chatgpt_gateway(tmp_path,monkeypatch,tls,'refused')as (gw,port,*rest):
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(proxy=f'socks5://127.0.0.1:{gw.port}',verify=True,trust_env=False),trust_env=False)as client:
            with pytest.raises(httpx.ConnectError):await client.get(f'https://chatgpt.com:{port}/test')
        assert gw.stats['geo_retries']==1

@pytest.mark.asyncio
async def test_all_comss_dns_answers_preserved_and_invalidation_clears_candidates():
    async def handle(request):
        q=await request.aread();first=answer(q)
        return httpx.Response(200,content=first[:6]+b'\0\x02'+first[8:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,120,4)+ipaddress.IPv4Address('8.8.4.4').packed)
    selected=Resolver(None,httpx.MockTransport(handle),providers=COMSS)
    normal=Resolver(None,httpx.MockTransport(handle));resolver=SmartDNS(normal=normal,smart=selected)
    try:
        first=await resolver.resolve('chatgpt.com');assert first=='93.184.216.34'
        assert resolver.candidates('chatgpt.com',first)==['93.184.216.34','8.8.4.4']
        resolver.invalidate('chatgpt.com');assert not selected.last_addresses
        assert resolver.candidates('chatgpt.com',first)==[first]
    finally:await resolver.close()

@pytest.mark.parametrize('tail',[b'',b'\x14\x03\x03\0\x01\x01',b'\x17\x03\x03\0\x03abc'])
def test_retry_is_restricted_to_initial_handshake_without_application_data(tail):
    payload=hello('chatgpt.com');assert client_hello_only(payload+tail)==(not tail or tail[0]==20)
    assert not client_hello_only(payload[:-1])
    assert not client_hello_only(b'POST /api HTTP/1.1\r\nHost: chatgpt.com\r\n\r\nmessage')

@pytest.mark.asyncio
async def test_early_data_is_not_replayed_to_another_address(monkeypatch):
    payload=hello('chatgpt.com')+b'\x17\x03\x03\0\x04data';seen=[];handlers=set()
    async def silent(reader,writer):
        handlers.add(asyncio.current_task())
        try:seen.append(await reader.readexactly(len(payload)));await reader.read()
        finally:writer.close();await writer.wait_closed();handlers.discard(asyncio.current_task())
    server=await asyncio.start_server(silent,'127.0.0.1',0);port=server.sockets[0].getsockname()[1]
    stats=dict(geo_attempts=0,geo_retries=0,geo_failures=0,tx_bytes=0);routes=GeoRoutes(stats);invalidated=[]
    try:
        with pytest.raises(GeoRouteError):await routes.connect('chatgpt.com',['127.0.0.1','127.0.0.2'],port,payload,.05,invalidated.append)
        assert seen==[payload]and stats['geo_attempts']==1 and stats['geo_retries']==0
        assert invalidated==['chatgpt.com']
    finally:server.close();await server.wait_closed();await asyncio.gather(*list(handlers),return_exceptions=True)

@pytest.mark.asyncio
async def test_cancellation_releases_failed_endpoint_socket_without_cooldown():
    entered=asyncio.Event();finished=asyncio.Event();payload=hello('chatgpt.com')
    async def silent(reader,writer):
        try:await reader.readexactly(len(payload));entered.set();await reader.read()
        finally:writer.close();await writer.wait_closed();finished.set()
    server=await asyncio.start_server(silent,'127.0.0.1',0);port=server.sockets[0].getsockname()[1]
    routes=GeoRoutes(dict(geo_attempts=0,geo_retries=0,geo_failures=0,tx_bytes=0))
    task=asyncio.create_task(routes.connect('chatgpt.com',['127.0.0.1'],port,payload,10,lambda host:None))
    try:
        await entered.wait();task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
        await asyncio.wait_for(finished.wait(),1);assert not routes.failed
    finally:server.close();await server.wait_closed()
