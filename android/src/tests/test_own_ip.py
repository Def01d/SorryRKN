"""Own-IP service routing uses canonical DNS and a real local DPI engine."""
import asyncio
import json
import socket
import subprocess
from pathlib import Path

import httpx
import pytest

import bridge_data
from gateway import Gateway
from smart_dns import SmartDNS
from extra_sites import TELEGRAM_WS_HOSTS
from traffic import Routes
from user_rules import DomainRules
from test_extra_sites import FakeDNS,query,setup_routes
from test_geo_route import tls

ROOT=Path(__file__).resolve().parents[1]


def bundled(tmp_path):
    (tmp_path/'bundled-data.json').write_bytes((ROOT/'app/src/main/assets/bundled-data.json').read_bytes())
    bridge_data.materialize(tmp_path)


@pytest.mark.asyncio
async def test_own_ip_never_creates_or_queries_comss_even_with_legacy_flag(monkeypatch,tmp_path):
    import smart_dns
    created=[]
    class Ordinary(FakeDNS):
        def __init__(self,port=None,**kwargs):
            assert 'providers' not in kwargs, 'Own-IP mode must not instantiate a relay resolver'
            super().__init__();created.append(self)
    monkeypatch.setattr(smart_dns,'Resolver',Ordinary)
    setup_routes(tmp_path)
    gateway=Gateway(port=0,directory=tmp_path,routes={
        'own_ip':True,'ai':1084,'smart_dns':True,'geo_domains':['custom.example'],
        'direct_domains':['auth.openai.com']})
    await gateway.start()
    try:
        resolver=gateway.resolver
        assert resolver.smart is None and len(created)==1
        for host in ('chatgpt.com','custom.example','auth.openai.com','www.youtube.com'):
            assert await resolver.query(query(host))
            assert await resolver.resolve(host)
        assert created[0].calls==[host for host in (
            'chatgpt.com','custom.example','auth.openai.com','www.youtube.com') for _ in range(2)]
        # Service HTTPS/SVCB hints cannot bypass local TLS processing, but a
        # user direct exception retains ordinary DNS answers and priority.
        assert await resolver.query(query('chatgpt.com',65))
        assert created[0].calls[-1]=='www.youtube.com'
        assert await resolver.query(query('auth.openai.com',65))
        assert created[0].calls[-1]=='auth.openai.com'
        assert gateway.routes.group('chatgpt.com')=='ai'
        assert gateway.routes.group('custom.example')=='ai'
        assert gateway.routes.group('auth.openai.com')=='direct'
    finally:await gateway.close()
    assert created[0].closed


@pytest.mark.parametrize('builtins',[False,True])
def test_local_extras_args_are_bounded_and_direct_exclusions_win(tmp_path,builtins):
    bundled(tmp_path)
    args=json.loads(bridge_data.extras_args('bye-disorder',tmp_path,True,
        json.dumps(['custom.example','chatgpt.com']),json.dumps(['chatgpt.com','skip.custom.example']),builtins))
    hosts=(tmp_path/'bye-extras-hosts.txt').read_text().splitlines()
    assert 'custom.example' in hosts and 'chatgpt.com' not in hosts
    assert ('instagram.com' in hosts)==builtins
    assert ('oaistatsig.com' in hosts)==builtins
    assert 'cloudflare.com' not in hosts and 'workos.com' not in hosts
    assert args[-1]=='--auto=none' and args.count('--auto=torst,ssl_err')==10
    assert all('bye-extras-hosts.txt' in a for a in args if a.startswith('--hosts='))
    routes=Routes(tmp_path,{'own_ip':True,'ai':1084,'instagram':1084,'builtin_extras':builtins,
                           'geo_domains':['custom.example','chatgpt.com'],
                           'direct_domains':['chatgpt.com','skip.custom.example']})
    assert routes.group('skip.custom.example')==routes.group('chatgpt.com')=='direct'
    assert routes.group('other.custom.example')=='ai'
    with pytest.raises(ValueError):
        bridge_data.extras_args('bye-disorder',tmp_path,True,'["--bad-option"]','[]',builtins)


def test_telegram_only_filter_uses_official_websocket_names_and_respects_direct_rules(tmp_path):
    bundled(tmp_path)
    bridge_data.extras_args('bye-disorder',tmp_path,True,'[]','["kws2.web.telegram.org"]',False,True)
    hosts=(tmp_path/'bye-extras-hosts.txt').read_text().splitlines()
    assert set(hosts)==set(TELEGRAM_WS_HOSTS)-{'kws2.web.telegram.org'}
    assert len(hosts)==9 and 'telegram.org' not in hosts and 'web.telegram.org' not in hosts


@pytest.mark.asyncio
async def test_own_ip_chatgpt_uses_real_byedpi_and_verified_tls_without_relay(tmp_path,monkeypatch,tls):
    bundled(tmp_path)
    options=json.loads(bridge_data.extras_args('bye-tls',tmp_path,False))
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));native_port=sock.getsockname()[1]
    native=subprocess.Popen([str(ROOT/'build/test-byedpi'),'--ip','127.0.0.1',
        f'--port={native_port}',*options],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    requests=[];names=[];tasks=set()
    tls[0].set_servername_callback(lambda sock,name,context:names.append(name))
    async def origin(reader,writer):
        task=asyncio.current_task();tasks.add(task)
        try:
            requests.append(await reader.readuntil(b'\r\n\r\n'))
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nworking')
            await writer.drain()
        except (OSError,asyncio.IncompleteReadError):pass
        finally:writer.close();await writer.wait_closed();tasks.discard(task)
    server=await asyncio.start_server(origin,'127.0.0.1',0,ssl=tls[0]);port=server.sockets[0].getsockname()[1]
    monkeypatch.setattr(Routes,'inspect_ports',Routes.inspect_ports|{port})
    gateway=Gateway(port=0,directory=tmp_path,routes={'own_ip':True,'ai':native_port})
    await gateway.start()
    resolved=[]
    async def canonical(host):resolved.append(host);return '127.0.0.1'
    async def forbidden_relay(*args,**kwargs):raise AssertionError('Comss relay used in own-IP mode')
    gateway.resolver.normal.resolve=canonical
    gateway.geo.connect=forbidden_relay
    try:
        for _ in range(100):
            try:
                _,writer=await asyncio.open_connection('127.0.0.1',native_port);writer.close();await writer.wait_closed();break
            except OSError:await asyncio.sleep(.01)
        else:pytest.fail('Native ByeDPI did not start')
        assert gateway.resolver.smart is None
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(
            proxy=f'socks5://127.0.0.1:{gateway.port}',verify=tls[1],trust_env=False),trust_env=False,timeout=3) as client:
            assert (await client.get(f'https://chatgpt.com:{port}/public-test')).text=='working'
            assert len(requests)==1 and requests[0].startswith(b'GET /public-test HTTP/1.1\r\n')
            assert b'\r\nHost: chatgpt.com:'+str(port).encode()+b'\r\n' in requests[0]
            # Stopping only the native listener must break selected traffic,
            # proving the successful HTTPS request actually traversed it.
            native.terminate();native.wait(timeout=3)
            with pytest.raises(httpx.HTTPError):await client.get(f'https://chatgpt.com:{port}/must-not-arrive')
            gateway.routes.rules.direct=('chatgpt.com',)
            assert (await client.get(f'https://chatgpt.com:{port}/direct-exception')).text=='working'
        assert names==['chatgpt.com','chatgpt.com'] and len(requests)==2
        assert gateway.stats['ai_tcp']==1 and gateway.stats['direct_tcp']==1
        assert gateway.stats['geo_attempts']==gateway.stats['geo_retries']==0
        assert resolved==['chatgpt.com']*3
    finally:
        await gateway.close();server.close();await server.wait_closed()
        await asyncio.gather(*list(tasks),return_exceptions=True)
        if native.poll() is None:native.terminate();native.wait(timeout=3)
