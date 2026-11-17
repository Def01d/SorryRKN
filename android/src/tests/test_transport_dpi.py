"""Real native ByeDPI against a TCP endpoint which drops unsplit TLS hellos."""
import asyncio
import contextlib
import datetime
import json
from pathlib import Path
import socket
import ssl
import subprocess

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from bridge_data import transport_args
from doh import Resolver
from gateway import Gateway
from traffic import Routes
from test_doh import QUERY, answer
from test_extra_sites import setup_routes


@contextlib.asynccontextmanager
async def blocked_tls(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'chatgpt.com')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
            .not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.SubjectAlternativeName([
                x509.DNSName('chatgpt.com'), x509.DNSName('dns.fixture.test')]), False).sign(key, hashes.SHA256()))
    cp, kp = tmp_path/'tls.pem', tmp_path/'tls.key'
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server_ssl.load_cert_chain(cp, kp)
    client_ssl = ssl.create_default_context(cafile=str(cp))
    state = {'blocked': 0, 'fragmented': 0, 'requests': [], 'names': [], 'active': set()}
    server_ssl.set_servername_callback(lambda sock, host, ctx: state['names'].append(host))

    async def close(writer):
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), .3)

    async def http(reader, writer):
        task = asyncio.current_task(); state['active'].add(task)
        task.add_done_callback(state['active'].discard)
        try:
            headers = await reader.readuntil(b'\r\n\r\n'); state['requests'].append(headers)
            if headers.startswith(b'POST /dns-query '):
                length = int(next(line.split(b':', 1)[1] for line in headers.split(b'\r\n')
                                  if line.lower().startswith(b'content-length:')))
                body = answer(await reader.readexactly(length))
            elif b'/api/auth/providers ' in headers:
                body = b'{"openai":{"id":"openai","type":"oauth"}}'
            else:
                body = b'working'
            writer.write(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
            await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            await close(writer); state['active'].discard(task)

    upstream = await asyncio.start_server(http, '127.0.0.1', 0, ssl=server_ssl)
    remote_port = upstream.sockets[0].getsockname()[1]
    async def pipe(reader, writer):
        while data := await reader.read(65536):
            writer.write(data); await writer.drain()

    async def gate(reader, writer):
        task = asyncio.current_task(); state['active'].add(task)
        task.add_done_callback(state['active'].discard)
        remote = None; pipes = []
        try:
            header = await reader.readexactly(5)
            payload = await reader.readexactly(int.from_bytes(header[3:5], 'big'))
            assert header[:2] == b'\x16\x03'
            if len(payload) >= 4+int.from_bytes(payload[1:4], 'big'):
                state['blocked'] += 1
                await reader.read()  # TCP succeeds, then no TLS response.
                return
            state['fragmented'] += 1
            incoming, remote = await asyncio.open_connection('127.0.0.1', remote_port)
            remote.write(header+payload); await remote.drain()
            pipes = [asyncio.create_task(pipe(reader, remote)), asyncio.create_task(pipe(incoming, writer))]
            await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            for pending in pipes: pending.cancel()
            await asyncio.gather(*pipes, return_exceptions=True)
            if remote: await close(remote)
            await close(writer); state['active'].discard(task)

    endpoint = await asyncio.start_server(gate, '127.0.0.1', 0)
    port = endpoint.sockets[0].getsockname()[1]
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); dpi_port = sock.getsockname()[1]
    native = subprocess.Popen([str(Path('build/test-byedpi').resolve()), '--ip', '127.0.0.1', '--port', str(dpi_port),
                               *json.loads(transport_args())], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            assert native.poll() is None, 'production transport arguments rejected by ByeDPI'
            try:
                _, writer = await asyncio.open_connection('127.0.0.1', dpi_port); await close(writer); break
            except OSError: await asyncio.sleep(.02)
        else: raise AssertionError('native transport listener not ready')
        monkeypatch.setattr('doh.verified_context', lambda: client_ssl)
        monkeypatch.setattr('gateway.verified_context', lambda: client_ssl)
        yield port, dpi_port, client_ssl, state
    finally:
        native.terminate(); await asyncio.to_thread(native.wait, 3)
        for server in (endpoint, upstream): server.close()
        for task in list(state['active']): task.cancel()
        if state['active']:
            await asyncio.wait_for(asyncio.gather(*list(state['active']), return_exceptions=True), 2)
        for server in (endpoint, upstream): await server.wait_closed()
        assert not state['active']


@pytest.mark.asyncio
async def test_verified_doh_recovers_when_tcp_works_but_direct_tls_is_dropped(tmp_path, monkeypatch):
    async with blocked_tls(tmp_path, monkeypatch) as (port, dpi_port, _, state):
        resolver = Resolver(None, providers=(('fixture', f'dns.fixture.test:{port}', '127.0.0.1'),), fallback_port=dpi_port)
        try:
            assert await asyncio.wait_for(resolver.query(QUERY), 4) == answer()
            assert resolver.provider == 'fixture · DPI'
            assert state['blocked'] == 1 and state['fragmented'] == 1
            assert state['names'] == ['dns.fixture.test']
            assert await resolver.resolve('www.youtube.com') == '8.8.4.4'
            assert len(state['requests']) == 1  # TTL cache; no additional DNS disclosure.
            resolver.invalidate('www.youtube.com')
            assert not resolver.cache and not resolver.fallback.cache
        finally: await resolver.close()


@pytest.mark.asyncio
async def test_chatgpt_probe_and_opaque_application_tls_use_native_dpi(tmp_path, monkeypatch):
    async with blocked_tls(tmp_path, monkeypatch) as (port, dpi_port, verify, state):
        setup_routes(tmp_path)
        monkeypatch.setattr('gateway.AI_ROUTE_URL', f'https://chatgpt.com:{port}/api/auth/providers')
        monkeypatch.setattr(Routes, 'inspect_ports', Routes.inspect_ports | {port})
        gateway = Gateway(port=0, directory=tmp_path, routes={'smart_dns': True, 'transport_dpi': dpi_port})
        await gateway.start()
        async def resolve(host):
            gateway.resolver.smart.last_addresses[host] = ['127.0.0.1']
            return '127.0.0.1'
        gateway.resolver.resolve = resolve
        try:
            result = await asyncio.wait_for(gateway.check_ai_route(), 4)
            assert result['verified'] and result['selected_route'] == 'dpi'
            assert not result['authenticated_access']
            transport = httpx.AsyncHTTPTransport(proxy=f'socks5://127.0.0.1:{gateway.port}', verify=verify, trust_env=False)
            async with httpx.AsyncClient(transport=transport, trust_env=False, timeout=4) as client:
                assert (await client.post(f'https://chatgpt.com:{port}/application-once', content=b'opaque-request')).text == 'working'
            assert gateway.stats['geo_last_route'] == 'dpi'
            assert len([r for r in state['requests'] if b'/application-once ' in r]) == 1
            assert state['blocked'] >= 1 and state['fragmented'] == 2
            assert set(state['names']) == {'chatgpt.com'}
        finally: await gateway.close()


@pytest.mark.asyncio
async def test_dns_cancellation_closes_direct_and_protected_sockets(tmp_path, monkeypatch):
    async with blocked_tls(tmp_path, monkeypatch) as (port, dpi_port, _, state):
        resolver = Resolver(None, providers=(('fixture', f'dns.fixture.test:{port}', '127.0.0.1'),), fallback_port=dpi_port)
        task = asyncio.create_task(resolver.query(QUERY))
        while not state['blocked']: await asyncio.sleep(.005)
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        await resolver.close()
        assert not resolver.inflight and not resolver.fallback.inflight


def test_transport_starts_with_the_strategy_verified_on_current_network():
    args = json.loads(transport_args('bye-fake-4'))
    first = args[:args.index('--auto=torst,ssl_err')]
    assert first[-6:] == ['--fake', '-1', '--ttl', '4', '--fake-sni', 'www.google.com']
    assert '--hosts' not in args and '--proto' in args


@pytest.mark.asyncio
async def test_protected_dns_does_not_accept_an_untrusted_certificate(tmp_path, monkeypatch):
    async with blocked_tls(tmp_path, monkeypatch) as (port, dpi_port, _, state):
        monkeypatch.setattr('doh.verified_context', ssl.create_default_context)
        resolver = Resolver(None, providers=(('fixture', f'dns.fixture.test:{port}', '127.0.0.1'),), fallback_port=dpi_port)
        try:
            assert await asyncio.wait_for(resolver.query(QUERY), 5) is None
            assert not state['requests'] and not resolver.cache
            assert state['fragmented'] >= 1
        finally: await resolver.close()
