"""Select ChatGPT relay endpoints with synthetic, certificate-verified HTTPS."""
import asyncio
import contextlib

import httpx
import pytest

from gateway import Gateway
from traffic import Routes
from test_extra_sites import setup_routes
from test_geo_route import tls


PROVIDERS = b'{"openai":{"id":"openai","type":"oauth"}}'


@contextlib.asynccontextmanager
async def endpoints(tmp_path, monkeypatch, tls, good_body=PROVIDERS, silent=False):
    setup_routes(tmp_path)
    requests = []
    names = []
    handlers = set()
    closed = asyncio.Event()
    tls[0].set_servername_callback(lambda sock, name, ctx: names.append(name))

    async def serve(reader, writer):
        task = asyncio.current_task()
        handlers.add(task)
        local = writer.get_extra_info('sockname')[0]
        try:
            request = await reader.readuntil(b'\r\n\r\n')
            requests.append((local, request))
            if silent:
                await reader.read()
                return
            body = good_body if local == '127.0.0.1' else b'Just a moment'
            status = b'200 OK' if local == '127.0.0.1' else b'403 Forbidden'
            headers = b'' if local == '127.0.0.1' else b'Cf-Mitigated: challenge\r\n'
            writer.write(b'HTTP/1.1 ' + status + b'\r\n' + headers + b'Content-Length: ' +
                         str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
            await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            handlers.discard(task)
            closed.set()

    good = await asyncio.start_server(serve, '127.0.0.1', 0, ssl=tls[0])
    port = good.sockets[0].getsockname()[1]
    bad = await asyncio.start_server(serve, '127.0.0.2', port, ssl=tls[0])
    monkeypatch.setattr('gateway.AI_ROUTE_URL', f'https://chatgpt.com:{port}/api/auth/providers')
    monkeypatch.setattr('gateway.verified_context', lambda: tls[1])
    monkeypatch.setattr(Routes, 'inspect_ports', Routes.inspect_ports | {port})
    gateway = Gateway(port=0, directory=tmp_path, routes={'smart_dns': True})
    await gateway.start()

    async def resolve(host):
        assert host == 'chatgpt.com'
        gateway.resolver.smart.last_addresses[host] = ['127.0.0.2', '127.0.0.1']
        return '127.0.0.2'

    gateway.resolver.resolve = resolve
    try:
        yield gateway, port, requests, names, closed
    finally:
        await gateway.close()
        for server in (good, bad):
            server.close()
            await server.wait_closed()
        await asyncio.gather(*list(handlers), return_exceptions=True)


@pytest.mark.asyncio
async def test_verified_tls_candidate_pins_future_gateway_connections_and_caches_probe(tmp_path, monkeypatch, tls):
    async with endpoints(tmp_path, monkeypatch, tls) as (gateway, port, requests, names, _):
        result = await gateway.check_ai_route()
        assert result['verified'] and result['state'] == 'verified_public'
        assert not result['authenticated_access']
        assert result['selected_address'] == '127.0.0.1'
        assert gateway.resolver.candidates('chatgpt.com', '127.0.0.2') == ['127.0.0.1', '127.0.0.2']
        count = len(requests)
        cached = await gateway.check_ai_route()
        assert cached['cached'] and len(requests) == count
        cached['candidates'].clear()
        assert gateway.ai_route_check['candidates']
        transport = httpx.AsyncHTTPTransport(proxy=f'socks5://127.0.0.1:{gateway.port}', verify=tls[1], trust_env=False)
        async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
            response = await client.get(f'https://chatgpt.com:{port}/real-application-request')
        assert response.status_code == 200
        application = [(address, request) for address, request in requests if b'/real-application-request ' in request]
        assert len(application) == 1 and application[0][0] == '127.0.0.1'
        assert names and set(names) == {'chatgpt.com'}
        assert all(f'Host: chatgpt.com:{port}\r\n'.encode() in request for _, request in requests)
        assert all(b'Cookie:' not in request and b'Authorization:' not in request for _, request in requests)
        gateway.resolver.invalidate('chatgpt.com')
        assert gateway.resolver.preferred('chatgpt.com') is None


@pytest.mark.asyncio
@pytest.mark.parametrize('body', [b'{}', b'[]', b'<html>success</html>', b'{"openai":{"id":"openai","type":"password"}}'])
async def test_http200_without_real_oauth_providers_never_verifies(tmp_path, monkeypatch, tls, body):
    async with endpoints(tmp_path, monkeypatch, tls, good_body=body) as (gateway, *_):
        result = await gateway.check_ai_route()
        assert not result['verified'] and result['state'] == 'challenge'
        assert not gateway.resolver.preferences
        assert {value['state'] for value in result['candidates']} == {'challenge', 'invalid_response'}


@pytest.mark.asyncio
async def test_relay_probe_never_accepts_untrusted_tls_certificate(tmp_path, monkeypatch, tls):
    from doh import verified_context
    async with endpoints(tmp_path, monkeypatch, tls) as (gateway, *_):
        monkeypatch.setattr('gateway.verified_context', verified_context)
        result = await gateway.check_ai_route()
        assert not result['verified'] and not gateway.resolver.preferences
        assert all(candidate['state'] == 'transport_error' for candidate in result['candidates'])


@pytest.mark.asyncio
async def test_total_timeout_cancels_real_tls_probe_sockets(tmp_path, monkeypatch, tls):
    async with endpoints(tmp_path, monkeypatch, tls, silent=True) as (gateway, _, requests, _, closed):
        monkeypatch.setattr('gateway.AI_ROUTE_TIMEOUT', .3)
        result = await asyncio.wait_for(gateway.check_ai_route(), 1)
        assert result['state'] == 'timeout' and not result['verified']
        assert requests and not gateway.resolver.preferences
        await asyncio.wait_for(closed.wait(), 1)
        assert gateway._ai_route_task is None


@pytest.mark.asyncio
async def test_close_cancels_probe_and_discards_endpoint_pins(tmp_path, monkeypatch, tls):
    async with endpoints(tmp_path, monkeypatch, tls, silent=True) as (gateway, _, requests, _, closed):
        task = asyncio.create_task(gateway.check_ai_route())
        async with asyncio.timeout(2):
            while not requests:
                await asyncio.sleep(.01)
        await gateway.close()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert (await gateway.check_ai_route())['state'] == 'disabled'
        await asyncio.wait_for(closed.wait(), 1)
        assert gateway.ai_route_check is None and not gateway.resolver.preferences


@pytest.mark.asyncio
@pytest.mark.parametrize('routes', [{'own_ip': True, 'builtin_extras': True}, {'smart_dns': True, 'direct_domains': ['chatgpt.com']}])
async def test_explicit_own_ip_and_direct_rules_disable_relay_probe(tmp_path, monkeypatch, routes):
    setup_routes(tmp_path)
    gateway = Gateway(port=0, directory=tmp_path, routes=routes)
    await gateway.start()
    async def forbidden(address):
        raise AssertionError('relay must not be contacted')
    gateway._check_ai_candidate = forbidden
    try:
        assert (await gateway.check_ai_route())['state'] == 'disabled'
    finally:
        await gateway.close()
