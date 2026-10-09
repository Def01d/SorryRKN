"""Actual verified SOCKS/TLS and bounded public-page diagnostic behaviour."""
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

import service_probe as probe


class Body(httpx.AsyncByteStream):
    def __init__(self, data):
        self.data = data
        self.closed = False
        self.reads = 0

    async def __aiter__(self):
        self.reads += 1
        yield self.data

    async def aclose(self):
        self.closed = True


def intercept(monkeypatch, status=200, content=b'<html>ChatGPT</html>', headers=None, stream=None):
    stream = stream or Body(content)
    requests = []
    async def respond(request):
        requests.append(request)
        return httpx.Response(status, headers=headers or {}, stream=stream)
    def transport(**kwargs):
        assert kwargs['proxy'] == 'socks5://127.0.0.1:12345'
        assert kwargs['verify'].verify_mode == ssl.CERT_REQUIRED
        assert kwargs['verify'].check_hostname
        assert kwargs['trust_env'] is False
        assert kwargs['retries'] == 0
        return httpx.MockTransport(respond)
    monkeypatch.setattr(probe.httpx, 'AsyncHTTPTransport', transport)
    return requests, stream


@pytest.mark.asyncio
@pytest.mark.parametrize('status,body,headers,expected', [
    (200, b'<html>ChatGPT</html>', {}, 'reachable_public'),
    (403, b'{"error":{"code":"unsupported_country_region_territory"}}', {}, 'regional_refusal'),
    (403, b'{"error":{"message":"Country, region, or territory not supported"}}', {}, 'regional_refusal'),
    (200, b"<h1>OpenAI's services are not available in your country</h1>", {}, 'regional_refusal'),
    (403, b'<title>Just a moment</title><script src="/cdn-cgi/challenge-platform/a.js"></script>', {}, 'challenge'),
    (403, b'Forbidden', {'cf-mitigated': 'challenge'}, 'challenge'),
    (403, b'Forbidden. Cloudflare', {}, 'denied'),
    (403, b'Forbidden', {}, 'denied'),
    (200, b'<html>ChatGPT<script>const error="unsupported_country_region_territory";</script></html>', {}, 'reachable_public'),
    (200, b'<script>const msg="Country, region, or territory not supported";</script>ChatGPT', {}, 'reachable_public'),
    (200, b'{"documentation":{"code":"unsupported_country_region_territory"}}', {}, 'reachable_public'),
    (200, b'<script>const msg="Country, region, or territory not supported";', {}, 'reachable_public'),
    (200, b'['*2000 + b']'*2000, {}, 'reachable_public'),
    (302, b'', {'location': 'https://untrusted.test/login?private=secret'}, 'login_unchecked'),
    (401, b'Authentication required', {}, 'http_error'),
    (503, b'Service unavailable', {}, 'http_error'),
    (200, b'not-decompressed', {'content-encoding': 'gzip'}, 'http_error'),
])
async def test_safe_classification_is_never_authenticated_access(monkeypatch, status, body, headers, expected):
    requests, stream = intercept(monkeypatch, status, body, headers)
    result = await probe.check_chatgpt(12345)
    assert result['state'] == expected
    assert result['authenticated_access'] is False
    assert result['http_status'] == status
    assert datetime.datetime.fromisoformat(result['checked_at']).utcoffset() == datetime.timedelta(0)
    assert len(requests) == 1
    request = requests[0]
    assert str(request.url) == 'https://chatgpt.com/' and request.method == 'GET'
    assert not request.content and not request.headers.get('authorization') and not request.headers.get('cookie')
    assert request.headers['accept-encoding'] == 'identity'
    assert 'secret' not in str(result) and 'body' not in result and stream.closed


@pytest.mark.asyncio
async def test_reads_only_bounded_prefix_and_closes_response(monkeypatch):
    class Endless(Body):
        async def __aiter__(self):
            while True:
                self.reads += 1
                yield b'X' * 4096
    stream = Endless(b'')
    intercept(monkeypatch, stream=stream)
    result = await probe.check_chatgpt(12345)
    assert stream.reads == probe.MAX_BODY // 4096
    assert result['body_bytes_examined'] == probe.MAX_BODY and stream.closed


@pytest.mark.asyncio
async def test_deadline_covers_slow_body_and_closes_only_probe(monkeypatch):
    finished = asyncio.Event()
    class Slow(Body):
        async def __aiter__(self):
            try:
                while True:
                    await asyncio.sleep(.01)
                    yield b'X'
            finally:
                finished.set()
    stream = Slow(b'')
    intercept(monkeypatch, stream=stream)
    monkeypatch.setattr(probe, 'TOTAL_TIMEOUT', .04)
    result = await asyncio.wait_for(probe.check_chatgpt(12345), .5)
    assert result['state'] == 'transport_error' and result['stage'] == 'timeout'
    assert stream.closed and finished.is_set()


@pytest.mark.asyncio
async def test_explicit_cancellation_cleans_up_probe(monkeypatch):
    entered = asyncio.Event()
    class Hanging(Body):
        async def __aiter__(self):
            entered.set()
            await asyncio.Event().wait()
            yield b''
    stream = Hanging(b'')
    intercept(monkeypatch, stream=stream)
    task = asyncio.create_task(probe.check_chatgpt(12345))
    await entered.wait()
    task.cancel()
    result = await asyncio.wait_for(task, .5)
    assert result['state'] == 'cancelled' and result['authenticated_access'] is False
    assert stream.closed


@pytest.fixture
def local_tls(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'chatgpt.com')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
            .not_valid_after(now+datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('chatgpt.com')]), False)
            .sign(key, hashes.SHA256()))
    cp = tmp_path/'cert.pem'
    kp = tmp_path/'key.pem'
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cp, kp)
    return context, ssl.create_default_context(cafile=str(cp))


@contextlib.asynccontextmanager
async def local_socks_tls(context):
    requests, destinations, names, tasks = [], [], [], set()
    context.set_servername_callback(lambda sock, name, ctx: names.append(name))
    async def serve(reader, writer):
        tasks.add(asyncio.current_task())
        try:
            requests.append(await reader.readuntil(b'\r\n\r\n'))
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nChatGPT')
            await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            tasks.discard(asyncio.current_task())
    server = await asyncio.start_server(serve, '127.0.0.1', 0, ssl=context)
    remote_port = server.sockets[0].getsockname()[1]
    async def relay(reader, writer):
        while chunk := await reader.read(16384):
            writer.write(chunk)
            await writer.drain()
    async def socks(reader, writer):
        tasks.add(asyncio.current_task())
        remote = None
        relays = []
        try:
            assert await reader.readexactly(3) == b'\x05\x01\x00'
            writer.write(b'\x05\x00')
            await writer.drain()
            assert await reader.readexactly(4) == b'\x05\x01\x00\x03'
            length = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(length)).decode()
            port = struct.unpack('!H', await reader.readexactly(2))[0]
            destinations.append((host, port))
            incoming, remote = await asyncio.open_connection('127.0.0.1', remote_port)
            writer.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
            await writer.drain()
            relays = [asyncio.create_task(relay(reader, remote)), asyncio.create_task(relay(incoming, writer))]
            await asyncio.wait(relays, return_when=asyncio.FIRST_COMPLETED)
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            for task in relays:
                task.cancel()
            await asyncio.gather(*relays, return_exceptions=True)
            writer.close()
            if remote:
                remote.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            tasks.discard(asyncio.current_task())
    proxy = await asyncio.start_server(socks, '127.0.0.1', 0)
    try:
        yield proxy.sockets[0].getsockname()[1], requests, destinations, names
    finally:
        proxy.close()
        server.close()
        await proxy.wait_closed()
        await server.wait_closed()
        await asyncio.gather(*list(tasks), return_exceptions=True)


@pytest.mark.asyncio
async def test_actual_socks_target_sni_and_verified_tls(monkeypatch, local_tls):
    monkeypatch.setattr(probe, 'verified_context', lambda: local_tls[1])
    async with local_socks_tls(local_tls[0]) as (port, requests, destinations, names):
        result = await probe.check_chatgpt(port)
    assert result['state'] == 'reachable_public' and result['authenticated_access'] is False
    assert destinations == [('chatgpt.com', 443)] and names == ['chatgpt.com']
    assert len(requests) == 1 and requests[0].startswith(b'GET / HTTP/1.1\r\n')


@pytest.mark.asyncio
async def test_untrusted_certificate_is_tls_failure_with_no_http_request(local_tls):
    async with local_socks_tls(local_tls[0]) as (port, requests, destinations, names):
        result = await probe.check_chatgpt(port)
    assert result['state'] == 'transport_error' and result['stage'] == 'TLS'
    assert result['error'] == 'ConnectError' and not requests
    assert destinations == [('chatgpt.com', 443)] and names == ['chatgpt.com']
    assert 'CERTIFICATE' not in str(result) and '127.0.0.1' not in str(result)
