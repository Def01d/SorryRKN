"""Telegram's TLS and WebSocket traffic through a local SOCKS5 DPI engine."""
import asyncio
import base64
import contextlib
import datetime
import hashlib
import ipaddress
import ssl
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from proxy.config import proxy_config
from proxy.raw_websocket import RawWebSocket

DOMAIN = 'kws2-1.web.telegram.org'


@pytest.fixture
def tls(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(DOMAIN)]), False)
            .sign(key, hashes.SHA256()))
    cp, kp = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cp, kp)
    return server, ssl.create_default_context(cafile=str(cp))


async def closed(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), .3)
    except (OSError, asyncio.TimeoutError):
        writer.transport.abort()


@contextlib.asynccontextmanager
async def local_dpi(monkeypatch, tls, mode='echo'):
    """A real byte-forwarding SOCKS proxy, not a patched client TLS handshake."""
    sessions = set()
    state = {'destinations': [], 'requests': [], 'names': [], 'payloads': [],
             'opened': 0, 'closed': 0, 'stage': asyncio.Event()}
    tls[0].set_servername_callback(lambda sock, name, ctx: state['names'].append(name))

    async def websocket(reader, writer):
        task = asyncio.current_task()
        sessions.add(task)
        try:
            request = await reader.readuntil(b'\r\n\r\n')
            state['requests'].append(request)
            state['stage'].set()
            if mode == 'upgrade_stall':
                # Headers keep arriving, but the entire upgrade must still time out.
                writer.write(b'HTTP/1.1 101 Switching Protocols\r\n')
                while True:
                    writer.write(b'X-Progress: 1\r\n')
                    await writer.drain()
                    await asyncio.sleep(.025)
            key = next(line.split(b': ', 1)[1] for line in request.split(b'\r\n')
                       if line.startswith(b'Sec-WebSocket-Key:'))
            accept = base64.b64encode(hashlib.sha1(
                key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
            writer.write(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                         b'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n')
            await writer.drain()
            ws = RawWebSocket(reader, writer)
            while (payload := await ws.recv()) is not None:
                state['payloads'].append(payload)
                writer.write(RawWebSocket._build_frame(RawWebSocket.OP_BINARY, payload))
                await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            await closed(writer)
            sessions.discard(task)

    upstream = await asyncio.start_server(websocket, '127.0.0.1', 0, ssl=tls[0])
    upstream_port = upstream.sockets[0].getsockname()[1]

    async def pipe(reader, writer):
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()

    async def socks(reader, writer):
        task = asyncio.current_task()
        sessions.add(task)
        state['opened'] += 1
        remote = None
        pipes = []
        try:
            assert await reader.readexactly(3) == b'\x05\x01\x00'
            if mode == 'greeting_stall':
                state['stage'].set()
                await reader.read()
                return
            writer.write(b'\x05\xff' if mode == 'greeting_reject' else b'\x05\x00')
            await writer.drain()
            if mode == 'greeting_reject':
                await reader.read()
                return
            command = await reader.readexactly(4)
            assert command[:3] == b'\x05\x01\x00'
            if command[3] == 3:
                size = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(size)).decode('ascii')
            else:
                host = str(ipaddress.ip_address(await reader.readexactly(
                    4 if command[3] == 1 else 16)))
            port = int.from_bytes(await reader.readexactly(2), 'big')
            state['destinations'].append((host, port))
            if mode == 'connect_stall':
                state['stage'].set()
                await reader.read()
                return
            if mode in ('connect_reject', 'invalid_reply'):
                writer.write(b'\x05\x05\x00\x01' if mode == 'connect_reject'
                             else b'\x05\x00\x00\x09')
                await writer.drain()
                await reader.read()
                return
            writer.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb')
            await writer.drain()
            if mode == 'tls_stall':
                hello = await reader.read(16384)
                assert hello[:2] == b'\x16\x03'
                state['stage'].set()
                await reader.read()
                return
            remote_reader, remote = await asyncio.open_connection('127.0.0.1', upstream_port)
            pipes = [asyncio.create_task(pipe(reader, remote)),
                     asyncio.create_task(pipe(remote_reader, writer))]
            await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            for pending in pipes:
                pending.cancel()
            await asyncio.gather(*pipes, return_exceptions=True)
            if remote:
                await closed(remote)
            await closed(writer)
            state['closed'] += 1
            sessions.discard(task)

    proxy = await asyncio.start_server(socks, '127.0.0.1', 0)
    monkeypatch.setattr(proxy_config, 'telegram_dpi_port', proxy.sockets[0].getsockname()[1])
    monkeypatch.setattr('proxy.raw_websocket._ssl_ctx', tls[1])
    try:
        yield state
    finally:
        proxy.close()
        upstream.close()
        await proxy.wait_closed()
        await upstream.wait_closed()
        if sessions:
            await asyncio.wait_for(asyncio.gather(*list(sessions), return_exceptions=True), 1)
        assert state['opened'] == state['closed']
        assert not sessions


@pytest.mark.asyncio
@pytest.mark.parametrize('host', ['149.154.167.99', '2001:db8::42', DOMAIN])
async def test_verified_tls_and_binary_media_cross_local_socks_unchanged(monkeypatch, tls, host):
    async with local_dpi(monkeypatch, tls) as state:
        ws = await RawWebSocket.connect(host, DOMAIN, timeout=2)
        try:
            payloads = [b'sticker\x00\xff', 'эмодзи 🦊'.encode(), bytes(range(256)) * 4096]
            for payload in payloads:
                await ws.send(payload)
                assert await asyncio.wait_for(ws.recv(), 2) == payload
            assert state['destinations'] == [(host, 443)]
            assert state['names'] == [DOMAIN]
            assert len(state['requests']) == 1
            assert state['requests'][0].startswith(b'GET /apiws HTTP/1.1\r\n')
            assert f'Host: {DOMAIN}\r\n'.encode() in state['requests'][0]
            assert state['payloads'] == payloads
            assert ws.writer.get_extra_info('ssl_object').context.check_hostname
            assert ws.writer.get_extra_info('ssl_object').context.verify_mode == ssl.CERT_REQUIRED
        finally:
            await ws.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['greeting_reject', 'connect_reject', 'invalid_reply'])
async def test_socks_rejections_close_underlying_connection(monkeypatch, tls, mode):
    async with local_dpi(monkeypatch, tls, mode) as state:
        with pytest.raises(ConnectionError):
            await RawWebSocket.connect('149.154.167.99', DOMAIN, timeout=1)
        assert not state['requests']


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['greeting_stall', 'connect_stall', 'tls_stall', 'upgrade_stall'])
async def test_every_handshake_stage_has_one_overall_deadline(monkeypatch, tls, mode):
    async with local_dpi(monkeypatch, tls, mode) as state:
        started = time.monotonic()
        with pytest.raises(asyncio.TimeoutError):
            await RawWebSocket.connect('149.154.167.99', DOMAIN, timeout=.15)
        assert state['stage'].is_set()
        assert time.monotonic() - started < .6


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['greeting_stall', 'connect_stall', 'tls_stall', 'upgrade_stall'])
async def test_cancellation_closes_every_incomplete_handshake(monkeypatch, tls, mode):
    async with local_dpi(monkeypatch, tls, mode) as state:
        task = asyncio.create_task(RawWebSocket.connect('149.154.167.99', DOMAIN, timeout=5))
        await asyncio.wait_for(state['stage'].wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
@pytest.mark.parametrize('reason', ['hostname', 'untrusted'])
async def test_local_dpi_does_not_bypass_telegram_certificate_validation(monkeypatch, tls, reason):
    async with local_dpi(monkeypatch, tls) as state:
        if reason == 'untrusted':
            monkeypatch.setattr('proxy.raw_websocket._ssl_ctx', ssl.create_default_context())
        name = 'kws5.web.telegram.org' if reason == 'hostname' else DOMAIN
        with pytest.raises(ssl.SSLCertVerificationError):
            await RawWebSocket.connect('149.154.167.99', name, timeout=2)
        assert not state['requests']
