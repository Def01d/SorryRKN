"""Telegram readiness requires a nonce-matched MTProto response, not a listener."""
import asyncio
import contextlib
import hashlib
import os
import struct

import pytest

import telegram_probe as probe
from proxy import tg_ws_proxy
from proxy._aes import Cipher, algorithms, modes
from proxy.config import proxy_config
from proxy.raw_websocket import RawWebSocket
from proxy.utils import PROTO_TAG_SECURE


def cipher(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def res_pq(nonce):
    # Independent fixture construction using the published TL constructors.
    pq = b'\x08' + bytes.fromhex('17ed48941a08f981') + b'\0' * 3
    body = struct.pack('<I', 0x05162463) + nonce + b'\x5a' * 16 + pq
    body += struct.pack('<IIQ', 0x1cb5c415, 1, 0xc3b42b026ce86b21)
    return struct.pack('<QQI', 0, 123456789, len(body)) + body + b'\xa5' * 9


@contextlib.asynccontextmanager
async def native_proxy(monkeypatch, mode='valid'):
    """Real native handler, independent upstream AES/WS and resPQ fixture.

    Only acquisition of a WebSocket is redirected to localhost. The native
    secret handshake, signed DC, stream ciphers, framing and bridge are real.
    """
    secret = os.urandom(16)
    tasks = set()
    seen = []
    requests = []
    failed = []
    entered = asyncio.Event()
    upstreams = []
    for name, value in [('fake_tls_domain', ''), ('proxy_protocol', False), ('force_test_dc', False)]:
        monkeypatch.setattr(proxy_config, name, value)

    def start(coro):
        task = asyncio.create_task(coro)
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    async def remote(reader, writer):
        ws = RawWebSocket(reader, writer)
        upstreams.append(ws)
        try:
            # Exchange a real HTTP101 too: it alone must never pass the check.
            request = await reader.readuntil(b'\r\n\r\n')
            assert request.startswith(b'GET /apiws ')
            writer.write(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
            await writer.drain()
            init = await ws.recv()
            assert init is not None and len(init) == 64
            keys = init[8:56]
            up = cipher(keys[:32], keys[32:])
            decoded = up.update(init)
            assert decoded[56:60] == PROTO_TAG_SECURE
            seen.append(struct.unpack_from('<h', decoded, 60)[0])
            reverse = keys[::-1]
            down = cipher(reverse[:32], reverse[32:])
            encrypted = await ws.recv()
            assert encrypted is not None
            frame = up.update(encrypted)
            length = struct.unpack_from('<I', frame)[0]
            packet = frame[4:]
            assert length == len(packet) == 47
            auth, message_id, size = struct.unpack_from('<QQI', packet)
            assert auth == 0 and message_id % 4 == 0 and size == 20
            assert struct.unpack_from('<I', packet, 20)[0] == 0xbe7e8ef1
            nonce = packet[24:40]
            requests.append((seen[-1], nonce))
            entered.set()
            if mode == 'silent':
                await ws.recv()
                return
            reply = res_pq(nonce if mode != 'wrong_nonce' else bytes(value ^ 1 for value in nonce))
            if mode == 'transport_error':
                reply = struct.pack('<i', -404)
            elif mode == 'wrong_constructor':
                reply = reply[:20] + b'FAIL' + reply[24:]
            elif mode == 'oversized':
                wire = down.update(struct.pack('<I', probe.MAX_PACKET + 1))
                writer.write(RawWebSocket._build_frame(RawWebSocket.OP_BINARY, wire))
                await writer.drain()
                await ws.recv()
                return
            wire = down.update(struct.pack('<I', len(reply)) + reply)
            # Both transport header and response cross WS/TCP boundaries.
            for offset in range(0, len(wire), 3):
                writer.write(RawWebSocket._build_frame(RawWebSocket.OP_BINARY, wire[offset:offset + 3]))
                await writer.drain()
            assert await ws.recv() is None, 'probe continued authentication after resPQ'
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception as error:
            failed.append(error)
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    server = await asyncio.start_server(lambda r, w: start(remote(r, w)), '127.0.0.1', 0)
    remote_port = server.sockets[0].getsockname()[1]
    class Pool:
        async def get(self, dc, is_media, is_test_dc=False):
            assert not is_test_dc
            reader, writer = await asyncio.open_connection('127.0.0.1', remote_port)
            writer.write(b'GET /apiws HTTP/1.1\r\nHost: kws2.web.telegram.org\r\nUpgrade: websocket\r\n\r\n')
            await writer.drain()
            assert (await reader.readuntil(b'\r\n\r\n')).startswith(b'HTTP/1.1 101 ')
            return RawWebSocket(reader, writer)

        def discard_media(self, dc, is_test_dc):
            raise AssertionError('readiness probe reset media pool')
    monkeypatch.setattr(tg_ws_proxy, 'ws_pool', Pool())
    local = await asyncio.start_server(
        lambda r, w: start(tg_ws_proxy._handle_client(r, w, secret)), '127.0.0.1', 0)
    try:
        yield local.sockets[0].getsockname()[1], secret, seen, requests, entered
    finally:
        local.close()
        server.close()
        await local.wait_closed()
        await server.wait_closed()
        await asyncio.wait_for(asyncio.gather(*list(tasks), return_exceptions=True), 1)
        assert not failed, failed


@pytest.mark.asyncio
@pytest.mark.parametrize('dc,media', [(2, False), (4, False), (2, True)])
async def test_real_native_proxy_round_trip_requires_matching_res_pq(monkeypatch, dc, media):
    async with native_proxy(monkeypatch) as (port, secret, seen, requests, entered):
        result = await probe.check_telegram(port, secret.hex(), dc=dc, is_media=media)
    assert result['state'] == 'reachable' and result['stage'] == 'MTProto'
    assert result['authenticated_access'] is False and result['account_checked'] is False
    assert result['media_access_checked'] is False and result['media'] is media
    assert seen == [-dc if media else dc] and len(requests) == 1
    assert secret.hex() not in str(result) and requests[0][1].hex() not in str(result)
    assert result['elapsed_ms'] < 5000


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,error', [
    ('wrong_nonce', 'NonceMismatch'), ('wrong_constructor', 'UnexpectedConstructor'),
    ('transport_error', 'TransportRejected'), ('oversized', 'InvalidPacketLength'),
])
async def test_response_must_be_authentic_to_request_and_bounded(monkeypatch, mode, error):
    async with native_proxy(monkeypatch, mode) as (port, secret, *rest):
        result = await probe.check_telegram(port, secret)
    assert result['state'] == 'unavailable' and result['error'] == error


@pytest.mark.asyncio
async def test_http101_and_open_listener_are_not_readiness(monkeypatch):
    monkeypatch.setattr(probe, 'TOTAL_TIMEOUT', .06)
    async with native_proxy(monkeypatch, 'silent') as (port, secret, seen, requests, entered):
        result = await probe.check_telegram(port, secret)
    assert seen == [2] and len(requests) == 1
    assert result['state'] == 'unavailable' and result['error'] == 'TimeoutError'
    assert result['stage'] == 'MTProto' and result['elapsed_ms'] < 500


@pytest.mark.asyncio
async def test_cancellation_closes_probe_and_propagates_to_lifecycle(monkeypatch):
    async with native_proxy(monkeypatch, 'silent') as (port, secret, seen, requests, entered):
        task = asyncio.create_task(probe.check_telegram(port, secret))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_fresh_check_does_not_change_existing_connection_or_configuration(monkeypatch):
    async with native_proxy(monkeypatch) as (port, secret, seen, requests, entered):
        before = dict(vars(proxy_config))
        results = await asyncio.gather(probe.check_telegram(port, secret, dc=2),
                                       probe.check_telegram(port, secret, dc=4))
        assert dict(vars(proxy_config)) == before
    assert all(result['state'] == 'reachable' for result in results)
    assert sorted(seen) == [2, 4] and len({nonce for _, nonce in requests}) == 2


@pytest.mark.asyncio
async def test_existing_native_socket_survives_readiness_check(monkeypatch):
    async with native_proxy(monkeypatch) as (port, secret, seen, requests, entered):
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        try:
            # This socket predates the probe. A listener/pool restart must not
            # disconnect it while the independent readiness check runs.
            result = await probe.check_telegram(port, secret, dc=2)
            assert result['state'] == 'reachable'
            init, up, down = probe._native_init(secret, 4)
            nonce = os.urandom(16)
            writer.write(init + up.update(probe._request(nonce)))
            await writer.drain()
            size = struct.unpack('<I', down.update(await reader.readexactly(4)))[0]
            probe._validate_reply(down.update(await reader.readexactly(size)), nonce)
        finally:
            writer.close()
            await writer.wait_closed()
    assert sorted(seen) == [2, 4] and len(requests) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize('port,secret', [(0, '00' * 16), (1443, 'dd' + '00' * 16), (1443, 'invalid')])
async def test_invalid_configuration_fails_without_dial(monkeypatch, port, secret):
    async def forbidden(*args, **kwargs):
        raise AssertionError('invalid configuration opened a connection')
    monkeypatch.setattr(probe.asyncio, 'open_connection', forbidden)
    result = await probe.check_telegram(port, secret)
    assert result['state'] == 'unavailable' and result['stage'] == 'configuration'


@pytest.mark.parametrize('modify', [
    lambda packet: b'\1' + packet[1:],
    lambda packet: packet[:16] + struct.pack('<I', 10000) + packet[20:],
    lambda packet: packet[:56] + b'\xff' + packet[57:],
    lambda packet: packet[:68] + b'FAIL' + packet[72:],
])
def test_invalid_envelope_or_tl_schema_cannot_report_reachable(modify):
    nonce = os.urandom(16)
    with pytest.raises(probe.ProbeProtocolError):
        probe._validate_reply(modify(res_pq(nonce)), nonce)
