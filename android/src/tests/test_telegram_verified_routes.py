"""Actual MTProto replies, rather than TCP/HTTP acceptance, select app routes."""
import asyncio
import contextlib
import hashlib
import os
import struct
import time
from unittest.mock import AsyncMock, Mock

import pytest

import telegram_probe
from proxy import verified_routes as routes, tg_ws_proxy, route_diagnostics
from proxy._aes import Cipher, algorithms, modes
from proxy.config import proxy_config
from proxy.utils import PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE
from test_telegram_probe import res_pq


def cipher(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def client_init(secret, dc, tag):
    raw = bytearray(os.urandom(64))
    raw[0] = 0x42
    raw[56:62] = tag + struct.pack('<h', dc)
    key = bytes(raw[8:56])
    enc = cipher(hashlib.sha256(key[:32] + secret).digest(), key[32:])
    reverse = key[::-1]
    dec = cipher(hashlib.sha256(reverse[:32] + secret).digest(), reverse[32:])
    wire = bytearray(raw)
    wire[56:] = enc.update(bytes(raw))[56:]
    return wire, enc, dec


async def packet(reader, dec, tag):
    if tag == PROTO_TAG_ABRIDGED:
        size = dec.update(await reader.readexactly(1))[0] & 127
        if size == 127:
            size = int.from_bytes(dec.update(await reader.readexactly(3)), 'little')
        size *= 4
    else:
        size = struct.unpack('<I', dec.update(await reader.readexactly(4)))[0] & 0x7FFFFFFF
    assert 0 < size <= 2 * 1024 * 1024
    return dec.update(await reader.readexactly(size))


def frame(payload, tag):
    if tag == PROTO_TAG_ABRIDGED:
        words = len(payload) // 4
        return (bytes([words]) if words < 127 else b'\x7f' + words.to_bytes(3, 'little')) + payload
    return struct.pack('<I', len(payload)) + payload


@contextlib.asynccontextmanager
async def native_fixture(monkeypatch):
    calls, errors, writers, tasks = [], [], set(), set()
    secret = os.urandom(16)
    error_nonces, silent_nonces = set(), set()
    monkeypatch.setattr(proxy_config, 'verified_routes', True)
    monkeypatch.setattr(proxy_config, 'fallback_cfproxy', False)
    monkeypatch.setattr(proxy_config, 'cfproxy_worker_domains', [])
    monkeypatch.setattr(proxy_config, 'dc_redirects', {})
    monkeypatch.setattr(proxy_config, 'telegram_dpi_port', 0)
    monkeypatch.setattr(routes._endpoints, 'addresses', AsyncMock(return_value=[]))
    routes.reset()

    def accept(coro, writer):
        writers.add(writer)
        task = asyncio.create_task(coro)
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    async def server(reader, writer):
        try:
            init = await reader.readexactly(64)
            key = init[8:56]
            dec = cipher(key[:32], key[32:])
            plain = dec.update(init)
            tag, dc = plain[56:60], struct.unpack_from('<h', plain, 60)[0]
            reverse = key[::-1]
            enc = cipher(reverse[:32], reverse[32:])
            while True:
                request = await packet(reader, dec, tag)
                nonce = request[24:40]
                calls.append((dc, tag, nonce))
                if nonce in silent_nonces:
                    await reader.read()
                    return
                if nonce in error_nonces:
                    response = struct.pack('<i', -404)
                else:
                    body = res_pq(nonce)[:-9]
                    if tag == PROTO_TAG_SECURE:
                        body += os.urandom(105)  # legitimate additional envelope padding
                    response = frame(body, tag)
                wire = enc.update(response)
                writer.write(wire[:3])
                await writer.drain()
                await asyncio.sleep(.001)
                writer.write(wire[3:])
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
            pass
        except Exception as exc:
            errors.append(exc)
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            writers.discard(writer)

    remote = await asyncio.start_server(lambda r, w: accept(server(r, w), w), '127.0.0.1', 0)
    target = ('127.0.0.1', remote.sockets[0].getsockname()[1])
    monkeypatch.setattr(routes, 'native_tcp_endpoints', lambda dc, test=False: (target,))
    local = await asyncio.start_server(
        lambda r, w: accept(tg_ws_proxy._handle_client(r, w, secret), w), '127.0.0.1', 0)
    try:
        yield local.sockets[0].getsockname()[1], secret, calls, target, error_nonces, silent_nonces
    finally:
        local.close()
        remote.close()
        for writer in list(writers):
            writer.close()
            writer.transport.abort()
        for task in list(tasks):
            task.cancel()
        await asyncio.gather(*list(tasks), return_exceptions=True)
        await local.wait_closed()
        await remote.wait_closed()
        await routes.close()
        assert not errors


@pytest.mark.asyncio
async def test_actual_handler_preserves_all_framings_media_dc_and_cipher_continuation(monkeypatch):
    async with native_fixture(monkeypatch) as (port, secret, calls, *_):
        async def client(dc, tag):
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            init, enc, dec = client_init(secret, dc, tag)
            writer.write(init)
            try:
                for _ in range(2):
                    nonce = os.urandom(16)
                    payload = telegram_probe._request(nonce)[4:44]
                    if tag == PROTO_TAG_SECURE:
                        payload += os.urandom(7)
                    wire = enc.update(frame(payload, tag))
                    writer.write(wire[:2])
                    await writer.drain()
                    await asyncio.sleep(.001)
                    writer.write(wire[2:])
                    await writer.drain()
                    response = await asyncio.wait_for(packet(reader, dec, tag), 2)
                    telegram_probe._validate_reply(response, nonce)
                    assert [(d, t) for d, t, n in calls if n == nonce] == [(dc, tag)]
            finally:
                writer.close()
                await writer.wait_closed()
        await asyncio.gather(*(client(dc, tag) for dc in (1, -2, 4, -5)
                               for tag in (PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE)))


@pytest.mark.asyncio
async def test_tcp_accept_blackhole_loses_to_valid_mtproto_route(monkeypatch):
    stalled = []
    async with native_fixture(monkeypatch) as (port, secret, calls, target, *_):
        blackhole = await asyncio.start_server(lambda r, w: stalled.append(w), '127.0.0.1', 0)
        blocked = ('127.0.0.1', blackhole.sockets[0].getsockname()[1])
        monkeypatch.setattr(routes, 'native_tcp_endpoints', lambda dc, test=False: (blocked, target))
        try:
            result = await telegram_probe.check_telegram(port, secret, dc=4, is_media=True)
            assert result['state'] == 'reachable', result
            assert result['elapsed_ms'] < 1000
            assert stalled
            assert all(dc == -4 for dc, _, _ in calls)
        finally:
            blackhole.close()
            for writer in stalled:
                writer.close()
                writer.transport.abort()
            await blackhole.wait_closed()


@pytest.mark.asyncio
async def test_first_reply_stall_closes_without_replaying_actual_request(monkeypatch):
    async with native_fixture(monkeypatch) as (port, secret, calls, target, errors, silent):
        nonce = os.urandom(16)
        silent.add(nonce)
        monkeypatch.setattr(routes, 'FIRST_REPLY_TIMEOUT', .04)
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        try:
            init, enc, dec = client_init(secret, 2, PROTO_TAG_SECURE)
            writer.write(init + enc.update(telegram_probe._request(nonce)))
            await writer.drain()
            assert await asyncio.wait_for(reader.read(), 1) == b''
            assert len([n for _, _, n in calls if n == nonce]) == 1
            assert (2, False, False) not in routes._cache
        finally:
            writer.close()
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_transport_minus404_is_delivered_without_route_retry(monkeypatch):
    async with native_fixture(monkeypatch) as (port, secret, calls, target, errors, _):
        nonce = os.urandom(16)
        errors.add(nonce)
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        try:
            init, enc, dec = client_init(secret, -2, PROTO_TAG_SECURE)
            writer.write(init + enc.update(telegram_probe._request(nonce)))
            await writer.drain()
            assert struct.unpack('<i', dec.update(await asyncio.wait_for(reader.readexactly(4), 1)))[0] == -404
            assert len([n for _, _, n in calls if n == nonce]) == 1
        finally:
            writer.close()
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_existing_local_socks_and_scoped_fronting_connector_are_preserved(monkeypatch):
    connect = AsyncMock(return_value=Mock())
    monkeypatch.setattr(routes.RawWebSocket, 'connect', connect)
    monkeypatch.setattr(proxy_config, 'telegram_dpi_port', 1084)
    route = routes.Route('ws', '149.154.167.99', domain='kws2.web.telegram.org')
    await routes.open_route(route)
    assert connect.await_args.kwargs['direct'] is False
    assert connect.await_args.kwargs['sni'] is None
    route = routes.Route('ws_fronting', '149.154.167.220', domain='kws4.web.telegram.org',
                         direct=True, sni='sprinthost.ru')
    await routes.open_route(route)
    assert connect.await_args.kwargs['direct'] is True
    assert connect.await_args.kwargs['sni'] == 'sprinthost.ru'


@pytest.mark.asyncio
async def test_all_candidates_and_dns_share_one_bounded_deadline(monkeypatch):
    async def stall(*_args):
        await asyncio.Future()
    routes.reset()
    monkeypatch.setattr(routes, 'open_route', stall)
    monkeypatch.setattr(routes._endpoints, 'addresses', stall)
    monkeypatch.setattr(routes, 'SELECT_TIMEOUT', .04)
    monkeypatch.setattr(proxy_config, 'fallback_cfproxy', False)
    monkeypatch.setattr(proxy_config, 'cfproxy_worker_domains', [])
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(routes.connect(2), .3)
    assert not routes._failed_until, 'cancelled probes must not blacklist healthy recovery routes'
    await routes.close()


@pytest.mark.asyncio
async def test_cached_media_route_keeps_twelve_private_dials_concurrent(monkeypatch):
    routes.reset()
    route = routes.Route('native_tcp', '149.154.167.51')
    routes._cache[(2, True, False)] = route, time.monotonic() + 60
    all_started = asyncio.Event()
    opened = []
    async def dial(selected):
        assert selected == route
        transport = Mock()
        opened.append(transport)
        if len(opened) == 12:
            all_started.set()
        await all_started.wait()
        return transport
    monkeypatch.setattr(routes, 'open_route', dial)
    try:
        result = await asyncio.wait_for(asyncio.gather(*(routes.connect(2, True) for _ in range(12))), .5)
        assert len({id(transport) for transport, _ in result}) == 12
    finally:
        routes.reset()


@pytest.mark.asyncio
async def test_unexpected_dns_error_cannot_discard_working_native_route(monkeypatch):
    async with native_fixture(monkeypatch) as (port, secret, *_):
        monkeypatch.setattr(routes._endpoints, 'addresses', AsyncMock(side_effect=RuntimeError('controlled')))
        result = await telegram_probe.check_telegram(port, secret)
        assert result['state'] == 'reachable', result


@pytest.mark.parametrize('padding', [0, 15, 16, 119, 256])
def test_valid_res_pq_envelope_padding_does_not_create_false_unavailable(padding):
    nonce = os.urandom(16)
    telegram_probe._validate_reply(res_pq(nonce)[:-9] + os.urandom(padding), nonce)


def test_old_session_failure_does_not_erase_new_verified_route():
    routes.reset()
    old = routes.Route('native_tcp', '149.154.167.51', 443)
    newer = routes.Route('native_tcp', '149.154.167.51', 5222)
    routes._cache[(2, True, False)] = newer, time.monotonic() + 60
    routes.invalidate(2, True, False, old)
    assert routes._cache[(2, True, False)][0] == newer
    assert (2, True, False, old) in routes._failed_until
    assert (2, False, False, old) not in routes._failed_until
    routes.reset()


@pytest.mark.asyncio
async def test_native_dial_failure_records_redacted_stage_endpoint_and_errno(monkeypatch):
    route_diagnostics.reset()
    routes.reset()
    monkeypatch.setattr(routes, 'open_route', AsyncMock(side_effect=OSError(111, 'private-sensitive-text')))
    route = routes.Route('native_tcp', '149.154.167.51', 443)
    try:
        assert await routes._probe(route, 2, 0) is None
        report = route_diagnostics.snapshot()
        assert not report['active']
        assert report['counts']['native_tcp:native_tcp:failure'] == 1
        entry = report['recent'][-1]
        assert entry['ip'] == route.host and entry['port'] == route.port
        assert entry['errno'] == 111
        assert 'private-sensitive-text' not in str(report)
    finally:
        route_diagnostics.reset()
        routes.reset()
