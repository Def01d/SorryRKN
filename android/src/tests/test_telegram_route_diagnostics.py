"""Safe stage diagnostics from controlled real sockets/TLS, not operator claims."""
import asyncio
import contextlib
import errno
import json
import socket
import ssl
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from proxy import route_diagnostics as diag
from proxy import bridge
from proxy.config import proxy_config
from proxy.pool import _WsPool
from proxy.raw_websocket import RawWebSocket, WsHandshakeError, SocksHandshakeError
from proxy.telegram_endpoints import TelegramEndpoints
from test_telegram_local_dpi import DOMAIN, tls, local_dpi, closed


@pytest.fixture(autouse=True)
def reset_diagnostics():
    diag.reset()
    yield
    diag.reset()


def stages():
    return [(item['stage'], item['outcome']) for item in diag.snapshot()['recent']]


@contextlib.asynccontextmanager
async def direct_endpoint(monkeypatch, tls, mode='403'):
    tasks = set()
    reached = asyncio.Event()
    async def serve(reader, writer):
        tasks.add(asyncio.current_task())
        try:
            if mode == 'tls_stall':
                assert (await reader.read(16384))[:2] == b'\x16\x03'
                reached.set()
                await reader.read()
                return
            await reader.readuntil(b'\r\n\r\n')
            reached.set()
            if mode == 'http_stall':
                writer.write(b'HTTP/1.1 101 partial\r\n')
                while True:
                    writer.write(b'X-Secret: never-record-this-secret\r\n')
                    await writer.drain()
                    await asyncio.sleep(.01)
            else:
                writer.write(b'HTTP/1.1 403 never-record-this-secret\r\n'
                             b'Set-Cookie: private=never-record-this-secret\r\n\r\n'
                             b'never-record-this-secret')
                await writer.drain()
                await reader.read()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            await closed(writer)
            tasks.discard(asyncio.current_task())
    server = await asyncio.start_server(serve, '127.0.0.1', 0,
                                       ssl=None if mode == 'tls_stall' else tls[0])
    port = server.sockets[0].getsockname()[1]
    real_open = asyncio.open_connection
    async def dial(host, outgoing_port, **kwargs):
        assert host == '149.154.167.99' and outgoing_port == 443
        assert not kwargs.get('ssl'), 'TCP and TLS stages must be distinguishable'
        return await real_open('127.0.0.1', port, **kwargs)
    monkeypatch.setattr('proxy.raw_websocket.asyncio.open_connection', dial)
    monkeypatch.setattr('proxy.raw_websocket._ssl_ctx', tls[1])
    monkeypatch.setattr(proxy_config, 'telegram_dpi_port', 0)
    try:
        yield reached
    finally:
        server.close()
        await server.wait_closed()
        await asyncio.wait_for(asyncio.gather(*list(tasks), return_exceptions=True), 1)


@pytest.mark.asyncio
async def test_real_tcp_refusal_has_errno_and_never_claims_tls_started(monkeypatch):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
    real_open = asyncio.open_connection
    async def dial(host, outgoing_port, **kwargs):
        return await real_open('127.0.0.1', port, **kwargs)
    monkeypatch.setattr('proxy.raw_websocket.asyncio.open_connection', dial)
    try:
        with pytest.raises(ConnectionRefusedError):
            await RawWebSocket.connect('149.154.167.99', DOMAIN, direct=True, timeout=.2)
    finally:
        listener.close()
    result = diag.snapshot()
    assert stages() == [('tcp', 'failure')]
    failure = result['recent'][0]
    assert failure['errno'] == errno.ECONNREFUSED
    assert failure['error'] == 'ConnectionRefusedError'
    assert failure['ip'] == '149.154.167.99' and failure['domain'] == DOMAIN
    assert failure['route'] == 'ws_direct' and failure['port'] == 443
    assert not result['active']


@pytest.mark.asyncio
@pytest.mark.parametrize('reason', ['untrusted', 'hostname'])
async def test_real_direct_tls_failure_retains_verify_code_but_no_certificate_text(monkeypatch, tls, reason):
    async with direct_endpoint(monkeypatch, tls):
        if reason == 'untrusted':
            monkeypatch.setattr('proxy.raw_websocket._ssl_ctx', ssl.create_default_context())
        domain = 'kws5.web.telegram.org' if reason == 'hostname' else DOMAIN
        with pytest.raises(ssl.SSLCertVerificationError):
            await RawWebSocket.connect('149.154.167.99', domain, timeout=.5)
    assert stages() == [('tcp', 'success'), ('tls', 'failure')]
    failure = diag.snapshot()['recent'][-1]
    assert failure['error'] == 'SSLCertVerificationError' and failure['verify_code'] > 0
    assert 'CERTIFICATE' not in json.dumps(diag.snapshot())


@pytest.mark.asyncio
async def test_real_http_refusal_records_only_numeric_status(monkeypatch, tls):
    async with direct_endpoint(monkeypatch, tls):
        with pytest.raises(WsHandshakeError):
            await RawWebSocket.connect('149.154.167.99', DOMAIN, timeout=.5)
    assert stages() == [('tcp', 'success'), ('tls', 'success'), ('http_upgrade', 'failure')]
    failure = diag.snapshot()['recent'][-1]
    assert failure['http_status'] == 403 and failure['error'] == 'WsHandshakeError'
    assert 'never-record-this-secret' not in json.dumps(diag.snapshot())


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,stage', [('tls_stall', 'tls'), ('http_stall', 'http_upgrade')])
async def test_direct_deadline_is_failure_at_actual_stage(monkeypatch, tls, mode, stage):
    async with direct_endpoint(monkeypatch, tls, mode) as reached:
        with pytest.raises(asyncio.TimeoutError):
            await RawWebSocket.connect('149.154.167.99', DOMAIN, timeout=.08)
        assert reached.is_set()
    failure = diag.snapshot()['recent'][-1]
    assert failure['stage'] == stage and failure['outcome'] == 'failure'
    assert failure['error'] == 'TimeoutError' and failure['elapsed_ms'] < 500
    assert not diag.snapshot()['active']


@pytest.mark.asyncio
async def test_real_cancellation_keeps_active_stage_and_is_not_failure(monkeypatch, tls):
    async with direct_endpoint(monkeypatch, tls, 'tls_stall') as reached:
        task = asyncio.create_task(RawWebSocket.connect('149.154.167.99', DOMAIN, timeout=1))
        await reached.wait()
        assert diag.snapshot()['active'][-1]['stage'] == 'tls'
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    event = diag.snapshot()['recent'][-1]
    assert event['stage'] == 'tls' and event['outcome'] == 'cancelled' and 'error' not in event
    assert not any(item['outcome'] == 'failure' for item in diag.snapshot()['recent'])


@pytest.mark.asyncio
@pytest.mark.parametrize('mode,reply', [('greeting_reject', 255), ('connect_reject', 5)])
async def test_real_local_socks_rejection_has_numeric_reply(monkeypatch, tls, mode, reply):
    async with local_dpi(monkeypatch, tls, mode):
        with pytest.raises(SocksHandshakeError):
            await RawWebSocket.connect('149.154.167.99', DOMAIN, timeout=.5)
    assert stages() == [('local_socket', 'success'), ('local_socks', 'failure')]
    event = diag.snapshot()['recent'][-1]
    assert event['route'] == 'ws_local_socks' and event['socks_reply'] == reply


@pytest.mark.asyncio
async def test_local_socks_success_does_not_claim_external_tcp_or_tls_success(monkeypatch, tls):
    async with local_dpi(monkeypatch, tls, 'tls_stall'):
        with pytest.raises(asyncio.TimeoutError):
            await RawWebSocket.connect('149.154.167.99', DOMAIN, timeout=.06)
    assert stages() == [('local_socket', 'success'), ('local_socks', 'success'), ('tls', 'failure')]
    assert diag.snapshot()['recent'][1]['socks_reply'] == 0


@pytest.mark.asyncio
async def test_real_native_tcp_backoff_separates_skipped_clients_from_dials():
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
    bridge.reset_tcp_backoff()
    try:
        for _ in range(3):
            assert await bridge._tcp_fallback(None, None, '127.0.0.1', port,
                                              b'initial-only', 'fixture', None) is False
        result = diag.snapshot()
        assert stages() == [('native_tcp', 'failure')]
        assert result['counts']['native_tcp_backoff_skipped'] == 2
        assert result['cooldowns'][0]['port'] == port and result['cooldowns'][0]['failures'] == 1
        assert 0 < result['cooldowns'][0]['remaining_ms'] <= 30000
        assert result['recent'][0]['errno'] == errno.ECONNREFUSED
    finally:
        listener.close()
        bridge.reset_tcp_backoff()
    assert not diag.snapshot()['cooldowns']


@pytest.mark.asyncio
async def test_dns_empty_answer_is_recorded_without_inventing_transport_error():
    endpoints = TelegramEndpoints()
    endpoints.resolver = SimpleNamespace(resolve=AsyncMock(return_value=None),
        last_addresses={}, close=AsyncMock())
    try:
        assert await endpoints.addresses(DOMAIN, '149.154.167.220') == ['149.154.167.220']
    finally:
        await endpoints.close()
    assert stages() == [('dns', 'failure')]
    event = diag.snapshot()['recent'][0]
    assert event['error'] == 'LookupError' and 'verify_code' not in event and 'errno' not in event


def test_bounded_detached_snapshot_excludes_messages_headers_and_reset_stale_attempts():
    old = diag.Attempt('ws_direct', DOMAIN, '149.154.167.99', 443)
    old.stage('tls')
    for _ in range(100):
        attempt = diag.Attempt('ws_direct', 'https://private.test/?secret=token', 'not-an-ip', 443)
        attempt.stage('tls')
        error = OSError(13, 'secret-request-content')
        error.headers = {'Authorization': 'private-key'}
        error.body = b'private-body'
        error.verify_code = 18
        attempt.failure(error)
    first = diag.snapshot()
    assert len(first['recent']) == diag.MAX_RECENT
    assert all(item['domain'] == '' and item['ip'] == '' for item in first['recent'])
    assert all(item['errno'] == 13 and item['verify_code'] == 18 for item in first['recent'])
    assert not any(value in json.dumps(first) for value in ('secret-request', 'private-key', 'private-body'))
    first['recent'][0]['error'] = 'mutated-snapshot'
    assert 'mutated-snapshot' not in json.dumps(diag.snapshot())
    diag.reset()
    old.failure(OSError('must-not-return'))
    assert diag.snapshot() == {'recent': [], 'active': [], 'counts': {}, 'cooldowns': []}


def test_concurrent_java_style_snapshot_reset_and_recording_stays_bounded():
    errors = []
    def write():
        try:
            for index in range(1000):
                attempt = diag.Attempt('native_tcp', host='149.154.167.51', port=443)
                attempt.stage('native_tcp')
                if index % 3:
                    attempt.failure(ConnectionRefusedError(errno.ECONNREFUSED, 'private-data'))
                diag.cooldown('149.154.167.51', 443, index + 1, time.monotonic() + 30)
        except BaseException as error:
            errors.append(error)
    thread = threading.Thread(target=write)
    thread.start()
    for index in range(1000):
        result = diag.snapshot()
        assert len(result['recent']) <= diag.MAX_RECENT and len(result['active']) <= diag.MAX_ACTIVE
        json.dumps(result)
        if index % 37 == 0:
            diag.reset()
    thread.join()
    assert not errors


@pytest.mark.asyncio
async def test_websocket_refill_backoff_reports_cooldown_and_skipped_dial(monkeypatch):
    pool = _WsPool()
    monkeypatch.setattr(proxy_config, 'pool_size', 1)
    monkeypatch.setattr(pool, '_schedule_rotation', Mock())
    dial = AsyncMock(return_value=None)
    monkeypatch.setattr(pool, '_connect_one', dial)
    key = (2, True, False)
    domains = ['kws2-1.web.telegram.org']
    try:
        pool._schedule_refill(key, '149.154.167.220', domains)
        await pool._refilling[key]
        pool._schedule_refill(key, '149.154.167.220', domains)
        dial.assert_awaited_once()
        result = diag.snapshot()
        assert result['counts']['ws_refill_backoff_skipped'] == 1
        cooldown = result['cooldowns'][0]
        assert cooldown['route'] == 'ws_pool' and cooldown['dc'] == 2
        assert cooldown['media'] is True and cooldown['failures'] == 1
        assert 0 < cooldown['remaining_ms'] <= 1000
    finally:
        await pool.close()
    assert not diag.snapshot()['cooldowns']
