"""Test-APK-only checks of packaged CA roots and real connection diagnostics.

All network operations use local fixture sockets. Default trust is measured
before any override; it must reject the fixture's self-signed certificate.
"""
import asyncio
import contextlib
import hashlib
import json
from pathlib import Path
import socket
import ssl

import certifi
import android_bridge
from proxy import raw_websocket, route_diagnostics, bridge
from proxy.config import proxy_config

DOMAIN = 'kws4-1.web.telegram.org'
TARGET = '192.0.2.77'


async def run(directory):
    cert_path, key_path = str(Path(directory) / 'cert.pem'), str(Path(directory) / 'key.pem')
    # Measure the already-created, actually packaged contexts. Constructing a
    # fresh test context here would hide a broken application's trust store.
    normal, legacy = raw_websocket._ssl_ctx, raw_websocket._ssl_ctx_fronting
    ca_bytes = Path(certifi.where()).read_bytes()
    defaults = {'openssl': ssl.OPENSSL_VERSION, 'certifi_version': certifi.__version__,
                'ca_file_bytes': len(ca_bytes), 'ca_file_sha256': hashlib.sha256(ca_bytes).hexdigest(),
                'normal_ca_count': normal.cert_store_stats()['x509_ca'],
                'legacy_ca_count': legacy.cert_store_stats()['x509_ca'],
                'normal_verify_mode': int(normal.verify_mode),
                'legacy_verify_mode': int(legacy.verify_mode),
                'normal_check_hostname': normal.check_hostname,
                'legacy_check_hostname': legacy.check_hostname,
                'normal_verify_flags': int(normal.verify_flags),
                'minimum_tls_version': int(normal.minimum_version)}
    assert defaults['normal_ca_count'] >= 100 and defaults['legacy_ca_count'] >= 100, defaults
    assert normal.verify_mode == legacy.verify_mode == ssl.CERT_REQUIRED
    assert normal.check_hostname and not legacy.check_hostname
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    trusted = ssl.create_default_context(cafile=cert_path)
    assert trusted.check_hostname and trusted.verify_mode == ssl.CERT_REQUIRED
    original_open = asyncio.open_connection
    old_port = proxy_config.telegram_dpi_port
    old_check = android_bridge._telegram_check
    old_backoff = dict(bridge._tcp_retry_after), dict(bridge._tcp_failures)
    canary = 'ROUTE_FIXTURE_PRIVATE_CONTENT_735920'
    current_port = None
    servers, writers, handlers, reserved = [], [], set(), []
    cases = []
    route_diagnostics.reset()

    async def mapped_open(host, port=None, **kwargs):
        if host == TARGET:
            assert port == 443 and current_port is not None
            return await original_open('127.0.0.1', current_port, **kwargs)
        assert host == '127.0.0.1', ('External access prohibited in fixture', host, port)
        return await original_open(host, port, **kwargs)

    async def start(handler, *, tls=False):
        async def accepted(reader, writer):
            task = asyncio.current_task()
            handlers.add(task)
            writers.append(writer)
            try:
                await handler(reader, writer)
            except (OSError, asyncio.IncompleteReadError):
                pass
            finally:
                writer.close()
                with contextlib.suppress(OSError, asyncio.TimeoutError):
                    await asyncio.wait_for(writer.wait_closed(), .5)
                writer.transport.abort()
                handlers.discard(task)
        server = await asyncio.start_server(accepted, '127.0.0.1', 0,
                                           ssl=server_context if tls else None)
        servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def closed_peer(reader, writer):
        await reader.read()

    def refused_port():
        # Keep the port reserved without listening: a real local ECONNREFUSED,
        # with no race in which another listener could claim the selected port.
        reserved_socket = socket.socket()
        reserved_socket.bind(('127.0.0.1', 0))
        reserved.append(reserved_socket)
        return reserved_socket.getsockname()[1]

    def last_outcome(stage, outcome, *, route='ws_direct'):
        snapshot = route_diagnostics.snapshot()
        matching = [entry for entry in snapshot['recent']
                    if entry['route'] == route and entry['stage'] == stage and entry['outcome'] == outcome]
        assert matching, snapshot
        assert not snapshot['active'], snapshot['active']
        return matching[-1]

    async def fails(name, expected, stage, *, timeout=3, domain=DOMAIN, direct=True,
                    route='ws_direct', **fields):
        before = len(route_diagnostics.snapshot()['recent'])
        try:
            ws = await raw_websocket.RawWebSocket.connect(
                TARGET, domain, timeout=timeout, path='/apiws?' + canary, direct=direct)
        except expected:
            pass
        else:
            await ws.close()
            raise AssertionError(name + ' unexpectedly succeeded')
        entry = last_outcome(stage, 'failure', route=route)
        assert len(route_diagnostics.snapshot()['recent']) > before
        for key, value in fields.items():
            assert entry.get(key) == value, (key, entry)
        cases.append(dict(entry, case=name))
        return entry

    try:
        asyncio.open_connection = mapped_open
        proxy_config.telegram_dpi_port = 0
        current_port = refused_port()
        await fails('tcp_refused', ConnectionRefusedError, 'tcp', errno=111)

        current_port = await start(closed_peer, tls=True)
        entry = await fails('default_ca_rejects_self_signed', ssl.SSLCertVerificationError, 'tls')
        assert isinstance(entry.get('verify_code'), int), entry
        assert raw_websocket._ssl_ctx is normal

        raw_websocket._ssl_ctx = trusted
        entry = await fails('trusted_ca_still_checks_hostname', ssl.SSLCertVerificationError,
                            'tls', domain='wrong.telegram-fixture.invalid')
        assert isinstance(entry.get('verify_code'), int), entry

        async def forbidden(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            writer.write(('HTTP/1.1 403 ' + canary + '\r\nX-Private: ' + canary +
                          '\r\nContent-Length: 0\r\n\r\n').encode())
            await writer.drain()
            await reader.read()
        current_port = await start(forbidden, tls=True)
        await fails('http_403', raw_websocket.WsHandshakeError, 'http_upgrade', http_status=403)

        for cancelled in (False, True):
            entered = asyncio.Event()
            async def tls_stall(reader, writer):
                hello = await reader.read(8192)
                assert hello[:2] == b'\x16\x03', hello[:2]
                entered.set()
                await reader.read()
            current_port = await start(tls_stall)
            if cancelled:
                task = asyncio.create_task(raw_websocket.RawWebSocket.connect(
                    TARGET, DOMAIN, timeout=5, direct=True))
                await asyncio.wait_for(entered.wait(), 2)
                assert any(item['stage'] == 'tls' for item in route_diagnostics.snapshot()['active'])
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
                entry = last_outcome('tls', 'cancelled')
                assert 'error' not in entry
                cases.append(dict(entry, case='tls_external_cancellation'))
            else:
                await fails('tls_deadline', asyncio.TimeoutError, 'tls', timeout=1,
                            error='TimeoutError')
                assert entered.is_set()

        async def http_stall(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            writer.write(b'HTTP/1.1 101 Switching Protocols\r\n')
            await writer.drain()
            await reader.read()
        current_port = await start(http_stall, tls=True)
        await fails('http_upgrade_deadline', asyncio.TimeoutError, 'http_upgrade', timeout=2,
                    error='TimeoutError')

        async def reject_socks(reader, writer):
            assert await reader.readexactly(3) == b'\x05\x01\x00'
            writer.write(b'\x05\x00')
            await writer.drain()
            assert await reader.readexactly(4) == b'\x05\x01\x00\x01'
            await reader.readexactly(6)
            writer.write(b'\x05\x04\x00\x01\0\0\0\0\0\0')
            await writer.drain()
            await reader.read()
        proxy_config.telegram_dpi_port = await start(reject_socks)
        await fails('socks_destination_rejected', ConnectionError, 'local_socks',
                    direct=False, route='ws_local_socks', socks_reply=4)
        proxy_config.telegram_dpi_port = 0

        current_port = refused_port()
        assert not await bridge._tcp_fallback(None, None, TARGET, 443, b'fixture-init', 'fixture', None)
        native = last_outcome('native_tcp', 'failure', route='native_tcp')
        assert native.get('errno') == 111, native
        assert not await bridge._tcp_fallback(None, None, TARGET, 443, b'fixture-init', 'fixture', None)
        cases.append(dict(native, case='native_tcp_refused'))
        snapshot = route_diagnostics.snapshot()
        assert snapshot['counts'].get('native_tcp_backoff_skipped') == 1, snapshot
        assert any(entry['ip'] == TARGET and entry['remaining_ms'] > 0
                   for entry in snapshot['cooldowns']), snapshot

        # Export via the application's actual Android bridge, with the original
        # production TLS contexts restored before inspecting the reported CAs.
        raw_websocket._ssl_ctx = normal
        android_bridge._telegram_check = {'state': 'checking', 'authenticated_access': False}
        exported_text = android_bridge.diagnostics()
        exported = json.loads(exported_text)
        assert exported['telegram_tls']['ca_certificates'] == defaults['normal_ca_count']
        assert exported['telegram_tls']['certificate_required']
        assert exported['telegram_counters_scope'] == 'current_connection'
        assert exported['telegram_routes']['recent'] == route_diagnostics.snapshot()['recent']
        assert canary not in exported_text and proxy_config.secret not in exported_text
        assert not exported['telegram_routes']['active']
        return {'result': 'PASS', 'default_tls': defaults, 'cases': cases,
                'export_has_routes': True, 'export_has_real_ca_count': True,
                'secret_and_peer_content_absent': True,
                'native_tcp_cooldown': exported['telegram_routes']['cooldowns'],
                'stage_counts': exported['telegram_routes']['counts']}
    finally:
        for server in servers:
            server.close()
        for writer in writers:
            writer.close()
            writer.transport.abort()
        for task in list(handlers):
            task.cancel()
        await asyncio.gather(*list(handlers), return_exceptions=True)
        for server in servers:
            await server.wait_closed()
        for item in reserved:
            item.close()
        asyncio.open_connection = original_open
        raw_websocket._ssl_ctx, raw_websocket._ssl_ctx_fronting = normal, legacy
        proxy_config.telegram_dpi_port = old_port
        android_bridge._telegram_check = old_check
        bridge._tcp_retry_after.clear()
        bridge._tcp_retry_after.update(old_backoff[0])
        bridge._tcp_failures.clear()
        bridge._tcp_failures.update(old_backoff[1])
