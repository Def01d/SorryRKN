"""Test APK only: real native MTProto fallback across alternative TCP endpoints.

All official destination addresses are mapped to explicitly allowed local
listeners. Production endpoint selection, acquisition racing, bridge, probe and
Android AES remain unchanged. No Telegram account or external network is used.
"""
import asyncio
import contextlib
import contextvars
import hashlib
import os
import socket
import struct
import time

from proxy import bridge, route_diagnostics, tg_ws_proxy
from proxy._aes import Cipher, algorithms, modes
from proxy.config import proxy_config
from proxy.stats import stats
from telegram_probe import check_telegram

DC4 = '149.154.167.91'
DC2 = '149.154.167.51'
BACKUP2 = '95.161.76.100'
INTERMEDIATE = b'\xee' * 4
PADDED = b'\xdd' * 4


def cipher(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def native_init(secret, dc):
    initial = bytearray(os.urandom(64))
    initial[0] = 0x42
    initial[56:62] = INTERMEDIATE + struct.pack('<h', dc)
    keys = bytes(initial[8:56])
    upload = cipher(hashlib.sha256(keys[:32] + secret).digest(), keys[32:])
    reverse = keys[::-1]
    download = cipher(hashlib.sha256(reverse[:32] + secret).digest(), reverse[32:])
    encrypted = upload.update(bytes(initial))
    initial[56:] = encrypted[56:]
    return bytes(initial), upload, download


async def packet(reader, decrypt):
    size = struct.unpack('<I', decrypt.update(await reader.readexactly(4)))[0]
    assert 0 < size <= 2 * 1024 * 1024, size
    return decrypt.update(await reader.readexactly(size))


async def run():
    original_open = asyncio.open_connection
    old_pool, old_h2 = tg_ws_proxy.ws_pool, tg_ws_proxy.cf_h2_pool
    fields = ('fallback_cfproxy', 'cfproxy_worker_domains', 'fake_tls_domain',
              'proxy_protocol', 'force_test_dc', 'telegram_dpi_port')
    old_config = {name: getattr(proxy_config, name) for name in fields}
    assert not bridge._tcp_connecting, 'Run the native fixture without a running application service'
    old_backoff = dict(bridge._tcp_retry_after), dict(bridge._tcp_failures)
    initial_tcp = stats.connections_tcp_fallback
    initial_ws = stats.connections_ws
    secret = os.urandom(16)
    native_identity = contextvars.ContextVar('fixture_native_identity', default=None)
    listeners, writers, clients, handlers = [], [], [], set()
    connections, errors, dialed, gates = [], [], [], {}
    native_index = 0
    first_replies = 0
    all_ready, bulk_ready = asyncio.Event(), asyncio.Event()
    route_ports = {}
    refused = socket.socket()
    refused.bind(('127.0.0.1', 0))
    refused_port = refused.getsockname()[1]

    class NativeOnlyPool:
        async def get(self, *args, **kwargs):
            # Inject only the WSS miss. The actual native fallback is entirely
            # production code, including shared-probe and endpoint cooldowns.
            return None

    async def dial(host, port=None, **kwargs):
        if host == '127.0.0.1':
            return await original_open(host, port, **kwargs)
        endpoint = host, port
        assert endpoint in route_ports, ('Unexpected external destination', endpoint)
        assert not kwargs.get('ssl'), 'Native fallback unexpectedly enabled TLS'
        identity = native_identity.get()
        assert identity is not None, 'Native dial occurred outside a client session'
        dialed.append((identity, host, port))
        writer = None
        try:
            reader, writer = await original_open('127.0.0.1', route_ports[endpoint], **kwargs)
            writers.append(writer)
            if host == DC4 and port in (5222, 80):
                # Both alternatives really establish TCP before either dial
                # returns. Thus every race has a connected loser whose closure
                # and zero received bytes can be observed at the remote side.
                ports, ready = gates.setdefault(identity, (set(), asyncio.Event()))
                ports.add(port)
                if ports == {5222, 80}:
                    ready.set()
                await ready.wait()
            return reader, writer
        except BaseException:
            if writer is not None:
                writer.close()
                writer.transport.abort()
            raise

    async def remote(reader, writer, endpoint):
        task = asyncio.current_task()
        handlers.add(task)
        writers.append(writer)
        entry = {'endpoint': endpoint, 'bytes': 0, 'initialised': False,
                 'clients': set(), 'nonces': set(), 'closed': False, 'packets': 0}
        connections.append(entry)
        try:
            try:
                initial = await reader.readexactly(64)
            except asyncio.IncompleteReadError as error:
                entry['bytes'] += len(error.partial)
                return
            entry['bytes'] += 64
            entry['initialised'] = True
            keys = initial[8:56]
            upload = cipher(keys[:32], keys[32:])
            decoded = upload.update(initial)
            tag, dc = decoded[56:60], struct.unpack('<h', decoded[60:62])[0]
            assert tag in (INTERMEDIATE, PADDED), tag.hex()
            assert abs(dc) == (2 if endpoint[0] == BACKUP2 else 4), dc
            reverse = keys[::-1]
            download = cipher(reverse[:32], reverse[32:])
            while True:
                try:
                    header = await reader.readexactly(4)
                except asyncio.IncompleteReadError as error:
                    entry['bytes'] += len(error.partial)
                    break
                size = struct.unpack('<I', upload.update(header))[0]
                assert 0 < size <= 2 * 1024 * 1024, size
                encrypted = await reader.readexactly(size)
                entry['bytes'] += 4 + size
                body = upload.update(encrypted)
                entry['packets'] += 1
                if body.startswith(b'SRKN'):
                    assert tag == INTERMEDIATE
                    client_id, sequence, payload_length = struct.unpack('<III', body[4:16])
                    assert len(body) == 16 + payload_length
                    entry['clients'].add(client_id)
                    reply = body
                else:
                    assert tag == PADDED and body[:8] == b'\0' * 8
                    message_length = struct.unpack('<I', body[16:20])[0]
                    assert 0 <= len(body) - 20 - message_length <= 15
                    body = body[:20 + message_length]
                    assert len(body) == 40 and body[20:24] == struct.pack('<I', 0xbe7e8ef1)
                    nonce = body[24:40]
                    entry['nonces'].add(nonce)
                    response_body = (struct.pack('<I', 0x05162463) + nonce + os.urandom(16)
                                     + b'\x02\x01\xb5\x00'
                                     + struct.pack('<IIQ', 0x1cb5c415, 1, 0x0102030405060708))
                    reply = b'\0' * 8 + struct.pack('<QI', (int(time.time()) << 32) | 1,
                                                     len(response_body)) + response_body
                payload = reply + (os.urandom(7) if tag == PADDED else b'')
                wire = download.update(struct.pack('<I', len(payload)) + payload)
                for offset in range(0, len(wire), 32768):
                    writer.write(wire[offset:offset + 32768])
                    await writer.drain()
                    await asyncio.sleep(0)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        except Exception as error:
            errors.append(type(error).__name__)
        finally:
            writer.close()
            writer.transport.abort()
            entry['closed'] = True
            handlers.discard(task)

    async def accepted_native(reader, writer):
        nonlocal native_index
        identity = native_index
        native_index += 1
        token = native_identity.set(identity)
        task = asyncio.current_task()
        handlers.add(task)
        writers.append(writer)
        try:
            await tg_ws_proxy._handle_client(reader, writer, secret)
        finally:
            handlers.discard(task)
            native_identity.reset(token)

    async def client(index, native_port):
        nonlocal first_replies
        reader, writer = await original_open('127.0.0.1', native_port)
        writers.append(writer)
        initial, upload, download = native_init(secret, -4 if index < 8 else 4)
        writer.write(initial[:13])
        await writer.drain()
        await asyncio.sleep(0)
        writer.write(initial[13:])
        total = 0
        try:
            for sequence, size in enumerate((24, 512 * 1024 if index < 8 else 16 * 1024, 128)):
                body = struct.pack('<4sIII', b'SRKN', index, sequence, size) + bytes([index + sequence]) * size
                wire = upload.update(struct.pack('<I', len(body)) + body)
                writer.write(wire[:3])
                await writer.drain()
                await asyncio.sleep(0)
                writer.write(wire[3:])
                await writer.drain()
                reply = await packet(reader, download)
                assert reply == body, (index, sequence, len(reply), len(body))
                total += len(reply)
                if sequence == 0:
                    first_replies += 1
                    if first_replies == 12:
                        all_ready.set()
                    await bulk_ready.wait()
            return total
        finally:
            writer.close()
            writer.transport.abort()

    try:
        bridge.reset_tcp_backoff()
        route_diagnostics.reset()
        tg_ws_proxy.ws_pool, tg_ws_proxy.cf_h2_pool = NativeOnlyPool(), None
        proxy_config.fallback_cfproxy = False
        proxy_config.cfproxy_worker_domains = []
        proxy_config.fake_tls_domain = ''
        proxy_config.proxy_protocol = proxy_config.force_test_dc = False
        proxy_config.telegram_dpi_port = 0
        for endpoint in ((DC4, 5222), (DC4, 80), (BACKUP2, 443)):
            server = await asyncio.start_server(
                lambda reader, writer, endpoint=endpoint: remote(reader, writer, endpoint), '127.0.0.1', 0)
            listeners.append(server)
            route_ports[endpoint] = server.sockets[0].getsockname()[1]
        for endpoint in ((DC4, 443), (DC2, 443), (DC2, 5222), (DC2, 80)):
            route_ports[endpoint] = refused_port
        native = await asyncio.start_server(accepted_native, '127.0.0.1', 0)
        listeners.append(native)
        native_port = native.sockets[0].getsockname()[1]
        asyncio.open_connection = dial
        async with asyncio.timeout(60):
            clients = [asyncio.create_task(client(index, native_port)) for index in range(12)]
            ready_task = asyncio.create_task(all_ready.wait())
            group = asyncio.gather(*clients)
            try:
                done, _ = await asyncio.wait((ready_task, group), return_when=asyncio.FIRST_COMPLETED)
                if group in done:
                    await group
                    raise AssertionError('Clients finished before the concurrent bulk barrier')
                await ready_task
                # Real production padded MTProto parser/AES, while all twelve
                # existing sessions remain connected and await their bulk work.
                probes = await asyncio.gather(
                    check_telegram(native_port, secret, dc=4, is_media=True),
                    check_telegram(native_port, secret, dc=2))
                assert all(item['state'] == 'reachable' and item['elapsed_ms'] < 5000 for item in probes), probes
                bulk_ready.set()
                totals = await group
            finally:
                ready_task.cancel()
                await asyncio.gather(ready_task, return_exceptions=True)
                if not group.done():
                    group.cancel()
                await asyncio.gather(group, return_exceptions=True)
            deadline = time.monotonic() + 3
            while any(not item['closed'] for item in connections) and time.monotonic() < deadline:
                await asyncio.sleep(.01)
            assert not errors, errors
            assert all(item['closed'] for item in connections), 'Race/client sockets remained open'
            winners = [item for item in connections if item['initialised']]
            losers = [item for item in connections if not item['initialised']]
            assert len(winners) == 14, len(winners)
            assert len(losers) >= 13 and all(item['bytes'] == 0 for item in losers), losers
            for index in range(12):
                selected = [item for item in winners if index in item['clients']]
                assert len(selected) == 1 and selected[0]['packets'] == 3, (index, len(selected))
            assert sum(len(item['nonces']) for item in winners) == 2
            assert sum(bool(item['nonces']) for item in winners if item['endpoint'] == (BACKUP2, 443)) == 1
            assert stats.connections_tcp_fallback - initial_tcp == 14
            assert stats.connections_ws == initial_ws
            assert not bridge._tcp_connecting
            return {'result': 'PASS', 'clients': 12, 'media_clients': 8,
                    'transferred_bytes_each_direction': sum(totals),
                    'verified_production_probes': probes,
                    'native_winners': len(winners), 'connected_losers': len(losers),
                    'loser_payload_bytes': sum(item['bytes'] for item in losers),
                    'one_winner_per_client': True, 'existing_clients_survived_probes': True,
                    'winner_endpoints': sorted(set('%s:%d' % item['endpoint'] for item in winners)),
                    'refused_endpoints': sorted(set('%s:%d' % endpoint for endpoint, port in route_ports.items()
                                                   if port == refused_port)),
                    'dial_attempts': len(dialed), 'external_connections': 0,
                    'all_remote_sockets_closed': True}
    finally:
        for server in listeners:
            server.close()
        for task in clients:
            task.cancel()
        for writer in writers:
            writer.close()
            writer.transport.abort()
        for task in list(handlers):
            task.cancel()
        try:
            async with asyncio.timeout(10):
                await asyncio.gather(*clients, *list(handlers), return_exceptions=True)
                for server in listeners:
                    await server.wait_closed()
        finally:
            asyncio.open_connection = original_open
            tg_ws_proxy.ws_pool, tg_ws_proxy.cf_h2_pool = old_pool, old_h2
            for name, value in old_config.items():
                setattr(proxy_config, name, value)
            bridge.reset_tcp_backoff()
            bridge._tcp_retry_after.update(old_backoff[0])
            bridge._tcp_failures.update(old_backoff[1])
            refused.close()
