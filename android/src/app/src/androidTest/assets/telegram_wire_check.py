"""Local wire check shared by desktop pytest and Android instrumentation.

Only the network dial is mapped to a trusted local TLS fixture. Native client
handshakes, AES streams, WS Upgrade, masks, pool acquisition and bridge traffic
all use the real application implementation. No Telegram account is involved.
"""
import asyncio
import base64
import contextvars
import hashlib
import json
import os
import ssl
import struct
import time

from proxy import tg_ws_proxy, raw_websocket
from proxy._aes import Cipher, algorithms, modes
from proxy.config import proxy_config
from proxy.pool import _WsPool
from proxy.utils import PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE


def _cipher(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def _frame(body, tag):
    if tag == PROTO_TAG_ABRIDGED:
        words = len(body) // 4
        return (bytes([words]) if words < 127 else b'\x7f' + words.to_bytes(3, 'little')) + body
    padding = b'\xa5\xa5\xa5' if tag == PROTO_TAG_SECURE else b''
    return struct.pack('<I', len(body) + len(padding)) + body + padding


async def _packet(reader, decryptor, tag):
    async def read(n):
        return decryptor.update(await reader.readexactly(n))
    if tag == PROTO_TAG_ABRIDGED:
        words = (await read(1))[0]
        if words == 127:
            words = int.from_bytes(await read(3), 'little')
        size = words * 4
    else:
        size = struct.unpack('<I', await read(4))[0]
    assert 0 < size <= 3 * 1024 * 1024, size
    body = await read(size)
    return body[:-3] if tag == PROTO_TAG_SECURE else body


def _ws_frame(body, opcode=2, final=True):
    first = opcode | (128 if final else 0)
    if len(body) < 126:
        return bytes([first, len(body)]) + body
    if len(body) < 65536:
        return bytes([first, 126]) + struct.pack('>H', len(body)) + body
    return bytes([first, 127]) + struct.pack('>Q', len(body)) + body


async def _read_ws(reader):
    head = await reader.readexactly(2)
    size = head[1] & 127
    if size == 126:
        size = struct.unpack('>H', await reader.readexactly(2))[0]
    elif size == 127:
        size = struct.unpack('>Q', await reader.readexactly(8))[0]
    assert head[1] & 128, 'native upstream WS frames must be masked'
    assert size <= 3 * 1024 * 1024
    mask = await reader.readexactly(4)
    raw = await reader.readexactly(size)
    body = bytes(value ^ mask[index % 4] for index, value in enumerate(raw))
    return head[0] & 15, body


def _native_handshake(secret, dc, tag):
    raw = bytearray(os.urandom(64))
    raw[0] = 0x42
    raw[56:62] = tag + struct.pack('<h', dc)
    keys = bytes(raw[8:56])
    up = _cipher(hashlib.sha256(keys[:32] + secret).digest(), keys[32:])
    reverse = keys[::-1]
    down = _cipher(hashlib.sha256(reverse[:32] + secret).digest(), reverse[32:])
    wire = bytearray(raw)
    wire[56:] = up.update(bytes(raw))[56:]
    return bytes(wire), up, down


async def run(cert_path, key_path):
    """Return measured results, raising if concurrent native traffic corrupts/stalls."""
    server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ssl.load_cert_chain(cert_path, key_path)
    client_ssl = ssl.create_default_context(cafile=cert_path)
    fronting_ssl = ssl.create_default_context(cafile=cert_path)
    fronting_ssl.check_hostname = False
    old_open = asyncio.open_connection
    old_connect = raw_websocket.RawWebSocket.connect
    old_contexts = raw_websocket._ssl_ctx, raw_websocket._ssl_ctx_fronting
    ws_target = contextvars.ContextVar('wire_fixture_ws_target', default=None)
    old_pool = tg_ws_proxy.ws_pool
    old_h2 = tg_ws_proxy.cf_h2_pool
    old_dpi_port = getattr(proxy_config, 'telegram_dpi_port', 0)
    proxy_config.telegram_dpi_port = 0
    old_config = {name: getattr(proxy_config, name) for name in
                  ('dc_redirects', 'pool_size', 'fallback_cfproxy',
                   'cfproxy_worker_domains', 'fake_tls_domain', 'proxy_protocol', 'force_test_dc')}
    proxy_config.dc_redirects = {2: '149.154.167.220', 4: '149.154.167.220'}
    proxy_config.pool_size = 2
    proxy_config.fallback_cfproxy = False
    proxy_config.cfproxy_worker_domains = []
    proxy_config.fake_tls_domain = ''
    proxy_config.proxy_protocol = False
    proxy_config.force_test_dc = False
    pool = tg_ws_proxy.ws_pool = _WsPool()
    tg_ws_proxy.cf_h2_pool = None
    trace_started = time.monotonic()
    acquire_trace, dial_trace = [], []
    real_get = pool.get

    async def traced_get(dc, is_media, *, is_test_dc=False):
        started = time.monotonic()
        key = dc, is_media, is_test_dc
        event = {'dc': dc, 'media': is_media,
                 'start': round(started - trace_started, 3), 'outcome': 'pending'}
        acquire_trace.append(event)
        try:
            ws = await real_get(dc, is_media, is_test_dc=is_test_dc)
            event['outcome'] = 'ok' if ws is not None else 'no_route'
            return ws
        except BaseException as exc:
            event['outcome'] = type(exc).__name__
            raise
        finally:
            now = time.monotonic()
            progress = getattr(pool, '_refill_progress', {}).get(key, 0)
            refill = pool._refilling.get(key)
            event.update(elapsed=round(now - started, 3),
                         progress_since_get=round(progress - started, 3) if progress else None,
                         progress_age=round(now - progress, 3) if progress else None,
                         refill_present=refill is not None,
                         refill_done=refill.done() if refill is not None else None,
                         backoff=round(max(0, pool._refill_after.get(key, 0) - now), 3),
                         ready=len(pool._idle.get(key, ())))

    pool.get = traced_get
    class VerifiedFixtureDNS:
        last_addresses = {}

        async def resolve(self, domain):
            assert domain.endswith('.web.telegram.org'), domain
            return '149.154.167.99'

        async def close(self):
            pass

    if hasattr(pool, '_endpoints'):
        # Separate resolver tests verify HTTPS DNS. Keep this wire fixture
        # deterministic and prohibit any external DNS or TCP dependency.
        pool._endpoints.resolver = VerifiedFixtureDNS()
    tasks, client_tasks, writers, errors, hosts = [], [], [], [], []
    endpoints, requests, tcp_endpoints = [], [], []
    secret = os.urandom(16)
    ready_bulk = asyncio.Event()
    first_replies = 0
    native_server = ws_server = tcp_server = None

    def start(coro):
        task = asyncio.create_task(coro)
        tasks.append(task)
        return task

    async def serve_ws(reader, writer):
        writers.append(writer)
        try:
            headers = await reader.readuntil(b'\r\n\r\n')
            assert headers.startswith(b'GET /apiws HTTP/1.1\r\n'), headers[:64]
            parsed = dict(line.split(b': ', 1) for line in headers.split(b'\r\n')[1:-2])
            assert parsed[b'Sec-WebSocket-Protocol'] == b'binary'
            hosts.append(parsed[b'Host'].decode())
            accept = base64.b64encode(hashlib.sha1(parsed[b'Sec-WebSocket-Key'] +
                b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
            writer.write(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                         b'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n')
            await writer.drain()
            opcode, init = await _read_ws(reader)
            if opcode == 8:
                return
            assert opcode == 2 and len(init) == 64
            keys = init[8:56]
            up = _cipher(keys[:32], keys[32:])
            decoded = up.update(init)
            tag, dc = decoded[56:60], struct.unpack('<h', decoded[60:62])[0]
            assert dc in (2, -1, -3, -4, -5), dc
            reverse = keys[::-1]
            down = _cipher(reverse[:32], reverse[32:])
            endpoints.append(dc)
            while True:
                opcode, encrypted = await _read_ws(reader)
                if opcode == 8:
                    return
                assert opcode == 2
                frame_reader = asyncio.StreamReader()
                frame_reader.feed_data(encrypted)
                body = await _packet(frame_reader, up, tag)
                magic, client, sequence, size = struct.unpack('<4sIII', body[:16])
                assert magic == b'SRKN' and len(body) == 40
                requests.append((client, sequence, size))
                reply = bytes([(client + sequence) % 256]) * size if size else struct.pack('<i', -404)
                wire = down.update(_frame(reply, tag))
                # Split one message into continuation frames; also split TLS writes.
                cut = min(11, len(wire) - 1)
                output = _ws_frame(wire[:cut], final=False) + _ws_frame(wire[cut:], opcode=0)
                for offset in range(0, len(output), 32768):
                    writer.write(output[offset:offset + 32768])
                    await writer.drain()
                    await asyncio.sleep(0)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            errors.append(repr(exc))
        finally:
            writer.close()

    async def serve_tcp_cdn(reader, writer):
        writers.append(writer)
        try:
            init = await reader.readexactly(64)
            keys = init[8:56]
            up = _cipher(keys[:32], keys[32:])
            decoded = up.update(init)
            tag, dc = decoded[56:60], struct.unpack('<h', decoded[60:62])[0]
            assert dc == -203, dc
            tcp_endpoints.append(dc)
            reverse = keys[::-1]
            down = _cipher(reverse[:32], reverse[32:])
            endpoints.append(dc)
            while True:
                body = await _packet(reader, up, tag)
                magic, client, sequence, size = struct.unpack('<4sIII', body[:16])
                assert magic == b'SRKN' and len(body) == 40
                requests.append((client, sequence, size))
                reply = bytes([(client + sequence) % 256]) * size
                wire = down.update(_frame(reply, tag))
                for offset in range(0, len(wire), 4096):
                    writer.write(wire[offset:offset + 4096])
                    await writer.drain()
                    await asyncio.sleep(0)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            errors.append(repr(exc))
        finally:
            writer.close()

    async def serve_native(reader, writer):
        writers.append(writer)
        await tg_ws_proxy._handle_client(reader, writer, secret)

    async def dial(host, port=None, **kwargs):
        if host in ('127.0.0.1', 'localhost'):
            return await old_open(host, port, **kwargs)
        # No test connection can accidentally escape to the Internet. Resolver
        # calls are unnecessary with the explicitly supplied pinned endpoints.
        if ws_target.get() is None:
            assert host == '91.105.192.100' and port == 443, 'cold WS miss fell through to raw TCP'
            return await old_open('127.0.0.1', tcp_port, **kwargs)
        assert port == 443 and kwargs.get('ssl') is None
        return await old_open('127.0.0.1', ws_port, **kwargs)

    async def connect_ws(host, domain, *args, **kwargs):
        # Preserve the production TLS context choice and original SNI. The
        # fixture certificate covers the real official Telegram hostnames.
        hostname = kwargs.get('sni') or domain
        started = time.monotonic()
        event = {'sni': hostname, 'address': host,
                 'start': round(started - trace_started, 3), 'outcome': 'pending',
                 'scope': 'tcp_tls_websocket'}
        dial_trace.append(event)
        token = ws_target.set(domain)
        try:
            assert domain in tuple('kws%d%s.web.telegram.org' % (dc, suffix)
                                   for dc in range(1, 6) for suffix in ('', '-1')), domain
            connection = await old_connect(host, domain, *args, **kwargs)
            event['outcome'] = 'ok'
            return connection
        except BaseException as exc:
            event['outcome'] = type(exc).__name__
            raise
        finally:
            event['elapsed'] = round(time.monotonic() - started, 3)
            ws_target.reset(token)

    async def client(index, media, tag, *, recovered=False, dc=None):
        nonlocal first_replies
        reader, writer = await old_open('127.0.0.1', native_port)
        writers.append(writer)
        native_dc = -(dc or 4) if media else (dc or 2)
        init, up, down = _native_handshake(secret, native_dc, tag)
        # Force the native init to span socket reads.
        writer.write(init[:13])
        await writer.drain()
        await asyncio.sleep(0)
        writer.write(init[13:])
        sizes = [24, (2 * 1024 * 1024 if media else 16384), 128]
        if recovered:
            sizes = [32768]
        if index == 0 and not recovered:
            sizes[-1] = 0
        total = 0
        try:
            for sequence, size in enumerate(sizes):
                body = struct.pack('<4sIII', b'SRKN', index, sequence, size) + b'k' * 24
                wire = up.update(_frame(body, tag))
                writer.write(wire[:3])
                await writer.drain()
                await asyncio.sleep(0)
                writer.write(wire[3:])
                await writer.drain()
                reply = await _packet(reader, down, tag)
                expected = bytes([(index + sequence) % 256]) * size if size else struct.pack('<i', -404)
                assert reply == expected, (index, sequence, len(reply), size)
                total += len(reply)
                if sequence == 0 and not recovered:
                    # The remote fixture and both client/proxy AES streams run
                    # on the same emulated CPU. Finish the cold acquisition
                    # burst before asking that CPU to encrypt 16 MiB of bulk
                    # replies, so fixture work cannot consume the production
                    # pool's unchanged 10-second connection deadline.
                    first_replies += 1
                    if first_replies == 12:
                        ready_bulk.set()
                    await ready_bulk.wait()
                await asyncio.sleep(0)
            return total
        finally:
            writer.close()

    try:
        tcp_server = await asyncio.start_server(lambda r, w: start(serve_tcp_cdn(r, w)),
                                                '127.0.0.1', 0)
        tcp_port = tcp_server.sockets[0].getsockname()[1]
        ws_server = await asyncio.start_server(lambda r, w: start(serve_ws(r, w)),
                                               '127.0.0.1', 0, ssl=server_ssl)
        ws_port = ws_server.sockets[0].getsockname()[1]
        native_server = await asyncio.start_server(lambda r, w: start(serve_native(r, w)),
                                                   '127.0.0.1', 0)
        native_port = native_server.sockets[0].getsockname()[1]
        asyncio.open_connection = dial
        raw_websocket.RawWebSocket.connect = staticmethod(connect_ws)
        raw_websocket._ssl_ctx, raw_websocket._ssl_ctx_fronting = client_ssl, fronting_ssl
        tags = (PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE)
        client_tasks = [asyncio.create_task(client(index, index < 8, tags[index % 3]))
                        for index in range(12)]
        try:
            completed = await asyncio.wait_for(asyncio.gather(*client_tasks), 90)
        except Exception as exc:
            # Only aggregate fixture state: never include secrets, packet
            # contents, account data or certificate/private-key material.
            details = {'failure': type(exc).__name__, 'first_replies': first_replies,
                       'clients_done': sum(task.done() for task in client_tasks),
                       'server_errors': errors[:8], 'requests': len(requests),
                       'native_dcs': endpoints, 'acquisitions': acquire_trace,
                       'tls_dials': dial_trace[:96]}
            raise AssertionError('Telegram wire acquisition failed: ' +
                                 json.dumps(details, separators=(',', ':'))) from exc
        # An expired media key in one channel must leave all others intact;
        # a fresh native connection must immediately be usable afterwards.
        recovery_task = asyncio.create_task(client(0, True, PROTO_TAG_SECURE, recovered=True))
        client_tasks.append(recovery_task)
        recovered_bytes = await asyncio.wait_for(recovery_task, 15)
        extra_tasks = [asyncio.create_task(
            client(20 + index, True, tags[index % 3], recovered=True, dc=dc))
            for index, dc in enumerate((1, 3, 5, 203))]
        client_tasks.extend(extra_tasks)
        extra_bytes = await asyncio.wait_for(asyncio.gather(*extra_tasks), 15)
        assert not errors, errors
        assert len(endpoints) == 17, endpoints
        assert len(requests) == 41, len(requests)
        assert all(-dc in endpoints for dc in (1, 3, 5, 203))
        assert endpoints.count(-4) == 9 and endpoints.count(2) == 4
        assert tcp_endpoints == [-203], tcp_endpoints
        return {'clients': 12, 'reconnected': 1, 'media_clients': 8,
                'received_bytes': sum(completed) + recovered_bytes + sum(extra_bytes),
                'native_dcs': sorted(set(abs(dc) for dc in endpoints)),
                'requests': len(requests), 'transport_error_forwarded': -404,
                'tags': ['abridged', 'intermediate', 'padded'],
                'hosts': sorted(set(hosts)), 'tls': True, 'cdn_203': 'native_tcp',
                'third_party_routes': 0}
    finally:
        # Python 3.12 Server.wait_closed() also waits for accepted connections.
        # A failed client must release the other clients at the bulk barrier
        # and every accepted socket before waiting for a server to close.
        for server in (native_server, ws_server, tcp_server):
            if server:
                server.close()
        for task in client_tasks + tasks:
            if not task.done():
                task.cancel()
        for writer in writers:
            writer.close()
            # A failed handshake does not need a graceful TLS close exchange.
            # Aborting also releases a peer blocked on read/drain immediately.
            writer.transport.abort()
        try:
            await asyncio.gather(*client_tasks, *tasks, return_exceptions=True)
            await pool.close()
            for server in (native_server, ws_server, tcp_server):
                if server:
                    await server.wait_closed()
        finally:
            asyncio.open_connection = old_open
            raw_websocket.RawWebSocket.connect = staticmethod(old_connect)
            raw_websocket._ssl_ctx, raw_websocket._ssl_ctx_fronting = old_contexts
            tg_ws_proxy.ws_pool = old_pool
            tg_ws_proxy.cf_h2_pool = old_h2
            proxy_config.telegram_dpi_port = old_dpi_port
            for name, value in old_config.items():
                setattr(proxy_config, name, value)
