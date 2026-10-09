"""Regression fixture: native MTProto works despite stalled DNS and failed DPI.

Only the approved pinned IP is mapped to the host-side TLS fixture. The real
pool, certificate checks, WebSocket, MTProto handshake and Android AES are used.
"""
import asyncio
import hashlib
import os
import ssl
import struct
import time

from proxy import raw_websocket, tg_ws_proxy
from proxy._aes import Cipher, algorithms, modes
from proxy.config import proxy_config
from proxy.pool import _WsPool

PIN = '149.154.167.220'
TAG = b'\xee' * 4


def cipher(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def native_init(secret):
    initial = bytearray(os.urandom(64))
    initial[0] = 0x42
    initial[56:62] = TAG + struct.pack('<h', -4)
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


async def run(ca_pem, server_ip='10.0.2.2'):
    strict = ssl.create_default_context(cadata=ca_pem)
    legacy = ssl.create_default_context(cadata=ca_pem)
    legacy.check_hostname = False
    original_open = asyncio.open_connection
    old_contexts = raw_websocket._ssl_ctx, raw_websocket._ssl_ctx_fronting
    old_pool, old_h2 = tg_ws_proxy.ws_pool, tg_ws_proxy.cf_h2_pool
    fields = ('dc_redirects', 'pool_size', 'fallback_cfproxy', 'cfproxy_worker_domains',
              'fake_tls_domain', 'proxy_protocol', 'force_test_dc', 'telegram_dpi_port')
    original_config = {key: getattr(proxy_config, key) for key in fields}
    state = {'dns_calls': 0, 'dpi_rejected': 0, 'direct_sni': []}
    tasks, writers = set(), []
    secret = os.urandom(16)
    pool = _WsPool()
    native = rejector = None

    class StalledDNS:
        last_addresses = {}

        async def resolve(self, name):
            state['dns_calls'] += 1
            await asyncio.Future()

        async def close(self):
            pass

    async def dial(host, port=None, **kwargs):
        if host == PIN and port == 443:
            assert kwargs.get('ssl') is None, 'Expected separate TCP and TLS stages'
            reader, writer = await original_open(server_ip, 443, **kwargs)
            original_tls = writer.start_tls
            async def observe_tls(context, **options):
                state['direct_sni'].append(options.get('server_hostname'))
                return await original_tls(context, **options)
            writer.start_tls = observe_tls
            return reader, writer
        assert host == '127.0.0.1', ('Unexpected external destination', host, port)
        return await original_open(host, port, **kwargs)

    async def reject_dpi(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        writers.append(writer)
        try:
            assert await reader.readexactly(3) == b'\x05\x01\x00'
            writer.write(b'\x05\x00')
            await writer.drain()
            command = await reader.readexactly(4)
            assert command == b'\x05\x01\x00\x01'
            await reader.readexactly(6)
            state['dpi_rejected'] += 1
            writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            await reader.read()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            tasks.discard(task)

    async def serve_native(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        writers.append(writer)
        try:
            await tg_ws_proxy._handle_client(reader, writer, secret)
        finally:
            tasks.discard(task)

    try:
        rejector = await asyncio.start_server(reject_dpi, '127.0.0.1', 0)
        proxy_config.telegram_dpi_port = rejector.sockets[0].getsockname()[1]
        proxy_config.dc_redirects = {4: PIN}
        proxy_config.pool_size = 1
        proxy_config.fallback_cfproxy = False
        proxy_config.cfproxy_worker_domains = []
        proxy_config.fake_tls_domain = ''
        proxy_config.proxy_protocol = proxy_config.force_test_dc = False
        pool._endpoints.resolver = StalledDNS()
        tg_ws_proxy.ws_pool, tg_ws_proxy.cf_h2_pool = pool, None
        raw_websocket._ssl_ctx, raw_websocket._ssl_ctx_fronting = strict, legacy
        asyncio.open_connection = dial
        native = await asyncio.start_server(serve_native, '127.0.0.1', 0)
        reader, writer = await original_open('127.0.0.1', native.sockets[0].getsockname()[1])
        writers.append(writer)
        initial, upload, download = native_init(secret)
        nonce = os.urandom(16)
        request_body = struct.pack('<I', 0xbe7e8ef1) + nonce
        request = b'\0' * 8 + struct.pack('<QI', int(time.time()) << 32, len(request_body)) + request_body
        started = time.monotonic()
        writer.write(initial + upload.update(struct.pack('<I', len(request)) + request))
        await writer.drain()
        response = await asyncio.wait_for(packet(reader, download), 8)
        first_reply = time.monotonic() - started
        assert response[:8] == b'\0' * 8
        size = struct.unpack('<I', response[16:20])[0]
        assert size == len(response) - 20
        assert response[20:24] == struct.pack('<I', 0x05162463), 'Expected resPQ'
        assert response[24:40] == nonce, 'resPQ nonce mismatch'
        # Exercise the packaged diagnostic itself, including its padded native
        # protocol, Android AES and complete resPQ parser. It must close only
        # its own connection: the original client stays live for the transfers
        # below and would fail if the check reset the pool or active sessions.
        import telegram_probe
        assert telegram_probe.TOTAL_TIMEOUT == 5.0
        probe = await telegram_probe.check_telegram(
            native.sockets[0].getsockname()[1], secret, dc=4, is_media=True)
        assert probe['state'] == 'reachable' and probe['stage'] == 'MTProto', probe
        assert not probe['error'] and probe['elapsed_ms'] < 5000, probe
        samples = [b'ECHOsticker\x00\xff', 'ECHOэмодзи 🦊'.encode(), b'ECHO' + bytes(range(256)) * 4096]
        samples = [sample + b'\0' * (-len(sample) % 4) for sample in samples]
        transfers = []
        for sample in samples:
            writer.write(upload.update(struct.pack('<I', len(sample)) + sample))
            await writer.drain()
            reply = await asyncio.wait_for(packet(reader, download), 15)
            assert reply == sample, (len(reply), len(sample))
            transfers.append({'bytes': len(reply), 'sha256': hashlib.sha256(reply).hexdigest()})
        assert state['dns_calls'] > 0, 'Stalled DNS was not exercised'
        assert state['dpi_rejected'] > 0, 'Failed canonical DPI route was not exercised'
        assert 'sprinthost.ru' in state['direct_sni'], state
        return {'result': 'PASS', 'transport': 'native MTProto -> pinned direct fronted WSS',
                'first_resPQ_seconds': round(first_reply, 3), 'nonce_verified': True,
                'packaged_probe': probe, 'existing_client_survived_probe': True,
                'stalled_dns_calls': state['dns_calls'], 'canonical_dpi_failures': state['dpi_rejected'],
                'sni': sorted(set(state['direct_sni'])), 'transfers': transfers,
                'third_party_relays': 0, 'certificate_chain_verified': legacy.verify_mode == ssl.CERT_REQUIRED}
    finally:
        for server in (native, rejector):
            if server:
                server.close()
        for writer in writers:
            writer.close()
        for task in list(tasks):
            task.cancel()
        await asyncio.gather(*list(tasks), return_exceptions=True)
        await pool.close()
        for server in (native, rejector):
            if server:
                await server.wait_closed()
        asyncio.open_connection = original_open
        raw_websocket._ssl_ctx, raw_websocket._ssl_ctx_fronting = old_contexts
        tg_ws_proxy.ws_pool, tg_ws_proxy.cf_h2_pool = old_pool, old_h2
        for key, value in original_config.items():
            setattr(proxy_config, key, value)
