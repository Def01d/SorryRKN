"""Offline protocol regressions: run with the bundled Python -m unittest."""
import asyncio
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from proxy import tg_ws_proxy, upstream, config as config_module
from proxy._aes import Cipher, algorithms, modes
from proxy.config import proxy_config
from proxy.mtproto_probe import (TcpTransport, client_crypto, probe_local, read_packet,
                                 req_pq_packet, validate_res_pq, RES_PQ)
from proxy.utils import PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE
from tg_runner import publish_health, configure_domains


class LocalTelegram:
    """Independent server-side obfuscated transport, no Internet connections."""
    def __init__(self):
        self.calls = []
        self.writers = set()
        self.tasks = set()
        self.error_nonce = None

    def accept(self, reader, writer):
        task = asyncio.create_task(self.handle(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def handle(self, reader, writer):
        self.writers.add(writer)
        try:
            init = await reader.readexactly(64)
            material = init[8:56]
            dec = Cipher(algorithms.AES(material[:32]), modes.CTR(material[32:])).encryptor()
            reverse = material[::-1]
            enc = Cipher(algorithms.AES(reverse[:32]), modes.CTR(reverse[32:])).encryptor()
            decrypted = dec.update(init)
            proto, dc = decrypted[56:60], struct.unpack_from('<h', decrypted, 60)[0]
            while True:
                if proto == PROTO_TAG_ABRIDGED:
                    words = dec.update(await reader.readexactly(1))[0] & 127
                    if words == 127:
                        words = int.from_bytes(dec.update(await reader.readexactly(3)), 'little')
                    size = words * 4
                else:
                    size = struct.unpack('<I', dec.update(await reader.readexactly(4)))[0] & 0x7FFFFFFF
                payload = dec.update(await reader.readexactly(size))
                nonce = payload[24:40]
                self.calls.append((dc, proto, nonce))
                if nonce == self.error_nonce:
                    writer.write(enc.update(struct.pack('<i', -404)))
                    await writer.drain()
                    continue
                body = (struct.pack('<I', RES_PQ) + nonce + bytes(16) + b'\x01\x11\0\0'
                        + struct.pack('<IIQ', 0x1CB5C415, 1, 123))
                reply = struct.pack('<QQI', 0, 1, len(body)) + body
                if proto == PROTO_TAG_SECURE:
                    reply += os.urandom(3)
                frame = ((bytes([len(reply) // 4]) if proto == PROTO_TAG_ABRIDGED
                          else struct.pack('<I', len(reply))) + reply)
                wire = enc.update(frame)
                # Exercise both upstream stream fragmentation and CTR continuation.
                writer.write(wire[:3])
                await writer.drain()
                await asyncio.sleep(.001)
                writer.write(wire[3:])
                await writer.drain()
        except (asyncio.IncompleteReadError, OSError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()
            self.writers.discard(writer)

    async def close(self):
        for writer in list(self.writers):
            writer.close()
        await asyncio.gather(*self.tasks, return_exceptions=True)


class TelegramProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.telegram = LocalTelegram()
        self.remote = await asyncio.start_server(self.telegram.accept, '127.0.0.1', 0)
        self.remote_port = self.remote.sockets[0].getsockname()[1]
        self.secret = bytes.fromhex('12' * 16)
        self.client_tasks = set()
        def accept(reader, writer):
            task = asyncio.create_task(tg_ws_proxy._handle_client(reader, writer, self.secret))
            self.client_tasks.add(task)
            task.add_done_callback(self.client_tasks.discard)
        self.proxy = await asyncio.start_server(accept, '127.0.0.1', 0)
        self.port = self.proxy.sockets[0].getsockname()[1]
        self.routes = patch.object(upstream, 'candidates', return_value=[
            upstream.Route('tcp', '127.0.0.1', self.remote_port)])
        self.routes.start()
        upstream.reset()
        self.test_mode = getattr(proxy_config, 'test_mode', False)
        proxy_config.test_mode = False

    async def asyncTearDown(self):
        self.routes.stop()
        self.proxy.close()
        self.remote.close()
        await self.proxy.wait_closed()
        await self.remote.wait_closed()
        for task in self.client_tasks:
            task.cancel()
        await asyncio.gather(*self.client_tasks, return_exceptions=True)
        await self.telegram.close()
        upstream.reset()
        proxy_config.test_mode = self.test_mode

    async def test_all_framings_cipher_continuation_and_media_dc(self):
        for dc in (1, -2, 4, -5):
            for proto in (PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE):
                transport = TcpTransport(*await asyncio.open_connection('127.0.0.1', self.port))
                init, enc, dec = client_crypto(dc, self.secret, proto)
                await transport.send(init)
                try:
                    for _ in range(2):
                        nonce = os.urandom(16)
                        packet = req_pq_packet(nonce)
                        payload = packet[4:44]  # remove secure padding for other formats
                        if proto == PROTO_TAG_ABRIDGED:
                            packet = bytes([len(payload) // 4]) + payload
                        elif proto == PROTO_TAG_INTERMEDIATE:
                            packet = struct.pack('<I', len(payload)) + payload
                        wire = enc.update(packet)
                        await transport.send(wire[:2])
                        await asyncio.sleep(.001)
                        await transport.send(wire[2:])
                        response = await asyncio.wait_for(read_packet(transport.reader.readexactly, dec, proto), 2)
                        validate_res_pq(response, nonce)
                        # Each actual request is delivered exactly once, on the correct DC.
                        self.assertEqual([(d, p) for d, p, n in self.telegram.calls if n == nonce], [(dc, proto)])
                finally:
                    await transport.close()

    async def test_local_probe_rejects_wrong_secret(self):
        with self.assertRaises(asyncio.TimeoutError):
            await probe_local('127.0.0.1', self.port, bytes(16), 2, timeout=.1)
        self.assertEqual(self.telegram.calls, [])

    async def test_upstream_transport_error_is_forwarded_without_replay(self):
        transport = TcpTransport(*await asyncio.open_connection('127.0.0.1', self.port))
        nonce = os.urandom(16)
        self.telegram.error_nonce = nonce
        init, enc, dec = client_crypto(2, self.secret)
        try:
            await transport.send(init)
            await transport.send(enc.update(req_pq_packet(nonce)))
            wire = await asyncio.wait_for(transport.reader.readexactly(4), 2)
            self.assertEqual(struct.unpack('<i', dec.update(wire))[0], -404)
            self.assertEqual(len([n for _, _, n in self.telegram.calls if n == nonce]), 1)
        finally:
            await transport.close()

    async def test_stalled_open_route_does_not_block_other_route(self):
        stalled_writers = []
        def accept_stalled(reader, writer):
            stalled_writers.append(writer)
        stalled = await asyncio.start_server(accept_stalled, '127.0.0.1', 0)
        stall_port = stalled.sockets[0].getsockname()[1]
        routes = [upstream.Route('tcp', '127.0.0.1', stall_port),
                  upstream.Route('tcp', '127.0.0.1', self.remote_port)]
        try:
            with patch.object(upstream, 'candidates', return_value=routes):
                latency = await probe_local('127.0.0.1', self.port, self.secret, 2, timeout=2)
            self.assertLess(latency, 1500)
            self.assertTrue(stalled_writers)
        finally:
            stalled.close()
            for writer in stalled_writers:
                writer.transport.abort()
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), 1)
            await stalled.wait_closed()

    async def test_all_routes_unresponsive_have_bounded_deadline(self):
        async def never(*_args):
            await asyncio.Future()
        with patch.object(upstream, 'open_route', side_effect=never), patch.object(upstream, 'PROBE_TIMEOUT', .03):
            with self.assertRaisesRegex(ConnectionError, 'no_verified_mtproto_route'):
                await asyncio.wait_for(upstream.connect(2), .5)

    async def test_test_mode_never_starts_domain_refresh(self):
        stop = asyncio.Event()
        stop.set()
        with patch.object(proxy_config, 'test_mode', True), \
                patch.object(proxy_config, 'port', 0), \
                patch.object(proxy_config, 'fallback_cfproxy', True), \
                patch.object(proxy_config, 'cfproxy_user_domains', []), \
                patch.object(tg_ws_proxy, 'start_cfproxy_domain_refresh') as refresh:
            await asyncio.wait_for(tg_ws_proxy._run(stop), 2)
            refresh.assert_not_called()


class HealthTests(unittest.TestCase):
    def test_snapshot_seeds_do_not_disable_periodic_refresh(self):
        seeds = ['old.example.com']
        refreshed = ['new1.example.com', 'new2.example.com', 'new3.example.com']
        with patch.object(proxy_config, 'cfproxy_seed_domains', []), \
                patch.object(proxy_config, 'cfproxy_user_domains', []), \
                patch.object(config_module, '_refresh_stop'), \
                patch.object(config_module.threading, 'Event') as event, \
                patch.object(config_module.threading, 'Thread') as thread, \
                patch.object(config_module, '_fetch_cfproxy_domain_list', return_value=refreshed), \
                patch.object(config_module.balancer, 'update_domains_list') as update:
            configure_domains({'domains': seeds})
            self.assertEqual(proxy_config.cfproxy_user_domains, [])
            event.return_value.wait.return_value = True
            config_module.start_cfproxy_domain_refresh()
            update.assert_called_once_with(seeds)
            thread.return_value.start.assert_called_once()
            # Run the refresh thread's first iteration synchronously/offline.
            thread.call_args.kwargs['target']()
            self.assertEqual(update.call_args.args[0], refreshed)
            event.return_value.wait.assert_called_once_with(timeout=3600)

    def test_explicit_domain_override_is_preserved(self):
        with patch.object(proxy_config, 'cfproxy_seed_domains', []), \
                patch.object(proxy_config, 'cfproxy_user_domains', []), \
                patch.object(config_module, '_fetch_cfproxy_domain_list') as fetch:
            configure_domains({'domains': ['seed.example.com'],
                               'cfproxy_user_domains': ['owned.example.com']})
            config_module.refresh_cfproxy_domains()
            self.assertEqual(proxy_config.cfproxy_user_domains, ['owned.example.com'])
            fetch.assert_not_called()

    def test_cf_generator_candidates_are_bounded(self):
        with patch.object(upstream.balancer, 'get_domains_for_dc',
                          return_value=(f'example{i}.com' for i in range(20))), \
                patch.object(proxy_config, 'fallback_cfproxy', True):
            routes = upstream.candidates(2, False, False)
        self.assertEqual(len([route for route in routes if route.kind == 'cf']), 2)
        self.assertEqual({route.port for route in routes if route.kind == 'tcp'}, {443, 5222, 80})

    def test_nonce_mismatch_is_rejected(self):
        response = struct.pack('<QQII', 0, 1, 36, RES_PQ) + bytes(32)
        with self.assertRaisesRegex(ValueError, 'nonce'):
            validate_res_pq(response, bytes([1]) * 16)

    def test_health_file_is_atomic_json_without_temporary_remains(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'health.json'
            publish_health(str(path), {'state': 'checking'})
            publish_health(str(path), {'state': 'ready', 'latency_ms': 120})
            self.assertEqual(__import__('json').loads(path.read_text())['state'], 'ready')
            self.assertEqual(list(Path(folder).iterdir()), [path])


if __name__ == '__main__':
    unittest.main()
