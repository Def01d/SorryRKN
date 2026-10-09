"""Real socket integration tests; the upstream SOCKS hop is native zapret/tpws."""
import asyncio
import contextlib
import os
from pathlib import Path
import socket
import struct
import subprocess
import unittest
from gateway import Gateway, encode_address, read_address, decode_datagram


class EchoDatagram(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)


class GatewayIntegration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            self.native_port = s.getsockname()[1]
        binary = Path(__file__).resolve().parents[1] / 'build/test-tpws'
        self.native = subprocess.Popen([str(binary), '--socks', '--bind-addr=127.0.0.1',
                                        f'--port={self.native_port}', '--split-pos=1,midsld', '--mss=1200'],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                r, w = await asyncio.open_connection('127.0.0.1', self.native_port)
                w.close(); await w.wait_closed()
                break
            except OSError:
                await asyncio.sleep(.02)
        else:
            self.native.terminate()
            self.fail('Native zapret failed to start')
        self.gateway = Gateway(port=0, upstream_port=self.native_port)
        await self.gateway.start()

    async def asyncTearDown(self):
        await self.gateway.close()
        self.native.terminate()
        self.native.wait(timeout=3)

    async def socks(self, command, host, port):
        r, w = await asyncio.open_connection('127.0.0.1', self.gateway.port)
        w.write(b'\x05\x01\0'); await w.drain()
        self.assertEqual(await r.readexactly(2), b'\x05\0')
        w.write(bytes([5, command, 0]) + encode_address(host, port)); await w.drain()
        self.assertEqual(await r.readexactly(3), b'\x05\0\0')
        bound_host, bound_port, _ = await read_address(r)
        return r, w, bound_host, bound_port

    async def test_native_tcp_large_response_after_half_close(self):
        async def remote(r, w):
            request = await r.read()
            w.write(request[::-1]); await w.drain()
            w.close(); await w.wait_closed()
        server = await asyncio.start_server(remote, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            r, w, _, _ = await self.socks(1, '127.0.0.1', port)
            payload = os.urandom(256 * 1024)
            w.write(payload); await w.drain(); w.write_eof()
            result = await asyncio.wait_for(r.read(), 5)
            self.assertEqual(result, payload[::-1])
            w.close(); await w.wait_closed()

    async def test_udp_relay_and_association_shutdown(self):
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            EchoDatagram, local_addr=('127.0.0.1', 0))
        port = transport.get_extra_info('sockname')[1]
        r, w, host, bound = await self.socks(3, '0.0.0.0', 0)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.setblocking(False)
        client.bind(('127.0.0.1', 0))
        try:
            payload = os.urandom(1200)
            loop = asyncio.get_running_loop()
            await loop.sock_sendto(client, b'\0\0\0' + encode_address('127.0.0.1', port) + payload, (host, bound))
            packet, _ = await asyncio.wait_for(loop.sock_recvfrom(client, 4096), 3)
            self.assertEqual(decode_datagram(packet), ('127.0.0.1', port, payload))
            w.close(); await w.wait_closed()
            await asyncio.sleep(.05)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind((host, bound))  # Association socket must actually be released.
        finally:
            client.close(); transport.close()
            w.close()

    async def test_dns_over_https_wire_response_and_tcp_dns(self):
        query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b'\x07example\x03com\x00\x00\x01\x00\x01'
        answer = query[:2] + b'\x81\x80' + query[4:]
        import httpx
        from doh import Resolver
        def handle(request):
            self.assertEqual(request.content,query)
            self.assertEqual(request.headers['content-type'],'application/dns-message')
            return httpx.Response(200,content=answer)
        await self.gateway.resolver.close()
        self.gateway.resolver=Resolver(self.native_port,transport=httpx.MockTransport(handle))
        r, w, _, _ = await self.socks(1, '8.8.8.8', 53)
        w.write(struct.pack('!H', len(query)) + query); await w.drain()
        size = struct.unpack('!H', await r.readexactly(2))[0]
        self.assertEqual(await r.readexactly(size), answer)
        w.close(); await w.wait_closed()
        r, w, host, bound = await self.socks(3, '0.0.0.0', 0)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.setblocking(False)
        loop = asyncio.get_running_loop()
        try:
            await loop.sock_sendto(client, b'\0\0\0'+encode_address('8.8.8.8',53)+query,(host,bound))
            packet, _ = await asyncio.wait_for(loop.sock_recvfrom(client,4096),3)
            self.assertEqual(decode_datagram(packet), ('8.8.8.8',53,answer))
        finally:
            client.close(); w.close(); await w.wait_closed()

    async def test_invalid_auth_and_quic_are_rejected(self):
        r, w = await asyncio.open_connection('127.0.0.1', self.gateway.port)
        w.write(b'\x05\x01\x02'); await w.drain()
        self.assertEqual(await r.readexactly(2), b'\x05\xff')
        w.close(); await w.wait_closed()
        r, w, host, port = await self.socks(3,'0.0.0.0',0)
        client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); client.setblocking(False)
        loop=asyncio.get_running_loop()
        try:
            await loop.sock_sendto(client,b'\0\0\0'+encode_address('127.0.0.1',443)+b'quic',(host,port))
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(loop.sock_recvfrom(client,4096),.1)
        finally:
            client.close(); w.close(); await w.wait_closed()

    async def test_shutdown_closes_open_tcp_clients(self):
        async def remote(r,w):
            try: await r.read()
            finally: w.close(); await w.wait_closed()
        server=await asyncio.start_server(remote,'127.0.0.1',0)
        async with server:
            r,w,_,_=await self.socks(1,'127.0.0.1',server.sockets[0].getsockname()[1])
            await self.gateway.close()
            self.assertEqual(await asyncio.wait_for(r.read(),2), b'')
            self.assertFalse(self.gateway.tasks)
            w.close(); await w.wait_closed()
