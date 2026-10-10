"""Bounded Telegram route discovery using synthetic, nonce-checked MTProto.

The app UID is excluded from its VpnService by BridgeService; native sockets
therefore preserve the existing protected path. Official WSS is opened by the
existing RawWebSocket connector, including local ByeDPI SOCKS/TLS and its narrowly
scoped legacy fronting compatibility. No user packet is ever raced or replayed.
"""
import asyncio
import contextlib
import struct
import os
import time
from dataclasses import dataclass
from itertools import islice
from urllib.parse import urlencode

from telegram_probe import _native_init, _request, _validate_reply, MAX_PACKET
from .balancer import balancer
from .config import proxy_config
from .native_endpoints import native_tcp_endpoints
from .raw_websocket import RawWebSocket, set_sock_opts
from .telegram_endpoints import TelegramEndpoints, legacy_fronting, websocket_dc
from .route_diagnostics import Attempt
from .utils import PROTO_TAG_ABRIDGED, WS_PATH, WS_PATH_TEST, ws_domains

CONNECT_TIMEOUT = 3.0
PROBE_TIMEOUT = 3.5
SELECT_TIMEOUT = 4.0
FIRST_REPLY_TIMEOUT = 8.0
CACHE_SECONDS = 60.0
FAILED_SECONDS = 15.0
MAX_CANDIDATES = 18
MAX_CLIENT_PACKET = 16 * 1024 * 1024
_cache, _locks, _failed_until = {}, {}, {}
_endpoints = TelegramEndpoints()


@dataclass(frozen=True)
class Route:
    kind: str
    host: str
    port: int = 443
    domain: str = ''
    path: str = WS_PATH
    sni: str | None = None
    direct: bool = False


class TcpTransport:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.last_payload_received = 0.0

    async def send(self, data):
        self.writer.write(data)
        await self.writer.drain()

    async def send_batch(self, parts):
        self.writer.writelines(parts)
        await self.writer.drain()

    async def recv(self):
        data = await self.reader.read(65536)
        if data:
            self.last_payload_received = time.monotonic()
        return data or None

    async def close(self):
        abort(self)


def abort(transport):
    if transport is not None:
        with contextlib.suppress(Exception):
            transport.writer.close()
        with contextlib.suppress(Exception):
            transport.writer.transport.abort()


def reset():
    _cache.clear()
    _locks.clear()
    _failed_until.clear()


async def close():
    await _endpoints.close()
    reset()


def invalidate(dc, media, test, route=None):
    key = dc, media, test
    cached = _cache.get(key)
    # A late failure from an older session must not erase its newer replacement.
    if route is None or (cached and cached[0] == route):
        _cache.pop(key, None)
    if route is not None:
        _failed_until[(*key, route)] = time.monotonic() + FAILED_SECONDS
        # Strictly bounded even after repeated DNS changes or hostile handshakes.
        while len(_failed_until) > 128:
            _failed_until.pop(next(iter(_failed_until)))


async def open_route(route):
    if route.kind == 'native_tcp':
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(route.host, route.port), CONNECT_TIMEOUT)
        set_sock_opts(writer.transport, proxy_config.buffer_size)
        return TcpTransport(reader, writer)
    return await RawWebSocket.connect(
        route.host, route.domain, timeout=CONNECT_TIMEOUT, path=route.path,
        sni=route.sni, direct=route.direct, secure=not proxy_config.disable_secure)


class PacketReader:
    def __init__(self, transport):
        self.transport, self.buffer = transport, bytearray()

    async def readexactly(self, size):
        while len(self.buffer) < size:
            data = await self.transport.recv()
            if not data:
                raise asyncio.IncompleteReadError(bytes(self.buffer), size)
            self.buffer.extend(data)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result


async def exchange(transport, dc):
    init, up, down = _native_init(None, dc)
    nonce = os.urandom(16)
    await transport.send(init)
    await transport.send(up.update(_request(nonce)))
    reader = PacketReader(transport)
    size = struct.unpack('<I', down.update(await reader.readexactly(4)))[0]
    if not 4 <= size <= MAX_PACKET:
        raise ValueError('InvalidProbeLength')
    _validate_reply(down.update(await reader.readexactly(size)), nonce)


async def _probe(route, dc, delay, test=False):
    transport = None
    failure_key = abs(dc), dc < 0, test, route
    diagnostic = route.kind if route.kind in ('native_tcp', 'ws_fronting') else 'ws_direct'
    attempt = None
    try:
        await asyncio.sleep(delay)
        if _failed_until.get(failure_key, 0) > time.monotonic():
            return None
        if route.kind == 'native_tcp':
            attempt = Attempt(diagnostic, route.domain, route.host, route.port)
            attempt.stage('native_tcp')
        async with asyncio.timeout(PROBE_TIMEOUT):
            transport = await open_route(route)
            if attempt is None:
                attempt = Attempt(diagnostic, route.domain, route.host, route.port)
            else:
                attempt.success()
            attempt.stage('mtproto_probe')
            await exchange(transport, dc)
            attempt.success()
        _failed_until.pop(failure_key, None)
        return route
    except asyncio.CancelledError:
        if attempt:
            attempt.cancel()
        raise
    except Exception as exc:
        if attempt:
            attempt.failure(exc)
        _failed_until[failure_key] = time.monotonic() + FAILED_SECONDS
        while len(_failed_until) > 128:
            _failed_until.pop(next(iter(_failed_until)))
        return None
    finally:
        if attempt:
            attempt.finish()
        abort(transport)


async def select(dc, media, test):
    tasks, pending, scheduled = set(), set(), set()
    signed_dc = -dc if media else dc
    path = WS_PATH_TEST if test else WS_PATH

    def task(coro):
        running = asyncio.create_task(coro)
        tasks.add(running)
        pending.add(running)

    def add(route, delay=0.0):
        if route not in scheduled and len(scheduled) < MAX_CANDIDATES:
            scheduled.add(route)
            task(_probe(route, signed_dc, delay, test))

    def websocket(address, domain, delay=0.0):
        add(Route('ws', address, domain=domain, path=path), delay)
        if proxy_config.telegram_dpi_port:
            add(Route('ws', address, domain=domain, path=path, direct=True), delay + .1)
        if legacy_fronting(address, domain):
            add(Route('ws_fronting', address, domain=domain, path=path,
                      sni='sprinthost.ru', direct=True), delay + .05)

    async def discover(domain):
        try:
            return domain, await _endpoints.addresses(domain)
        except asyncio.CancelledError:
            raise
        except Exception:
            # DNS failure cannot discard a simultaneously working native route.
            return domain, []

    native = native_tcp_endpoints(dc, test)
    if not native:
        raise ConnectionError('UnsupportedDatacenter')
    for index, (host, port) in enumerate(native):
        add(Route('native_tcp', host, port), index * .04)
    pin = proxy_config.dc_redirects.get(dc)
    if websocket_dc(dc) is not None or pin:
        for index, domain in enumerate(ws_domains(dc, media)):
            if pin:
                websocket(pin, domain, index * .05)
            if not test and websocket_dc(dc) is not None:
                task(discover(domain))
    if proxy_config.fallback_cfproxy and not test:
        for index, base in enumerate(islice(balancer.get_domains_for_dc(dc), 2)):
            domain = f'kws{dc}.{base}'
            add(Route('cf', domain, domain=domain), .6 + index * .1)
    for index, domain in enumerate(proxy_config.cfproxy_worker_domains[:2]):
        query = urlencode({'dst': native[0][0], 'dc': dc})
        add(Route('worker', domain, domain=domain, path='/apiws?' + query), .6 + index * .1)
    try:
        async with asyncio.timeout(SELECT_TIMEOUT):
            while pending:
                done, still_pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                pending = still_pending
                for completed in done:
                    result = completed.result()
                    if isinstance(result, Route):
                        return result
                    if isinstance(result, tuple):
                        domain, addresses = result
                        for index, address in enumerate(addresses):
                            websocket(address, domain, index * .05)
        raise ConnectionError('NoVerifiedTelegramRoute')
    finally:
        for running in tasks:
            running.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def connect(dc, media=False, test=False):
    if not native_tcp_endpoints(dc, test):
        raise ConnectionError('UnsupportedDatacenter')
    key = dc, media, test
    for attempt in range(2):
        async with _locks.setdefault(key, asyncio.Lock()):
            cached = _cache.get(key)
            if cached and cached[1] > time.monotonic():
                route = cached[0]
            else:
                route = await select(dc, media, test)
                _cache[key] = route, time.monotonic() + CACHE_SECONDS
        # Discovery is coalesced, sockets/ciphers are never shared. A cached
        # route must support simultaneous media clients without serial dial waits.
        try:
            return await open_route(route), route
        except asyncio.CancelledError:
            raise
        except Exception:
            current = _cache.get(key)
            if current and current[0] == route:
                invalidate(dc, media, test, route)
            if attempt:
                raise


async def first_client_packet(reader, decryptor, proto):
    """Buffer exactly one frame; user bytes are not used for route discovery."""
    wire = await reader.readexactly(1 if proto == PROTO_TAG_ABRIDGED else 4)
    plain = decryptor.update(wire)
    if proto == PROTO_TAG_ABRIDGED:
        words = plain[0] & 0x7F
        if words == 0x7F:
            extra = await reader.readexactly(3)
            wire += extra
            words = int.from_bytes(decryptor.update(extra), 'little')
        size = words * 4
    else:
        size = struct.unpack('<I', plain)[0] & 0x7FFFFFFF
    if not 0 < size <= MAX_CLIENT_PACKET:
        raise ValueError('InvalidClientPacketLength')
    return wire + await reader.readexactly(size)
