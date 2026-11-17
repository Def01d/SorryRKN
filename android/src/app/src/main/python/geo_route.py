"""Try alternate DNS-profile addresses without replaying application requests."""
import asyncio
import contextlib
import time
from collections import OrderedDict
from connection_health import open_socks

COOLDOWN = 90.0
CONNECT_TIMEOUT = 10.0
FIRST_ROUTE_TIMEOUT = 3.0
MAX_ROUTE_ATTEMPTS = 4


class GeoRouteError(OSError):
    def __init__(self, stage, cause):
        self.stage = stage
        super().__init__(f'DNS profile {stage}: {type(cause).__name__}')


def client_hello_only(data):
    """Only an initial TLS handshake may be sent again, never HTTP or 0-RTT."""
    offset = 0
    handshake = bytearray()
    while offset < len(data):
        if offset + 5 > len(data) or data[offset+1] != 3:
            return False
        kind = data[offset]
        size = int.from_bytes(data[offset+3:offset+5], 'big')
        end = offset + 5 + size
        if end > len(data):
            return False
        if kind == 22:
            handshake.extend(data[offset+5:end])
        elif kind != 20 or data[offset+5:end] != b'\x01':
            return False
        offset = end
    return (len(handshake) >= 4 and handshake[0] == 1
            and len(handshake) == 4 + int.from_bytes(handshake[1:4], 'big'))


async def close_failed(writer):
    if writer is not None:
        writer.close()
        # A failed TLS/TCP route does not need to wait for peer shutdown.
        with contextlib.suppress(AttributeError, OSError):
            writer.transport.abort()


class GeoRoutes:
    def __init__(self, stats, proxy_port=None):
        self.stats = stats
        self.failed = OrderedDict()
        self.proxy_port = proxy_port
        self.preferred = OrderedDict()

    def prefer(self, name, address, port, route):
        key = (name, address, port)
        self.preferred[key] = (self.proxy_port if route == 'dpi' else None, time.monotonic() + COOLDOWN)
        self.preferred.move_to_end(key)
        while len(self.preferred) > 512:
            self.preferred.popitem(last=False)
        for path in (None, self.proxy_port):
            self.failed.pop((*key, path), None)

    async def connect(self, name, addresses, port, initial, reply_timeout, invalidate):
        now = time.monotonic()
        for key, until in list(self.failed.items()):
            if until <= now:
                self.failed.pop(key, None)
        candidates = list(dict.fromkeys(addresses))[:MAX_ROUTE_ATTEMPTS]
        tls = initial[:2] == b'\x16\x03'
        replayable = client_hello_only(initial)
        paths = []
        for address in candidates:
            options = [self.proxy_port, None] if self.proxy_port and tls else [None]
            preferred = self.preferred.get((name, address, port))
            if preferred and preferred[1] > now and preferred[0] in options:
                options.remove(preferred[0]); options.insert(0, preferred[0])
            paths.extend((address, option) for option in options)
        paths.sort(key=lambda path: self.failed.get((name, path[0], port, path[1]), 0) > now)
        last = None
        expires = time.monotonic() + CONNECT_TIMEOUT
        for index, (address, proxy_port) in enumerate(paths):
            writer = None
            sent = False
            stage = 'connect'
            self.stats['geo_attempts'] += 1
            if index:
                self.stats['geo_retries'] += 1
            try:
                # Leave time for the spare address before ordinary clients time out.
                remaining = expires - time.monotonic()
                if remaining <= 0:
                    break
                deadline = min(remaining, FIRST_ROUTE_TIMEOUT) if index < len(paths)-1 else remaining
                async with asyncio.timeout(deadline):
                    connection = (open_socks(address, port, proxy_port) if proxy_port
                                  else asyncio.open_connection(address, port))
                    reader, writer = await asyncio.wait_for(connection, CONNECT_TIMEOUT)
                    stage = 'write'
                    sent = True
                    writer.write(initial)
                    await writer.drain()
                    self.stats['tx_bytes'] += len(initial)
                    reply = b''
                    if tls:
                        stage = 'tls'
                        async with asyncio.timeout(reply_timeout):
                            header = await reader.readexactly(5)
                            length = int.from_bytes(header[3:5], 'big')
                            if header[0] not in (20, 21, 22) or header[1] != 3 or not 0 < length <= 18432:
                                raise OSError('Invalid initial TLS record')
                            reply = header + await reader.readexactly(length)
                            if header[0] == 21 and reply[5:6] == b'\x02':
                                raise OSError('Fatal TLS alert')
                    self.prefer(name, address, port, 'dpi' if proxy_port else 'direct')
                    self.stats['geo_last_stage'] = 'tls_reply' if tls else 'connected'
                    self.stats['geo_last_endpoint'] = address
                    self.stats['geo_last_route'] = 'dpi' if proxy_port else 'direct'
                    return reader, writer, reply
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as error:
                last = GeoRouteError(stage, error)
                self.stats['geo_failures'] += 1
                self.stats['geo_last_stage'] = stage + ':' + type(error).__name__
                self.stats['geo_last_endpoint'] = address
                self.failed[(name, address, port, proxy_port)] = time.monotonic() + COOLDOWN
                self.failed.move_to_end((name, address, port, proxy_port))
                while len(self.failed) > 512:
                    self.failed.popitem(last=False)
                await close_failed(writer)
                if sent and not replayable:
                    break
            except BaseException:
                await close_failed(writer)
                raise
        invalidate(name)
        raise last or GeoRouteError('dns', OSError('No DNS profile addresses'))
