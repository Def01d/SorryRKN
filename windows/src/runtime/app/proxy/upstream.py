"""Select a Telegram route by an actual MTProto response, with bounded retries.

Only synthetic req_pq requests are raced. User packets are sent once, after a
route has been verified; a failed session is closed for Telegram to reconnect.
"""
import asyncio
import logging
import time
from itertools import islice
from dataclasses import dataclass
from urllib.parse import urlencode

from .balancer import balancer
from .config import proxy_config
from .mtproto_probe import TcpTransport, exchange
from .raw_websocket import RawWebSocket
from .utils import DC_DEFAULT_IPS, DC_TEST_IPS, WS_PATH, WS_PATH_TEST, ws_domains

log = logging.getLogger('tg-mtproto-proxy')
CONNECT_TIMEOUT = 4.0
PROBE_TIMEOUT = 5.0
SELECT_TIMEOUT = 9.0
CACHE_SECONDS = 180.0
FAILED_SECONDS = 15.0
_cache = {}
_locks = {}
_failed_until = {}


@dataclass(frozen=True)
class Route:
    kind: str
    host: str
    port: int = 443
    domain: str = ''
    path: str = WS_PATH


def reset():
    _cache.clear()
    _locks.clear()
    _failed_until.clear()


def invalidate(dc, is_media, is_test_dc):
    key = (dc, is_media, is_test_dc)
    old = _cache.pop(key, None)
    if old is not None:
        _failed_until[(*key, old[0])] = time.monotonic() + FAILED_SECONDS
        while len(_failed_until) > 128:
            _failed_until.pop(next(iter(_failed_until)))


def candidates(dc, is_media, is_test_dc):
    ip = (DC_TEST_IPS if is_test_dc else DC_DEFAULT_IPS).get(dc)
    if not ip:
        return []
    routes = [Route('tcp', ip, 443)]
    if not is_test_dc and dc in range(1, 6):
        routes.append(Route('tcp', ip, 5222))
    path = WS_PATH_TEST if is_test_dc else WS_PATH
    for domain in ws_domains(dc, is_media):
        routes.append(Route('ws', proxy_config.dc_redirects.get(dc) or domain,
                            domain=domain, path=path))
    if not is_test_dc and dc in range(1, 6):
        routes.append(Route('tcp', ip, 80))
    if dc == 2 and not is_test_dc:
        routes.append(Route('tcp', '95.161.76.100', 443))
    for domain in proxy_config.cfproxy_worker_domains[:2]:
        routes.append(Route('worker', domain, domain=domain,
                            path='/apiws?' + urlencode({'dst': ip, 'dc': dc})))
    if proxy_config.fallback_cfproxy and not is_test_dc:
        now = time.monotonic()
        cf_added = 0
        for base in balancer.get_domains_for_dc(dc):
            domain = f'kws{dc}.{base}'
            route = Route('cf', domain, domain=domain)
            if _failed_until.get((dc, is_media, is_test_dc, route), 0) > now:
                continue
            routes.append(route)
            cf_added += 1
            if cf_added >= 2:
                break
    return routes


async def open_route(route):
    if route.kind == 'tcp':
        return TcpTransport(*await asyncio.wait_for(
            asyncio.open_connection(route.host, route.port), CONNECT_TIMEOUT))
    return await asyncio.wait_for(RawWebSocket.connect(
        route.host, route.domain, timeout=CONNECT_TIMEOUT, path=route.path,
        secure=not proxy_config.disable_secure), CONNECT_TIMEOUT)


async def close_transport(transport):
    if transport is not None:
        try:
            await asyncio.wait_for(transport.close(), 1)
        except (Exception, asyncio.CancelledError):
            # TLS close_notify may never arrive on blocked routes.
            transport.writer.close()


async def _probe(route, dc, delay):
    transport = None
    try:
        await asyncio.sleep(delay)
        async def run():
            nonlocal transport
            transport = await open_route(route)
            await exchange(transport, dc)
        await asyncio.wait_for(run(), PROBE_TIMEOUT)
        return route
    finally:
        await close_transport(transport)


async def _select(dc, is_media, is_test_dc):
    now = time.monotonic()
    all_routes = candidates(dc, is_media, is_test_dc)
    routes = [r for r in all_routes if _failed_until.get((dc, is_media, is_test_dc, r), 0) <= now] or all_routes
    tasks = [asyncio.create_task(_probe(route, -dc if is_media else dc, index * .12))
             for index, route in enumerate(routes)]
    try:
        for completed in asyncio.as_completed(tasks, timeout=SELECT_TIMEOUT):
            try:
                route = await completed
                if route.kind == 'cf' and '.' in route.domain:
                    balancer.update_domain_for_dc(dc, route.domain.split('.', 1)[1])
                log.info('DC%d%s verified route=%s port=%d', dc,
                         ' media' if is_media else '', route.kind, route.port)
                return route
            except (OSError, ValueError, ConnectionError, asyncio.TimeoutError,
                    asyncio.IncompleteReadError):
                continue
            except Exception as exc:
                log.debug('DC%d route probe failed: %s', dc, type(exc).__name__)
        raise ConnectionError('no_verified_mtproto_route')
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def connect(dc, is_media=False, is_test_dc=False):
    key = (dc, is_media, is_test_dc)
    for attempt in range(2):
        # Coalesce route discovery only; dial cached routes outside the lock so
        # parallel media streams never block one another.
        async with _locks.setdefault(key, asyncio.Lock()):
            cached = _cache.get(key)
            if cached and cached[1] > time.monotonic():
                route = cached[0]
            else:
                route = await _select(dc, is_media, is_test_dc)
                _cache[key] = (route, time.monotonic() + CACHE_SECONDS)
        try:
            transport = await open_route(route)
            current = _cache.get(key)
            if current and current[0] == route:
                _cache[key] = (route, time.monotonic() + CACHE_SECONDS)
            return transport, route.kind
        except asyncio.CancelledError:
            raise
        except Exception:
            current = _cache.get(key)
            if current and current[0] == route:
                invalidate(dc, is_media, is_test_dc)
            if attempt:
                raise
