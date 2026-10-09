import asyncio
import logging
import random
import time

from collections import deque
from urllib.parse import urlencode
from typing import Dict, List, Optional, Tuple, Set

from .raw_websocket import RawWebSocket, WsHandshakeError
from .route_diagnostics import increment, pool_cooldown, clear_pool_cooldown
from .stats import stats
from .config import proxy_config
from .utils import ws_domains, DC_DEFAULT_IPS, WS_PATH, WS_PATH_TEST
from .telegram_endpoints import TelegramEndpoints, websocket_dc, legacy_fronting

log = logging.getLogger('tg-mtproto-proxy')


class _WsPool:
    WS_POOL_MAX_AGE = 120.0
    WS_POOL_CHECK_INTERVAL = 5.0
    REFILL_BACKOFF_INITIAL = 1.0
    REFILL_BACKOFF_MAX = 30.0
    ACQUIRE_TIMEOUT = 3.0
    MEDIA_ACQUIRE_TIMEOUT = 10.0
    HEALTHY_ACQUIRE_TIMEOUT = 10.0
    CONNECT_TIMEOUT = 4.0
    
    def __init__(self):
        self._idle: Dict[Tuple[int, bool, bool], deque] = {}
        self._refilling: Dict[Tuple[int, bool, bool], asyncio.Task] = {}
        self._rotating: Dict[Tuple[int, bool, bool], asyncio.Task] = {}
        self._refill_failures: Dict[Tuple[int, bool, bool], int] = {}
        self._refill_after: Dict[Tuple[int, bool, bool], float] = {}
        self._changed: Dict[Tuple[int, bool, bool], asyncio.Event] = {}
        self._refill_progress: Dict[Tuple[int, bool, bool], float] = {}
        self._generation = 0
        self._endpoints = TelegramEndpoints()
        self.try_fronting_first = False

    async def get(self, dc: int, is_media: bool, *, is_test_dc: bool = False
                  ) -> Optional[RawWebSocket]:
        target_ip = proxy_config.dc_redirects.get(dc)
        if (not target_ip and websocket_dc(dc) is None) or proxy_config.pool_size <= 0:
            return None
        key = (dc, is_media, is_test_dc)
        domains = ws_domains(dc, is_media)
        changed = self._changed.setdefault(key, asyncio.Event())
        generation = self._generation
        started = time.monotonic()
        # Negative DCs are media sessions, not Telegram's five-second proxy
        # checks. Preserve their previous ten-second setup budget, including
        # cold bursts queued behind native handshakes on slower devices.
        idle_timeout = self.MEDIA_ACQUIRE_TIMEOUT if is_media else self.ACQUIRE_TIMEOUT
        hard_deadline = started + self.HEALTHY_ACQUIRE_TIMEOUT
        deadline = min(started + idle_timeout, hard_deadline)
        waiting = False
        while generation == self._generation:
            # Clear before inspecting state: a refill completing while this
            # client waits must wake it, including on a failed/cancelled batch.
            changed.clear()
            now = time.monotonic()
            progress = self._refill_progress.get(key, 0)
            if progress >= started:
                # A successful socket taken by another waiting client proves
                # this route is making progress. Give a healthy media burst
                # time to acquire its own sockets, without making a dead
                # route miss Telegram's five-second proxy-check deadline.
                deadline = max(deadline, min(hard_deadline, progress + idle_timeout))
            bucket = self._idle.setdefault(key, deque())
            while bucket:
                ws, created = bucket.popleft()
                if self._is_stale(ws, created, now):
                    asyncio.create_task(self._quiet_close(ws))
                    continue
                if not waiting:
                    stats.pool_hits += 1
                log.debug("WS pool acquired DC%d%s%s (age=%.1fs, left=%d)",
                          dc, 't' if is_test_dc else '', 'm' if is_media else '',
                          now - created, len(bucket))
                self._schedule_refill(key, target_ip, domains)
                return ws
            if not waiting:
                stats.pool_misses += 1
                waiting = True
            self._schedule_refill(key, target_ip, domains)
            # A known failed route should reach fallback immediately. A cold
            # or exhausted healthy pool is different: let demand consume the
            # next completed connection instead of discarding that client.
            if key not in self._refilling:
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                await asyncio.wait_for(changed.wait(), remaining)
            except asyncio.TimeoutError:
                # Recheck progress which raced with this timeout. Failed
                # dials, DNS answers and mere wakeups never extend the wait.
                continue
        return None

    def _is_stale(self, ws, created, now):
        return (now - created >= self.WS_POOL_MAX_AGE or ws._closed
                or ws.writer.transport.is_closing() or ws.reader.at_eof()
                or ws.reader.exception() is not None)

    def discard_media(self, dc, is_test_dc=False):
        """Drop only unused sockets for the media route which stopped replying."""
        key = (dc, True, is_test_dc)
        task = self._refilling.pop(key, None)
        if task is not None:
            task.cancel()
        for ws, _ in self._idle.pop(key, ()):
            ws.writer.transport.abort()
        self._refill_failures.pop(key, None)
        self._refill_progress.pop(key, None)
        # Let the next native connection use existing fallback routes instead
        # of taking another socket from the same failed warmup batch.
        self._refill_after[key] = time.monotonic() + 15
        pool_cooldown(*key, 0, self._refill_after[key])
        if key in self._changed:
            self._changed[key].set()
        stats.media_pool_resets += 1

    def _schedule_refill(self, key, target_ip, domains):
        if proxy_config.pool_size <= 0:
            return
        self._schedule_rotation(key, target_ip, domains)
        if key in self._refilling:
            increment('ws_refill_wait_shared')
            return
        if time.monotonic() < self._refill_after.get(key, 0):
            increment('ws_refill_backoff_skipped')
            return
        self._refilling[key] = asyncio.create_task(
            self._refill(key, target_ip, domains))

    async def _refill(self, key, target_ip, domains):
        dc, is_media, is_test_dc = key
        tasks = []
        adopted = set()
        try:
            bucket = self._idle.setdefault(key, deque())
            needed = proxy_config.pool_size - len(bucket)
            if needed <= 0:
                return
            # A failed route gets one recovery probe per refill. Rebuild the
            # full idle pool only after a connection has actually succeeded.
            if self._refill_failures.get(key, 0) > 0:
                needed = 1
            connected = 0
            tasks = [asyncio.create_task(
                self._connect_one(target_ip, domains,
                                  WS_PATH_TEST if is_test_dc else WS_PATH,
                                  **({} if websocket_dc(dc) is not None
                                     else {'resolve_dns': False})))
                for _ in range(needed)]
            for t in asyncio.as_completed(tasks):
                try:
                    ws = await t
                    if ws:
                        if self._refilling.get(key) is not asyncio.current_task():
                            return
                        completed_at = time.monotonic()
                        bucket.append((ws, completed_at))
                        self._refill_progress[key] = completed_at
                        adopted.add(ws)
                        connected += 1
                        if key in self._changed:
                            self._changed[key].set()
                except Exception as exc:
                    log.debug("WS pool connect failed: %r", exc)
            if connected:
                self._refill_failures.pop(key, None)
                self._refill_after.pop(key, None)
                clear_pool_cooldown(*key)
            else:
                failures = self._refill_failures.get(key, 0) + 1
                self._refill_failures[key] = failures
                delay = min(
                    self.REFILL_BACKOFF_INITIAL
                    * (2 ** min(failures - 1, 12)),
                    self.REFILL_BACKOFF_MAX,
                )
                self._refill_after[key] = time.monotonic() + delay
                pool_cooldown(*key, failures, self._refill_after[key])
                log.info(
                    "WS pool refill failed for DC%d%s%s, retry in %.0fs",
                    dc, 't' if is_test_dc else '', 'm' if is_media else '', delay)
            log.debug("WS pool refilled DC%d%s%s: %d ready",
                      dc, 't' if is_test_dc else '', 'm' if is_media else '', len(bucket))
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for ws in results:
                if ws is not None and not isinstance(ws, BaseException) and ws not in adopted:
                    await self._quiet_close(ws)
            if self._refilling.get(key) is asyncio.current_task():
                self._refilling.pop(key, None)
                if key in self._changed:
                    self._changed[key].set()

    def _schedule_rotation(self, key, target_ip, domains):
        if key in self._rotating:
            return
        self._rotating[key] = asyncio.create_task(
            self._rotate(key, target_ip, domains))

    async def _rotate(self, key, target_ip, domains):
        dc, is_media, is_test_dc = key
        try:
            while proxy_config.pool_size > 0:
                bucket = self._idle.setdefault(key, deque())
                now = time.monotonic()
                expired = []
                ready = deque()
                while bucket:
                    ws, created = bucket.popleft()
                    if self._is_stale(ws, created, now):
                        expired.append(ws)
                    else:
                        ready.append((ws, created))
                bucket.extend(ready)

                if expired:
                    for ws in expired:
                        asyncio.create_task(self._quiet_close(ws))
                    log.debug(
                        "WS pool rotated DC%d%s%s: %d stale, %d ready",
                        dc, 't' if is_test_dc else '', 'm' if is_media else '',
                        len(expired), len(bucket))

                if len(bucket) < proxy_config.pool_size:
                    self._schedule_refill(key, target_ip, domains)

                wake_at = now + self.WS_POOL_CHECK_INTERVAL
                if bucket:
                    wake_at = min(wake_at, min(
                        created + self.WS_POOL_MAX_AGE for _, created in bucket))
                if key not in self._refilling and self._refill_after.get(key, 0) > now:
                    wake_at = min(wake_at, self._refill_after[key])
                await asyncio.sleep(max(0, wake_at - time.monotonic()))
        finally:
            if self._rotating.get(key) is asyncio.current_task():
                self._rotating.pop(key, None)

    async def _connect_one(self, target_ip, domains, path=WS_PATH, *, resolve_dns=True) -> Optional[RawWebSocket]:
        # Telegram Android's proxy check has a five-second deadline. Do not
        # spend most of it waiting for DNS before trying an existing pin, or
        # serialize the media hostname ahead of the ordinary hostname.
        tasks = set()
        pending = set()
        scheduled = set()
        winner = None

        def add(coro):
            task = asyncio.create_task(coro)
            tasks.add(task)
            pending.add(task)

        async def dial(address, domain, fronted, direct, delay):
            if delay:
                await asyncio.sleep(delay)
            try:
                options = {'direct': True} if direct else {}
                ws = await RawWebSocket.connect(
                    address, domain, timeout=self.CONNECT_TIMEOUT, path=path,
                    sni='sprinthost.ru' if fronted else None, **options)
                return 'ws', ws, fronted, address, domain
            except Exception as exc:
                stats.ws_errors += 1
                log.debug('WS connect %s%s via %s (fronting=%s direct=%s): %s',
                          domain, path, address, fronted, direct, type(exc).__name__)
                return None

        def schedule(address, domain, delay=0.0):
            if not address:
                return
            routes = [(False, False, delay)]
            if getattr(proxy_config, 'telegram_dpi_port', 0):
                # A failed/mis-selected local strategy must not disable an
                # otherwise reachable first-party Telegram endpoint.
                routes.append((False, True, delay + .10))
            if legacy_fronting(address, domain):
                routes.append((True, True, delay + (.02 if self.try_fronting_first else .05)))
            for fronted, direct, start_delay in routes:
                key = address, domain, fronted, direct
                if key not in scheduled:
                    scheduled.add(key)
                    add(dial(address, domain, fronted, direct, start_delay))

        async def discover(domain):
            try:
                return 'addresses', domain, await self._endpoints.addresses(domain)
            except (OSError, ValueError, asyncio.TimeoutError):
                return 'addresses', domain, []

        for index, domain in enumerate(domains):
            schedule(target_ip, domain, index * .05)
            if resolve_dns:
                add(discover(domain))
        try:
            while pending:
                done, remaining = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                pending = remaining
                # Adopt a ready connection before processing newly discovered
                # targets; no MTProto request is copied to any losing route.
                for task in done:
                    result = task.result()
                    if result and result[0] == 'ws':
                        _, winner, fronted, address, domain = result
                        self.try_fronting_first = fronted
                        increment('ws_race_selected')
                        if fronted:
                            stats.connections_fronting += 1
                        log.debug('WS connected %s%s via %s (fronting=%s)',
                                  domain, path, address, fronted)
                        return winner
                for task in done:
                    result = task.result()
                    if result and result[0] == 'addresses':
                        _, domain, addresses = result
                        for index, address in enumerate(addresses):
                            schedule(address, domain, index * .10)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, tuple) and result[0] == 'ws' and result[1] is not winner:
                        # These sockets have not carried MTProto. Waiting for
                        # their TLS close-notify can delay the winning route
                        # beyond Telegram's proxy-check deadline.
                        increment('ws_race_lost')
                        result[1]._closed = True
                        result[1].writer.transport.abort()
            except asyncio.CancelledError:
                # A chosen winner is still unowned until cleanup completes.
                for task in tasks:
                    if task.done() and not task.cancelled() and task.exception() is None:
                        result = task.result()
                        if result and result[0] == 'ws':
                            result[1].writer.transport.abort()
                raise
        return None

    async def _quiet_close(self, ws):
        try:
            await ws.close()
        except Exception:
            pass

    async def warmup(self):
        for dc, target_ip in proxy_config.dc_redirects.items():
            if target_ip is None:
                continue
            for is_media in (False, True):
                domains = ws_domains(dc, is_media)
                key = (dc, is_media, proxy_config.force_test_dc)
                self._schedule_refill(key, target_ip, domains)
        log.info("WS pool warmup started for %d DC(s)", len(proxy_config.dc_redirects))

    def reset(self):
        clear_pool_cooldown()
        self._generation += 1
        for changed in self._changed.values():
            changed.set()
        self._changed.clear()
        self._refill_progress.clear()
        loop = asyncio.get_running_loop()
        for task in list(self._rotating.values()) + list(self._refilling.values()):
            if not task.done() and task.get_loop() is loop:
                task.cancel()
        for bucket in self._idle.values():
            for ws, _ in bucket:
                try:
                    ws.writer.close()
                except Exception as exc:
                    log.debug("WS pool close failed: %r", exc)
        self._idle.clear()
        self._refilling.clear()
        self._rotating.clear()
        self._refill_failures.clear()
        self._refill_after.clear()
        self.try_fronting_first = False

    async def close(self):
        tasks = list(self._rotating.values()) + list(self._refilling.values())
        self.reset()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self._endpoints.close()


class _CfWorkerPool:
    WS_POOL_MAX_AGE = 100.0
    PER_DC_LIMIT = 1

    def __init__(self):
        self._idle: Dict[int, deque] = {}
        self._refilling: Set[int] = set()
        self._exhausted_until: Dict[str, float] = {}

    async def get(self, dc: int, fallback_dst: str,
                  worker_domains: List[str]
                  ) -> Optional[Tuple[RawWebSocket, str]]:
        now = time.monotonic()

        bucket = self._idle.get(dc)
        if bucket is None:
            bucket = deque()
            self._idle[dc] = bucket
        while bucket:
            ws, created, worker_domain = bucket.popleft()
            age = now - created
            if (age > self.WS_POOL_MAX_AGE or ws._closed
                    or ws.writer.transport.is_closing()):
                asyncio.create_task(self._quiet_close(ws))
                continue
            stats.cf_pool_hits += 1
            log.debug(
                "CF worker pool hit DC%d via %s (age=%.1fs, left=%d)",
                dc, worker_domain, age, len(bucket))
            self._schedule_refill(dc, fallback_dst, worker_domains)
            return ws, worker_domain

        stats.cf_pool_misses += 1
        return None

    def _schedule_refill(self, dc, fallback_dst, worker_domains):
        if dc in self._refilling:
            return
        self._refilling.add(dc)
        asyncio.create_task(self._refill(
            dc, fallback_dst, list(worker_domains)))

    async def _refill(self, dc, fallback_dst, worker_domains):
        try:
            bucket = self._idle.setdefault(dc, deque())
            target_size = min(proxy_config.pool_size, self.PER_DC_LIMIT)
            needed = target_size - len(bucket)
            if needed <= 0:
                return

            for _ in range(needed):
                connected = await self._connect_one(
                    worker_domains, fallback_dst, dc)
                if connected is None:
                    break
                ws, worker_domain = connected
                bucket.append((ws, time.monotonic(), worker_domain))
            log.debug("CF worker pool refilled DC%d: %d ready",
                      dc, len(bucket))
        finally:
            self._refilling.discard(dc)

    async def _connect_one(self, worker_domains, fallback_dst, dc):
        query = urlencode({
            'dst': fallback_dst,
            'dc': str(dc),
        })
        path = f'/apiws?{query}'
        for worker_domain in self.available_domains(worker_domains):
            try:
                ws = await RawWebSocket.connect(
                    worker_domain, worker_domain, timeout=8, path=path,
                    secure=not proxy_config.disable_secure)
                return ws, worker_domain
            except Exception as exc:
                self.report_failure(worker_domain, exc)
        return None

    def available_domains(self, worker_domains: List[str]) -> List[str]:
        now = time.time()
        domains = []
        for domain in worker_domains:
            if domain in domains:
                continue
            exhausted_until = self._exhausted_until.get(domain, 0)
            if exhausted_until > now:
                continue
            if exhausted_until:
                self._exhausted_until.pop(domain, None)
            domains.append(domain)
        random.shuffle(domains)
        return domains

    def report_failure(self, worker_domain: str, exc: Exception) -> None:
        return  # TODO: check status code after daily limit reached
        if not isinstance(exc, WsHandshakeError) or exc.status_code != 429:
            return

        now = time.time()
        if self._exhausted_until.get(worker_domain, 0) > now:
            return
        exhausted_until = now + (86400 - (now % 86400))
        self._exhausted_until[worker_domain] = exhausted_until
        log.warning(
            "CF worker %s reached its request limit, disabled for %d seconds", worker_domain, int(exhausted_until - now))

    async def _quiet_close(self, ws):
        try:
            await ws.close()
        except Exception:
            pass

    async def warmup(self):
        cf_fallbacks = {
            dc: ip for dc, ip in DC_DEFAULT_IPS.items()
            if dc not in proxy_config.dc_redirects
        }

        if not cf_fallbacks or not proxy_config.cfproxy_worker_domains:
            return

        worker_domains = list(proxy_config.cfproxy_worker_domains)
        for dc, fallback_dst in cf_fallbacks.items():
            self._schedule_refill(dc, fallback_dst, worker_domains)

        log.info("CF worker pool warmup started for %d DC(s)", len(cf_fallbacks))

    def reset(self):
        self._idle.clear()
        self._refilling.clear()
        self._exhausted_until.clear()


ws_pool = _WsPool()
cf_worker_pool = _CfWorkerPool()
