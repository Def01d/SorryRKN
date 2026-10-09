import asyncio
import logging
import struct
import time

from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode

from .utils import *
from .stats import stats
from .balancer import balancer
from .config import proxy_config
from .raw_websocket import RawWebSocket
from .pool import cf_worker_pool
from ._aes import Cipher, algorithms, modes
from .network_debug import WsActivity
from .cf_h2 import bridge_h2
from .media_health import MediaHealth, close_writer
from .native_endpoints import MAX_NATIVE_CANDIDATES, native_tcp_endpoints
from . import route_diagnostics


log = logging.getLogger('tg-mtproto-proxy')
_st_I_le = struct.Struct('<I')

TCP_BACKOFF_INITIAL = 30.0
TCP_BACKOFF_MAX = 30.0
TCP_CONNECT_TIMEOUT = 10.0
_tcp_failures: Dict[Tuple[str, int], int] = {}
_tcp_retry_after: Dict[Tuple[str, int], float] = {}
_tcp_connecting: Dict[Tuple[str, int], asyncio.Future] = {}


def reset_tcp_backoff() -> None:
    route_diagnostics.clear_cooldown()
    _tcp_failures.clear()
    _tcp_retry_after.clear()
    for pending in _tcp_connecting.values():
        if not pending.done():
            pending.set_result(False)
    _tcp_connecting.clear()

ZERO_64 = b'\x00' * 64


class CryptoCtx:
    __slots__ = ('clt_dec', 'clt_enc', 'tg_enc', 'tg_dec')

    def __init__(self, clt_dec, clt_enc, tg_enc, tg_dec):
        self.clt_dec = clt_dec  # decrypt from client
        self.clt_enc = clt_enc  # encrypt to client
        self.tg_enc = tg_enc    # encrypt to telegram
        self.tg_dec = tg_dec    # decrypt from telegram


class MsgSplitter:
    """
    Splits TCP stream data into individual MTProto transport packets
    so each can be sent as a separate WS frame.
    """
    __slots__ = ('_dec', '_proto', '_cipher_buf', '_plain_buf', '_disabled')

    def __init__(self, relay_init: bytes, proto_int: int):
        cipher = Cipher(algorithms.AES(relay_init[8:40]),
                        modes.CTR(relay_init[40:56]))
        self._dec = cipher.encryptor()
        self._dec.update(ZERO_64)
        self._proto = proto_int
        self._cipher_buf = bytearray()
        self._plain_buf = bytearray()
        self._disabled = False

    def split(self, chunk: bytes) -> List[bytes]:
        if not chunk:
            return []
        if self._disabled:
            return [chunk]

        self._cipher_buf.extend(chunk)
        self._plain_buf.extend(self._dec.update(chunk))

        parts = []
        offset = 0
        buf_len = len(self._cipher_buf)
        # Walk the buffer with an offset instead of deleting each packet from
        # the front. Front-deletion on a bytearray shifts the remaining bytes,
        # so a chunk holding many small packets degrades to O(N^2); a single
        # trailing del keeps splitting O(N).
        while offset < buf_len:
            packet_len = self._next_packet_len(offset, buf_len - offset)
            if packet_len is None:
                break
            if packet_len <= 0:
                parts.append(bytes(self._cipher_buf[offset:]))
                offset = buf_len
                self._disabled = True
                break
            parts.append(bytes(self._cipher_buf[offset:offset + packet_len]))
            offset += packet_len

        if offset:
            del self._cipher_buf[:offset]
            del self._plain_buf[:offset]
        return parts

    def flush(self) -> List[bytes]:
        if not self._cipher_buf:
            return []
        tail = bytes(self._cipher_buf)
        self._cipher_buf.clear()
        self._plain_buf.clear()
        return [tail]

    def _next_packet_len(self, offset: int, avail: int) -> Optional[int]:
        if avail <= 0:
            return None
        if self._proto == PROTO_ABRIDGED_INT:
            return self._next_abridged_len(offset, avail)
        if self._proto in (PROTO_INTERMEDIATE_INT,
                           PROTO_PADDED_INTERMEDIATE_INT):
            return self._next_intermediate_len(offset, avail)
        return 0

    def _next_abridged_len(self, offset: int, avail: int) -> Optional[int]:
        first = self._plain_buf[offset]
        if first in (0x7F, 0xFF):
            if avail < 4:
                return None
            payload_len = int.from_bytes(
                self._plain_buf[offset + 1:offset + 4], 'little') * 4
            header_len = 4
        else:
            payload_len = (first & 0x7F) * 4
            header_len = 1
        if payload_len <= 0:
            return 0
        packet_len = header_len + payload_len
        if avail < packet_len:
            return None
        return packet_len

    def _next_intermediate_len(self, offset: int, avail: int) -> Optional[int]:
        if avail < 4:
            return None
        payload_len = _st_I_le.unpack_from(self._plain_buf, offset)[0] & 0x7FFFFFFF
        if payload_len <= 0:
            return 0
        packet_len = 4 + payload_len
        if avail < packet_len:
            return None
        return packet_len


async def do_fallback(reader, writer, relay_init, label,
                       dc: int, is_test_dc: bool, is_media: bool, media_tag: str,
                       ctx: CryptoCtx, splitter=None, *, h2_pool=None, proto_tag=None):
    ip_table = DC_TEST_IPS if is_test_dc else DC_DEFAULT_IPS
    fallback_dst = ip_table.get(dc)
    use_cf = proxy_config.fallback_cfproxy and not is_test_dc
    worker_domains = proxy_config.cfproxy_worker_domains

    methods: List[str] = []

    if worker_domains and fallback_dst:
        methods.append('cf_worker')
    if use_cf:
        methods.append('cf')
    if fallback_dst:
        methods.append('tcp')

    for method in methods:
        if method == 'cf_worker' and fallback_dst:
            ok = await _cfproxy_worker_fallback(
                reader, writer, relay_init, label, ctx,
                dc=dc, is_test_dc=is_test_dc, is_media=is_media,
                fallback_dst=fallback_dst, splitter=splitter)
            if ok:
                return True
        elif method == 'cf':
            if is_media and h2_pool is not None and proto_tag is not None:
                channel = await h2_pool.open(dc, label)
                if channel is not None:
                    stats.connections_h2 += 1
                    stats.connections_cfproxy += 1
                    await bridge_h2(reader, writer, channel, ctx, proto_tag)
                    return True
            ok = await _cfproxy_fallback(
                reader, writer, relay_init, label, ctx,
                dc=dc, is_media=is_media,
                splitter=splitter)
            if ok:
                return True
        elif method == 'tcp' and fallback_dst:
            ok = await _tcp_fallback_endpoints(
                reader, writer, native_tcp_endpoints(dc, is_test_dc),
                relay_init, label, ctx, is_media=is_media, dc=dc)
            if ok:
                return True
    return False


async def _cfproxy_worker_fallback(reader, writer, relay_init, label,
                                   ctx: CryptoCtx,
                                   dc: int, is_test_dc: bool, is_media: bool,
                                   fallback_dst: str,
                                   splitter=None):
    media_tag = ' media' if is_media else ''
    worker_domains = proxy_config.cfproxy_worker_domains
    if not worker_domains:
        return False

    pooled = None if is_test_dc else await cf_worker_pool.get(
        dc, fallback_dst, worker_domains)
    if pooled:
        ws, worker_domain = pooled
        log.info("[%s] DC%d%s -> CF worker pool hit via %s for %s",
                 label, dc, media_tag, worker_domain, fallback_dst)
    else:
        query = urlencode({
            'dst': fallback_dst,
            'dc': str(dc),
        })
        path = f'/apiws?{query}'

        ws = None
        for worker_domain in cf_worker_pool.available_domains(worker_domains):
            log.info("[%s] DC%d%s -> trying CF worker %s for %s",
                     label, dc, media_tag, worker_domain, fallback_dst)

            try:
                ws = await RawWebSocket.connect(worker_domain, worker_domain,
                                                timeout=10.0, path=path, 
                                                secure=not proxy_config.disable_secure)
                break
            except Exception as exc:
                cf_worker_pool.report_failure(worker_domain, exc)
                log.warning("[%s] DC%d%s CF worker %s failed: %s",
                            label, dc, media_tag, worker_domain, repr(exc))
                continue

        if ws is None:
            return False

    stats.connections_cfproxy += 1
    await ws.send(relay_init)
    await bridge_ws_reencrypt(reader, writer, ws, label, ctx,
                              dc=dc, is_media=is_media,
                              splitter=None, route='worker-ws')
    return True


async def _cfproxy_fallback(reader, writer, relay_init, label,
                            ctx: CryptoCtx,
                            dc: int, is_media: bool,
                            splitter=None):
    media_tag = ' media' if is_media else ''
    ws = None
    chosen_domain = None

    log.info("[%s] DC%d%s -> trying CF proxy",
            label, dc, media_tag)
    connect_started = time.monotonic()

    for base_domain in balancer.get_domains_for_dc(dc):
        domain = f'kws{dc}.{base_domain}'
        try:
            ws = await RawWebSocket.connect(domain, domain, timeout=10.0, 
                                            secure=not proxy_config.disable_secure)
            chosen_domain = base_domain
            break
        except Exception as exc:
            log.warning("[%s] DC%d%s CF proxy failed: %s",
                        label, dc, media_tag, repr(exc))

    if ws is None:
        return False

    log.debug('[%s] WS CONNECT DC%d%s route=cf setup_ms=%.0f',
              label, dc, media_tag, (time.monotonic() - connect_started) * 1000)
    if chosen_domain and balancer.update_domain_for_dc(dc, chosen_domain):
        log.info("[%s] Switched active CF domain", label)

    stats.connections_cfproxy += 1
    await ws.send(relay_init)
    await bridge_ws_reencrypt(reader, writer, ws, label, ctx,
                               dc=dc, is_media=is_media,
                               splitter=splitter, route='cf-ws')
    return True


def _tcp_failed(key, exc, label):
    dst, port = key
    failures = _tcp_failures.get(key, 0) + 1
    _tcp_failures[key] = failures
    delay = min(TCP_BACKOFF_INITIAL * 2 ** min(failures - 1, 7),
                TCP_BACKOFF_MAX)
    _tcp_retry_after[key] = time.monotonic() + delay
    route_diagnostics.cooldown(dst, port, failures, _tcp_retry_after[key])
    log.warning("[%s] TCP fallback to %s:%d failed: %s; retry in %.0fs",
                label, dst, port, type(exc).__name__, delay)


def _tcp_succeeded(key):
    _tcp_failures.pop(key, None)
    _tcp_retry_after.pop(key, None)
    route_diagnostics.clear_cooldown(*key)


def _abort_tcp_writer(writer):
    # A race loser has sent no application bytes and needs no graceful close.
    try:
        writer.transport.abort()
    except (AttributeError, OSError):
        try:
            writer.close()
        except OSError:
            pass


async def _open_tcp_endpoint(dst, port, label, deadline):
    """Acquire one private socket, coalescing only its first unproven dial."""
    key = (dst, port)
    probe = None
    loop = asyncio.get_running_loop()
    while True:
        if time.monotonic() < _tcp_retry_after.get(key, 0):
            route_diagnostics.increment('native_tcp_backoff_skipped')
            return None
        remaining = deadline - loop.time()
        if remaining <= 0:
            return None
        pending = _tcp_connecting.get(key)
        if pending is None:
            probe = loop.create_future()
            _tcp_connecting[key] = probe
            break
        route_diagnostics.increment('native_tcp_wait_shared')
        try:
            healthy = await asyncio.wait_for(asyncio.shield(pending), remaining)
        except asyncio.TimeoutError:
            # Expiring while waiting is not a failed dial to this endpoint.
            return None
        if healthy:
            # Every healthy session gets its own socket; never share MTProto
            # ciphertext, readers or cipher state between native clients.
            if deadline <= loop.time():
                return None
            if time.monotonic() < _tcp_retry_after.get(key, 0):
                route_diagnostics.increment('native_tcp_backoff_skipped')
                return None
            break
        # A cancelled speculative probe is no evidence of unreachability.
        # Re-enter the gate so its waiters cannot all become new probes.

    rw = None
    healthy = False
    attempt = route_diagnostics.Attempt('native_tcp', host=dst, port=port)
    attempt.stage('native_tcp')
    try:
        try:
            log.info("[%s] TCP fallback to %s:%d", label, dst, port)
            rr, rw = await asyncio.wait_for(
                asyncio.open_connection(dst, port),
                timeout=max(0, deadline - loop.time()))
            attempt.success()
            _tcp_succeeded(key)
            healthy = True
            result = (key, rr, rw)
            rw = None  # Ownership moves to the race until a winner is adopted.
            return result
        except asyncio.CancelledError:
            attempt.cancel()
            raise
        except Exception as exc:
            attempt.failure(exc)
            _tcp_failed(key, exc, label)
            return None
        finally:
            attempt.finish()
            if probe is not None:
                if _tcp_connecting.get(key) is probe:
                    _tcp_connecting.pop(key, None)
                if not probe.done():
                    probe.set_result(healthy)
    finally:
        if rw is not None:
            _abort_tcp_writer(rw)


async def _race_tcp_endpoints(endpoints, label, deadline):
    """Race only TCP handshakes. No init or native payload reaches a loser."""
    endpoints = tuple(dict.fromkeys(endpoints))[:MAX_NATIVE_CANDIDATES]
    tasks = [asyncio.create_task(_open_tcp_endpoint(dst, port, label, deadline))
             for dst, port in endpoints]
    pending = set(tasks)
    winner = None
    try:
        while pending and winner is None:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            # Stable preference when several connects finish in the same turn.
            for task in tasks:
                if task in done:
                    result = task.result()
                    if result is not None:
                        winner = result
                        break
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        except BaseException:
            # Cancellation during cleanup must not orphan even the selected
            # socket: ownership has not yet passed to the single relay.
            for task in tasks:
                if task.done() and not task.cancelled():
                    result = task.result()
                    if isinstance(result, tuple):
                        _abort_tcp_writer(result[2])
            raise
        for result in results:
            if isinstance(result, tuple) and result is not winner:
                _abort_tcp_writer(result[2])
    return winner


async def _tcp_fallback_endpoints(reader, writer, endpoints, relay_init, label,
                                  ctx: CryptoCtx, *, is_media=False, dc=None):
    deadline = asyncio.get_running_loop().time() + TCP_CONNECT_TIMEOUT
    connection = await _race_tcp_endpoints(endpoints, label, deadline)
    if connection is None:
        return False
    key, rr, rw = connection
    attempt = route_diagnostics.Attempt('native_tcp', host=key[0], port=key[1])
    attempt.stage('native_init')
    try:
        try:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError()
            rw.write(relay_init)
            await asyncio.wait_for(rw.drain(), remaining)
            attempt.success()
        except asyncio.CancelledError:
            attempt.cancel()
            raise
        except Exception as exc:
            attempt.failure(exc)
            _tcp_failed(key, exc, label)
            # Init has already been sent: let Telegram create a fresh native
            # session instead of replaying cipher state on another endpoint.
            return False
        finally:
            attempt.finish()

        stats.connections_tcp_fallback += 1
        await _bridge_tcp_reencrypt(reader, writer, rr, rw, label, ctx,
                                    is_media=is_media, dc=dc)
        return True
    finally:
        if rw is not None:
            try:
                await close_writer(rw)
            except (OSError, ConnectionError):
                pass


async def _tcp_fallback(reader, writer, dst, port, relay_init, label, ctx: CryptoCtx,
                        *, is_media=False, dc=None):
    """Compatibility entry point for one explicitly supplied endpoint."""
    return await _tcp_fallback_endpoints(
        reader, writer, ((dst, port),), relay_init, label, ctx,
        is_media=is_media, dc=dc)


async def bridge_ws_reencrypt(reader, writer, ws: RawWebSocket, label,
                               ctx: CryptoCtx,
                               dc=None, is_media=False,
                               splitter: Optional[MsgSplitter] = None,
                               route='ws', on_stall=None):
    """
    Bidirectional TCP(client) <-> WS(telegram) with re-encryption.
    client ciphertext → decrypt(clt_key) → encrypt(tg_key) → WS
    WS data → decrypt(tg_key) → encrypt(clt_key) → client TCP
    """
    dc_tag = f"DC{dc}{'m' if is_media else ''}" if dc else "DC?"

    up_bytes = 0
    down_bytes = 0
    up_packets = 0
    down_packets = 0
    start_time = asyncio.get_running_loop().time()
    close_reason = 'normal'
    activity = WsActivity(label, dc_tag) if log.isEnabledFor(logging.DEBUG) else None
    health = (MediaHealth(route, dc, progress=lambda: ws.last_payload_received,
                          on_stall=on_stall) if is_media else None)

    async def tcp_to_ws():
        nonlocal up_bytes, up_packets, close_reason
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    if splitter:
                        tail = splitter.flush()
                        if tail:
                            if activity is not None:
                                activity.send_started()
                            await ws.send(tail[0])
                            if activity is not None:
                                activity.sent(len(tail[0]))
                    break
                n = len(chunk)
                if activity is not None:
                    activity.input(n)
                stats.bytes_up += n
                up_bytes += n
                up_packets += 1
                plain = ctx.clt_dec.update(chunk)
                chunk = ctx.tg_enc.update(plain)
                if splitter:
                    parts = splitter.split(chunk)
                    if not parts:
                        continue
                    if health:
                        health.input()
                    if activity is not None:
                        activity.send_started()
                    if len(parts) > 1:
                        await ws.send_batch(parts)
                    else:
                        await ws.send(parts[0])
                    if activity is not None:
                        activity.sent(sum(map(len, parts)))
                else:
                    if health:
                        health.input()
                    if activity is not None:
                        activity.send_started()
                    await ws.send(chunk)
                    if activity is not None:
                        activity.sent(len(chunk))
        except asyncio.CancelledError:
            return
        except (ConnectionError, OSError) as e:
            close_reason = f"client: {type(e).__name__}"
        except Exception as e:
            close_reason = f"client: {type(e).__name__}: {e}"
            log.debug("[%s] tcp->ws ended: %s", label, e)

    async def ws_to_tcp():
        nonlocal down_bytes, down_packets, close_reason
        try:
            while True:
                data = await ws.recv()
                if data is None:
                    if close_reason == 'normal':
                        close_reason = 'upstream: ws_close'
                    break
                n = len(data)
                if health and data:
                    health.received()
                if activity is not None:
                    activity.received(n)
                stats.bytes_down += n
                down_bytes += n
                down_packets += 1
                plain = ctx.tg_dec.update(data)
                data = ctx.clt_enc.update(plain)
                if health:
                    health.writing_native = True
                writer.write(data)
                await writer.drain()
                if health:
                    health.delivered()
                if activity is not None:
                    activity.delivered(n)
        except asyncio.CancelledError:
            return
        except (ConnectionError, OSError) as e:
            close_reason = f"upstream: {type(e).__name__}"
        except asyncio.IncompleteReadError:
            close_reason = 'upstream: tcp_reset'
        except Exception as e:
            close_reason = f"upstream: {type(e).__name__}: {e}"
            log.debug("[%s] ws->tcp ended: %s", label, e)

    tasks = [asyncio.create_task(tcp_to_ws()),
             asyncio.create_task(ws_to_tcp())]
    if health:
        tasks.append(asyncio.create_task(health.run()))
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        if health:
            if health.stalled:
                close_reason = 'media: no response to request'
            health.close()
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except BaseException:
                pass
        elapsed = asyncio.get_running_loop().time() - start_time
        if activity is not None:
            activity.close()
        log.info("[%s] %s WS session closed (%s): "
                 "^%s (%d pkts) v%s (%d pkts) in %.1fs",
                 label, dc_tag, close_reason,
                 human_bytes(up_bytes), up_packets,
                 human_bytes(down_bytes), down_packets,
                 elapsed)
        try:
            await ws.close()
        except BaseException:
            pass
        try:
            await close_writer(writer)
        except BaseException:
            pass


async def _bridge_tcp_reencrypt(reader, writer, remote_reader, remote_writer,
                                label, ctx: CryptoCtx, *, is_media=False, dc=None):
    """Bidirectional TCP <-> TCP with re-encryption."""
    health = MediaHealth('tcp', dc) if is_media else None

    async def forward(src, dst_w, is_up):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                n = len(data)
                if is_up:
                    if health:
                        health.input()
                    stats.bytes_up += n
                    plain = ctx.clt_dec.update(data)
                    data = ctx.tg_enc.update(plain)
                else:
                    if health:
                        health.received()
                        health.writing_native = True
                    stats.bytes_down += n
                    plain = ctx.tg_dec.update(data)
                    data = ctx.clt_enc.update(plain)
                dst_w.write(data)
                await dst_w.drain()
                if health and not is_up:
                    health.delivered()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.debug("[%s] forward ended: %s", label, e)

    tasks = [
        asyncio.create_task(forward(reader, remote_writer, True)),
        asyncio.create_task(forward(remote_reader, writer, False)),
    ]
    if health:
        tasks.append(asyncio.create_task(health.run()))
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        if health:
            health.close()
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except BaseException:
                pass
        for w in (writer, remote_writer):
            try:
                await close_writer(w)
            except BaseException:
                pass
