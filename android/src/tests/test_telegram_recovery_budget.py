"""A recovered Telegram route must be retried without toggling the app off/on.

Advance only the route's monotonic clock; asyncio's own clock is untouched.
Failures pass through the real refill scheduler / TCP fallback, so these tests
exercise retry suppression rather than duplicating its exponential formula.
"""
import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from proxy import bridge
from proxy import pool as pool_module
from proxy.config import proxy_config


class RouteClock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


class AsyncioWithDial:
    """Replace one module's dial, without replacing asyncio for other tasks."""
    def __init__(self, dial):
        self.open_connection = dial

    def __getattr__(self, name):
        return getattr(asyncio, name)


@pytest.mark.asyncio
async def test_websocket_refill_retries_recovered_route_within_thirty_seconds(monkeypatch):
    clock = RouteClock()
    monkeypatch.setattr(pool_module, 'time', clock)
    monkeypatch.setattr(proxy_config, 'pool_size', 1)
    pool = pool_module._WsPool()
    # Drive the same scheduler explicitly when the controlled clock reaches a
    # retry deadline. Do not create a real periodic sleep in the unit test.
    monkeypatch.setattr(pool, '_schedule_rotation', Mock())
    key = (2, False, False)
    domain = ['kws2.web.telegram.org']
    attempts = []
    recovered = False
    healthy = Mock(close=AsyncMock())

    async def dial(*args, **kwargs):
        attempts.append(clock.now)
        return healthy if recovered else None

    monkeypatch.setattr(pool, '_connect_one', dial)

    async def tick():
        pool._schedule_refill(key, '149.154.167.220', domain)
        refill = pool._refilling.get(key)
        if refill is not None:
            await refill

    try:
        for failure in range(13):
            await tick()
            assert len(attempts) == failure + 1
            assert not pool._idle.get(key)
            if failure < 12:
                # Read the scheduler's actual deadline, never its formula.
                clock.now = pool._refill_after[key]
        failed_at = clock.now
        scheduled_delay = pool._refill_after[key] - failed_at
        recovered = True
        clock.now = failed_at + 30.001
        previous = len(attempts)
        await tick()
        assert len(attempts) == previous + 1, (
            f'Restored WS route still suppressed after 30 s; '
            f'last scheduled backoff was {scheduled_delay:g} s')
        assert pool._idle[key][0][0] is healthy
        assert key not in pool._refill_failures
        assert key not in pool._refill_after
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_native_tcp_retries_recovered_route_within_thirty_seconds(monkeypatch):
    clock = RouteClock()
    monkeypatch.setattr(bridge, 'time', clock)
    bridge.reset_tcp_backoff()
    key = ('149.154.167.51', 443)
    attempts = []
    recovered = False
    writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock())

    async def dial(*args, **kwargs):
        attempts.append(clock.now)
        if not recovered:
            raise OSError(101, 'controlled temporary network failure')
        return Mock(), writer

    monkeypatch.setattr(bridge, 'asyncio', AsyncioWithDial(dial))
    relay = AsyncMock()
    monkeypatch.setattr(bridge, '_bridge_tcp_reencrypt', relay)

    async def connect():
        return await bridge._tcp_fallback(
            Mock(), Mock(), *key, b'controlled relay init', 'recovery-check', Mock(), dc=2)

    try:
        for failure in range(9):
            assert not await connect()
            assert len(attempts) == failure + 1
            if failure < 8:
                clock.now = bridge._tcp_retry_after[key]
        failed_at = clock.now
        scheduled_delay = bridge._tcp_retry_after[key] - failed_at
        recovered = True
        clock.now = failed_at + 30.001
        previous = len(attempts)
        connected = await connect()
        assert len(attempts) == previous + 1, (
            f'Restored native TCP route still suppressed after 30 s; '
            f'last scheduled backoff was {scheduled_delay:g} s')
        assert connected
        relay.assert_awaited_once()
        assert key not in bridge._tcp_failures
        assert key not in bridge._tcp_retry_after
    finally:
        bridge.reset_tcp_backoff()


@pytest.mark.asyncio
async def test_failed_pool_uses_one_recovery_probe_then_restores_full_burst_capacity(monkeypatch):
    clock = RouteClock()
    monkeypatch.setattr(pool_module, 'time', clock)
    monkeypatch.setattr(proxy_config, 'pool_size', 4)
    monkeypatch.setattr(proxy_config, 'dc_redirects', {2: '149.154.167.220'})
    pool = pool_module._WsPool()
    monkeypatch.setattr(pool, '_schedule_rotation', Mock())
    key = (2, True, False)
    domains = ['kws2-1.web.telegram.org', 'kws2.web.telegram.org']
    phase = 'failed'
    calls = []
    probe_started, release_probe = asyncio.Event(), asyncio.Event()
    full_batch = asyncio.Event()
    healthy_active = healthy_peak = 0
    clients = []

    def opened_ws():
        ws = Mock(_closed=False, close=AsyncMock())
        ws.reader.at_eof.return_value = False
        ws.reader.exception.return_value = None
        ws.writer.transport.is_closing.return_value = False
        return ws

    async def dial(*args, **kwargs):
        nonlocal phase, healthy_active, healthy_peak
        calls.append(phase)
        if phase == 'failed':
            return None
        if phase == 'recovery':
            probe_started.set()
            await release_probe.wait()
            phase = 'healthy'
            return opened_ws()
        healthy_active += 1
        healthy_peak = max(healthy_peak, healthy_active)
        if healthy_active == 4:
            full_batch.set()
        try:
            # Hold the first healthy batch until all four slots are started.
            # A pool accidentally stuck in single-probe mode cannot pass.
            await full_batch.wait()
            return opened_ws()
        finally:
            healthy_active -= 1

    monkeypatch.setattr(pool, '_connect_one', dial)
    try:
        pool._schedule_refill(key, '149.154.167.220', domains)
        await pool._refilling[key]
        assert calls == ['failed'] * 4
        assert pool._refill_failures[key] == 1

        clock.now = pool._refill_after[key]
        phase = 'recovery'
        clients = [asyncio.create_task(pool.get(2, True)) for _ in range(12)]
        async with asyncio.timeout(1):
            await probe_started.wait()
            await asyncio.sleep(0)
            assert calls.count('recovery') == 1, (
                'Many waiting native clients must share one recovery probe for this DC')
            assert all(not client.done() for client in clients)
            release_probe.set()
            await full_batch.wait()
            results = await asyncio.gather(*clients)
        assert len({id(ws) for ws in results if ws is not None}) == 12
        assert healthy_peak == 4
        assert key not in pool._refill_failures
        assert key not in pool._refill_after
    finally:
        release_probe.set()
        full_batch.set()
        for client in clients:
            if not client.done():
                client.cancel()
        await asyncio.gather(*clients, return_exceptions=True)
        await pool.close()
