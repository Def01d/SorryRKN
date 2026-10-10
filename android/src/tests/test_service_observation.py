"""Background observations recover without controlling active user sessions."""
import asyncio
from types import SimpleNamespace

import pytest

import android_bridge
import service_probe


@pytest.mark.asyncio
async def test_chatgpt_monitor_rechecks_failures_and_exits_on_probe_cancellation(monkeypatch):
    observations = iter(['transport_error', 'reachable_public', 'cancelled'])
    intervals = []
    async def check(port):
        assert port == 1081
        return {'state': next(observations), 'authenticated_access': False}
    async def sleep(delay):
        intervals.append(delay)
    monkeypatch.setattr(service_probe, 'check_chatgpt', check)
    monkeypatch.setattr(android_bridge, 'asyncio', SimpleNamespace(sleep=sleep))
    monkeypatch.setattr(android_bridge, '_chatgpt_check', {})
    await asyncio.wait_for(android_bridge._check_chatgpt(1081), .5)
    assert intervals == [30, 120]
    assert android_bridge._chatgpt_check['state'] == 'cancelled'


@pytest.mark.asyncio
async def test_chatgpt_monitor_does_not_swallow_cancellation(monkeypatch):
    started = asyncio.Event()
    async def check(port):
        started.set()
        await asyncio.Future()
    monkeypatch.setattr(service_probe, 'check_chatgpt', check)
    task = asyncio.create_task(android_bridge._check_chatgpt(1081))
    await asyncio.wait_for(started.wait(), .5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, .5)


@pytest.mark.asyncio
async def test_chatgpt_route_probe_precedes_page_and_failure_does_not_skip_page(monkeypatch):
    calls = []
    class Gateway:
        async def check_ai_route(self):
            calls.append('route')
            raise OSError('No verified candidate')
    async def check(port):
        calls.append('page')
        return {'state': 'cancelled'}
    monkeypatch.setattr(service_probe, 'check_chatgpt', check)
    monkeypatch.setattr(android_bridge, '_chatgpt_check', {})
    await asyncio.wait_for(android_bridge._check_chatgpt(1081, Gateway()), .5)
    assert calls == ['route', 'page']
