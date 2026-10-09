"""Telegram status observes protocol replies without controlling user sessions."""
import asyncio
import copy
import json
import threading
from types import SimpleNamespace

import pytest

import android_bridge as bridge
import telegram_probe

SECRET = '1830ab' * 5 + 'cd'


class ObservationClock:
    """Gate only the observer's long interval, leaving socket I/O real."""
    def __init__(self):
        self.rounds = asyncio.Queue()
        self.advance = asyncio.Queue()

    def __getattr__(self, name):
        return getattr(asyncio, name)

    async def sleep(self, seconds):
        if seconds not in (30, 120):
            return await asyncio.sleep(seconds)
        await self.rounds.put((seconds, copy.deepcopy(bridge._telegram_check)))
        await self.advance.get()


@pytest.mark.asyncio
async def test_unavailable_partial_reachable_and_recovery_do_not_interrupt_user_socket(monkeypatch):
    rounds = [(False, False), (True, False), (True, True), (False, False)]
    calls = {2: 0, 4: 0}
    clock = ObservationClock()
    monkeypatch.setattr(bridge, 'asyncio', clock)
    monkeypatch.setattr(bridge, '_telegram_check', {'state': 'checking'})
    monkeypatch.setattr(bridge, '_stop_event', asyncio.Event())
    async def observe(port, secret, dc=2, is_media=False):
        assert port == 1443 and secret == SECRET and is_media is False
        ok = rounds[calls[dc]][0 if dc == 2 else 1]
        calls[dc] += 1
        return {'state': 'reachable' if ok else 'unavailable', 'dc': dc,
                'authenticated_access': False, 'account_checked': False,
                'media_access_checked': False, 'error': '' if ok else 'TimeoutError'}
    monkeypatch.setattr(telegram_probe, 'check_telegram', observe)
    async def no_reset(*args, **kwargs):
        raise AssertionError('An observation must not start or stop the service')
    monkeypatch.setattr(bridge, 'start', no_reset)
    monkeypatch.setattr(bridge, 'stop', no_reset)
    ended = asyncio.Event()
    async def user_session(reader, writer):
        try:
            while data := await reader.read(1024):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            ended.set()
    server = await asyncio.start_server(user_session, '127.0.0.1', 0)
    reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
    task = asyncio.create_task(bridge._check_telegram(SECRET))
    try:
        for expected, interval in [('unavailable', 30), ('partial', 30), ('reachable', 120), ('unavailable', 30)]:
            delay, result = await asyncio.wait_for(clock.rounds.get(), .5)
            assert result['state'] == expected and delay == interval
            assert len(result['targets']) == 2
            assert all(result[field] is False for field in (
                'authenticated_access', 'account_checked', 'media_access_checked'))
            assert SECRET not in json.dumps(result)
            assert not bridge._stop_event.is_set() and not task.done()
            writer.write(b'active user traffic')
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(19), .5) == b'active user traffic'
            if expected != 'unavailable' or calls[2] == 1:
                await clock.advance.put(None)
        assert calls == {2: 4, 4: 4}
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()
        await asyncio.wait_for(ended.wait(), .5)


@pytest.mark.asyncio
async def test_unexpected_probe_exception_is_unavailable_without_secret_or_stale_green(monkeypatch):
    clock = ObservationClock()
    monkeypatch.setattr(bridge, 'asyncio', clock)
    monkeypatch.setattr(bridge, '_telegram_check', {'state': 'reachable'})
    async def faulty(port, secret, dc=2, is_media=False):
        if dc == 2:
            raise RuntimeError('private secret=' + secret)
        return {'state': 'unavailable', 'dc': dc, 'error': 'TimeoutError'}
    monkeypatch.setattr(telegram_probe, 'check_telegram', faulty)
    task = asyncio.create_task(bridge._check_telegram(SECRET))
    try:
        delay, result = await asyncio.wait_for(clock.rounds.get(), .5)
        assert result['state'] == 'unavailable' and delay == 30
        assert result['targets'][0]['error'] == 'RuntimeError'
        assert SECRET not in json.dumps(result) and 'private secret' not in json.dumps(result)
        assert not task.done()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_startup_is_ready_while_observations_wait_and_shutdown_cancels_them_first(monkeypatch):
    from proxy import config, tg_ws_proxy
    order = []
    entered = set()
    cancelled = set()
    probes_started = asyncio.Event()
    never = asyncio.Event()
    runs = []
    class Gateway:
        port = 1081
        def __init__(self, **kwargs):
            self.stats = {}
            self.resolver = SimpleNamespace(provider='local test')
        async def start(self):order.append('gateway started')
        async def close(self):order.append('gateway closed')
    class Server:
        def close(self):order.append('server closed')
        async def wait_closed(self):pass
    class Pool:
        async def close(self):order.append('pool closed')
    async def run_proxy(stop):
        runs.append(True)
        tg_ws_proxy._server_instance = Server()
        try:await stop.wait()
        finally:order.append('proxy stopped')
    async def hanging(port, secret, dc=2, is_media=False):
        assert port == 1443 and secret == SECRET
        entered.add(dc)
        if entered == {2, 4}:probes_started.set()
        try:await never.wait()
        finally:
            cancelled.add(dc)
            order.append('probe cancelled')
    monkeypatch.setattr(bridge, 'Gateway', Gateway)
    monkeypatch.setattr(bridge, '_ready', threading.Event())
    monkeypatch.setattr(bridge, '_data_directory', None)
    monkeypatch.setattr(bridge, '_routes', {'own_ip': True, 'telegram_dpi': 1084, 'builtin_extras': False})
    for name in ('_loop', '_stop_event', '_gateway'):
        monkeypatch.setattr(bridge, name, None)
    monkeypatch.setattr(bridge, '_active', False)
    monkeypatch.setattr(bridge, '_telegram_check', {'state': 'disabled'})
    monkeypatch.setattr(bridge, '_chatgpt_check', {'state': 'disabled'})
    monkeypatch.setattr(tg_ws_proxy, '_run', run_proxy)
    monkeypatch.setattr(tg_ws_proxy, '_server_instance', None)
    monkeypatch.setattr(tg_ws_proxy, '_client_tasks', set())
    monkeypatch.setattr(tg_ws_proxy, 'ws_pool', Pool())
    monkeypatch.setattr(tg_ws_proxy, 'cf_h2_pool', None)
    monkeypatch.setattr(config, '_refresh_stop', threading.Event())
    for field in ('host', 'port', 'secret', 'pool_size', 'fallback_cfproxy',
                  'cfproxy_h2_media', 'cfproxy_worker_domains', 'telegram_dpi_port'):
        monkeypatch.setattr(config.proxy_config, field, getattr(config.proxy_config, field))
    monkeypatch.setattr(telegram_probe, 'check_telegram', hanging)
    service = asyncio.create_task(bridge._serve(SECRET, True, True))
    try:
        await asyncio.wait_for(probes_started.wait(), .5)
        assert bridge._ready.is_set() and bridge._active and not service.done()
        assert bridge._telegram_check['state'] == 'checking'
        assert len(runs) == 1 and not cancelled
        report = json.loads(bridge.diagnostics())
        assert report['telegram_check']['state'] == 'checking'
        assert SECRET not in json.dumps(report)
        bridge._stop_event.set()
        await asyncio.wait_for(service, .5)
        assert cancelled == {2, 4} and len(runs) == 1
        assert order.index('probe cancelled') < order.index('gateway closed')
        assert order.index('proxy stopped') < order.index('gateway closed')
        assert not bridge._active and bridge._gateway is None
        assert tg_ws_proxy._server_instance is None
    finally:
        service.cancel()
        await asyncio.gather(service, return_exceptions=True)
