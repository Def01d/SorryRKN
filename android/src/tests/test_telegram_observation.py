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
    rounds = [(False,) * 5, (True, False, True, False, False), (True,) * 5, (False,) * 5]
    calls = {dc: 0 for dc in range(1, 6)}
    clock = ObservationClock()
    monkeypatch.setattr(bridge, 'asyncio', clock)
    monkeypatch.setattr(bridge, '_telegram_check', {'state': 'checking'})
    monkeypatch.setattr(bridge, '_stop_event', asyncio.Event())
    async def observe(port, secret, dc=2, is_media=False, timeout=None):
        assert port == 1443 and secret == SECRET and is_media is False
        assert timeout == 15
        ok = rounds[calls[dc]][dc - 1]
        calls[dc] += 1
        return {'state': 'reachable' if ok else 'unavailable', 'dc': dc,
                'authenticated_access': False, 'account_checked': False,
                'latency_ms': 100 + dc if ok else None,
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
        for expected, interval, passed in [('unavailable', 30, 0), ('partial', 30, 2), ('reachable', 120, 5), ('unavailable', 30, 0)]:
            delay, result = await asyncio.wait_for(clock.rounds.get(), .5)
            assert result['state'] == expected and delay == interval
            assert len(result['targets']) == result['total'] == 5
            assert result['passed'] == passed
            assert result['latency_ms'] == (101 if passed else None)
            assert [target['dc'] for target in result['targets']] == list(range(1, 6))
            assert all(result[field] is False for field in (
                'authenticated_access', 'account_checked', 'media_access_checked'))
            assert SECRET not in json.dumps(result)
            assert not bridge._stop_event.is_set() and not task.done()
            writer.write(b'active user traffic')
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(19), .5) == b'active user traffic'
            if expected != 'unavailable' or calls[2] == 1:
                await clock.advance.put(None)
        assert calls == {dc: 4 for dc in range(1, 6)}
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
    async def faulty(port, secret, dc=2, is_media=False, timeout=None):
        assert timeout == 15
        if dc == 1:
            raise RuntimeError('private secret=' + secret)
        return {'state': 'unavailable', 'dc': dc, 'error': 'TimeoutError'}
    monkeypatch.setattr(telegram_probe, 'check_telegram', faulty)
    task = asyncio.create_task(bridge._check_telegram(SECRET))
    try:
        delay, result = await asyncio.wait_for(clock.rounds.get(), .5)
        assert result['state'] == 'unavailable' and delay == 30
        assert result['passed'] == 0 and result['total'] == 5 and result['latency_ms'] is None
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
    async def hanging(port, secret, dc=2, is_media=False, timeout=None):
        assert port == 1443 and secret == SECRET
        assert timeout == 15
        entered.add(dc)
        if entered == set(range(1, 6)):probes_started.set()
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
                  'cfproxy_h2_media', 'cfproxy_worker_domains', 'telegram_dpi_port',
                  'verified_routes', 'cfproxy_seed_domains', 'cfproxy_user_domains'):
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
        assert cancelled == set(range(1, 6)) and len(runs) == 1
        assert order.index('probe cancelled') < order.index('gateway closed')
        assert order.index('proxy stopped') < order.index('gateway closed')
        assert not bridge._active and bridge._gateway is None
        assert tg_ws_proxy._server_instance is None
    finally:
        service.cancel()
        await asyncio.gather(service, return_exceptions=True)


def test_app_snapshot_is_seed_and_does_not_suppress_cf_refresh(monkeypatch):
    import bridge_data
    from proxy import config
    from proxy.balancer import balancer
    seeds = ['old1.example.com', 'old2.example.com', 'old3.example.com']
    fresh = ['new1.example.com', 'new2.example.com', 'new3.example.com']
    updated = []
    monkeypatch.setattr(bridge_data, 'cf_domains', lambda directory: seeds)
    monkeypatch.setattr(balancer, 'update_domains_list', lambda domains: updated.append(list(domains)))
    monkeypatch.setattr(config, '_fetch_cfproxy_domain_list', lambda: fresh)
    monkeypatch.setattr(config.proxy_config, 'cfproxy_seed_domains', [])
    monkeypatch.setattr(config.proxy_config, 'cfproxy_user_domains', ['legacy-snapshot.example.com'])
    bridge.apply_data('controlled-fixture')
    assert config.proxy_config.cfproxy_seed_domains == seeds
    assert config.proxy_config.cfproxy_user_domains == []
    config.refresh_cfproxy_domains()
    assert updated == [seeds, fresh]
