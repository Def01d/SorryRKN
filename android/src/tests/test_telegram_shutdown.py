"""Accepted native sockets must close even when their handler never starts."""
import asyncio
import copy
import json
import threading

import pytest

from proxy import tg_ws_proxy as proxy
from proxy.config import proxy_config


class AsyncioHook:
    def __init__(self, accept, cancel_handler):
        self.accept = accept
        self.cancel_handler = cancel_handler
        self.force_ephemeral = False

    def __getattr__(self, key):return getattr(asyncio, key)

    async def start_server(self, callback, *args, **kwargs):
        def accepted(reader, writer):
            self.accept.append(writer)
            callback(reader, writer)
        if self.force_ephemeral:
            args = (args[0], 0, *args[2:])
        return await asyncio.start_server(accepted, *args, **kwargs)

    def create_task(self, coroutine, **kwargs):
        task = asyncio.create_task(coroutine, **kwargs)
        if self.cancel_handler and coroutine.cr_code is proxy._handle_client.__code__:
            # Reproduce a stop arriving after accept but before the handler's
            # first step. Its own try/finally never owns or closes this writer.
            task.cancel()
        return task


class Pool:
    def __init__(self):self.closed = False
    def reset(self):self.closed = False
    async def warmup(self):pass
    async def close(self):self.closed = True


@pytest.fixture
def listener(monkeypatch):
    accepted = []
    pool = Pool()
    # _serve configures the shared ProxyConfig beyond listener fields. Preserve
    # every field so a worker lifecycle test cannot switch later legacy fixtures
    # into the app's verified-route mode or leak seed/DPI configuration.
    for key, value in vars(proxy_config).items():
        monkeypatch.setattr(proxy_config, key, copy.deepcopy(value))
    for key, value in {'host': '127.0.0.1', 'port': 0, 'secret': '11' * 16,
                       'fallback_cfproxy': False, 'cfproxy_h2_media': False,
                       'cfproxy_user_domains': [], 'cfproxy_worker_domains': []}.items():
        monkeypatch.setattr(proxy_config, key, value)
    monkeypatch.setattr(proxy, '_server_instance', None)
    monkeypatch.setattr(proxy, '_client_tasks', set())
    if hasattr(proxy, '_client_writers'):
        monkeypatch.setattr(proxy, '_client_writers', set())
    monkeypatch.setattr(proxy, 'ws_pool', pool)
    monkeypatch.setattr(proxy, 'cf_worker_pool', Pool())
    monkeypatch.setattr(proxy, 'asyncio', AsyncioHook(accepted, True))
    return accepted, pool


@pytest.mark.asyncio
async def test_cancelled_before_first_step_does_not_keep_listener_alive(listener):
    accepted, pool = listener
    stop = asyncio.Event()
    run = asyncio.create_task(proxy._run(stop))
    writer = None
    try:
        async with asyncio.timeout(1):
            while proxy._server_instance is None:await asyncio.sleep(0)
        port = proxy._server_instance.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        async with asyncio.timeout(1):
            while not accepted or proxy._client_tasks:await asyncio.sleep(0)
        stop.set()
        await asyncio.wait_for(asyncio.shield(run), .4)
        assert await asyncio.wait_for(reader.read(), .2) == b''
        assert pool.closed and proxy._server_instance is None
        assert not proxy._client_tasks
        assert not getattr(proxy, '_client_writers', set())
    finally:
        # Deterministic cleanup also lets the old implementation fail without
        # leaving a hung server/task behind in the regression suite.
        for native in accepted:native.transport.abort()
        if writer:
            writer.close()
            await writer.wait_closed()
        stop.set()
        if not run.done():
            await asyncio.wait_for(run, 1)


@pytest.mark.asyncio
async def test_android_worker_restarts_after_prestart_handler_cancellation(listener, monkeypatch):
    import android_bridge as bridge
    accepted, pool = listener
    proxy.asyncio.force_ephemeral = True
    monkeypatch.setattr(bridge, '_ready', threading.Event())
    for key in ('_thread', '_loop', '_stop_event', '_gateway'):
        monkeypatch.setattr(bridge, key, None)
    for key in ('_routes', '_data_directory'):
        monkeypatch.setattr(bridge, key, None)
    monkeypatch.setattr(bridge, '_active', False)
    async def quiet_observer(secret):await asyncio.Future()
    monkeypatch.setattr(bridge, '_check_telegram', quiet_observer)
    try:
        for _ in range(3):
            await asyncio.to_thread(bridge.start, '22' * 16, True, False, None,
                                    json.dumps({'own_ip': True, 'telegram_relay': False}))
            assert bridge.is_running()
            port = proxy._server_instance.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            try:
                # Stop can race the accepted handler's first coroutine step.
                await asyncio.wait_for(asyncio.to_thread(bridge.stop), 1)
                assert await asyncio.wait_for(reader.read(), .2) == b''
                assert bridge._thread is None and not bridge.is_running()
                assert proxy._server_instance is None and pool.closed
                assert not proxy._client_tasks and not proxy._client_writers
            finally:
                writer.close()
                await writer.wait_closed()
    finally:
        for writer in accepted:writer.transport.abort()
        if bridge._thread is not None:await asyncio.to_thread(bridge.stop)


@pytest.mark.asyncio
async def test_listener_rebind_preserves_accepted_clients(listener, monkeypatch):
    accepted, pool = listener
    proxy.asyncio.cancel_handler = False
    monkeypatch.setattr(proxy, 'LISTENER_RESTART_DELAY', .01)
    monkeypatch.setattr(proxy, 'LISTENER_CHECK_INTERVAL', .01)
    stop = asyncio.Event()
    run = asyncio.create_task(proxy._run(stop))
    clients = []
    try:
        async with asyncio.timeout(1):
            while proxy._server_instance is None:await asyncio.sleep(0)
        original = proxy._server_instance
        port = original.sockets[0].getsockname()[1]
        # Rebind the same actual TCP port, not a fresh ephemeral listener.
        monkeypatch.setattr(proxy_config, 'port', port)
        clients.append(await asyncio.open_connection('127.0.0.1', port))
        async with asyncio.timeout(1):
            while not accepted or not proxy._client_tasks:await asyncio.sleep(0)
        original.close()
        async with asyncio.timeout(.4):
            while proxy._server_instance is original:await asyncio.sleep(.001)
        assert not accepted[0].transport.is_closing()
        assert not clients[0][0].at_eof()
        clients.append(await asyncio.open_connection('127.0.0.1', port))
        async with asyncio.timeout(1):
            while len(accepted) != 2:await asyncio.sleep(0)
        stop.set()
        await asyncio.wait_for(asyncio.shield(run), .4)
        for reader, _ in clients:
            assert await asyncio.wait_for(reader.read(), .2) == b''
        await asyncio.wait_for(original.wait_closed(), .2)
        assert pool.closed and proxy._server_instance is None
        assert not proxy._client_tasks and not proxy._client_writers
    finally:
        for native in accepted:native.transport.abort()
        stop.set()
        for _, writer in clients:
            writer.close()
            await writer.wait_closed()
        if not run.done():await asyncio.wait_for(run, 1)
