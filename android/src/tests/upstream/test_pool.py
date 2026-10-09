import asyncio
import time
import unittest

from collections import deque
from types import SimpleNamespace
from unittest import mock

from proxy.config import proxy_config
from proxy.pool import _WsPool
from proxy.raw_websocket import RawWebSocket, WsHandshakeError
from proxy.utils import ws_domains


class _StopRotation(Exception):
    pass


def _open_ws():
    transport = SimpleNamespace(is_closing=lambda: False)
    writer = mock.Mock(transport=transport, drain=mock.AsyncMock(),
                       wait_closed=mock.AsyncMock())
    return RawWebSocket(asyncio.StreamReader(), writer)


class WsPoolRotationTest(unittest.IsolatedAsyncioTestCase):
    async def test_warmup_preserves_media_ws_with_or_without_h2(self):
        for cf, secure, opted_out, media in [(True, True, False, True),
                                            (False, True, False, True),
                                            (True, False, False, True),
                                            (True, True, True, True)]:
            with self.subTest(cf=cf, secure=secure, opted_out=opted_out), \
                    mock.patch.object(proxy_config, 'dc_redirects', {2: '149.154.167.220'}), \
                    mock.patch.object(proxy_config, 'fallback_cfproxy', cf), \
                    mock.patch.object(proxy_config, 'disable_secure', not secure), \
                    mock.patch.object(proxy_config, 'cfproxy_h2_media', not opted_out), \
                    mock.patch.object(proxy_config, 'force_test_dc', False):
                pool = _WsPool()
                with mock.patch.object(pool, '_schedule_refill') as refill:
                    await pool.warmup()
                keys = [call.args[0] for call in refill.call_args_list]
                self.assertIn((2, False, False), keys)
                self.assertEqual((2, True, False) in keys, media)

    async def test_refills_partially_populated_bucket(self):
        pool = _WsPool()
        key = (2, False, False)
        pool._idle[key] = deque([
            (_open_ws(), time.monotonic()),
            (_open_ws(), time.monotonic()),
        ])
        async def stop_after_one_iteration(_delay):
            raise _StopRotation

        with mock.patch.object(proxy_config, 'pool_size', 4):
            with mock.patch(
                    'proxy.pool.asyncio.sleep',
                    side_effect=stop_after_one_iteration):
                with mock.patch.object(
                        pool, '_schedule_refill') as schedule_refill:
                    with self.assertRaises(_StopRotation):
                        await pool._rotate(
                            key, '149.154.167.220', ['example.com'])

        schedule_refill.assert_called_once_with(
            key, '149.154.167.220', ['example.com'])


class WsPoolTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.pool = _WsPool()
        self.key = (2, False, False)
        self.pool.WS_POOL_CHECK_INTERVAL = .01
        self.pool.ACQUIRE_TIMEOUT = .1
        endpoints = mock.patch.object(self.pool._endpoints, 'addresses',
            return_value=[])
        endpoints.start()
        self.addCleanup(endpoints.stop)
        for name, value in [('dc_redirects', {2: '192.0.2.1'}),
                            ('pool_size', 1), ('force_test_dc', False)]:
            patcher = mock.patch.object(proxy_config, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addAsyncCleanup(self.pool.close)

    async def wait_for(self, predicate):
        async def wait():
            while not predicate():
                await asyncio.sleep(.001)
        await asyncio.wait_for(wait(), 1)

    async def test_regular_sessions_never_use_media_domain(self):
        for dc in (2, 4):
            with self.subTest(dc=dc), mock.patch(
                    'proxy.pool.RawWebSocket.connect',
                    side_effect=WsHandshakeError(302, 'redirect')) as connect:
                self.assertIsNone(await self.pool._connect_one('149.154.167.220', ws_domains(dc, False)))
                self.assertEqual([call.args[1] for call in connect.call_args_list],
                                 [f'kws{dc}.web.telegram.org'] * 2)

    async def test_media_tries_regular_domain_without_waiting_for_stalled_media_alias(self):
        ready = _open_ws()

        async def connect(address, domain, **kwargs):
            if domain == 'kws2-1.web.telegram.org':
                await asyncio.Future()
            return ready

        with mock.patch('proxy.pool.RawWebSocket.connect', side_effect=connect):
            self.assertIs(await asyncio.wait_for(
                self.pool._connect_one('149.154.167.220', ws_domains(2, True)), .2), ready)

    async def test_concurrent_preference_change_does_not_skip_fronting(self):
        ws = _open_ws()

        async def connect(*args, **kwargs):
            if kwargs['sni'] is None:
                self.pool.try_fronting_first = True
                raise asyncio.TimeoutError()
            return ws

        with mock.patch('proxy.pool.RawWebSocket.connect', side_effect=connect) as dial:
            self.assertIs(await self.pool._connect_one('149.154.167.220', ws_domains(2, False)), ws)
        self.assertEqual(dial.await_count, 2)

    async def test_unresponsive_pool_has_bounded_wait_and_one_shared_refill(self):
        started = asyncio.Event()

        async def connect(*args):
            started.set()
            await asyncio.Future()

        with mock.patch.object(self.pool, '_connect_one', side_effect=connect) as dial:
            results = await asyncio.gather(*(self.pool.get(2, False) for _ in range(10)))
            self.assertEqual(results, [None] * 10)
            await asyncio.wait_for(started.wait(), 1)
            self.assertEqual(dial.await_count, 1)
            await self.pool.close()

    async def test_cold_pool_waits_for_healthy_direct_connection(self):
        ready = _open_ws()
        with mock.patch.object(self.pool, '_connect_one', return_value=ready):
            self.assertIs(await self.pool.get(2, False), ready)

    async def test_burst_larger_than_pool_gets_distinct_direct_connections(self):
        made = []

        async def connect(*args):
            await asyncio.sleep(.005)
            ws = _open_ws()
            made.append(ws)
            return ws

        with mock.patch.object(proxy_config, 'pool_size', 2), \
                mock.patch.object(self.pool, '_connect_one', side_effect=connect):
            result = await asyncio.gather(*(self.pool.get(2, True) for _ in range(8)))
        self.assertEqual(len({id(ws) for ws in result if ws is not None}), 8)
        self.assertTrue(all(ws in made for ws in result))

    async def test_healthy_burst_extends_past_three_seconds_while_refills_progress(self):
        self.pool.ACQUIRE_TIMEOUT = 3.0
        self.pool.HEALTHY_ACQUIRE_TIMEOUT = 10.0

        async def connect(*args):
            await asyncio.sleep(.85)
            return _open_ws()

        with mock.patch.object(proxy_config, 'pool_size', 2), \
                mock.patch.object(self.pool, '_connect_one', side_effect=connect):
            started = time.monotonic()
            results = await asyncio.gather(*(self.pool.get(2, False) for _ in range(8)))
            elapsed = time.monotonic() - started
        self.assertEqual(len({id(ws) for ws in results if ws is not None}), 8)
        self.assertGreater(elapsed, 3.0)
        self.assertLess(elapsed, 6.0)

    async def test_blocked_pool_still_reaches_fallback_after_three_seconds(self):
        self.pool.ACQUIRE_TIMEOUT = 3.0
        self.pool.HEALTHY_ACQUIRE_TIMEOUT = 10.0

        async def connect(*args):
            await asyncio.Future()

        with mock.patch.object(self.pool, '_connect_one', side_effect=connect):
            started = time.monotonic()
            self.assertIsNone(await self.pool.get(2, False))
            elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 2.9)
        self.assertLess(elapsed, 4.0)

    async def test_refill_progress_for_chat_does_not_extend_blocked_media_wait(self):
        self.pool.MEDIA_ACQUIRE_TIMEOUT = .1
        async def connect(target, domains, *args):
            if '-1.' in domains[0]:
                await asyncio.Future()
            await asyncio.sleep(.025)
            return _open_ws()

        with mock.patch.object(self.pool, '_connect_one', side_effect=connect):
            chats = [asyncio.create_task(self.pool.get(2, False)) for _ in range(8)]
            started = time.monotonic()
            self.assertIsNone(await self.pool.get(2, True))
            self.assertLess(time.monotonic() - started, .18)
            self.assertTrue(any(not task.done() for task in chats))
            self.assertTrue(all(await asyncio.gather(*chats)))

    async def test_continuous_healthy_progress_still_obeys_total_wait_cap(self):
        self.pool.ACQUIRE_TIMEOUT = .1
        self.pool.HEALTHY_ACQUIRE_TIMEOUT = .2

        async def connect(*args):
            await asyncio.sleep(.03)
            return _open_ws()

        with mock.patch.object(self.pool, '_connect_one', side_effect=connect):
            started = time.monotonic()
            results = await asyncio.gather(*(self.pool.get(2, True) for _ in range(16)))
            elapsed = time.monotonic() - started
        self.assertIn(None, results)
        self.assertGreater(sum(ws is not None for ws in results), 3)
        self.assertGreaterEqual(elapsed, .19)
        self.assertLess(elapsed, .3)

    async def test_first_media_connection_retains_ten_second_setup_budget(self):
        # This is the first success for the key: there is no refill progress
        # which could extend a three-second deadline. Cold media still works.
        self.pool.ACQUIRE_TIMEOUT = 3.0
        self.pool.MEDIA_ACQUIRE_TIMEOUT = 10.0
        self.pool.HEALTHY_ACQUIRE_TIMEOUT = 10.0
        ready = _open_ws()

        async def connect(*args):
            await asyncio.sleep(3.1)
            return ready

        with mock.patch.object(self.pool, '_connect_one', side_effect=connect):
            started = time.monotonic()
            self.assertIs(await self.pool.get(2, True), ready)
            self.assertGreater(time.monotonic() - started, 3.0)

    async def test_dead_media_has_its_own_bounded_setup_budget(self):
        # Scale the protocol's 3:10-second budgets to avoid a ten-second idle
        # test while checking that media is not cut off at the proxy deadline.
        self.pool.ACQUIRE_TIMEOUT = .06
        self.pool.MEDIA_ACQUIRE_TIMEOUT = .2
        self.pool.HEALTHY_ACQUIRE_TIMEOUT = .2

        async def connect(*args):
            await asyncio.Future()

        with mock.patch.object(self.pool, '_connect_one', side_effect=connect):
            started = time.monotonic()
            self.assertIsNone(await self.pool.get(2, True))
            elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, .19)
        self.assertLess(elapsed, .35)

    async def test_cancelling_waiter_does_not_cancel_shared_healthy_refill(self):
        started, release = asyncio.Event(), asyncio.Event()
        ready = _open_ws()

        async def connect(*args):
            started.set()
            await release.wait()
            return ready

        with mock.patch.object(self.pool, '_connect_one', side_effect=connect):
            first = asyncio.create_task(self.pool.get(2, False))
            await started.wait()
            second = asyncio.create_task(self.pool.get(2, False))
            first.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await first
            release.set()
            self.assertIs(await second, ready)

    async def test_shutdown_wakes_waiters_without_connecting_again(self):
        started = asyncio.Event()

        async def connect(*args):
            started.set()
            await asyncio.Future()

        with mock.patch.object(self.pool, '_connect_one', side_effect=connect) as dial:
            client = asyncio.create_task(self.pool.get(2, False))
            await started.wait()
            await self.pool.close()
            self.assertIsNone(await asyncio.wait_for(client, .05))
            self.assertEqual(dial.await_count, 1)
            self.assertFalse(self.pool._refilling)

    async def test_empty_pool_recovers_in_background_after_backoff(self):
        ws = _open_ws()
        self.pool.REFILL_BACKOFF_INITIAL = .02
        with mock.patch.object(self.pool, '_connect_one',
                               side_effect=[None, ws]) as dial:
            self.assertIsNone(await self.pool.get(2, False))
            await self.wait_for(lambda: self.key in self.pool._refill_after)
            self.assertEqual(dial.await_count, 1)
            # No new client requests are needed to resume refilling.
            await self.wait_for(lambda: bool(self.pool._idle[self.key]))
            self.assertEqual(dial.await_count, 2)
            self.assertNotIn(self.key, self.pool._refill_failures)
            await self.pool.close()

    async def test_ready_connection_is_available_before_slower_attempt(self):
        ready = _open_ws()
        slow_started = asyncio.Event()
        calls = 0

        async def connect(*args):
            nonlocal calls
            calls += 1
            if calls == 1:
                slow_started.set()
                await asyncio.Future()
            return ready

        with mock.patch.object(proxy_config, 'pool_size', 2), \
                mock.patch.object(self.pool, '_connect_one', side_effect=connect):
            self.assertIs(await self.pool.get(2, False), ready)
            await asyncio.wait_for(slow_started.wait(), 1)
            self.assertIn(self.key, self.pool._refilling)
            await self.pool.close()

    async def test_stale_connections_are_skipped(self):
        for state in ('expired', 'eof', 'exception', 'closed', 'closing'):
            with self.subTest(state=state):
                stale, good = _open_ws(), _open_ws()
                created = time.monotonic()
                if state == 'expired':
                    created -= self.pool.WS_POOL_MAX_AGE
                elif state == 'eof':
                    stale.reader.feed_eof()
                elif state == 'exception':
                    stale.reader.set_exception(ConnectionResetError())
                elif state == 'closed':
                    stale._closed = True
                else:
                    stale.writer.transport.is_closing = lambda: True
                self.pool._idle[self.key] = deque([(stale, created), (good, time.monotonic())])
                with mock.patch.object(self.pool, '_schedule_refill'):
                    self.assertIs(await self.pool.get(2, False), good)
                await asyncio.sleep(0)

    async def test_hit_does_not_reset_failed_refill_backoff(self):
        self.pool._idle[self.key] = deque([(_open_ws(), time.monotonic())])
        self.pool._refill_failures[self.key] = 3
        self.pool._refill_after[self.key] = time.monotonic() + 60
        with mock.patch.object(self.pool, '_schedule_rotation'):
            self.assertIsNotNone(await self.pool.get(2, False))
        self.assertEqual(self.pool._refill_failures[self.key], 3)
        self.assertFalse(self.pool._refilling)

    async def test_zero_size_and_unconfigured_dc_do_not_connect(self):
        with mock.patch.object(self.pool, '_connect_one') as dial:
            self.assertIsNone(await self.pool.get(6, False))
            with mock.patch.object(proxy_config, 'pool_size', 0):
                await self.pool.warmup()
                self.assertIsNone(await self.pool.get(2, False))
            self.assertFalse(self.pool._rotating)
            self.assertFalse(self.pool._refilling)
            dial.assert_not_called()

    async def test_test_dc_has_separate_pool_and_path(self):
        prod = _open_ws()
        self.pool._idle[self.key] = deque([(prod, time.monotonic())])
        with mock.patch.object(self.pool, '_connect_one', return_value=_open_ws()) as dial:
            self.assertIsNotNone(await self.pool.get(2, False, is_test_dc=True))
            dial.assert_awaited_once_with('192.0.2.1', ['kws2.web.telegram.org'], '/apiws_test')
            self.assertIs(self.pool._idle[self.key][0][0], prod)
            await self.pool.close()

    async def test_close_cancels_refill_and_closes_unclaimed_connections(self):
        ready = _open_ws()
        idle = _open_ws()
        started = asyncio.Event()
        self.pool._idle[self.key] = deque([(idle, time.monotonic())])

        async def connect(*args):
            started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                # Completion raced with shutdown; it must not leak into the pool.
                return ready

        with mock.patch.object(proxy_config, 'pool_size', 2), \
                mock.patch.object(self.pool, '_connect_one', side_effect=connect):
            self.pool._schedule_refill(self.key, '192.0.2.1', ws_domains(2, False))
            await asyncio.wait_for(started.wait(), 1)
            await self.pool.close()
        self.assertFalse(self.pool._idle)
        self.assertFalse(self.pool._rotating)
        self.assertFalse(self.pool._refilling)
        ready.writer.close.assert_called_once()
        idle.writer.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
