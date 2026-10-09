import asyncio
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch

from proxy import bridge


class TcpFallbackTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        bridge.reset_tcp_backoff()
        self.addCleanup(bridge.reset_tcp_backoff)
        self.key = ('192.0.2.1', 443)
        self.remote = Mock(drain=AsyncMock(), wait_closed=AsyncMock())

    async def fallback(self, dst='192.0.2.1', port=443):
        return await bridge._tcp_fallback(
            Mock(), Mock(), dst, port, b'init', 'test', Mock())

    async def test_failure_backoff_stays_within_thirty_seconds_and_skips_new_connections(self):
        with patch.object(bridge.asyncio, 'open_connection',
                          AsyncMock(side_effect=asyncio.TimeoutError())) as connect:
            for _ in range(9):
                bridge._tcp_retry_after[self.key] = 0
                start = time.monotonic()
                self.assertFalse(await self.fallback())
                remaining = bridge._tcp_retry_after[self.key] - start
                self.assertGreaterEqual(remaining, 30 - .001)
                self.assertLess(remaining, 30 + 1)
                count = connect.await_count
                self.assertFalse(await self.fallback())
                self.assertEqual(connect.await_count, count)
        self.assertFalse(bridge._tcp_connecting)

    async def test_other_ips_and_ports_are_not_blocked(self):
        bridge._tcp_retry_after[self.key] = time.monotonic() + 60
        with patch.object(bridge.asyncio, 'open_connection', AsyncMock(
                return_value=(Mock(), self.remote))) as connect, \
                patch.object(bridge, '_bridge_tcp_reencrypt', AsyncMock()):
            self.assertTrue(await self.fallback('192.0.2.2'))
            self.assertTrue(await self.fallback(port=80))
        self.assertEqual(connect.await_count, 2)

    async def test_success_clears_backoff_and_allows_following_sessions(self):
        bridge._tcp_failures[self.key] = 5
        bridge._tcp_retry_after[self.key] = 0
        with patch.object(bridge.asyncio, 'open_connection', AsyncMock(
                return_value=(Mock(), self.remote))) as connect, \
                patch.object(bridge, '_bridge_tcp_reencrypt', AsyncMock()):
            self.assertTrue(await self.fallback())
            self.assertNotIn(self.key, bridge._tcp_failures)
            self.assertNotIn(self.key, bridge._tcp_retry_after)
            self.assertTrue(await self.fallback())
        self.assertEqual(connect.await_count, 2)

    async def test_concurrent_requests_only_start_one_connection_attempt(self):
        started = asyncio.Event()
        release = asyncio.Event()

        async def connect(*args):
            started.set()
            await release.wait()
            raise ConnectionRefusedError()

        with patch.object(bridge.asyncio, 'open_connection', side_effect=connect) as dial:
            first = asyncio.create_task(self.fallback())
            try:
                await asyncio.wait_for(started.wait(), 1)
                followers = [asyncio.create_task(self.fallback()) for _ in range(8)]
                await asyncio.sleep(0)
                self.assertEqual(dial.await_count, 1)
                self.assertTrue(all(not task.done() for task in followers))
                release.set()
                self.assertFalse(await first)
                self.assertEqual(await asyncio.gather(*followers), [False] * 8)
            finally:
                first.cancel()
                await asyncio.gather(first, return_exceptions=True)

    async def test_healthy_concurrent_media_clients_all_get_their_own_connection(self):
        started, release = asyncio.Event(), asyncio.Event()

        async def connect(*args):
            started.set()
            await release.wait()
            return Mock(), Mock(drain=AsyncMock(), wait_closed=AsyncMock())

        with patch.object(bridge.asyncio, 'open_connection', side_effect=connect) as dial, \
                patch.object(bridge, '_bridge_tcp_reencrypt', AsyncMock()) as relay:
            first = asyncio.create_task(self.fallback())
            await started.wait()
            followers = [asyncio.create_task(self.fallback()) for _ in range(7)]
            await asyncio.sleep(0)
            release.set()
            self.assertEqual(await asyncio.gather(first, *followers), [True] * 8)
            self.assertEqual(dial.await_count, 8)
            self.assertEqual(relay.await_count, 8)
            self.assertEqual(len({id(call.args[3]) for call in relay.call_args_list}), 8)
        self.assertFalse(bridge._tcp_connecting)

    async def test_cancelling_waiter_does_not_cancel_first_connect(self):
        started, release = asyncio.Event(), asyncio.Event()

        async def connect(*args):
            started.set()
            await release.wait()
            return Mock(), self.remote

        with patch.object(bridge.asyncio, 'open_connection', side_effect=connect), \
                patch.object(bridge, '_bridge_tcp_reencrypt', AsyncMock()):
            first = asyncio.create_task(self.fallback())
            await started.wait()
            second = asyncio.create_task(self.fallback())
            await asyncio.sleep(0)
            second.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await second
            release.set()
            self.assertTrue(await first)
        self.assertFalse(bridge._tcp_failures)

    async def test_init_failure_closes_socket_and_enters_backoff(self):
        self.remote.drain.side_effect = ConnectionResetError()
        with patch.object(bridge.asyncio, 'open_connection', AsyncMock(
                return_value=(Mock(), self.remote))), \
                patch.object(bridge, '_bridge_tcp_reencrypt', AsyncMock()) as forward:
            self.assertFalse(await self.fallback())
        self.remote.close.assert_called_once()
        forward.assert_not_awaited()
        self.assertIn(self.key, bridge._tcp_retry_after)

    async def test_cancellation_releases_attempt_without_marking_ip_blocked(self):
        started = asyncio.Event()

        async def drain():
            started.set()
            await asyncio.Future()

        self.remote.drain.side_effect = drain
        with patch.object(bridge.asyncio, 'open_connection', AsyncMock(
                return_value=(Mock(), self.remote))):
            task = asyncio.create_task(self.fallback())
            await asyncio.wait_for(started.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.remote.close.assert_called_once()
        self.assertFalse(bridge._tcp_connecting)
        self.assertFalse(bridge._tcp_failures)


if __name__ == '__main__':
    unittest.main()
