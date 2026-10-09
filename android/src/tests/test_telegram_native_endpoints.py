"""Direct Telegram TCP alternatives must never duplicate an MTProto session."""
import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from proxy import bridge
from proxy.config import proxy_config
from proxy import route_diagnostics


class AsyncioWithDial:
    def __init__(self, dial):
        self.open_connection = dial

    def __getattr__(self, name):
        return getattr(asyncio, name)


@pytest.fixture(autouse=True)
def reset_routes(monkeypatch):
    bridge.reset_tcp_backoff()
    route_diagnostics.reset()
    monkeypatch.setattr(proxy_config, 'fallback_cfproxy', False)
    monkeypatch.setattr(proxy_config, 'cfproxy_worker_domains', [])
    yield
    bridge.reset_tcp_backoff()


async def fallback(dc=2, *, media=False, test=False):
    return await bridge.do_fallback(
        Mock(), Mock(), b'one encrypted init', 'native-endpoint-test',
        dc, test, media, ' media' if media else '', Mock())


@pytest.mark.asyncio
async def test_blocked_443_can_reach_working_official_alternate_port(monkeypatch):
    calls = []
    remote = Mock(drain=AsyncMock(), wait_closed=AsyncMock())

    async def dial(host, port):
        calls.append((host, port))
        if (host, port) == ('149.154.167.51', 5222):
            return Mock(), remote
        raise TimeoutError()

    relay = AsyncMock()
    monkeypatch.setattr(bridge, 'asyncio', AsyncioWithDial(dial))
    monkeypatch.setattr(bridge, '_bridge_tcp_reencrypt', relay)
    assert await fallback(), (
        'Telegram DC2:443 failed but the real fallback never tried the '
        'working official same-DC TCP transport on port 5222')
    assert ('149.154.167.51', 5222) in calls
    remote.write.assert_called_once_with(b'one encrypted init')
    relay.assert_awaited_once()
    assert relay.await_args.args[3] is remote


def test_only_documented_same_dc_bootstrap_endpoints_are_candidates():
    from proxy.native_endpoints import native_tcp_endpoints
    from proxy.utils import DC_DEFAULT_IPS, DC_TEST_IPS

    for dc in range(1, 6):
        endpoints = native_tcp_endpoints(dc)
        assert endpoints[:3] == tuple((DC_DEFAULT_IPS[dc], port)
                                     for port in (443, 5222, 80))
        assert len(endpoints) == (4 if dc == 2 else 3)
    assert native_tcp_endpoints(2)[3] == ('95.161.76.100', 443)
    assert native_tcp_endpoints(203) == ((DC_DEFAULT_IPS[203], 443),)
    for dc, host in DC_TEST_IPS.items():
        assert native_tcp_endpoints(dc, True) == ((host, 443),)
    assert native_tcp_endpoints(201) == ()
    assert native_tcp_endpoints(202) == ()
    assert native_tcp_endpoints(5, True) == ()


@pytest.mark.asyncio
async def test_same_dc_backup_ip_gets_a_chance_when_primary_ip_is_unreachable(monkeypatch):
    calls = []
    remote = Mock(drain=AsyncMock(), wait_closed=AsyncMock())

    async def dial(host, port):
        calls.append((host, port))
        if host == '95.161.76.100':
            return Mock(), remote
        raise TimeoutError()

    monkeypatch.setattr(bridge, 'asyncio', AsyncioWithDial(dial))
    monkeypatch.setattr(bridge, '_bridge_tcp_reencrypt', AsyncMock())
    assert await fallback()
    assert len(calls) == 4
    assert calls[-1] == ('95.161.76.100', 443)
    remote.write.assert_called_once_with(b'one encrypted init')


@pytest.mark.asyncio
async def test_alternative_does_not_wait_for_stalled_443_deadline(monkeypatch):
    calls, cancelled = [], []
    started = asyncio.Event()
    remote = Mock(drain=AsyncMock(), wait_closed=AsyncMock())

    async def dial(host, port):
        endpoint = (host, port)
        calls.append(endpoint)
        if len(calls) == 4:
            started.set()
        if endpoint == ('149.154.167.51', 80):
            await started.wait()
            return Mock(), remote
        try:
            await asyncio.Future()
        finally:
            cancelled.append(endpoint)

    monkeypatch.setattr(bridge, 'asyncio', AsyncioWithDial(dial))
    monkeypatch.setattr(bridge, '_bridge_tcp_reencrypt', AsyncMock())
    monkeypatch.setattr(bridge, 'TCP_CONNECT_TIMEOUT', 1)
    assert await asyncio.wait_for(fallback(), .2)
    assert len(calls) == 4
    assert len(cancelled) == 3
    assert not bridge._tcp_failures
    remote.write.assert_called_once_with(b'one encrypted init')


@pytest.mark.asyncio
async def test_all_unreachable_candidates_share_one_deadline(monkeypatch):
    calls, cancelled = [], []

    async def dial(host, port):
        calls.append((host, port))
        try:
            await asyncio.Future()
        finally:
            cancelled.append((host, port))

    monkeypatch.setattr(bridge, 'asyncio', AsyncioWithDial(dial))
    monkeypatch.setattr(bridge, 'TCP_CONNECT_TIMEOUT', .03)
    started = asyncio.get_running_loop().time()
    assert not await fallback()
    elapsed = asyncio.get_running_loop().time() - started
    assert .02 <= elapsed < .11
    assert len(calls) == len(cancelled) == 4
    assert set(bridge._tcp_failures) == set(calls)
    assert not bridge._tcp_connecting


@pytest.mark.asyncio
async def test_shared_probe_wait_consumes_its_own_common_deadline(monkeypatch):
    started = asyncio.Event()
    calls = []

    async def dial(host, port):
        calls.append((host, port))
        started.set()
        await asyncio.Future()

    monkeypatch.setattr(bridge, 'asyncio', AsyncioWithDial(dial))
    key = ('149.154.167.51', 443)
    loop = asyncio.get_running_loop()
    first = asyncio.create_task(bridge._race_tcp_endpoints((key,), 'first', loop.time() + 1))
    try:
        await started.wait()
        before = loop.time()
        assert await bridge._race_tcp_endpoints((key,), 'waiting', before + .03) is None
        assert .02 <= loop.time() - before < .1
        assert not first.done()
        assert calls == [key]
        assert not bridge._tcp_failures
    finally:
        first.cancel()
        await asyncio.gather(first, return_exceptions=True)
    assert not bridge._tcp_connecting


@pytest.mark.asyncio
async def test_all_successful_losers_close_without_init_or_payload(monkeypatch):
    remotes = []

    async def dial(*endpoint):
        remote = Mock(drain=AsyncMock(), wait_closed=AsyncMock())
        remotes.append(remote)
        return Mock(), remote

    monkeypatch.setattr(bridge, 'asyncio', AsyncioWithDial(dial))
    relay = AsyncMock()
    monkeypatch.setattr(bridge, '_bridge_tcp_reencrypt', relay)
    assert await fallback()
    assert len(remotes) == 4
    winner = relay.await_args.args[3]
    winner.write.assert_called_once_with(b'one encrypted init')
    winner.close.assert_called_once()
    for remote in remotes:
        if remote is not winner:
            remote.write.assert_not_called()
            remote.transport.abort.assert_called_once()


@pytest.mark.asyncio
async def test_init_failure_never_replays_on_successful_alternative(monkeypatch):
    remotes = []

    async def dial(*endpoint):
        remote = Mock(drain=AsyncMock(side_effect=ConnectionResetError()),
                      wait_closed=AsyncMock())
        remotes.append(remote)
        return Mock(), remote

    monkeypatch.setattr(bridge, 'asyncio', AsyncioWithDial(dial))
    relay = AsyncMock()
    monkeypatch.setattr(bridge, '_bridge_tcp_reencrypt', relay)
    assert not await fallback()
    assert len(remotes) == 4
    assert sum(remote.write.call_count for remote in remotes) == 1
    relay.assert_not_awaited()
    assert set(bridge._tcp_failures) == {('149.154.167.51', 443)}
    assert all(remote.close.called or remote.transport.abort.called for remote in remotes)


@pytest.mark.asyncio
async def test_cancel_closes_every_dial_without_poisoning_any_endpoint(monkeypatch):
    started = asyncio.Event()
    calls, cancelled = [], []

    async def dial(host, port):
        calls.append((host, port))
        if len(calls) == 4:
            started.set()
        try:
            await asyncio.Future()
        finally:
            cancelled.append((host, port))

    monkeypatch.setattr(bridge, 'asyncio', AsyncioWithDial(dial))
    request = asyncio.create_task(fallback())
    await asyncio.wait_for(started.wait(), 1)
    request.cancel()
    with pytest.raises(asyncio.CancelledError):
        await request
    assert len(calls) == len(cancelled) == 4
    assert not bridge._tcp_failures
    assert not bridge._tcp_retry_after
    assert not bridge._tcp_connecting
    counts = route_diagnostics.snapshot()['counts']
    assert counts['native_tcp:native_tcp:cancelled'] == 4
    assert 'native_tcp:native_tcp:failure' not in counts


@pytest.mark.asyncio
async def test_cancelled_shared_owner_allows_only_one_new_probe(monkeypatch):
    first_started, second_started, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    calls = []

    async def dial(*endpoint):
        calls.append(endpoint)
        if len(calls) == 1:
            first_started.set()
            await asyncio.Future()
        second_started.set()
        await release.wait()
        return Mock(), Mock(drain=AsyncMock(), wait_closed=AsyncMock())

    async def one():
        return await bridge._tcp_fallback(
            Mock(), Mock(), '149.154.167.51', 443, b'init', 'one', Mock())

    monkeypatch.setattr(bridge, 'asyncio', AsyncioWithDial(dial))
    monkeypatch.setattr(bridge, '_bridge_tcp_reencrypt', AsyncMock())
    first = asyncio.create_task(one())
    followers = []
    try:
        await first_started.wait()
        followers = [asyncio.create_task(one()) for _ in range(8)]
        # Let every follower enter its real shared Future wait.
        for _ in range(5):
            await asyncio.sleep(0)
        first.cancel()
        await asyncio.gather(first, return_exceptions=True)
        await second_started.wait()
        for _ in range(5):
            await asyncio.sleep(0)
        assert len(calls) == 2
        assert all(not follower.done() for follower in followers)
        release.set()
        assert await asyncio.gather(*followers) == [True] * 8
        assert len(calls) == 9
    finally:
        for task in (first, *followers):
            task.cancel()
        await asyncio.gather(first, *followers, return_exceptions=True)
    assert not bridge._tcp_failures
    assert not bridge._tcp_connecting


@pytest.mark.asyncio
async def test_twelve_simultaneous_media_clients_keep_independent_single_relays(monkeypatch):
    started, release = asyncio.Event(), asyncio.Event()
    remotes = []

    async def dial(*endpoint):
        remote = Mock(drain=AsyncMock(), wait_closed=AsyncMock())
        remotes.append(remote)
        if len(remotes) == 4:
            started.set()
        await release.wait()
        return Mock(), remote

    async def relay(reader, writer, rr, rw, label, ctx, **kwargs):
        assert kwargs == {'is_media': True, 'dc': 2}
        rw.write(b'independent encrypted media payload')

    relays = AsyncMock(side_effect=relay)
    monkeypatch.setattr(bridge, 'asyncio', AsyncioWithDial(dial))
    monkeypatch.setattr(bridge, '_bridge_tcp_reencrypt', relays)
    clients = [asyncio.create_task(fallback(media=True)) for _ in range(12)]
    try:
        await asyncio.wait_for(started.wait(), 1)
        for _ in range(5):
            await asyncio.sleep(0)
        assert len(remotes) == 4  # One unproven probe per endpoint, not per client.
        release.set()
        assert await asyncio.wait_for(asyncio.gather(*clients), 2) == [True] * 12
    finally:
        for task in clients:
            task.cancel()
        await asyncio.gather(*clients, return_exceptions=True)
    winners = [call.args[3] for call in relays.await_args_list]
    assert len({id(remote) for remote in winners}) == 12
    assert len({id(call.args[5]) for call in relays.await_args_list}) == 12
    assert sum(remote.write.call_count for remote in remotes) == 24
    for remote in remotes:
        if any(remote is winner for winner in winners):
            assert [call.args[0] for call in remote.write.call_args_list] == [
                b'one encrypted init', b'independent encrypted media payload']
            remote.close.assert_called_once()
        else:
            remote.write.assert_not_called()
            remote.transport.abort.assert_called_once()
    assert not bridge._tcp_connecting


@pytest.mark.asyncio
async def test_cooldown_is_per_endpoint_and_dc4_never_borrows_dc2(monkeypatch):
    calls = []
    bridge._tcp_retry_after[('149.154.167.51', 443)] = bridge.time.monotonic() + 30

    async def dial(host, port):
        calls.append((host, port))
        if host == '149.154.167.91':
            raise TimeoutError()
        return Mock(), Mock(drain=AsyncMock(), wait_closed=AsyncMock())

    monkeypatch.setattr(bridge, 'asyncio', AsyncioWithDial(dial))
    monkeypatch.setattr(bridge, '_bridge_tcp_reencrypt', AsyncMock())
    assert not await fallback(4)
    assert calls == [('149.154.167.91', port) for port in (443, 5222, 80)]
    calls.clear()
    assert await fallback(2)
    assert ('149.154.167.51', 443) not in calls
    assert ('149.154.167.51', 5222) in calls
    assert set(bridge._tcp_failures) == {('149.154.167.91', port) for port in (443, 5222, 80)}


@pytest.mark.asyncio
async def test_cancel_during_race_cleanup_closes_selected_unadopted_socket(monkeypatch):
    cleanup = asyncio.Event()
    remote = Mock()

    async def open_endpoint(host, port, label, deadline):
        if port == 443:
            return (host, port), Mock(), remote
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            cleanup.set()
            # Model a pending connect's asynchronous cancellation cleanup.
            await asyncio.Future()

    monkeypatch.setattr(bridge, '_open_tcp_endpoint', open_endpoint)
    request = asyncio.create_task(fallback())
    await asyncio.wait_for(cleanup.wait(), 1)
    request.cancel()
    with pytest.raises(asyncio.CancelledError):
        await request
    remote.write.assert_not_called()
    # Two port443 candidates complete, but both refer to this test writer.
    assert remote.transport.abort.call_count == 2


@pytest.mark.asyncio
async def test_tcp_race_enforces_candidate_bound_even_for_oversized_input(monkeypatch):
    calls = []

    async def dial(host, port):
        calls.append((host, port))
        raise TimeoutError()

    monkeypatch.setattr(bridge, 'asyncio', AsyncioWithDial(dial))
    endpoints = [('192.0.2.' + str(index), 443) for index in range(1, 10)]
    result = await bridge._race_tcp_endpoints(
        endpoints, 'bounded', asyncio.get_running_loop().time() + 1)
    assert result is None
    assert calls == endpoints[:4]
