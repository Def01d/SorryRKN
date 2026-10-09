"""Regression: a working pre-0.10 Telegram route must survive a failed DPI path."""
import asyncio
import importlib.machinery
import importlib.util
import os
import time
from unittest.mock import AsyncMock, Mock

import pytest

from proxy.config import proxy_config
from proxy.pool import _WsPool
from proxy.telegram_endpoints import legacy_fronting


@pytest.fixture
def pool_type():
    # For the recorded before/after check, load the exact bytecode extracted
    # from the published APK, with the same controlled network outcomes.
    baseline = os.environ.get('SORRYRKN_POOL_BASELINE')
    if not baseline:
        return _WsPool
    loader = importlib.machinery.SourcelessFileLoader('proxy._published_pool', baseline)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module._WsPool


def opened_ws():
    ws = Mock(_closed=False, close=AsyncMock())
    ws.reader.at_eof.return_value = False
    ws.reader.exception.return_value = None
    ws.writer.transport.is_closing.return_value = False
    return ws


@pytest.mark.asyncio
@pytest.mark.parametrize('dns_stalls', [False, True])
async def test_proxy_ping_has_working_pinned_route_when_dns_or_dpi_fails(monkeypatch, pool_type, dns_stalls):
    pool = pool_type()
    # A shorter laboratory deadline distinguishes routing choices without a
    # five-second sleep. Production uses Android's existing five-second check.
    pool.ACQUIRE_TIMEOUT = .3
    monkeypatch.setattr(proxy_config, 'dc_redirects', {2: '149.154.167.220'})
    monkeypatch.setattr(proxy_config, 'pool_size', 1)
    monkeypatch.setattr(proxy_config, 'telegram_dpi_port', 1084)
    dns_cancelled = asyncio.Event()
    attempts = []
    winner = opened_ws()

    async def discover(domain, pinned=None):
        if dns_stalls:
            try:
                await asyncio.Future()
            finally:
                dns_cancelled.set()
        return ['149.154.167.99', '149.154.167.220']

    async def connect(address, domain, **kwargs):
        attempts.append((address, domain, kwargs.get('sni'), kwargs.get('direct', False)))
        if (address == '149.154.167.220' and kwargs.get('sni') == 'sprinthost.ru'):
            assert kwargs.get('direct'), 'Compatibility route must not depend on the failing local DPI engine'
            return winner
        raise ConnectionResetError('Operator drops the canonical TLS route')

    monkeypatch.setattr(pool._endpoints, 'addresses', discover)
    monkeypatch.setattr('proxy.pool.RawWebSocket.connect', connect)
    try:
        started = time.monotonic()
        assert await pool.get(2, False) is winner, f'Working pinned route was never selected: {attempts}'
        assert time.monotonic() - started < .25
        assert any(row[2] == 'sprinthost.ru' for row in attempts)
        assert all(row[0] in ('149.154.167.99', '149.154.167.220') for row in attempts)
        if dns_stalls:
            assert dns_cancelled.is_set()
    finally:
        await pool.close()
        await winner.close()


@pytest.mark.asyncio
async def test_multiple_successful_losers_cannot_delay_proxy_ping(monkeypatch):
    pool = _WsPool()
    candidates = []
    both_ready = asyncio.Event()
    monkeypatch.setattr(pool._endpoints, 'addresses', AsyncMock(return_value=['149.154.167.99']))

    async def connect(address, domain, **kwargs):
        ws = opened_ws()
        async def slow_close():
            await asyncio.sleep(2)
        ws.close.side_effect = slow_close
        candidates.append(ws)
        if len(candidates) == 2:
            both_ready.set()
        await both_ready.wait()
        return ws

    monkeypatch.setattr('proxy.pool.RawWebSocket.connect', connect)
    try:
        winner = await asyncio.wait_for(pool._connect_one('149.154.167.220',
            ['kws2.web.telegram.org']), .2)
        assert winner in candidates
        assert len(candidates) >= 2
        for ws in candidates:
            if ws is not winner:
                ws.writer.transport.abort.assert_called_once()
                ws.close.assert_not_awaited()
    finally:
        await pool.close()


@pytest.mark.parametrize('address,domain,sni,allowed', [
    ('149.154.167.220', 'kws2.web.telegram.org', 'sprinthost.ru', True),
    ('149.154.167.220', 'kws4-1.web.telegram.org', 'sprinthost.ru', True),
    ('149.154.167.99', 'kws2.web.telegram.org', 'sprinthost.ru', False),
    ('149.154.167.220', 'kws5.web.telegram.org', 'sprinthost.ru', False),
    ('149.154.167.220', 'attacker.example', 'sprinthost.ru', False),
    ('149.154.167.220', 'kws2.web.telegram.org', 'other.example', False),
])
def test_legacy_certificate_policy_is_scoped_to_existing_pinned_route(address, domain, sni, allowed):
    assert legacy_fronting(address, domain, sni) is allowed
