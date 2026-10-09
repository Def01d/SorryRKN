"""Direct Telegram endpoint discovery and bounded connection races."""
import asyncio
import struct
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from doh import Resolver
from proxy.config import proxy_config
from proxy.pool import _WsPool
from proxy.telegram_endpoints import TelegramEndpoints, websocket_dc


@pytest.mark.asyncio
async def test_endpoint_lookup_uses_verified_doh_names_and_all_addresses():
    requests = []

    async def handle(request):
        requests.append(request)
        query = request.content
        records = b''.join(b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + ip
                           for ip in (b'\x95\x9a\xa7\x63', b'\x95\x9a\xa7\xdc'))
        answer = query[:2] + struct.pack('!5H', 0x8180, 1, 2, 0, 0) + query[12:] + records
        return httpx.Response(200, content=answer)

    endpoints = TelegramEndpoints()
    endpoints.resolver = Resolver(None, httpx.MockTransport(handle))
    try:
        assert await endpoints.addresses('kws2.web.telegram.org', '149.154.167.220') == [
            '149.154.167.99', '149.154.167.220']
        assert all(request.url.host in ('8.8.8.8', '1.1.1.1', '9.9.9.9') for request in requests)
        assert all(request.extensions['sni_hostname'] == request.headers['host'] for request in requests)
    finally:
        await endpoints.close()


@pytest.mark.asyncio
async def test_dns_failure_uses_only_explicit_pinned_ip_and_unknown_dc_is_not_guessed():
    endpoints = TelegramEndpoints()
    endpoints.resolver = SimpleNamespace(resolve=AsyncMock(return_value=None),
        last_addresses={}, close=AsyncMock())
    assert await endpoints.addresses('kws2.web.telegram.org', '149.154.167.220') == ['149.154.167.220']
    assert await endpoints.addresses('kws5.web.telegram.org') == []
    assert await endpoints.addresses('kws5.web.telegram.org', 'relay.example') == []
    assert [websocket_dc(dc) for dc in (1, 2, 3, 4, 5, 203, 201, 202, 6)] == [1, 2, 3, 4, 5, None, None, None, None]
    await endpoints.close()


@pytest.mark.asyncio
async def test_pool_reaches_official_dc_without_preconfigured_ip(monkeypatch):
    pool = _WsPool()
    ws = Mock(_closed=False, reader=SimpleNamespace(at_eof=lambda:False, exception=lambda:None),
        writer=SimpleNamespace(transport=SimpleNamespace(is_closing=lambda:False), close=lambda:None),
        close=AsyncMock())
    calls = []

    async def connect(*args):
        calls.append(args)
        return ws

    monkeypatch.setattr(proxy_config, 'dc_redirects', {})
    monkeypatch.setattr(proxy_config, 'pool_size', 1)
    monkeypatch.setattr(pool, '_connect_one', connect)
    try:
        assert await pool.get(5, True) is ws
        assert calls == [(None, ['kws5-1.web.telegram.org', 'kws5.web.telegram.org'], '/apiws')]
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_cdn_dc_never_resolves_regular_dc_websocket_address(monkeypatch):
    pool = _WsPool()
    monkeypatch.setattr(proxy_config, 'dc_redirects', {2: '149.154.167.220', 4: '149.154.167.220'})
    dial = AsyncMock()
    monkeypatch.setattr(pool, '_connect_one', dial)
    try:
        assert await pool.get(203, True) is None
        assert await pool.get(201, True) is None
        assert await pool.get(202, True) is None
        dial.assert_not_awaited()
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_explicit_nonstandard_dc_pin_does_not_discover_another_dc_address(monkeypatch):
    pool = _WsPool()
    lookup = AsyncMock()
    dial = AsyncMock(return_value=SimpleNamespace(close=AsyncMock()))
    monkeypatch.setattr(pool._endpoints, 'addresses', lookup)
    monkeypatch.setattr('proxy.pool.RawWebSocket.connect', dial)
    try:
        assert await pool._connect_one('91.105.192.100', ['kws2.web.telegram.org'], resolve_dns=False) is not None
        lookup.assert_not_awaited()
        assert dial.call_args.args == ('91.105.192.100', 'kws2.web.telegram.org')
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_silent_first_address_does_not_hide_healthy_backup_and_loser_is_cancelled(monkeypatch):
    pool = _WsPool()
    loser_closed = asyncio.Event()
    winner = SimpleNamespace(close=AsyncMock())
    monkeypatch.setattr(pool._endpoints, 'addresses', AsyncMock(return_value=['149.154.167.99', '149.154.167.220']))

    async def connect(address, domain, **kwargs):
        assert domain == 'kws2-1.web.telegram.org'
        if address == '149.154.167.99':
            try:
                await asyncio.Future()
            finally:
                loser_closed.set()
        return winner

    monkeypatch.setattr('proxy.pool.RawWebSocket.connect', connect)
    try:
        assert await asyncio.wait_for(pool._connect_one(None, ['kws2-1.web.telegram.org']), .6) is winner
        assert loser_closed.is_set()
        winner.close.assert_not_awaited()
    finally:
        await pool.close()


@pytest.mark.asyncio
async def test_local_dpi_route_always_uses_verified_official_sni(monkeypatch):
    pool = _WsPool()
    pool.try_fronting_first = True
    monkeypatch.setattr(proxy_config, 'telegram_dpi_port', 1084, raising=False)
    monkeypatch.setattr(pool._endpoints, 'addresses', AsyncMock(return_value=['149.154.167.99']))
    dial = AsyncMock(return_value=SimpleNamespace(close=AsyncMock()))
    monkeypatch.setattr('proxy.pool.RawWebSocket.connect', dial)
    try:
        assert await pool._connect_one(None, ['kws2.web.telegram.org']) is not None
        dial.assert_awaited_once_with('149.154.167.99', 'kws2.web.telegram.org',
                                     timeout=4.0, path='/apiws', sni=None)
    finally:
        await pool.close()
