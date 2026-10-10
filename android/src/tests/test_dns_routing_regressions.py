"""Provider outages, wrong DNS answers, ECH and missing service-list regressions."""
import asyncio
import struct

import httpx
import pytest

from doh import Resolver, valid_answer
from gateway import Gateway, UDPAssociation, encode_address
from geo_route import GeoRoutes
from smart_dns import COMSS, SmartDNS
from traffic import Routes
from user_rules import DomainRules
from test_doh import QUERY, answer
from test_extra_sites import FakeDNS, query, setup_routes
from test_traffic import hello


@pytest.mark.asyncio
async def test_comss_bootstrap_addresses_are_distinct_and_fail_over():
    attempted = []
    async def handle(request):
        attempted.append(request.url.host)
        assert request.headers['host'] == request.extensions['sni_hostname'] == 'dns.comss.one'
        if request.url.host != COMSS[-1][2]:
            return httpx.Response(503)
        return httpx.Response(200, content=answer(request.content))
    resolver = Resolver(None, httpx.MockTransport(handle), providers=COMSS)
    try:
        assert await resolver.query(QUERY) == answer()
        assert set(attempted) == {entry[2] for entry in COMSS}
        assert resolver.preferred == COMSS[-1]
    finally:
        await resolver.close()


@pytest.mark.asyncio
async def test_silent_preferred_dns_does_not_hold_up_healthy_provider():
    cancelled = asyncio.Event()
    async def handle(request):
        if request.url.host == COMSS[0][2]:
            try:
                await asyncio.Future()
            finally:
                cancelled.set()
        return httpx.Response(200, content=answer(request.content))
    resolver = Resolver(None, httpx.MockTransport(handle), providers=COMSS)
    resolver.preferred = COMSS[0]
    try:
        assert await asyncio.wait_for(resolver.query(QUERY), .8) == answer()
        assert cancelled.is_set()
    finally:
        await resolver.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('bad', [
    answer()[:-1],
    answer()[:13] + b'bad' + answer()[16:],
    answer()[:12] + b'\xc0\x0c' + answer()[14:],
    answer() + b'trailing',
])
async def test_invalid_positive_dns_response_never_wins_provider_race(bad):
    async def handle(request):
        return httpx.Response(200, content=bad if request.url.host == '8.8.8.8' else answer(request.content))
    resolver = Resolver(None, httpx.MockTransport(handle))
    try:
        assert not valid_answer(QUERY, bad)
        assert await resolver.query(QUERY) == answer()
        assert resolver.preferred[2] != '8.8.8.8'
    finally:
        await resolver.close()


@pytest.mark.asyncio
async def test_only_enabled_service_https_hints_are_suppressed(tmp_path):
    setup_routes(tmp_path)
    routes = Routes(tmp_path, {'youtube': 1080, 'discord': 1083, 'instagram': 1084,
                               'direct_domains': ['private.youtube.com'], 'builtin_extras': False})
    normal = FakeDNS()
    resolver = SmartDNS(normal=normal, rules=routes.rules, own_ip=True, protected=routes.protected)
    try:
        for host in ('r1.googlevideo.com', 'gateway.discord.gg', 'www.instagram.com'):
            for kind in (64, 65):
                response = await resolver.query(query(host, kind))
                assert struct.unpack_from('!H', response, 6)[0] == 0
        assert normal.calls == []
        for host in ('private.youtube.com', 'cloudflare-ech.com', 'example.com', 'chatgpt.com'):
            assert await resolver.query(query(host, 65))
        # Native DPI supports IPv6; suppressing public AAAA globally would break
        # otherwise working direct and IPv6-only paths.
        assert await resolver.query(query('www.youtube.com', 28))
        assert normal.calls == ['private.youtube.com', 'cloudflare-ech.com', 'example.com', 'chatgpt.com', 'www.youtube.com']
    finally:
        await resolver.close()


def test_service_routes_do_not_depend_on_downloaded_hostlist_completeness(tmp_path):
    (tmp_path / 'hosts.txt').write_text('unrelated.example\n')
    (tmp_path / 'exclude.txt').write_text('private.discord.gg\n')
    routes = Routes(tmp_path, {'youtube': 1080, 'discord': 1083})
    for host in ('www.youtube.com', 'r1.googlevideo.com', 'youtubei.googleapis.com'):
        assert routes.group(host) == 'youtube'
    for host in ('gateway.discord.gg', 'cdn.discordapp.com', 'media.discordapp.net', 'dis.gd'):
        assert routes.group(host) == 'discord'
    for host in ('private.discord.gg', 'not-discord.example', 'discord.com.evil.example', 'cloudflare-ech.com'):
        assert routes.group(host) == 'direct'
    assert routes.group('GATEWAY.DISCORD.GG.') == 'discord'


@pytest.mark.asyncio
async def test_gateway_dns_failure_returns_servfail_without_claiming_success():
    gateway = Gateway()
    gateway.resolver = FakeDNS(working=False)
    response = await gateway.dns(query('chatgpt.com'))
    assert response[:2] == query('chatgpt.com')[:2]
    assert response[2] & 0x80 and response[3] & 15 == 2
    assert gateway.stats['dns_ok'] == 0 and gateway.stats['dns_failed'] == 1
    assert await gateway.dns(b'\0' * 11) is None


@pytest.mark.asyncio
async def test_geo_route_tries_third_address_without_replaying_application_data(monkeypatch):
    attempts = []
    class Writer:
        def __init__(self): self.sent = []
        def write(self, value): self.sent.append(value)
        async def drain(self): pass
        def close(self): pass
    writer = Writer()
    reader = asyncio.StreamReader()
    reader.feed_data(b'\x16\x03\x03\0\x01\x02')
    async def connect(address, port):
        attempts.append(address)
        if address != '8.8.4.4': raise OSError('route unavailable')
        return reader, writer
    monkeypatch.setattr('geo_route.asyncio.open_connection', connect)
    stats = dict(geo_attempts=0, geo_retries=0, geo_failures=0, tx_bytes=0)
    routes = GeoRoutes(stats)
    payload = hello('chatgpt.com')
    _, _, reply = await routes.connect('chatgpt.com', ['1.1.1.1', '8.8.8.8', '8.8.4.4'],
                                       443, payload, 1, lambda host: None)
    assert attempts == ['1.1.1.1', '8.8.8.8', '8.8.4.4']
    assert writer.sent == [payload] and reply == b'\x16\x03\x03\0\x01\x02'
    assert stats['geo_attempts'] == 3 and stats['geo_retries'] == 2


def test_udp_dns_memory_ignores_unrelated_records_and_follows_cname():
    rules = DomainRules(direct=['direct.example'])
    packet = query('direct.example')
    alias = b'\x03cdn\x07example\0'
    unrelated = b'\x09unrelated\x07example\0'
    cname = b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 120, len(alias)) + alias
    address = alias + struct.pack('!HHIH', 1, 1, 120, 4) + bytes([8,8,4,4])
    extra = unrelated + struct.pack('!HHIH', 1, 1, 120, 4) + bytes([8,8,8,8])
    response = packet[:2] + struct.pack('!5H', 0x8180, 1, 3, 0, 0) + packet[12:] + cname + address + extra
    rules.remember('direct.example', packet, response)
    assert rules.direct_address('8.8.4.4')
    assert not rules.direct_address('8.8.8.8')


@pytest.mark.asyncio
async def test_udp443_blocks_cached_ip_quic_preserving_voice_and_direct(tmp_path):
    setup_routes(tmp_path)
    gateway = Gateway(directory=tmp_path, routes={'discord': 1083})
    rules = gateway.routes.rules
    packet = query('gateway.discord.gg')
    rules.remember('gateway.discord.gg', packet, answer(packet), protected=True)
    address = '8.8.4.4'
    association = UDPAssociation(gateway)
    forwarded = []
    async def forward(host, port, payload):
        forwarded.append((host, payload))
    association.forward = forward
    quic = b'\xc0\x00\x00\x00\x01\x00\x00'
    rtp, dtls, stun = b'\x80\x78voice', b'\x16\xfe\xfdvoice', b'\x00\x01stun'
    turn=b'\x40\x01\0\x05voice'
    padded_turn=turn+b'\0\0\0'
    try:
        for payload in (quic, rtp, dtls, stun, turn, padded_turn):
            association.datagram_received(b'\0\0\0' + encode_address(address,443) + payload, ('127.0.0.1',6000))
        association.datagram_received(b'\0\0\0' + encode_address('8.8.8.8',443) + quic, ('127.0.0.1',6000))
        await asyncio.gather(*association.tasks)
        assert forwarded == [(address,rtp),(address,dtls),(address,stun),(address,turn),(address,padded_turn)]
        assert gateway.stats['quic_blocked'] == 2
        # A direct exception learned later wins even on a shared CDN address.
        rules.direct = ('direct.example',)
        q = query('direct.example')
        rules.remember('direct.example', q, answer(q))
        association.datagram_received(b'\0\0\0' + encode_address(address,443) + quic, ('127.0.0.1',6000))
        await asyncio.gather(*association.tasks)
        assert forwarded[-1] == (address,quic)
    finally:
        await association.close()
