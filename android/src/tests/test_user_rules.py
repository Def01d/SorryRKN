import asyncio
import ipaddress
import socket
import struct
import pytest
from user_rules import DomainRules,parse_domains
from smart_dns import SmartDNS
from traffic import Routes
from gateway import Gateway,encode_address,read_address,UDPAssociation,decode_datagram
from test_extra_sites import FakeDNS,query,answer,setup_routes

def test_domain_normalization_and_rejection():
    assert parse_domains(' HTTPS://Example.COM:443/path?q=1\r\n*.example.com\nпример.рф\n api.example.net. ') == ['example.com','xn--e1afmkfd.xn--p1ai','api.example.net']
    for value in ['file:///tmp/x','https://user:password@example.com/','127.0.0.1','[::1]','localhost','example..com','-example.com','example.com & calc.exe','https://example.com:0/','https://example.com:65536/','example.com\n--dpi-desync=fake','x'*32769]:
        with pytest.raises(ValueError):parse_domains(value)
    with pytest.raises(ValueError):parse_domains('\n'.join(f'd{i}.example.com'for i in range(257)))

@pytest.mark.asyncio
async def test_direct_dns_wins_even_for_builtin_geo_and_does_not_suppress_hints():
    rules=DomainRules(['example.com','chatgpt.com'],['chatgpt.com','private.example.com'])
    normal,smart=FakeDNS(),FakeDNS();resolver=SmartDNS(normal=normal,smart=smart,rules=rules)
    try:
        for host in ('chatgpt.com','api.chatgpt.com','private.example.com'):
            for kind in (1,28,64,65):assert await resolver.query(query(host,kind))
            assert await resolver.resolve(host)
        assert not smart.calls
        assert await resolver.query(query('api.example.com',1))
        assert smart.calls==['api.example.com']
        for host in ('evilexample.com','example.com.evil.test'):assert not rules.is_geo(host)
        smart.working=False;count=len(normal.calls)
        assert await resolver.resolve('example.com') is None and len(normal.calls)==count
    finally:await resolver.close()

@pytest.mark.asyncio
async def test_excluded_youtube_uses_direct_socket_and_normal_address(tmp_path):
    setup_routes(tmp_path)
    received=[]
    async def echo(reader,writer):
        try:
            data=await reader.readuntil(b'\r\n\r\n');received.append(data);writer.write(data);await writer.drain()
        finally:writer.close()
    server=await asyncio.start_server(echo,'127.0.0.1',0);port=server.sockets[0].getsockname()[1]
    before=set(Routes.inspect_ports);Routes.inspect_ports.add(port)
    gateway=Gateway(port=0,directory=tmp_path,routes={'youtube':1,'smart_dns':True,'geo_domains':['youtube.com'],'direct_domains':['youtube.com']})
    try:
        await gateway.start()
        calls=[]
        async def normal(host):calls.append(host);return '127.0.0.1'
        async def smart(host):raise AssertionError('excluded resource reached smart DNS')
        gateway.resolver.normal.resolve=normal;gateway.resolver.smart.resolve=smart
        reader,writer=await asyncio.open_connection('127.0.0.1',gateway.port)
        writer.write(b'\x05\x01\0');await writer.drain();assert await reader.readexactly(2)==b'\x05\0'
        # A stale proxy address must be replaced with a fresh normal DNS result.
        writer.write(b'\x05\x01\0'+encode_address('192.0.2.77',port));await writer.drain()
        assert await reader.readexactly(3)==b'\x05\0\0';await read_address(reader)
        data=b'GET / HTTP/1.1\r\nHost: www.youtube.com\r\n\r\n';writer.write(data);await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(len(data)),2)==data
        writer.close();await writer.wait_closed()
        assert calls==['www.youtube.com'] and gateway.stats['direct_tcp']==1 and gateway.stats['youtube_tcp']==gateway.stats['ai_tcp']==0
        assert received==[data]
    finally:
        await gateway.close();server.close();await server.wait_closed();Routes.inspect_ports=before

def test_direct_udp_address_learning_and_ttl(monkeypatch):
    rules=DomainRules(direct=['bank.example.com'])
    q=query('bank.example.com');r=answer(q);rules.remember('bank.example.com',q,r)
    assert rules.direct_address('93.184.216.34') and not rules.direct_address('93.184.216.35')
    rules.remember('other.example.com',q,r)
    monkeypatch.setattr('user_rules.time.monotonic',lambda:10**20)
    assert not rules.direct_address('93.184.216.34')

@pytest.mark.asyncio
async def test_excluded_udp443_is_forwarded_without_global_quic_drop(tmp_path):
    setup_routes(tmp_path)
    gateway=Gateway(directory=tmp_path,routes={'direct_domains':['bank.example.com']})
    rules=gateway.routes.rules;q=query('bank.example.com')
    r=bytearray(answer(q));r[-4:]=ipaddress.ip_address('127.0.0.1').packed;rules.remember('bank.example.com',q,bytes(r))
    association=UDPAssociation(gateway);forwarded=[]
    async def forward(host,port,payload):forwarded.append((host,port,payload))
    association.forward=forward
    association.datagram_received(b'\0\0\0'+encode_address('127.0.0.1',443)+b'QUIC',( '127.0.0.1',6000))
    await asyncio.gather(*association.tasks)
    assert forwarded==[('127.0.0.1',443,b'QUIC')]
    protected_query=query('www.youtube.com')
    protected_reply=bytearray(answer(protected_query));protected_reply[-4:]=ipaddress.ip_address('127.0.0.2').packed
    rules.remember('www.youtube.com',protected_query,bytes(protected_reply),protected=True)
    association.datagram_received(b'\0\0\0'+encode_address('127.0.0.2',443)+b'QUIC',('127.0.0.1',6000))
    assert len(forwarded)==1
    await association.close()
