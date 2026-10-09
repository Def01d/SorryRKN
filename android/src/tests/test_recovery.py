"""Real socket regressions for silent peers, DNS recovery and cancellation."""
import asyncio
import struct
from types import SimpleNamespace
import httpx
import pytest
from doh import Resolver, cache_records
from proxy.raw_websocket import RawWebSocket
from proxy.bridge import bridge_ws_reencrypt
from test_doh import QUERY, answer

@pytest.mark.asyncio
async def test_only_smart_dns_provider_retries_after_transient_failure():
    calls=[]
    async def handle(request):
        calls.append(True)
        return httpx.Response(503) if len(calls)==1 else httpx.Response(200,content=answer(request.content))
    r=Resolver(None,httpx.MockTransport(handle),providers=(('Comss','dns.comss.one','195.133.25.16'),))
    r.preferred=r.providers[0]
    try:
        assert await r.query(QUERY)==answer() and len(calls)==2
        assert r.provider=='Comss'
    finally:await r.close()

@pytest.mark.asyncio
async def test_dns_burst_is_one_lookup_with_correct_ids_and_ttl():
    calls=[];entered=asyncio.Event();release=asyncio.Event()
    async def handle(request):
        calls.append(True);entered.set();await release.wait()
        return httpx.Response(200,content=answer(request.content))
    r=Resolver(None,httpx.MockTransport(handle),providers=(('DNS','dns.google','8.8.8.8'),))
    tasks=[asyncio.create_task(r.query(struct.pack('!H',i)+QUERY[2:]))for i in range(32)]
    try:
        await entered.wait();tasks[0].cancel();release.set()
        values=await asyncio.gather(*tasks,return_exceptions=True)
        assert len(calls)==1 and isinstance(values[0],asyncio.CancelledError)
        assert [int.from_bytes(v[:2],'big')for v in values[1:]]==list(range(1,32))
        stored,expires,wire,records=r.cache[QUERY[2:]]
        r.cache[QUERY[2:]]=(stored-5,expires,wire,records)
        cached=await r.query(QUERY)
        assert len(calls)==1 and cached[:2]==QUERY[:2]
        assert struct.unpack_from('!I',cached,records[0][0])[0]<=55
        r.cache[QUERY[2:]]=(stored,0,wire,records)
        assert await r.query(QUERY)==answer() and len(calls)==2
        assert not r.inflight
    finally:
        for t in tasks:t.cancel()
        await asyncio.gather(*tasks,return_exceptions=True);await r.close()

@pytest.mark.parametrize('bad',[answer(flags=0x8183),answer()[:-2],answer()[:6]+b'\0\0'+answer()[8:]])
def test_dns_failures_are_not_cached(bad):assert cache_records(QUERY,bad)==[]

class Identity:
    def update(self,data):return data

@pytest.mark.asyncio
async def test_telegram_idle_media_peer_without_pong_remains_connected():
    """Some TG frontends carry binary frames but do not answer client PINGs."""
    handlers=set();opcodes=[];server_pong=asyncio.Event()
    async def upstream(reader,writer):
        task=asyncio.current_task();handlers.add(task);ws=RawWebSocket(reader,writer)
        writer.write(ws._build_frame(ws.OP_PING,b'server-check'));await writer.drain()
        try:
            while True:
                opcode,payload,_=await ws._read_frame();opcodes.append(opcode)
                if opcode==ws.OP_CLOSE:break
                if opcode==ws.OP_PONG and payload==b'server-check':server_pong.set()
                if opcode==ws.OP_BINARY:
                    frame=ws._build_frame(ws.OP_BINARY,payload)
                    # Deliver a fragmented, slow media frame while the client is idle.
                    for offset in range(0,len(frame),1024):
                        writer.write(frame[offset:offset+1024]);await writer.drain();await asyncio.sleep(.002)
                # Deliberately never reply to client PING, only binary payloads.
        except (OSError,asyncio.IncompleteReadError):pass
        finally:await ws.close();handlers.discard(task)
    up=await asyncio.start_server(upstream,'127.0.0.1',0)
    async def local(reader,writer):
        task=asyncio.current_task();handlers.add(task)
        rr,rw=await asyncio.open_connection('127.0.0.1',up.sockets[0].getsockname()[1])
        ctx=SimpleNamespace(**{name:Identity()for name in ('clt_dec','clt_enc','tg_dec','tg_enc')})
        try:await bridge_ws_reencrypt(reader,writer,RawWebSocket(rr,rw),'regression',ctx)
        finally:handlers.discard(task)
    app=await asyncio.start_server(local,'127.0.0.1',0)
    reader,writer=await asyncio.open_connection('127.0.0.1',app.sockets[0].getsockname()[1])
    try:
        await asyncio.wait_for(server_pong.wait(),1)
        for payload in (b'photo'*20000,b'voice'*15000,b'circle'*12000):
            await asyncio.sleep(.12)
            writer.write(payload);await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(len(payload)),2)==payload
        assert RawWebSocket.OP_PING not in opcodes
        assert opcodes.count(RawWebSocket.OP_BINARY)>=3
    finally:
        writer.close();await writer.wait_closed();app.close();up.close()
        await app.wait_closed();await up.wait_closed();await asyncio.sleep(.02)
        pending=list(handlers)
        for task in pending:task.cancel()
        await asyncio.gather(*pending,return_exceptions=True)

@pytest.mark.asyncio
async def test_silent_smart_route_closes_tls_attempt_and_refreshes_dns(tmp_path,monkeypatch):
    from gateway import Gateway,encode_address,read_address
    from traffic import Routes
    from test_traffic import hello
    from test_extra_sites import setup_routes
    setup_routes(tmp_path);payload=hello('chatgpt.com');received=[];handlers=set()
    async def silent(reader,writer):
        handlers.add(asyncio.current_task())
        try:
            received.append(await reader.readexactly(len(payload)))
            await reader.read()
        finally:writer.close();await writer.wait_closed();handlers.discard(asyncio.current_task())
    server=await asyncio.start_server(silent,'127.0.0.1',0);port=server.sockets[0].getsockname()[1]
    monkeypatch.setattr(Routes,'inspect_ports',Routes.inspect_ports|{port})
    monkeypatch.setattr('gateway.TLS_FIRST_REPLY_TIMEOUT',.04)
    gateway=Gateway(port=0,directory=tmp_path,routes={'smart_dns':True})
    await gateway.start();invalidated=[]
    async def resolve(host):return '127.0.0.1'
    gateway.resolver.resolve=resolve;gateway.resolver.invalidate=invalidated.append
    reader,writer=await asyncio.open_connection('127.0.0.1',gateway.port)
    try:
        writer.write(b'\x05\x01\0');await writer.drain();assert await reader.readexactly(2)==b'\x05\0'
        writer.write(b'\x05\x01\0'+encode_address('192.0.2.77',port));await writer.drain()
        assert await reader.readexactly(3)==b'\x05\0\0';await read_address(reader)
        writer.write(payload);await writer.drain()
        assert await asyncio.wait_for(reader.read(),.5)==b''
        assert received==[payload]and invalidated==['chatgpt.com']
        assert gateway.stats['relay_failed']==1
    finally:
        writer.close();await writer.wait_closed();await gateway.close()
        server.close();await server.wait_closed();await asyncio.gather(*list(handlers),return_exceptions=True)

@pytest.mark.asyncio
async def test_upstream_eof_releases_relay_with_local_client_still_open():
    from gateway import Gateway
    handlers=set();finished=asyncio.Event()
    async def upstream(reader,writer):
        handlers.add(asyncio.current_task())
        writer.write(b'reply');await writer.drain();writer.write_eof()
        try:await reader.read()
        finally:writer.close();await writer.wait_closed();handlers.discard(asyncio.current_task())
    server=await asyncio.start_server(upstream,'127.0.0.1',0)
    async def local(reader,writer):
        rr,rw=await asyncio.open_connection('127.0.0.1',server.sockets[0].getsockname()[1])
        try:await Gateway.relay(reader,writer,rr,rw)
        finally:
            writer.close();rw.close();await writer.wait_closed();await rw.wait_closed();finished.set()
    app=await asyncio.start_server(local,'127.0.0.1',0)
    reader,writer=await asyncio.open_connection('127.0.0.1',app.sockets[0].getsockname()[1])
    try:
        assert await asyncio.wait_for(reader.read(),.5)==b'reply'
        await asyncio.wait_for(finished.wait(),.5)
    finally:
        writer.close();await writer.wait_closed();app.close();server.close()
        await app.wait_closed();await server.wait_closed();await asyncio.gather(*list(handlers),return_exceptions=True)
