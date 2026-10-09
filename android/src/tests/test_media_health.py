"""Demand-only media recovery over actual local sockets and HTTP/2 packets."""
import asyncio
import contextlib
import struct
import time
from collections import deque
from types import SimpleNamespace
from unittest.mock import Mock
import httpx
import pytest
from proxy import media_health
from proxy.bridge import bridge_ws_reencrypt, _bridge_tcp_reencrypt
from proxy.raw_websocket import RawWebSocket
from proxy.pool import _WsPool
from proxy.config import proxy_config
from proxy.stats import stats
from proxy.cf_h2 import _HttpLane, _HttpChannel, bridge_h2
from proxy.utils import PROTO_TAG_INTERMEDIATE

class Identity:
    def update(self,data):return data

def crypto():return SimpleNamespace(**{key:Identity()for key in ('clt_enc','clt_dec','tg_enc','tg_dec')})

@pytest.fixture
def deadline(monkeypatch):
    monkeypatch.setattr(media_health,'MEDIA_RESPONSE_TIMEOUT',.09)
    monkeypatch.setattr(media_health,'CHECK_INTERVAL',.005)
    monkeypatch.setattr(media_health,'CLOSE_TIMEOUT',.05)

@contextlib.asynccontextmanager
async def websocket_app(mode,is_media=True,**kwargs):
    tasks=set();connections=[];opcodes=[];release=asyncio.Event();n=0
    async def remote(reader,writer):
        nonlocal n
        task=asyncio.current_task();tasks.add(task);n+=1;index=n
        ws=RawWebSocket(reader,writer)
        try:
            while True:
                op,data,_=await ws._read_frame();opcodes.append(op)
                if op==ws.OP_CLOSE:break
                if op!=ws.OP_BINARY:continue
                if mode=='silent' or (mode=='retry' and index==1):continue
                if mode=='backpressure-silent' and data==b'second':continue
                frame=ws._build_frame(ws.OP_BINARY,data)
                if mode=='slow':
                    for off in range(0,len(frame),512):
                        writer.write(frame[off:off+512]);await writer.drain();await asyncio.sleep(.02)
                elif mode=='partial':writer.write(frame[:10]);await writer.drain()
                else:writer.write(frame);await writer.drain()
        except (OSError,asyncio.IncompleteReadError):pass
        finally:await ws.close();tasks.discard(task)
    up=await asyncio.start_server(remote,'127.0.0.1',0)
    async def local(reader,writer):
        task=asyncio.current_task();tasks.add(task)
        rr,rw=await asyncio.open_connection('127.0.0.1',up.sockets[0].getsockname()[1])
        if mode.startswith('backpressure'):
            original=writer
            class SlowWriter:
                def write(self,data):original.write(data)
                async def drain(self):await release.wait();await original.drain()
                def close(self):original.close()
                async def wait_closed(self):await original.wait_closed()
                transport=original.transport
            writer=SlowWriter()
        try:await bridge_ws_reencrypt(reader,writer,RawWebSocket(rr,rw),'local',crypto(),dc=2,is_media=is_media,**kwargs)
        finally:tasks.discard(task)
    app=await asyncio.start_server(local,'127.0.0.1',0)
    async def connect():
        reader,writer=await asyncio.open_connection('127.0.0.1',app.sockets[0].getsockname()[1]);connections.append(writer)
        return reader,writer
    try:yield SimpleNamespace(connect=connect,opcodes=opcodes,release=release)
    finally:
        release.set()
        for writer in connections:writer.close()
        await asyncio.gather(*(w.wait_closed()for w in connections),return_exceptions=True)
        app.close();up.close();await app.wait_closed();await up.wait_closed();await asyncio.sleep(.03)
        pending=list(tasks)
        for task in pending:task.cancel()
        await asyncio.gather(*pending,return_exceptions=True)

@pytest.mark.asyncio
async def test_silent_media_request_closes_only_failed_session_and_retry_loads_video(deadline):
    stalls=stats.media_stalls;invalidated=[]
    async with websocket_app('retry',on_stall=lambda:invalidated.append(2))as app:
        reader,writer=await app.connect();writer.write(b'video-request');await writer.drain()
        assert await asyncio.wait_for(reader.read(),.6)==b''
        assert invalidated==[2]and stats.media_stalls==stalls+1
        reader,writer=await app.connect();payload=b'video'*10000;writer.write(payload);await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(len(payload)),1)==payload
        assert RawWebSocket.OP_PING not in app.opcodes
    assert media_health.diagnostics()['active']==0

@pytest.mark.asyncio
@pytest.mark.parametrize('media',[False,True])
async def test_idle_media_and_nonmedia_waits_are_never_timed_out(deadline,media):
    async with websocket_app('silent',is_media=media)as app:
        reader,writer=await app.connect()
        if not media:writer.write(b'chat-long-poll');await writer.drain()
        with pytest.raises(asyncio.TimeoutError):await asyncio.wait_for(reader.read(1),.24)
        assert not writer.is_closing()
        assert RawWebSocket.OP_PING not in app.opcodes

@pytest.mark.asyncio
async def test_slow_frame_progress_and_idle_after_reply_are_preserved(deadline):
    count=stats.media_stalls
    async with websocket_app('slow')as app:
        reader,writer=await app.connect();payload=b'video'*2400
        writer.write(payload);await writer.drain();began=time.monotonic()
        assert await asyncio.wait_for(reader.readexactly(len(payload)),2)==payload
        assert time.monotonic()-began>media_health.MEDIA_RESPONSE_TIMEOUT*3
        with pytest.raises(asyncio.TimeoutError):await asyncio.wait_for(reader.read(1),.24)
        assert stats.media_stalls==count

@pytest.mark.asyncio
async def test_frame_which_stops_halfway_is_recovered(deadline):
    async with websocket_app('partial')as app:
        reader,writer=await app.connect();writer.write(b'video'*200);await writer.drain()
        assert await asyncio.wait_for(reader.read(),.6)==b''

@pytest.mark.asyncio
async def test_slow_native_consumer_does_not_trigger_remote_recovery(deadline):
    count=stats.media_stalls
    async with websocket_app('backpressure')as app:
        reader,writer=await app.connect();writer.write(b'first');await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(5),1)==b'first'
        writer.write(b'second');await writer.drain();await asyncio.sleep(.24)
        assert media_health.diagnostics()['sessions'][0]['client_backpressure']
        assert stats.media_stalls==count
        app.release.set();assert await asyncio.wait_for(reader.readexactly(6),1)==b'second'

@pytest.mark.asyncio
async def test_response_deadline_excludes_time_client_was_not_reading(deadline):
    async with websocket_app('backpressure-silent')as app:
        reader,writer=await app.connect();writer.write(b'first');await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(5),1)==b'first'
        writer.write(b'second');await writer.drain();await asyncio.sleep(.24)
        app.release.set()
        with pytest.raises(asyncio.TimeoutError):await asyncio.wait_for(reader.read(1),.04)
        assert await asyncio.wait_for(reader.read(),.6)==b''

@pytest.mark.asyncio
async def test_pool_reset_is_scoped_to_failed_media_dc(deadline,monkeypatch):
    pool=_WsPool();failed=Mock();chat=Mock();other=Mock();test_dc=Mock();now=time.monotonic()
    for key,ws in (((2,True,False),failed),((2,False,False),chat),((4,True,False),other),((2,True,True),test_dc)):
        pool._idle[key]=deque([(ws,now)])
    task=asyncio.create_task(asyncio.sleep(30));pool._refilling[(2,True,False)]=task
    pool.discard_media(2);await asyncio.gather(task,return_exceptions=True)
    failed.writer.transport.abort.assert_called_once()
    for ws in (chat,other,test_dc):ws.writer.transport.abort.assert_not_called()
    assert (2,True,False)not in pool._idle
    assert task.cancelled()and pool._refill_after[(2,True,False)]>now
    monkeypatch.setattr(proxy_config,'dc_redirects',{2:'192.0.2.1'})
    monkeypatch.setattr(proxy_config,'pool_size',1)
    assert await pool.get(2,True)is None  # Native retry takes fallback, no stale batch.
    await pool.close()

@pytest.mark.asyncio
async def test_remote_close_frame_releases_real_socket(deadline):
    finished=asyncio.Event()
    async def remote(reader,writer):
        writer.write(RawWebSocket._build_frame(RawWebSocket.OP_CLOSE,b'\x03\xe8'));await writer.drain()
        try:await reader.read();finished.set()
        finally:writer.close();await writer.wait_closed()
    server=await asyncio.start_server(remote,'127.0.0.1',0)
    reader,writer=await asyncio.open_connection('127.0.0.1',server.sockets[0].getsockname()[1])
    try:
        ws=RawWebSocket(reader,writer);assert await ws.recv()is None
        await ws.close();await asyncio.wait_for(finished.wait(),.3)
        assert writer.is_closing()
    finally:writer.close();await writer.wait_closed();server.close();await server.wait_closed()

@pytest.mark.asyncio
async def test_tcp_media_silence_releases_client_without_restart(deadline):
    tasks=set()
    async def remote(reader,writer):
        tasks.add(asyncio.current_task())
        try:await reader.read()
        finally:writer.close();await writer.wait_closed();tasks.discard(asyncio.current_task())
    up=await asyncio.start_server(remote,'127.0.0.1',0)
    async def local(reader,writer):
        tasks.add(asyncio.current_task());rr,rw=await asyncio.open_connection('127.0.0.1',up.sockets[0].getsockname()[1])
        try:await _bridge_tcp_reencrypt(reader,writer,rr,rw,'media',crypto(),is_media=True,dc=2)
        finally:tasks.discard(asyncio.current_task())
    server=await asyncio.start_server(local,'127.0.0.1',0)
    reader,writer=await asyncio.open_connection('127.0.0.1',server.sockets[0].getsockname()[1])
    try:
        writer.write(b'file');await writer.drain();assert await asyncio.wait_for(reader.read(),.6)==b''
    finally:
        writer.close();await writer.wait_closed();server.close();up.close();await server.wait_closed();await up.wait_closed()
        await asyncio.gather(*list(tasks),return_exceptions=True)

@pytest.mark.asyncio
@pytest.mark.parametrize('slow',[False,True])
async def test_h2_empty_http_responses_recover_but_slow_body_and_other_channel_survive(deadline,slow):
    lane=_HttpLane('local.test',1);await lane.client.aclose()
    class SlowBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(12):yield b'body';await asyncio.sleep(.02)
    async def handle(request):
        if request.content==b'v'*40:
            return httpx.Response(200,stream=SlowBody()if slow else httpx.ByteStream(b''),extensions={'http_version':b'HTTP/2'})
        return httpx.Response(200,content=b'y'*40,extensions={'http_version':b'HTTP/2'})
    lane.client=httpx.AsyncClient(transport=httpx.MockTransport(handle));channel=_HttpChannel(lane,1,'media')
    other=_HttpChannel(lane,2,'another-video');tasks=set()
    async def local(reader,writer):
        task=asyncio.current_task();tasks.add(task)
        try:await bridge_h2(reader,writer,channel,crypto(),PROTO_TAG_INTERMEDIATE)
        finally:writer.close();await writer.wait_closed();tasks.discard(task)
    server=await asyncio.start_server(local,'127.0.0.1',0)
    reader,writer=await asyncio.open_connection('127.0.0.1',server.sockets[0].getsockname()[1])
    count=stats.media_stalls
    try:
        writer.write(struct.pack('<I',40)+b'v'*40);await writer.drain()
        if slow:
            assert await asyncio.wait_for(reader.readexactly(52),1)==struct.pack('<I',48)+b'body'*12
            assert stats.media_stalls==count
        else:
            assert await asyncio.wait_for(reader.read(),.6)==b''
            assert stats.media_stalls==count+1 and channel.closed
            assert lane.failed_until > time.monotonic()
        assert not lane.closed and not other.closed
        await other.send(b'x'*40,False);assert await asyncio.wait_for(other.receive(),1)==b'y'*40
    finally:
        writer.close();await writer.wait_closed();server.close();await server.wait_closed()
        pending=list(tasks)
        for task in pending:task.cancel()
        await asyncio.gather(*pending,return_exceptions=True)
        await lane.close()
    assert media_health.diagnostics()['active']==0
