"""Separate test-APK scenario: native Android AES, real sockets, production timer."""
import asyncio,json,time
from types import SimpleNamespace
from proxy.bridge import bridge_ws_reencrypt
from proxy.raw_websocket import RawWebSocket
from proxy.pool import _WsPool
from proxy._aes import Cipher,algorithms,modes
from proxy import media_health
from proxy.stats import stats

def cipher(key):return Cipher(algorithms.AES(key*32),modes.CTR(key*16)).encryptor()
def crypto():return SimpleNamespace(clt_dec=cipher(b'c'),clt_enc=cipher(b'c'),tg_dec=cipher(b't'),tg_enc=cipher(b't'))

async def scenario():
    assert media_health.MEDIA_RESPONSE_TIMEOUT==60
    tasks=set();writers=[];opcodes=[];connections=0;chats=0;pool=_WsPool()
    async def remote(reader,writer):
        task=asyncio.current_task();tasks.add(task);ws=RawWebSocket(reader,writer)
        try:
            while True:
                op,data,_=await ws._read_frame();opcodes.append(op)
                if op==ws.OP_CLOSE:break
                if op==ws.OP_BINARY and data!=b'':
                    # First TCP session is a blackhole after accepting WS data.
                    if getattr(writer,'_silent_test',False):continue
                    writer.write(ws._build_frame(ws.OP_BINARY,data));await writer.drain()
        except (OSError,asyncio.IncompleteReadError):pass
        finally:await ws.close();tasks.discard(task)
    # Tag remote sessions with their accept index, independently of ciphertext.
    remote_index=0
    async def accepted(reader,writer):
        nonlocal remote_index
        remote_index+=1;writer._silent_test=remote_index==1
        await remote(reader,writer)
    upstream=await asyncio.start_server(accepted,'127.0.0.1',0)
    async def local(reader,writer):
        nonlocal connections
        connections+=1;index=connections;task=asyncio.current_task();tasks.add(task)
        rr,rw=await asyncio.open_connection('127.0.0.1',upstream.sockets[0].getsockname()[1])
        try:await bridge_ws_reencrypt(reader,writer,RawWebSocket(rr,rw),'test',crypto(),dc=2,
                                      is_media=index!=2,on_stall=lambda:pool.discard_media(2))
        finally:tasks.discard(task)
    server=await asyncio.start_server(local,'127.0.0.1',0)
    async def connect():
        r,w=await asyncio.open_connection('127.0.0.1',server.sockets[0].getsockname()[1]);writers.append(w)
        return r,w,cipher(b'c'),cipher(b'c')
    start_count=stats.media_stalls;chat_task=None
    try:
        dead,dw,enc,_=await connect();dw.write(enc.update(b'video-request'));await dw.drain()
        chat,cw,ce,cd=await connect()
        async def chat_flow():
            nonlocal chats
            while True:
                payload=b'chat-and-voice';cw.write(ce.update(payload));await cw.drain()
                assert cd.update(await asyncio.wait_for(chat.readexactly(len(payload)),3))==payload
                chats+=1;await asyncio.sleep(2)
        chat_task=asyncio.create_task(chat_flow());started=time.monotonic()
        assert await asyncio.wait_for(dead.read(),66)==b''
        elapsed=time.monotonic()-started
        assert 59<=elapsed<=65 and stats.media_stalls==start_count+1
        assert chats>=20 and not chat_task.done()
        assert pool._refill_after[(2,True,False)]>time.monotonic()
        video,vw,ve,vd=await connect();payload=b'video-frame-'*(1024*1024//12)
        vw.write(ve.update(payload));await vw.drain()
        assert vd.update(await asyncio.wait_for(video.readexactly(len(payload)),8))==payload
        assert RawWebSocket.OP_PING not in opcodes
        return {'result':'PASS','production_timeout_seconds':round(elapsed,2),
                'chat_roundtrips':chats,'retry_bytes':len(payload),'client_ping_frames':0,
                'aes':'Android native AES-CTR bidirectional stream'}
    finally:
        if chat_task:chat_task.cancel();await asyncio.gather(chat_task,return_exceptions=True)
        for writer in writers:writer.close()
        await asyncio.gather(*(w.wait_closed()for w in writers),return_exceptions=True)
        server.close();upstream.close();await server.wait_closed();await upstream.wait_closed();await asyncio.sleep(.03)
        pending=list(tasks)
        for task in pending:task.cancel()
        await asyncio.gather(*pending,return_exceptions=True);await pool.close()

def run():return json.dumps(asyncio.run(scenario()))
