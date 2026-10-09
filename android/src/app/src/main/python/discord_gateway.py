"""Anonymous Discord WebSocket Hello through SOCKS; no token or account access."""
import asyncio
import base64
import hashlib
import json
import secrets
import ssl
import certifi
from gateway import encode_address,read_address

HOST='gateway.discord.gg'
GUID='258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

def masked_frame(opcode,payload):
    if len(payload)>125:raise ValueError('Large control frame')
    mask=secrets.token_bytes(4)
    return bytes([0x80|opcode,0x80|len(payload)])+mask+bytes(b^mask[i%4] for i,b in enumerate(payload))

async def hello(reader,writer):
    message=bytearray();started=False
    for _ in range(16):
        a,b=await reader.readexactly(2);opcode=a&15;fin=bool(a&128);size=b&127
        if a&0x70 or b&128:raise ValueError('Unsupported server frame')
        if size==126:size=int.from_bytes(await reader.readexactly(2),'big')
        elif size==127:size=int.from_bytes(await reader.readexactly(8),'big')
        if size>16384 or len(message)+size>16384:raise ValueError('Large gateway response')
        if opcode>=8 and (not fin or size>125):raise ValueError('Invalid control frame')
        payload=await reader.readexactly(size)
        if opcode==9:
            writer.write(masked_frame(10,payload));await writer.drain();continue
        if opcode==10:continue
        if opcode==8:raise ValueError('Gateway closed before Hello')
        if opcode==1 and not started:started=True
        elif opcode!=0 or not started:raise ValueError('Invalid Hello opcode')
        message.extend(payload)
        if fin:
            value=json.loads(message)
            if not isinstance(value,dict) or not isinstance(value.get('d'),dict):raise ValueError('Not a Discord Hello')
            interval=value['d'].get('heartbeat_interval')
            if value.get('op')!=10 or type(interval)!=int or not 0<interval<=600000:
                raise ValueError('Not a Discord Hello')
            return True
    raise ValueError('Too many gateway frames')

async def check_gateway(port,address,verify=True,timeout=3,target_port=443):
    detail={'name':'Gateway','ok':False,'stage':'SOCKS','error':''};writer=None
    try:
        async with asyncio.timeout(timeout):
            reader,writer=await asyncio.open_connection('127.0.0.1',int(port))
            writer.write(b'\x05\x01\0');await writer.drain()
            if await reader.readexactly(2)!=b'\x05\0':raise ValueError('SOCKS authentication rejected')
            writer.write(b'\x05\x01\0'+encode_address(address,target_port));await writer.drain()
            reply=await reader.readexactly(3);await read_address(reader)
            if reply!=b'\x05\0\0':raise ValueError('SOCKS connect rejected')
            detail['stage']='TLS'
            context=verify if isinstance(verify,ssl.SSLContext) else ssl.create_default_context(cafile=certifi.where())
            await writer.start_tls(context,server_hostname=HOST)
            detail['stage']='WebSocket upgrade'
            key=base64.b64encode(secrets.token_bytes(16)).decode()
            writer.write((f'GET /?v=10&encoding=json HTTP/1.1\r\nHost: {HOST}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                          f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: GrayBridge/0.6\r\n\r\n').encode())
            await writer.drain();header=await reader.readuntil(b'\r\n\r\n')
            if len(header)>8192:raise ValueError('Large upgrade response')
            lines=header.decode('ascii').split('\r\n')
            if not lines[0].startswith('HTTP/1.1 101 '):raise ValueError('Missing WebSocket upgrade')
            headers={}
            for line in lines[1:]:
                if ':' in line:
                    name,value=line.split(':',1)
                    if name.lower() in headers:raise ValueError('Duplicate upgrade header')
                    headers[name.lower()]=value.strip()
            expected=base64.b64encode(hashlib.sha1((key+GUID).encode()).digest()).decode()
            if (headers.get('sec-websocket-accept')!=expected or headers.get('upgrade','').lower()!='websocket'
                or 'upgrade' not in {x.strip().lower() for x in headers.get('connection','').split(',')}
                or 'sec-websocket-extensions' in headers):raise ValueError('Invalid WebSocket handshake')
            detail['stage']='WebSocket Hello'
            detail['ok']=await hello(reader,writer)
            writer.write(masked_frame(8,b'\x03\xe8'));await writer.drain()
    except (OSError,ValueError,asyncio.TimeoutError,asyncio.IncompleteReadError,asyncio.LimitOverrunError) as error:
        detail['error']=type(error).__name__
    finally:
        if writer:
            writer.close()
            try:await asyncio.wait_for(writer.wait_closed(),.15)
            except (OSError,asyncio.TimeoutError):writer.transport.abort()
    return detail
