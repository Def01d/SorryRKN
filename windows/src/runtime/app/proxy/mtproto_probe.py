"""Small unauthenticated MTProto health exchange. No account or API credentials."""
import asyncio
import hashlib
import os
import struct
import time

from ._aes import Cipher, algorithms, modes
from .utils import (PROTO_TAG_ABRIDGED, PROTO_TAG_SECURE, RESERVED_FIRST_BYTES,
                    RESERVED_STARTS, RESERVED_CONTINUE)

REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463
MAX_PACKET = 16 * 1024 * 1024


def client_crypto(dc, secret=None, proto=PROTO_TAG_SECURE):
    """Return wire init and client-side ciphers, including the 64-byte advance."""
    while True:
        init = bytearray(os.urandom(64))
        if (init[0] not in RESERVED_FIRST_BYTES and bytes(init[:4]) not in RESERVED_STARTS
                and init[4:8] != RESERVED_CONTINUE):
            break
    material = bytes(init[8:56])
    reverse = material[::-1]
    key = lambda raw: hashlib.sha256(raw + secret).digest() if secret is not None else raw
    enc = Cipher(algorithms.AES(key(material[:32])), modes.CTR(material[32:])).encryptor()
    dec = Cipher(algorithms.AES(key(reverse[:32])), modes.CTR(reverse[32:])).encryptor()
    init[56:60] = proto
    init[60:62] = struct.pack('<h', dc)
    encrypted = enc.update(bytes(init))
    init[56:64] = encrypted[56:64]
    return bytes(init), enc, dec


def req_pq_packet(nonce):
    body = struct.pack('<I', REQ_PQ_MULTI) + nonce
    message_id = (int(time.time() * (1 << 32)) & ~3)
    payload = struct.pack('<QQI', 0, message_id, len(body)) + body
    # Secure intermediate permits 0..15 random padding bytes.
    payload += os.urandom(4)
    return struct.pack('<I', len(payload)) + payload


async def read_packet(readexactly, decryptor, proto=PROTO_TAG_SECURE, *, encrypted=False):
    """Read one complete transport frame, respecting fragmented stream reads."""
    header_size = 1 if proto == PROTO_TAG_ABRIDGED else 4
    wire_header = await readexactly(header_size)
    header = decryptor.update(wire_header)
    if proto == PROTO_TAG_ABRIDGED:
        words = header[0] & 0x7F
        if words == 0x7F:
            extra = await readexactly(3)
            wire_header += extra
            words = int.from_bytes(decryptor.update(extra), 'little')
        size = words * 4
    else:
        size = struct.unpack('<I', header)[0] & 0x7FFFFFFF
    if not 0 < size <= MAX_PACKET:
        raise ValueError('invalid_transport_length')
    wire_payload = await readexactly(size)
    payload = decryptor.update(wire_payload)
    return wire_header + wire_payload if encrypted else payload


def validate_res_pq(payload, nonce):
    if len(payload) < 56 or payload[:8] != bytes(8):
        raise ValueError('invalid_res_pq')
    size = struct.unpack_from('<I', payload, 16)[0]
    if size < 36 or size > len(payload) - 20:
        raise ValueError('invalid_res_pq_length')
    if struct.unpack_from('<I', payload, 20)[0] != RES_PQ or payload[24:40] != nonce:
        raise ValueError('invalid_res_pq_nonce')
    body = payload[20:20 + size]
    # Parse the TL pq string and fingerprint vector, rather than trusting only
    # an echoed constructor/nonce. Ignore permitted random transport padding.
    if len(body) < 48:
        raise ValueError('invalid_res_pq_body')
    pq_size = body[36]
    prefix = 1
    if pq_size == 254:
        pq_size = int.from_bytes(body[37:40], 'little')
        prefix = 4
    if not 1 <= pq_size <= 8:
        raise ValueError('invalid_res_pq_factor')
    vector_offset = 36 + ((prefix + pq_size + 3) // 4) * 4
    if vector_offset + 8 > len(body):
        raise ValueError('invalid_res_pq_vector')
    vector, count = struct.unpack_from('<II', body, vector_offset)
    if vector != 0x1CB5C415 or not 1 <= count <= 64 or vector_offset + 8 + count * 8 != len(body):
        raise ValueError('invalid_res_pq_fingerprints')


class TransportReader:
    def __init__(self, transport):
        self.transport = transport
        self.buffer = bytearray()

    async def readexactly(self, size):
        while len(self.buffer) < size:
            data = await self.transport.recv()
            if not data:
                raise asyncio.IncompleteReadError(bytes(self.buffer), size)
            self.buffer.extend(data)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result


async def exchange(transport, dc, secret=None):
    init, enc, dec = client_crypto(dc, secret)
    nonce = os.urandom(16)
    await transport.send(init)
    await transport.send(enc.update(req_pq_packet(nonce)))
    payload = await read_packet(TransportReader(transport).readexactly, dec)
    validate_res_pq(payload, nonce)


class TcpTransport:
    """The same byte transport contract as RawWebSocket, without framing."""
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer

    async def send(self, data):
        self.writer.write(data)
        await self.writer.drain()

    async def send_batch(self, parts):
        self.writer.writelines(parts)
        await self.writer.drain()

    async def recv(self):
        return await self.reader.read(65536) or None

    async def close(self):
        self.writer.close()
        try:
            await asyncio.wait_for(self.writer.wait_closed(), 1)
        except (OSError, asyncio.TimeoutError):
            pass


async def probe_local(host, port, secret, dc, timeout=15):
    started = time.monotonic()
    transport = None
    try:
        async def run():
            nonlocal transport
            transport = TcpTransport(*await asyncio.open_connection(host, port))
            await exchange(transport, dc, secret)
        await asyncio.wait_for(run(), timeout)
        return round((time.monotonic() - started) * 1000)
    finally:
        if transport is not None:
            await transport.close()
