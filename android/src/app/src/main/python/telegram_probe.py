"""Unauthenticated MTProto round-trip through the app's own local proxy.

A listening socket or successful WebSocket upgrade is insufficient. Success
requires a structurally valid Telegram resPQ matching this request's random
nonce. This does not prove login, an account's home DC, or file/CDN access.
"""
import asyncio
import contextlib
import datetime
import hashlib
import hmac
import os
import struct
import time

from proxy._aes import Cipher, algorithms, modes
from proxy.utils import PROTO_TAG_SECURE, RESERVED_FIRST_BYTES, RESERVED_STARTS, RESERVED_CONTINUE

TOTAL_TIMEOUT = 5.0
MAX_PACKET = 4096
REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463
VECTOR = 0x1CB5C415


class ProbeProtocolError(ValueError):
    """A fixed diagnostic reason, never bytes supplied by the peer."""


def _cipher(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def _native_init(secret, dc):
    while True:
        raw = bytearray(os.urandom(64))
        if (raw[0] not in RESERVED_FIRST_BYTES and bytes(raw[:4]) not in RESERVED_STARTS
                and raw[4:8] != RESERVED_CONTINUE):
            break
    raw[56:62] = PROTO_TAG_SECURE + struct.pack('<h', dc)
    keys = bytes(raw[8:56])
    up = _cipher(hashlib.sha256(keys[:32] + secret).digest(), keys[32:])
    reverse = keys[::-1]
    down = _cipher(hashlib.sha256(reverse[:32] + secret).digest(), reverse[32:])
    wire = bytearray(raw)
    wire[56:] = up.update(bytes(raw))[56:]
    return bytes(wire), up, down


def _request(nonce):
    # Unencrypted auth_key_id=0, a client msg_id divisible by four, then req_pq.
    # No auth key is created: the probe stops before req_DH_params.
    message_id = (time.time_ns() * (1 << 32) // 1_000_000_000) & ~3
    body = struct.pack('<I', REQ_PQ_MULTI) + nonce
    packet = struct.pack('<QQI', 0, message_id, len(body)) + body + os.urandom(7)
    return struct.pack('<I', len(packet)) + packet


def _validate_reply(packet, nonce):
    if len(packet) == 4:
        # Do not expose even a peer-supplied transport error as arbitrary text.
        raise ProbeProtocolError('TransportRejected')
    if len(packet) < 20:
        raise ProbeProtocolError('ShortEnvelope')
    auth_key, message_id, size = struct.unpack_from('<QQI', packet)
    if auth_key != 0 or not message_id & 1 or size % 4 or size < 44:
        raise ProbeProtocolError('InvalidEnvelope')
    if size > len(packet) - 20 or not 0 <= len(packet) - 20 - size <= 15:
        raise ProbeProtocolError('InvalidLength')
    body = packet[20:20 + size]
    if struct.unpack_from('<I', body)[0] != RES_PQ:
        raise ProbeProtocolError('UnexpectedConstructor')
    if not hmac.compare_digest(body[4:20], nonce):
        raise ProbeProtocolError('NonceMismatch')
    # resPQ: nonce:int128 server_nonce:int128 pq:bytes fingerprints:Vector<long>.
    # Telegram's PQ is at most 64 bits, so TL's long-string form is unnecessary.
    pq_length = body[36]
    if not 1 <= pq_length <= 8 or 37 + pq_length > len(body):
        raise ProbeProtocolError('InvalidPQ')
    if not any(body[37:37 + pq_length]):
        raise ProbeProtocolError('InvalidPQ')
    vector_offset = 36 + ((1 + pq_length + 3) // 4) * 4
    if vector_offset + 8 > len(body):
        raise ProbeProtocolError('ShortFingerprints')
    constructor, count = struct.unpack_from('<II', body, vector_offset)
    if constructor != VECTOR or not 1 <= count <= 16 or vector_offset + 8 + count * 8 != len(body):
        raise ProbeProtocolError('InvalidFingerprints')


async def check_telegram(port, secret, dc=2, is_media=False):
    """Check one DC over a fresh local native-proxy connection within five seconds.

    `secret` is the stored raw 16-byte secret or its 32-character hexadecimal
    representation, without the Telegram link's dd marker. Cancellation is
    propagated after closing only this diagnostic connection. No running
    sessions, pools, routing decisions, or authentication keys are reset.
    """
    started = time.monotonic()
    result = {
        'service': 'Telegram', 'state': 'unavailable', 'stage': 'TCP', 'error': '',
        'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
        'dc': dc, 'media': bool(is_media), 'authenticated_access': False,
        'account_checked': False, 'media_access_checked': False,
    }
    writer = None
    try:
        if (isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
                or isinstance(dc, bool) or not isinstance(dc, int) or dc not in (1, 2, 3, 4, 5, 203)):
            raise ValueError('InvalidConfiguration')
        if isinstance(secret, str):
            secret = bytes.fromhex(secret) if len(secret) == 32 else b''
        if not isinstance(secret, bytes) or len(secret) != 16:
            raise ValueError('InvalidConfiguration')
        async with asyncio.timeout(TOTAL_TIMEOUT):
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            result['stage'] = 'MTProto'
            init, up, down = _native_init(secret, -dc if is_media else dc)
            nonce = os.urandom(16)
            writer.write(init + up.update(_request(nonce)))
            await writer.drain()
            size = struct.unpack('<I', down.update(await reader.readexactly(4)))[0]
            if not 4 <= size <= MAX_PACKET:
                raise ProbeProtocolError('InvalidPacketLength')
            packet = down.update(await reader.readexactly(size))
            _validate_reply(packet, nonce)
            result['state'] = 'reachable'
    except ProbeProtocolError as error:
        result['error'] = str(error)
    except asyncio.TimeoutError:
        result['error'] = 'TimeoutError'
    except asyncio.IncompleteReadError:
        result['error'] = 'IncompleteReadError'
    except ValueError:
        result.update(stage='configuration', error='ValueError')
    except OSError as error:
        result['error'] = type(error).__name__
    finally:
        if writer is not None:
            # This is a local unencrypted TCP socket. No close-notify or peer
            # acknowledgement is needed; closing it must not extend the deadline.
            with contextlib.suppress(Exception):
                writer.close()
                writer.transport.abort()
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
    return result
