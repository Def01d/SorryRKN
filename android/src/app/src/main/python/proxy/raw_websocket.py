import os
import logging
import base64
import struct
import asyncio
import contextlib
import ipaddress
import socket as _socket
import time
from .media_health import close_writer, CLOSE_TIMEOUT
from .route_diagnostics import Attempt

from typing import List, Optional, Tuple
from .config import proxy_config
from .utils import create_ssl_context
from .telegram_endpoints import legacy_fronting

log = logging.getLogger('tg-mtproto-proxy')


_st_BB = struct.Struct('>BB')
_st_BBH = struct.Struct('>BBH')
_st_BBQ = struct.Struct('>BBQ')
_st_BB4s = struct.Struct('>BB4s')
_st_BBH4s = struct.Struct('>BBH4s')
_st_BBQ4s = struct.Struct('>BBQ4s')
_st_H = struct.Struct('>H')
_st_Q = struct.Struct('>Q')

_ssl_ctx = create_ssl_context()
_ssl_ctx_fronting = create_ssl_context(check_hostname=False)

class WsHandshakeError(Exception):
    def __init__(self, status_code: int, status_line: str,
                 headers: Optional[dict] = None, location: Optional[str] = None):
        self.status_code = status_code
        self.http_status = status_code
        self.status_line = status_line
        self.headers = headers or {}
        self.location = location
        super().__init__(f"HTTP {status_code}: {status_line}")

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)


def _xor_mask(data: bytes, mask: bytes) -> bytes:
    if not data:
        return data
    n = len(data)
    mask_rep = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(data, 'big') ^
            int.from_bytes(mask_rep, 'big')).to_bytes(n, 'big')


def set_sock_opts(transport, buffer_size):
    sock = transport.get_extra_info('socket')
    if sock is None:
        return
    
    try:
        sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
    except (OSError, AttributeError):
        pass
    
    try:
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF, buffer_size)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_SNDBUF, buffer_size)
    except OSError:
        pass


class SocksHandshakeError(ConnectionError):
    def __init__(self, reply):
        super().__init__('Local SOCKS handshake rejected')
        self.socks_reply = reply


async def _socks_connect(reader, writer, host):
    """Negotiate an unauthenticated, device-local SOCKS5 connection."""
    writer.write(b'\x05\x01\x00')
    await writer.drain()
    greeting = await reader.readexactly(2)
    if greeting != b'\x05\x00':
        raise SocksHandshakeError(greeting[1])
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode('idna')
        if not 0 < len(encoded) <= 255:
            raise ValueError('Invalid Telegram endpoint hostname')
        destination = b'\x03' + bytes([len(encoded)]) + encoded
    else:
        destination = bytes([1 if address.version == 4 else 4]) + address.packed
    writer.write(b'\x05\x01\x00' + destination + b'\x01\xbb')
    await writer.drain()
    reply = await reader.readexactly(4)
    if reply[:3] != b'\x05\x00\x00':
        raise SocksHandshakeError(reply[1])
    if reply[3] == 1:
        await reader.readexactly(6)
    elif reply[3] == 4:
        await reader.readexactly(18)
    elif reply[3] == 3:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)
    else:
        raise SocksHandshakeError(reply[1])


class RawWebSocket:
    __slots__ = ('reader', 'writer', '_closed', '_frag', 'last_payload_received')

    OP_CONT = 0x0
    OP_BINARY = 0x2
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    MAX_MESSAGE_LEN = 16 * 1024 * 1024

    def __init__(self, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self._closed = False
        self._frag = bytearray()
        self.last_payload_received = 0.0

    @staticmethod
    async def connect(host: str, domain: str, timeout: float = 10.0,
                      path: str = '/apiws', *,
                      sni: Optional[str] = None, secure = True,
                      direct: bool = False) -> 'RawWebSocket':
        # One deadline covers TCP, SOCKS, TLS and every HTTP response header.
        # A slow or broken peer cannot keep a pool slot indefinitely occupied.
        compatible = legacy_fronting(host, domain, sni)
        use_dpi = (not direct and not compatible and secure
                   and domain.lower().endswith('.web.telegram.org')
                   and proxy_config.telegram_dpi_port > 0)
        route = 'ws_fronting' if compatible else ('ws_local_socks' if use_dpi else 'ws_direct')
        attempt = Attempt(route, domain, host, 443 if secure else 80)
        attempt.stage('local_socket' if use_dpi else 'tcp')
        try:
            # Own the deadline outside _connect so timeout cancellation is a
            # failed stage, while a losing race/lifecycle stop is cancellation.
            async with asyncio.timeout(timeout):
                return await RawWebSocket._connect(host, domain, timeout, path,
                    sni=sni, secure=secure, direct=direct, attempt=attempt)
        except asyncio.CancelledError:
            attempt.cancel()
            raise
        except Exception as error:
            attempt.failure(error)
            raise
        finally:
            attempt.finish()

    @staticmethod
    async def _connect(host, domain, timeout, path, *, sni, secure, direct=False, attempt):
        compatible = legacy_fronting(host, domain, sni)
        # This pinned Telegram endpoint historically requires a decoy SNI.
        # Preserve upstream certificate-chain verification for exactly that
        # route; all other endpoints retain normal hostname verification.
        ssl_context = _ssl_ctx_fronting if compatible else _ssl_ctx

        if sni is None:
            sni = domain

        use_dpi = (not direct and not compatible and secure
                   and domain.lower().endswith('.web.telegram.org')
                   and proxy_config.telegram_dpi_port > 0)
        writer = None
        try:
            if use_dpi:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection('127.0.0.1', proxy_config.telegram_dpi_port),
                    timeout=min(timeout, 10))
                attempt.success()
                set_sock_opts(writer.transport, proxy_config.buffer_size)
                attempt.stage('local_socks')
                await _socks_connect(reader, writer, host)
                attempt.success(socks_reply=0)
                attempt.stage('tls')
                # TLS is still end-to-end with Telegram. The local engine sees
                # the encrypted stream and never receives a trusted CA key.
                await writer.start_tls(ssl_context, server_hostname=sni,
                                       ssl_handshake_timeout=min(timeout, 10))
                attempt.success()
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, 443 if secure else 80),
                    timeout=min(timeout, 10))
                attempt.success()
                if secure:
                    attempt.stage('tls')
                    await writer.start_tls(ssl_context, server_hostname=sni,
                                           ssl_handshake_timeout=min(timeout, 10))
                    attempt.success()
            set_sock_opts(writer.transport, proxy_config.buffer_size)
            attempt.stage('http_upgrade')

            ws_key = base64.b64encode(os.urandom(16)).decode()

            req = (
                f'GET {path} HTTP/1.1\r\n'
                f'Host: {domain}\r\n'
                f'Upgrade: websocket\r\n'
                f'Connection: Upgrade\r\n'
                f'Sec-WebSocket-Key: {ws_key}\r\n'
                f'Sec-WebSocket-Version: 13\r\n'
                f'Sec-WebSocket-Protocol: binary\r\n'
                f'\r\n'
            )

            writer.write(req.encode())
            await writer.drain()

            response_lines: list[str] = []
            while True:
                line = await asyncio.wait_for(reader.readline(),
                                              timeout=timeout)
                if line in (b'\r\n', b'\n', b''):
                    break
                response_lines.append(
                    line.decode('utf-8', errors='replace').strip())

            if not response_lines:
                raise WsHandshakeError(0, 'empty response')

            first_line = response_lines[0]
            parts = first_line.split(' ', 2)
            try:
                status_code = int(parts[1]) if len(parts) >= 2 else 0
            except ValueError:
                status_code = 0

            if status_code == 101:
                attempt.success(http_status=101)
                return RawWebSocket(reader, writer)

            headers: dict[str, str] = {}
            for hl in response_lines[1:]:
                if ':' in hl:
                    k, v = hl.split(':', 1)
                    headers[k.strip().lower()] = v.strip()

            raise WsHandshakeError(status_code, first_line, headers,
                                    location=headers.get('location'))
        except BaseException:
            if writer is not None:
                # Preserve the original diagnostic cause even if the failed
                # transport also raises while it is being torn down.
                with contextlib.suppress(Exception):
                    writer.close()
                # Incomplete TLS handshakes have no useful close-notify
                # exchange. Abort promptly on cancellation or handshake failure.
                with contextlib.suppress(Exception):
                    writer.transport.abort()
            raise

    async def send(self, data: bytes):
        if self._closed:
            raise ConnectionError("WebSocket closed")
        frame = self._build_frame(self.OP_BINARY, data, mask=True)
        self.writer.write(frame)
        await self.writer.drain()

    async def send_batch(self, parts: List[bytes]):
        if self._closed:
            raise ConnectionError("WebSocket closed")
        for part in parts:
            self.writer.write(
                self._build_frame(self.OP_BINARY, part, mask=True))
        await self.writer.drain()

    async def recv(self) -> Optional[bytes]:
        while not self._closed:
            opcode, payload, fin = await self._read_frame()

            if opcode == self.OP_CLOSE:
                self._closed = True
                code, reason = self._parse_close(payload)
                log.debug("WS OP_CLOSE from upstream: code=%s reason=%r",
                          code, reason)
                try:
                    self.writer.write(self._build_frame(
                        self.OP_CLOSE,
                        payload[:2] if payload else b'', mask=True))
                    await asyncio.wait_for(self.writer.drain(), CLOSE_TIMEOUT)
                except Exception:
                    pass
                return None

            if opcode == self.OP_PING:
                try:
                    self.writer.write(
                        self._build_frame(self.OP_PONG, payload, mask=True))
                    await self.writer.drain()
                except Exception:
                    pass
                continue

            if opcode == self.OP_PONG:
                continue

            if opcode in (self.OP_CONT, 0x1, self.OP_BINARY):
                if fin and not self._frag:
                    return payload
                self._frag.extend(payload)
                if len(self._frag) > self.MAX_MESSAGE_LEN:
                    raise ConnectionError(
                        f"WS message too large: {len(self._frag)} bytes")
                if not fin:
                    continue
                message = bytes(self._frag)
                self._frag.clear()
                return message
            continue
        return None

    async def close(self):
        was_closed = self._closed
        self._closed = True
        try:
            if not was_closed:
                self.writer.write(self._build_frame(self.OP_CLOSE, b'', mask=True))
                await asyncio.wait_for(self.writer.drain(), CLOSE_TIMEOUT)
        except Exception:
            pass
        finally:
            try:
                await close_writer(self.writer)
            except Exception:
                pass

    _WS_CLOSE_REASONS = {
        1000: 'normal', 1001: 'going_away', 1002: 'protocol_error',
        1003: 'unsupported_data', 1006: 'abnormal', 1007: 'bad_data',
        1008: 'policy_violation', 1009: 'too_big', 1010: 'missing_extension',
        1011: 'internal_error',
    }

    @classmethod
    def _parse_close(cls, payload: Optional[bytes]) -> Tuple[Optional[int], str]:
        if not payload or len(payload) < 2:
            return None, ''
        try:
            code = int.from_bytes(payload[:2], 'big')
            text = payload[2:].decode('utf-8', errors='replace')
            name = cls._WS_CLOSE_REASONS.get(code)
            return code, f"{text} ({name})" if name else text
        except Exception:
            return None, ''

    @staticmethod
    def _build_frame(opcode: int, data: bytes,
                     mask: bool = False) -> bytes:
        length = len(data)
        fb = 0x80 | opcode
        if not mask:
            if length < 126:
                return _st_BB.pack(fb, length) + data
            if length < 65536:
                return _st_BBH.pack(fb, 126, length) + data
            return _st_BBQ.pack(fb, 127, length) + data
        mask_key = os.urandom(4)
        masked = _xor_mask(data, mask_key)
        if length < 126:
            return _st_BB4s.pack(fb, 0x80 | length, mask_key) + masked
        if length < 65536:
            return _st_BBH4s.pack(fb, 0x80 | 126, length, mask_key) + masked
        return _st_BBQ4s.pack(fb, 0x80 | 127, length, mask_key) + masked

    async def _read_frame(self) -> Tuple[int, bytes, bool]:
        hdr = await self.reader.readexactly(2)
        fin = bool(hdr[0] & 0x80)
        opcode = hdr[0] & 0x0F
        length = hdr[1] & 0x7F
        if length == 126:
            length = _st_H.unpack(await self.reader.readexactly(2))[0]
        elif length == 127:
            length = _st_Q.unpack(await self.reader.readexactly(8))[0]
        if length > self.MAX_MESSAGE_LEN:
            raise ConnectionError(f"WS frame too large: {length} bytes")
        if hdr[1] & 0x80:
            mask_key = await self.reader.readexactly(4)
            payload = await self._read_payload(length, opcode)
            return opcode, _xor_mask(payload, mask_key), fin
        payload = await self._read_payload(length, opcode)
        return opcode, payload, fin

    async def _read_payload(self, length, opcode):
        if opcode not in (self.OP_CONT, 0x1, self.OP_BINARY):
            return await self.reader.readexactly(length)
        # readexactly hides partial-frame progress. Count arriving payload bytes
        # so a slow video frame is never mistaken for a silent connection.
        payload = bytearray()
        while len(payload) < length:
            chunk = await self.reader.read(min(65536, length - len(payload)))
            if not chunk:
                raise asyncio.IncompleteReadError(bytes(payload), length)
            payload.extend(chunk)
            self.last_payload_received = time.monotonic()
        return bytes(payload)
