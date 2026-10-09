"""Host-side WSS echo fixture for the packaged Android native DPI engine.

This script writes its private fixture key outside the Android project. Only
cert.pem or cert.der is passed to the test APK; never copy key.pem into it.
"""
import argparse
import asyncio
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import ssl
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

DOMAIN = 'kws4-1.web.telegram.org'


def certificate(directory):
    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = directory / 'cert.pem', directory / 'key.pem'
    if not cert_path.exists() or not key_path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=14))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(DOMAIN)]), False)
                .sign(key, hashes.SHA256()))
        with os.fdopen(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'wb') as out:
            out.write(key.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (directory / 'cert.der').write_bytes(cert.public_bytes(serialization.Encoding.DER))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    context.set_servername_callback(lambda sock, name, ctx: print(
        json.dumps({'event': 'tls_client_hello', 'sni': name}), flush=True))
    return context


def frame(opcode, payload):
    head = bytes([0x80 | opcode])
    size = len(payload)
    if size < 126:
        return head + bytes([size]) + payload
    if size < 65536:
        return head + b'\x7e' + struct.pack('>H', size) + payload
    return head + b'\x7f' + struct.pack('>Q', size) + payload


async def read_frame(reader):
    head = await reader.readexactly(2)
    assert head[0] & 0x80, 'Fixture expects complete client messages'
    assert head[1] & 0x80, 'Client frames must be masked'
    size = head[1] & 127
    if size == 126:
        size = struct.unpack('>H', await reader.readexactly(2))[0]
    elif size == 127:
        size = struct.unpack('>Q', await reader.readexactly(8))[0]
    assert size <= 3 * 1024 * 1024
    mask = await reader.readexactly(4)
    payload = await reader.readexactly(size)
    payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return head[0] & 15, payload


async def accepted(reader, writer):
    try:
        request = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 12)
        lines = request.split(b'\r\n')
        assert lines[0] == b'GET /apiws HTTP/1.1', lines[0]
        headers = {key.strip().lower(): value.strip()
                   for line in lines[1:] if b':' in line
                   for key, value in [line.split(b':', 1)]}
        assert headers[b'host'] == DOMAIN.encode(), headers.get(b'host')
        assert headers[b'upgrade'].lower() == b'websocket'
        accept = base64.b64encode(hashlib.sha1(headers[b'sec-websocket-key'] +
                                  b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
        writer.write(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                     b'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n')
        await writer.drain()
        while True:
            opcode, payload = await asyncio.wait_for(read_frame(reader), 20)
            if opcode == 8:
                writer.write(frame(8, payload))
                await writer.drain()
                break
            if opcode == 9:
                writer.write(frame(10, payload))
            else:
                assert opcode == 2, opcode
                writer.write(frame(2, payload))
                print(json.dumps({'event': 'echo', 'bytes': len(payload),
                                  'sha256': hashlib.sha256(payload).hexdigest()}), flush=True)
            await writer.drain()
    except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError, AssertionError) as error:
        print(json.dumps({'event': 'connection_error', 'error': repr(error)}), flush=True)
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (OSError, asyncio.TimeoutError):
            writer.transport.abort()
        print(json.dumps({'event': 'closed'}), flush=True)


async def main(args):
    context = certificate(Path(args.fixture_dir))
    server = await asyncio.start_server(accepted, args.host, args.port, ssl=context)
    print(json.dumps({'event': 'listening', 'host': args.host, 'port': args.port,
                      'domain': DOMAIN, 'fixture_dir': args.fixture_dir}), flush=True)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--fixture-dir', required=True, help='Private directory for generated local test certificates')
    asyncio.run(main(parser.parse_args()))
