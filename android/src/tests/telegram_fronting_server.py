"""Local TLS/MTProto fixture: canonical SNI fails; pinned decoy-SNI route works."""
import asyncio
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import ssl
import struct
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID
from telegram_dpi_server import frame, read_frame


def certificate(directory):
    directory.mkdir(parents=True, exist_ok=True)
    cp, kp = directory / 'cert.pem', directory / 'key.pem'
    if not cp.exists() or not kp.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'legacy-fixture.invalid')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=14))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('legacy-fixture.invalid')]), False)
                .sign(key, hashes.SHA256()))
        with os.fdopen(os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'wb') as out:
            out.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
        cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (directory / 'cert.der').write_bytes(cert.public_bytes(serialization.Encoding.DER))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cp, kp)
    def sni(sock, name, ctx):
        print(json.dumps({'event': 'client_hello', 'sni': name}), flush=True)
        if name != 'sprinthost.ru':
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
    context.set_servername_callback(sni)
    return context


def crypt(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


async def accepted(reader, writer):
    try:
        request = await reader.readuntil(b'\r\n\r\n')
        lines = request.split(b'\r\n')
        assert lines[0] == b'GET /apiws HTTP/1.1'
        headers = dict(line.split(b': ', 1) for line in lines[1:] if b': ' in line)
        assert headers[b'Host'] in (b'kws4.web.telegram.org', b'kws4-1.web.telegram.org')
        accept = base64.b64encode(hashlib.sha1(headers[b'Sec-WebSocket-Key'] +
                                  b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
        writer.write(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                     b'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n')
        await writer.drain()
        opcode, initial = await read_frame(reader)
        if opcode == 8:
            return
        assert opcode == 2 and len(initial) == 64
        keys = initial[8:56]
        upload = crypt(keys[:32], keys[32:])
        decoded = upload.update(initial)
        tag = decoded[56:60]
        assert tag in (b'\xee' * 4, b'\xdd' * 4)
        padded = tag == b'\xdd' * 4
        assert struct.unpack('<h', decoded[60:62])[0] == -4
        reverse = keys[::-1]
        download = crypt(reverse[:32], reverse[32:])
        buffered = bytearray()
        while True:
            opcode, encrypted = await read_frame(reader)
            if opcode == 8:
                return
            assert opcode == 2
            buffered.extend(upload.update(encrypted))
            while len(buffered) >= 4:
                size = struct.unpack('<I', buffered[:4])[0]
                assert 0 < size <= 2 * 1024 * 1024
                if len(buffered) < size + 4:
                    break
                body = bytes(buffered[4:4 + size])
                del buffered[:4 + size]
                if body.startswith(b'ECHO'):
                    reply = body
                    event = 'echo'
                else:
                    assert body[:8] == b'\0' * 8
                    assert len(body) >= 20
                    message_length = struct.unpack('<I', body[16:20])[0]
                    message_end = 20 + message_length
                    padding_length = len(body) - message_end
                    assert 0 <= padding_length <= (15 if padded else 0)
                    body = body[:message_end]
                    assert body[20:24] == struct.pack('<I', 0xbe7e8ef1)
                    assert len(body) == 40
                    nonce = body[24:40]
                    response_body = (struct.pack('<I', 0x05162463) + nonce + os.urandom(16)
                                     + b'\x02\x01\xb5\x00'  # TL bytes: 437 = 19 * 23.
                                     + struct.pack('<IIQ', 0x1cb5c415, 1, 0x0102030405060708))
                    reply = (b'\0' * 8 + struct.pack('<QI', (int(time.time()) << 32) | 1,
                                                    len(response_body)) + response_body)
                    event = 'resPQ'
                transport_reply = reply + (os.urandom(7) if padded else b'')
                encrypted_reply = download.update(struct.pack('<I', len(transport_reply)) + transport_reply)
                writer.write(frame(2, encrypted_reply))
                await writer.drain()
                print(json.dumps({'event': event, 'bytes': len(reply),
                                  'protocol': 'padded' if padded else 'intermediate',
                                  'host': headers[b'Host'].decode()}), flush=True)
    except (OSError, asyncio.IncompleteReadError):
        pass
    except Exception as error:
        print(json.dumps({'event': 'error', 'error': repr(error)}), flush=True)
        raise
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (OSError, asyncio.TimeoutError):
            writer.transport.abort()


async def main(args):
    server = await asyncio.start_server(accepted, '0.0.0.0', args.port,
                                        ssl=certificate(Path(args.fixture_dir)))
    print(json.dumps({'event': 'listening', 'port': args.port}), flush=True)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--fixture-dir', required=True, help='Private directory for generated local test certificates')
    asyncio.run(main(parser.parse_args()))
