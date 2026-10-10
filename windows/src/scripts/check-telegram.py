"""Check the bundled Telegram proxy against real Telegram without an account.

Run from the source checkout:
    runtime/python/python.exe scripts/check-telegram.py --output telegram-check.json

The script starts its own worker on an unused loopback port, with a temporary
random secret. It does not read or change the installed application's settings.
Each production DC (1--5), including its media route, must return a complete
resPQ matching a fresh nonce. Network access is required; no pip installation or
Telegram account is needed. A successful check does not prove account login,
file downloads, voice calls, or access on a different ISP.

Exit codes: 0 = all ten checks and cleanup passed; 1 = failed check/cleanup;
2 = invalid arguments or unavailable runtime. Only redacted JSON is reported.
"""

import argparse
import asyncio
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time


REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463
VECTOR = 0x1CB5C415
MAX_REPLY = 4096
PROTOCOL_ERRORS = frozenset(('transport_error', 'invalid_reply', 'invalid_envelope',
                             'invalid_constructor', 'nonce_mismatch', 'missing_pq',
                             'invalid_pq', 'missing_fingerprints', 'invalid_fingerprints',
                             'invalid_transport_length'))


def _arguments():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--runtime', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'runtime',
                        help='Directory containing app/tg_runner.py and python/python.exe')
    parser.add_argument('--output', type=Path, help='Also save the redacted JSON report')
    parser.add_argument('--timeout', type=float, default=25,
                        help='Deadline for each MTProto round trip, in seconds (default: 25)')
    parser.add_argument('--parallel', type=int, default=4,
                        help='Simultaneous diagnostic clients, 1--10 (default: 4)')
    args = parser.parse_args()
    if not 1 <= args.timeout <= 120:
        parser.error('--timeout must be between 1 and 120 seconds')
    if not 1 <= args.parallel <= 10:
        parser.error('--parallel must be between 1 and 10')
    args.runtime = args.runtime.resolve()
    return args


def _unused_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def _listening(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=.25):
            return True
    except OSError:
        return False


def _validate_reply(payload, nonce):
    """Validate the whole TL resPQ, not just the constructor or an open socket."""
    if len(payload) == 4:
        code, = struct.unpack('<i', payload)
        raise ValueError('transport_error' if code < 0 else 'invalid_reply')
    if len(payload) < 56 or payload[:8] != bytes(8):
        raise ValueError('invalid_envelope')
    message_id, size = struct.unpack_from('<QI', payload, 8)
    # Parse the declared message body: real Telegram padded replies may carry
    # more than 15 trailing bytes. The enclosing frame is capped at MAX_REPLY.
    if not message_id & 1 or size % 4 or not 0 <= size <= len(payload) - 20:
        raise ValueError('invalid_envelope')
    body = payload[20:20 + size]
    if len(body) < 36 or struct.unpack_from('<I', body)[0] != RES_PQ:
        raise ValueError('invalid_constructor')
    if not hmac.compare_digest(body[4:20], nonce):
        raise ValueError('nonce_mismatch')
    # resPQ = constructor + nonce + server_nonce + TL bytes(pq) + Vector<long>.
    offset = 36
    if offset >= len(body):
        raise ValueError('missing_pq')
    length = body[offset]
    header = 1
    if length == 254:
        if offset + 4 > len(body):
            raise ValueError('invalid_pq')
        length = int.from_bytes(body[offset + 1:offset + 4], 'little')
        header = 4
    if not 1 <= length <= 8 or offset + header + length > len(body):
        raise ValueError('invalid_pq')
    pq = int.from_bytes(body[offset + header:offset + header + length], 'big')
    if pq <= 1:
        raise ValueError('invalid_pq')
    offset += (header + length + 3) & ~3
    if offset + 8 > len(body):
        raise ValueError('missing_fingerprints')
    constructor, count = struct.unpack_from('<II', body, offset)
    if constructor != VECTOR or not 1 <= count <= 64 or offset + 8 + count * 8 != len(body):
        raise ValueError('invalid_fingerprints')


async def _probe(port, secret, dc, timeout, cipher_types):
    Cipher, algorithms, modes = cipher_types
    writer = None
    started = time.monotonic()
    result = {'dc': abs(dc), 'media': dc < 0, 'ok': False, 'latency_ms': None}
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            # A real MTProxy client hashes each key with the local proxy secret.
            while True:
                init = bytearray(os.urandom(64))
                if (init[0] != 0xEF and bytes(init[:4]) not in
                        (b'HEAD', b'POST', b'GET ', b'\xee' * 4, b'\xdd' * 4,
                         b'\x16\x03\x01\x02') and init[4:8] != bytes(4)):
                    break
            material = bytes(init[8:56])
            reverse = material[::-1]
            encryptor = Cipher(algorithms.AES(hashlib.sha256(material[:32] + secret).digest()),
                               modes.CTR(material[32:])).encryptor()
            decryptor = Cipher(algorithms.AES(hashlib.sha256(reverse[:32] + secret).digest()),
                               modes.CTR(reverse[32:])).encryptor()
            init[56:60] = b'\xdd' * 4
            init[60:62] = struct.pack('<h', dc)
            encrypted_init = encryptor.update(bytes(init))
            init[56:64] = encrypted_init[56:64]
            nonce = os.urandom(16)
            body = struct.pack('<I', REQ_PQ_MULTI) + nonce
            message_id = ((time.time_ns() << 32) // 1_000_000_000) & ~3
            payload = struct.pack('<QQI', 0, message_id, len(body)) + body + os.urandom(7)
            writer.write(bytes(init) + encryptor.update(struct.pack('<I', len(payload)) + payload))
            await writer.drain()
            length, = struct.unpack('<I', decryptor.update(await reader.readexactly(4)))
            if not 4 <= length <= MAX_REPLY:
                raise ValueError('invalid_transport_length')
            reply = decryptor.update(await reader.readexactly(length))
            _validate_reply(reply, nonce)
            result['ok'] = True
    except Exception as exc:
        # Deliberately exclude exception text, packet bytes, nonce and secret.
        result['error'] = type(exc).__name__
        if isinstance(exc, ValueError) and str(exc) in PROTOCOL_ERRORS:
            result['reason'] = str(exc)
    finally:
        result['latency_ms'] = round((time.monotonic() - started) * 1000)
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (OSError, asyncio.TimeoutError):
                writer.transport.abort()
    return result


async def _checks(port, secret, args, cipher_types):
    semaphore = asyncio.Semaphore(args.parallel)

    async def one(dc):
        async with semaphore:
            return await _probe(port, secret, dc, args.timeout, cipher_types)

    return await asyncio.gather(*(one(dc * sign) for dc in range(1, 6) for sign in (1, -1)))


def main():
    args = _arguments()
    python = args.runtime / 'python' / 'python.exe'
    worker = args.runtime / 'app' / 'tg_runner.py'
    if not python.is_file() or not worker.is_file():
        print(json.dumps({'ok': False, 'error': 'runtime_missing'}))
        return 2
    # Use exactly the runtime being diagnosed, including its crypto provider.
    if os.path.normcase(str(Path(sys.executable).resolve())) != os.path.normcase(str(python)):
        return subprocess.run([str(python), str(Path(__file__).resolve()), *sys.argv[1:]],
                              check=False).returncode
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        print(json.dumps({'ok': False, 'error': 'bundled_crypto_missing'}))
        return 2

    report = {'schema': 1, 'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'ok': False, 'checks': [], 'cleanup': {'process_stopped': False, 'listener_closed': False}}
    port = _unused_port()
    secret = os.urandom(16)
    process = None
    try:
        config = {'secret': secret.hex(), 'port': port}
        bundled = args.runtime / 'app' / 'bundled-data.json'
        if bundled.is_file():
            config['domains'] = json.loads(bundled.read_text(encoding='utf-8')).get('cf', [])
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        process = subprocess.Popen([str(python), '-u', str(worker)], cwd=str(args.runtime),
                                   stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env=environment,
                                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        try:
            process.stdin.write((json.dumps(config) + '\n').encode('utf-8'))
            process.stdin.flush()
        finally:
            process.stdin.close()
        deadline = time.monotonic() + 10
        while process.poll() is None and time.monotonic() < deadline and not _listening(port):
            time.sleep(.1)
        if process.poll() is not None or not _listening(port):
            report['error'] = 'worker_not_listening'
        else:
            report['checks'] = asyncio.run(_checks(port, secret, args, (Cipher, algorithms, modes)))
    except KeyboardInterrupt:
        report['error'] = 'interrupted'
    except Exception as exc:
        report['error'] = type(exc).__name__
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            report['cleanup']['process_stopped'] = process.poll() is not None
        else:
            report['cleanup']['process_stopped'] = True
        report['cleanup']['listener_closed'] = not _listening(port)
    report['ok'] = (len(report['checks']) == 10 and all(check['ok'] for check in report['checks'])
                    and all(report['cleanup'].values()) and 'error' not in report)
    encoded = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output is not None:
        try:
            args.output.write_text(encoded + '\n', encoding='utf-8')
        except OSError:
            report['ok'] = False
            report['error'] = 'report_write_failed'
            encoded = json.dumps(report, ensure_ascii=False, indent=2)
    print(encoded)
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    raise SystemExit(main())
