"""Only invoked as root by integration-linux.sh inside a disposable VM."""
import hashlib
import http.client
import ipaddress
import json
import pathlib
import socket
import ssl
import struct
import subprocess
import threading
import urllib.parse
import uuid
import base64
import sys

record = pathlib.Path(sys.argv[1]).read_text().strip().split('\t')[-1]
node = urllib.parse.urlsplit(record)
query = urllib.parse.parse_qs(node.query)
relay_id = uuid.UUID(query['relay'][0])
ca = ssl.DER_cert_to_PEM_cert(base64.urlsafe_b64decode(query['ca'][0] + '==='))
context = ssl.create_default_context(cadata=ca)
authorization = base64.b64encode(f'{node.username}:{node.password}'.encode()).decode()


def exact(stream, size):
    result = bytearray()
    while len(result) < size:
        chunk = stream.recv(size - len(result))
        if not chunk:
            raise EOFError('Relay closed')
        result.extend(chunk)
    return bytes(result)


def connect(host, port):
    stream = context.wrap_socket(socket.create_connection(('127.0.0.1', 443), timeout=5), server_hostname='127.0.0.1')
    stream.settimeout(5)
    stream.sendall(f'CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: Basic {authorization}\r\n\r\n'.encode())
    head = bytearray()
    while not head.endswith(b'\r\n\r\n'):
        head.extend(exact(stream, 1))
        assert len(head) < 16384
    if not head.startswith(b'HTTP/1.1 200 '):
        stream.close()
        raise ConnectionError('CONNECT refused')
    return stream


def vless(command, host, port):
    stream = connect('relay.sorryrkn.invalid', 443)
    address = ipaddress.ip_address(host)
    stream.sendall(b'\0' + relay_id.bytes + b'\0' + bytes([command]) + struct.pack('!H', port) +
                   bytes([1 if address.version == 4 else 3]) + address.packed)
    return stream


config_path = pathlib.Path('/etc/sorryrkn-https/relay.json')
saved = config_path.read_bytes()
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(('127.0.0.1', 0))
port = udp.getsockname()[1]


def echo():
    try:
        for _ in range(100):
            data, peer = udp.recvfrom(65535)
            udp.sendto(data, peer)
    except OSError:
        pass


threading.Thread(target=echo, daemon=True).start()
try:
    config = json.loads(saved)
    config['route']['rules'].insert(1, dict(inbound=['payload'], ip_cidr=['198.18.78.2/32'], port=[port],
        action='route', outbound='exit', override_address='127.0.0.1'))
    config_path.write_text(json.dumps(config))
    subprocess.run(['systemctl', 'restart', 'sorryrkn-relay'], check=True)
    # Restart Type=simple can return before listen. Retry only the handshake.
    import time
    for attempt in range(30):
        try:
            stream = vless(2, '198.18.78.2', port)
            break
        except (OSError, EOFError):
            time.sleep(.1)
    else:
        raise AssertionError('Relay unavailable')
    with stream:
        for index in range(100):
            data = bytes([index]) * (64, 160, 1000, 1300)[index % 4]
            stream.sendall(struct.pack('!H', len(data)) + data)
            if index == 0:
                version, extra = exact(stream, 2)
                assert version == 0
                exact(stream, extra)
            size = struct.unpack('!H', exact(stream, 2))[0]
            assert exact(stream, size) == data, f'UDP payload mismatch {index}'
finally:
    udp.close()
    config_path.write_bytes(saved)
    subprocess.run(['systemctl', 'restart', 'sorryrkn-relay'], check=True)

# The upstream must retain the private-destination policy Caddy no longer applies.
time.sleep(.4)
for private in ('127.0.0.1', '169.254.169.254', '10.0.0.1'):
    try:
        with connect(private, 22) as stream:
            # SOCKS may optimistically acknowledge before routing. Verify that
            # no private-service payload traverses the established HTTP stream.
            stream.sendall(b'probe\r\n')
            if stream.recv(256):
                raise AssertionError('Private destination returned data')
    except (ConnectionError, EOFError, OSError):
        pass
print('HTTPS TCP/UDP: 100 VLESS UDP frames (64/160/1000/1300 bytes) traversed authenticated Caddy CONNECT, loopback gateway and real UDP socket; private destinations refused.')
