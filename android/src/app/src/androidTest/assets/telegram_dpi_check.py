"""Test APK only: real packaged ByeDPI -> end-to-end TLS -> WSS echo."""
import asyncio
import hashlib
import ssl
import time

from proxy.config import proxy_config
from proxy import raw_websocket


async def run(port, ca_pem, server_ip='10.0.2.2'):
    """No socket patches: use the service's listening native SOCKS5 engine."""
    port = int(port)
    assert 0 < port < 65536
    if isinstance(ca_pem, bytes):
        ca_pem = ca_pem.decode('ascii')
    context = ssl.create_default_context(cadata=ca_pem)
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    old_context = raw_websocket._ssl_ctx
    default_ca_count = old_context.cert_store_stats()['x509_ca']
    old_port = proxy_config.telegram_dpi_port
    ws = None
    started = time.monotonic()
    try:
        proxy_config.telegram_dpi_port = port
        raw_websocket._ssl_ctx = context
        ws = await raw_websocket.RawWebSocket.connect(
            server_ip, 'kws4-1.web.telegram.org', timeout=12)
        peer = ws.writer.get_extra_info('peername')
        assert peer[0] == '127.0.0.1' and peer[1] == port, peer
        tls = ws.writer.get_extra_info('ssl_object')
        assert tls is not None and tls.context is context
        samples = [b'sticker\x00\xff\x01\x80',
                   'эмодзи 🦊 — Telegram'.encode('utf-8'),
                   bytes(range(256)) * 4096]
        measurements = []
        for sample in samples:
            await asyncio.wait_for(ws.send(sample), 10)
            reply = await asyncio.wait_for(ws.recv(), 10)
            assert reply == sample, (len(sample), len(reply) if reply else reply)
            measurements.append({'bytes': len(sample),
                                 'sha256': hashlib.sha256(reply).hexdigest()})
        return {'result': 'PASS', 'transport': 'local SOCKS5 + verified Telegram WSS',
                'socks_port': port, 'sni': 'kws4-1.web.telegram.org',
                'tls': tls.version(), 'hostname_verified': context.check_hostname,
                'default_ca_certificates_before_fixture': default_ca_count,
                'transfers': measurements,
                'total_bytes_each_direction': sum(len(sample) for sample in samples),
                'seconds': round(time.monotonic() - started, 3)}
    finally:
        try:
            if ws is not None:
                await ws.close()
        finally:
            raw_websocket._ssl_ctx = old_context
            proxy_config.telegram_dpi_port = old_port
