"""Test APK only: live, account-free checks through the real running service.

No production connector is replaced. All five main/media DC checks enter the
service's secret-protected loopback proxy and validate the complete resPQ nonce.
Two extra WSS checks observe the actual local ByeDPI/TLS path independently.
"""
import asyncio
import datetime
import json
import ssl
import threading
import time

import android_bridge
from proxy import _aes, raw_websocket, verified_routes
from proxy.config import proxy_config
from proxy.stats import stats
from telegram_probe import check_telegram


async def _run(secret):
    assert proxy_config.verified_routes, 'Verified route selection is not enabled'
    assert proxy_config.telegram_dpi_port == 1084, 'Native local DPI engine missing'
    assert hasattr(_aes, '_JavaCipher'), 'Packaged Android AES provider not active'
    assert raw_websocket._ssl_ctx.verify_mode == ssl.CERT_REQUIRED
    assert raw_websocket._ssl_ctx.check_hostname
    engine_thread = android_bridge._thread
    limit = asyncio.Semaphore(4)

    async def check(dc, media):
        async with limit:
            result = await check_telegram(1443, secret, dc=dc, is_media=media, timeout=20)
            cached = verified_routes._cache.get((dc, media, False))
            if cached:
                route = cached[0]
                result['route'] = {'kind': route.kind, 'ip': route.host,
                                   'port': route.port, 'domain': route.domain,
                                   'local_dpi': bool(route.kind == 'ws' and not route.direct),
                                   'tls': route.kind != 'native_tcp'}
            return result

    async def tls_check(dc):
        transport = None
        started = time.monotonic()
        domain = f'kws{dc}.web.telegram.org'
        result = {'dc': dc, 'domain': domain, 'local_dpi_port': 1084,
                  'certificate_validation_required': True, 'hostname_validation_required': True,
                  'certificate_chain_verified': False, 'hostname_verified': False,
                  'state': 'unavailable', 'error': ''}
        try:
            async with asyncio.timeout(8):
                # Actual authenticated TLS to the official host via the running
                # native SOCKS engine; no CA/key substitution in this live check.
                route = verified_routes.Route('ws', domain, domain=domain)
                transport = await verified_routes.open_route(route)
                await verified_routes.exchange(transport, dc)
                result['state'] = 'reachable'
                result['certificate_chain_verified'] = result['hostname_verified'] = True
        except Exception as exc:
            result['error'] = type(exc).__name__
        finally:
            verified_routes.abort(transport)
        result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
        return result

    checks = await asyncio.gather(*(check(dc, media) for dc in range(1, 6) for media in (False, True)))
    tls = await asyncio.gather(*(tls_check(dc) for dc in (2, 4)))
    passed = sum(check['state'] == 'reachable' for check in checks)
    return {'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'result': 'PASS' if passed == 10 else 'FAIL', 'passed': passed, 'total': 10,
            'checks': checks, 'tls_checks': tls, 'android_aes': True,
            'external_relays_enabled': proxy_config.fallback_cfproxy,
            'engine_preserved': android_bridge._thread is engine_thread and android_bridge.is_running(),
            'connections': {'native_tcp': stats.connections_tcp_fallback,
                            'websocket': stats.connections_ws,
                            'fronting': stats.connections_fronting,
                            'cfproxy': stats.connections_cfproxy},
            'authenticated_access': False, 'media_access_checked': False,
            'scope': 'Real Android service, synthetic MTProto only; no account login, message, file, or call checks'}


def run(secret):
    assert android_bridge.is_running() and android_bridge._loop is not None
    assert threading.current_thread() is not android_bridge._thread
    future = asyncio.run_coroutine_threadsafe(_run(secret), android_bridge._loop)
    try:
        return json.dumps(future.result(timeout=75))
    finally:
        if not future.done():
            future.cancel()
