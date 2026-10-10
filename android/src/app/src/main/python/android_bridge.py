"""Lifecycle adapter for Flowseal's MTProto server; called on a serial worker."""
import asyncio
import contextlib
import logging
import json
import threading
from gateway import Gateway

_thread = None
_loop = None
_stop_event = None
_ready = threading.Event()
_error = ""
_active = False
_data_directory = None
_gateway = None
_routes = None
_chatgpt_check = {"state": "disabled", "authenticated_access": False}
_telegram_check = {"state": "disabled", "authenticated_access": False}


async def _check_telegram(secret):
    """Observe protocol replies without restarting sessions or blocking startup."""
    global _telegram_check
    from telegram_probe import check_telegram
    while True:
        results = await asyncio.gather(*(
            check_telegram(1443, secret, dc=dc, timeout=15) for dc in range(1, 6)),
            return_exceptions=True)
        targets = [result if isinstance(result, dict) else {
            'state': 'unavailable', 'dc': dc, 'stage': 'probe',
            'error': type(result).__name__, 'authenticated_access': False,
            'account_checked': False, 'media_access_checked': False,
        } for dc, result in zip(range(1, 6), results)]
        passed = sum(target.get('state') == 'reachable' for target in targets)
        _telegram_check = {
            'state': 'reachable' if passed == len(targets) else 'partial' if passed else 'unavailable',
            'targets': targets, 'authenticated_access': False,
            'passed': passed, 'total': len(targets),
            'latency_ms': min((t['latency_ms'] for t in targets
                               if t.get('state') == 'reachable' and 'latency_ms' in t), default=None),
            'account_checked': False, 'media_access_checked': False,
        }
        # Retry a failed observation, never tear down user connections. The
        # next successful request updates the UI after a network recovers.
        await asyncio.sleep(120 if passed == len(targets) else 30)


async def _check_chatgpt(port, gateway=None):
    global _chatgpt_check
    from service_probe import check_chatgpt
    while True:
        if gateway is not None:
            # Route selection uses only a fresh public diagnostic request.
            # Existing user sockets and their encrypted bytes are untouched.
            with contextlib.suppress(Exception):
                await gateway.check_ai_route()
        try:
            _chatgpt_check = await check_chatgpt(port)
            if _chatgpt_check.get('state') == 'cancelled':
                return
        except Exception as error:
            _chatgpt_check = {'state': 'transport_error', 'error': type(error).__name__,
                              'authenticated_access': False}
        await asyncio.sleep(120 if _chatgpt_check.get('state') == 'reachable_public' else 30)


def apply_data(directory):
    from bridge_data import cf_domains
    from proxy.config import proxy_config
    from proxy.balancer import balancer
    pool = cf_domains(directory)
    proxy_config.cfproxy_seed_domains = pool
    proxy_config.cfproxy_user_domains = []
    balancer.update_domains_list(pool)


async def _serve(secret, telegram, dpi):
    global _loop, _stop_event, _active, _gateway, _chatgpt_check, _telegram_check
    _loop = asyncio.get_running_loop()
    _stop_event = asyncio.Event()
    gateway = Gateway(directory=_data_directory,routes=_routes) if dpi else None
    _gateway = gateway
    telegram_task = None
    service_task = None
    telegram_check_task = None
    _chatgpt_check = {"state": "disabled", "authenticated_access": False}
    _telegram_check = {"state": "disabled", "authenticated_access": False}
    from proxy.route_diagnostics import reset as reset_route_diagnostics
    from proxy.stats import stats as telegram_stats
    reset_route_diagnostics()
    telegram_stats.reset()
    try:
        if gateway:
            await gateway.start()
        if telegram:
            from proxy.config import proxy_config
            from proxy import tg_ws_proxy
            proxy_config.host, proxy_config.port = "127.0.0.1", 1443
            proxy_config.secret = secret
            proxy_config.pool_size = 4
            # Only synthetic req_pq probes select routes. User ciphertext is
            # sent once, after a genuine Telegram protocol reply was checked.
            proxy_config.verified_routes = True
            proxy_config.fallback_cfproxy = bool((_routes or {}).get('telegram_relay', True))
            proxy_config.cfproxy_h2_media = False
            proxy_config.cfproxy_worker_domains = []
            proxy_config.telegram_dpi_port = int((_routes or {}).get('telegram_dpi', 0))
            if _data_directory:
                apply_data(_data_directory)
            telegram_task = asyncio.create_task(tg_ws_proxy._run(_stop_event))
            for _ in range(200):
                if telegram_task.done():
                    telegram_task.result()
                    raise RuntimeError("Telegram listener stopped")
                if tg_ws_proxy._server_instance is not None:
                    break
                await asyncio.sleep(0.05)
            else:
                raise RuntimeError("Telegram listener startup timed out")
        _active = True
        if telegram:
            _telegram_check = {"state": "checking", "authenticated_access": False}
            telegram_check_task = asyncio.create_task(_check_telegram(secret))
        if gateway and _routes and _routes.get('builtin_extras'):
            _chatgpt_check = {"state": "checking", "authenticated_access": False}
            service_task = asyncio.create_task(_check_chatgpt(gateway.port, gateway))
        _ready.set()
        stop_task = asyncio.create_task(_stop_event.wait())
        waiters = [stop_task] + ([telegram_task] if telegram_task else [])
        try:
            await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
            if telegram_task and telegram_task.done():
                telegram_task.result()
        finally:
            stop_task.cancel()
            await asyncio.gather(stop_task, return_exceptions=True)
    finally:
        _active = False
        if telegram_check_task:
            telegram_check_task.cancel()
            await asyncio.gather(telegram_check_task, return_exceptions=True)
        if service_task:
            service_task.cancel()
            await asyncio.gather(service_task, return_exceptions=True)
        if telegram_task:
            from proxy import config
            from proxy import tg_ws_proxy
            config._refresh_stop.set()
            # _run observes this same event and owns orderly listener/client/
            # pool shutdown. Cancelling it here could interrupt its finally
            # halfway through, leaving accepted transports and refills alive.
            _stop_event.set()
            if tg_ws_proxy._server_instance:
                tg_ws_proxy._server_instance.close()
            tg_ws_proxy._abort_clients()
            await asyncio.gather(telegram_task, return_exceptions=True)
            if tg_ws_proxy._server_instance:
                tg_ws_proxy._server_instance.close()
            tg_ws_proxy._abort_clients()
            for task in list(tg_ws_proxy._client_tasks):
                task.cancel()
            await asyncio.gather(*list(tg_ws_proxy._client_tasks), return_exceptions=True)
            await tg_ws_proxy.ws_pool.close()
            if tg_ws_proxy.cf_h2_pool:
                await tg_ws_proxy.cf_h2_pool.close()
                tg_ws_proxy.cf_h2_pool = None
            if tg_ws_proxy._server_instance:
                await tg_ws_proxy._server_instance.wait_closed()
            tg_ws_proxy._server_instance = None
        if gateway:
            await gateway.close()
        _gateway = None


def check_dns():
    if not _gateway or not _loop: return json.dumps({"ok":False,"error":"DNS-модуль не запущен"})
    future=asyncio.run_coroutine_threadsafe(_gateway.check_dns(),_loop)
    try: return json.dumps(future.result(timeout=5),ensure_ascii=False)
    except Exception:
        future.cancel()
        return json.dumps({"ok":False,"error":"Таймаут проверки DNS"},ensure_ascii=False)


def diagnostics():
    result=dict(_gateway.stats) if _gateway else {}
    if _gateway:
        result["dns_provider"]=_gateway.resolver.provider
        if getattr(_gateway, 'ai_route_check', None) is not None:
            result['ai_route_check'] = _gateway.ai_route_check
        if getattr(_gateway.resolver,'smart',None):
            result.update(_gateway.resolver.stats)
            result['smart_dns_provider']=_gateway.resolver.smart.provider
    from proxy.stats import stats as telegram_stats
    result["telegram"] = dict(vars(telegram_stats))
    result["telegram_counters_scope"] = "current_connection"
    from proxy.route_diagnostics import snapshot as route_snapshot
    result["telegram_routes"] = route_snapshot()
    if _telegram_check.get('state') != 'disabled':
        import ssl
        from proxy.raw_websocket import _ssl_ctx, _ssl_ctx_fronting
        result['telegram_tls'] = {
            'openssl': ssl.OPENSSL_VERSION,
            'ca_certificates': _ssl_ctx.cert_store_stats().get('x509_ca', 0),
            'certificate_required': _ssl_ctx.verify_mode == ssl.CERT_REQUIRED,
            'hostname_verified': _ssl_ctx.check_hostname,
            'legacy_certificate_required': _ssl_ctx_fronting.verify_mode == ssl.CERT_REQUIRED,
            'legacy_hostname_verified': _ssl_ctx_fronting.check_hostname,
        }
    from proxy.media_health import diagnostics as media_diagnostics
    result['telegram_media'] = media_diagnostics()
    result["engine_running"]=is_running()
    result['own_ip'] = bool(_routes and _routes.get('own_ip'))
    result['telegram_external_relays'] = bool(_active and _telegram_check.get('state') != 'disabled'
                                              and (_routes or {}).get('telegram_relay', True))
    result['chatgpt_check'] = dict(_chatgpt_check)
    result['telegram_check'] = dict(_telegram_check)
    if _gateway and _routes:result['routes']={key:value for key,value in _routes.items() if key not in ('geo_domains','direct_domains')}
    return json.dumps(result,ensure_ascii=False)


def _worker(secret, telegram, dpi):
    global _error, _loop, _stop_event
    try:
        logging.getLogger("tg-mtproto-proxy").setLevel(logging.WARNING)
        asyncio.run(_serve(secret, telegram, dpi))
    except BaseException as error:
        _error = type(error).__name__ + ": " + str(error)
    finally:
        _loop = _stop_event = None
        _ready.set()


def start(secret, telegram=True, dpi=True, data_directory=None,routes_json=None):
    global _thread, _error, _data_directory,_routes
    if _thread and _thread.is_alive():
        raise RuntimeError("Previous network engine is still running")
    _error = ""
    _data_directory = data_directory
    _routes=json.loads(routes_json) if routes_json else None
    _ready.clear()
    _thread = threading.Thread(target=_worker, args=(secret, telegram, dpi),
                               name="graybridge-network", daemon=True)
    _thread.start()
    if not _ready.wait(15):
        stop()
        raise RuntimeError("Network engine startup timed out")
    if _error:
        raise RuntimeError(_error)
    if not _active:
        raise RuntimeError("Network engine did not start")


def stop():
    global _thread
    loop, event = _loop, _stop_event
    if loop and event and not loop.is_closed():
        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(event.set)
    if _thread:
        _thread.join(10)
        if _thread.is_alive():
            raise RuntimeError("Network engine shutdown timed out")
    _thread = None


def is_running():
    return bool(_active and _thread and _thread.is_alive())
