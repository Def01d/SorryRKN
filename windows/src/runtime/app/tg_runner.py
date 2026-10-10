"""SorryRKN Telegram worker. Receives the device secret via stdin, never argv."""
import asyncio
import datetime
import json
import logging
import os
import sys
import tempfile

from proxy import tg_ws_proxy
from proxy.config import proxy_config, coerce_domain_list
from proxy.mtproto_probe import probe_local
from proxy.stats import stats


def configure_domains(config):
    # The app's domain snapshot is a seed, not a user-owned override. Only the
    # explicit upstream option pins the pool and suppresses remote refresh.
    proxy_config.cfproxy_seed_domains = coerce_domain_list(config.get('domains'))
    proxy_config.cfproxy_user_domains = coerce_domain_list(config.get('cfproxy_user_domains'))


def publish_health(path, health):
    """Atomically replace the optional private health file, never persist secrets."""
    if not path:
        return
    parent = os.path.dirname(os.path.abspath(path))
    filename = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=parent,
                                         prefix='.tg-health-', delete=False) as output:
            filename = output.name
            json.dump(health, output)
        os.replace(filename, path)
    finally:
        if filename and os.path.exists(filename):
            os.unlink(filename)


async def monitor_health(path, secret, test_mode=False):
    while tg_ws_proxy._server_instance is None:
        await asyncio.sleep(.05)
    while True:
        checked = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if test_mode:
            health = {'state': 'test', 'checked_at': checked, 'latency_ms': 0,
                      'datacenters': {}, 'error': ''}
        else:
            async def check(dc):
                try:
                    latency = await probe_local(proxy_config.host, proxy_config.port,
                                                secret, dc, timeout=20)
                    return str(dc), {'ok': True, 'latency_ms': latency, 'error': ''}
                except Exception as exc:
                    # Fixed error categories avoid logging endpoint URLs or secrets.
                    return str(dc), {'ok': False, 'latency_ms': 0,
                                     'error': type(exc).__name__}
            results = dict(await asyncio.gather(*(check(dc) for dc in range(1, 6))))
            good = [value['latency_ms'] for value in results.values() if value['ok']]
            health = {'state': 'ready' if len(good) == 5 else 'degraded' if good else 'unavailable',
                      'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'latency_ms': max(good) if good else 0,
                      'datacenters': results,
                      'error': '' if len(good) == 5 else 'mtproto_probe_failed'}
        try:
            publish_health(path, health)
        except OSError as exc:
            logging.warning('Health file update failed: %s', type(exc).__name__)
        print(json.dumps({'telegram': vars(stats), 'health': health}), flush=True)
        await asyncio.sleep(30)


async def main():
    config = json.loads(sys.stdin.readline())
    secret = config['secret']
    if len(secret) != 32 or len(bytes.fromhex(secret)) != 16:
        raise ValueError('Invalid secret')
    proxy_config.secret = secret
    proxy_config.host = '127.0.0.1'
    proxy_config.port = int(config.get('port', 1443))
    if not 1 <= proxy_config.port <= 65535:
        raise ValueError('Invalid port')
    proxy_config.pool_size = 0
    proxy_config.cfproxy_h2_media = False
    configure_domains(config)
    test_mode = bool(config.get('test_mode'))
    proxy_config.test_mode = test_mode
    if test_mode:
        proxy_config.dc_redirects = {}
        proxy_config.fallback_cfproxy = False
    logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
    health_path = config.get('health_path')
    initial = {'state': 'checking', 'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'latency_ms': 0, 'datacenters': {}, 'error': ''}
    publish_health(health_path, initial)
    print(json.dumps({'telegram': vars(stats), 'health': initial}), flush=True)
    task = asyncio.create_task(monitor_health(health_path, bytes.fromhex(secret), test_mode))
    try:
        await tg_ws_proxy._run(asyncio.Event())
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as exc:
        print(json.dumps({'error': type(exc).__name__}), flush=True)
        sys.exit(1)
