"""SorryRKN Telegram worker. Receives the device secret via stdin, never argv."""
import asyncio,json,logging,sys,os
from proxy import tg_ws_proxy
from proxy.config import proxy_config
from proxy.stats import stats

async def main():
    config=json.loads(sys.stdin.readline())
    secret=config['secret']
    if len(secret)!=32 or len(bytes.fromhex(secret))!=16:raise ValueError('Invalid secret')
    proxy_config.secret=secret
    proxy_config.host='127.0.0.1';proxy_config.port=1443
    proxy_config.pool_size=4
    domains=config.get('domains') or []
    if domains:proxy_config.cfproxy_user_domains=domains
    if config.get('test_mode'):
        proxy_config.dc_redirects={}
        proxy_config.pool_size=0
        proxy_config.fallback_cfproxy=False
        proxy_config.cfproxy_h2_media=False
        proxy_config.cfproxy_user_domains=['example.com']
    logging.basicConfig(level=logging.WARNING,format='%(levelname)s: %(message)s')
    async def report():
        while True:
            await asyncio.sleep(3)
            print(json.dumps({'telegram':vars(stats)}),flush=True)
    task=asyncio.create_task(report())
    try:await tg_ws_proxy._run(asyncio.Event())
    finally:task.cancel()

if __name__=='__main__':
    try:asyncio.run(main())
    except (KeyboardInterrupt,SystemExit):pass
    except Exception as e:
        print(json.dumps({'error':type(e).__name__}),flush=True)
        sys.exit(1)
