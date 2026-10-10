"""Read-only live service checks through the Android Python gateway.

Run with Linux build/test-byedpi to include the real native DPI path. With no
binary, only the DNS/AI relay and direct public services are exercised. No TUN,
system proxy/DNS changes, login, credentials, messages, or media uploads occur.
"""
import argparse
import asyncio
import datetime
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app/src/main/python'))

import httpx
import bridge_data
from discord_gateway import check_gateway
from doh import verified_context
from gateway import Gateway
from service_probe import _classify

HTTP_TARGETS = (
    ('YouTube', 'https://www.youtube.com/generate_204', '204'),
    ('YouTube image CDN', 'https://i.ytimg.com/vi/jNQXAC9IVRw/default.jpg', 'jpeg'),
    ('Discord API', 'https://discord.com/api/v10/gateway', 'gateway'),
    ('Discord CDN', 'https://cdn.discordapp.com/embed/avatars/0.png', 'png'),
    ('Instagram', 'https://www.instagram.com/', 'instagram'),
    ('ChatGPT page', 'https://chatgpt.com/', 'chatgpt'),
    ('ChatGPT auth providers', 'https://chatgpt.com/api/auth/providers', 'providers'),
    ('Telegram web', 'https://web.telegram.org/', 'telegram'),
)


def unused_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


async def start_native(binary, directory, profile, extras):
    port = unused_port()
    options = (bridge_data.extras_args(profile, directory, True, builtins=True, telegram=True)
               if extras else bridge_data.bye_args(profile, directory, True))
    process = subprocess.Popen([str(binary), '--ip', '127.0.0.1', f'--port={port}', *json.loads(options)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        async with asyncio.timeout(5):
            while process.poll() is None:
                try:
                    _, writer = await asyncio.open_connection('127.0.0.1', port)
                    writer.close()
                    await writer.wait_closed()
                    return process, port
                except OSError:
                    await asyncio.sleep(.05)
        raise RuntimeError('native process exited')
    except BaseException:
        if process.poll() is None:
            process.terminate()
        await asyncio.to_thread(process.wait, timeout=3)
        raise


def expected_response(kind, status, body):
    if kind == '204':
        return status == 204 and not body
    if status != 200:
        return False
    if kind == 'png': return body.startswith(b'\x89PNG\r\n\x1a\n')
    if kind == 'jpeg': return body.startswith(b'\xff\xd8\xff')
    if kind in ('providers', 'gateway'):
        try:
            value = json.loads(body)
            if kind == 'gateway': return value.get('url') == 'wss://gateway.discord.gg'
            return value.get('openai', {}).get('id') == 'openai' and value['openai'].get('type') == 'oauth'
        except (ValueError, AttributeError, KeyError):
            return False
    marker = {'instagram': b'static.cdninstagram.com', 'chatgpt': b'chatgpt', 'telegram': b'telegram'}[kind]
    return marker in body.lower()


async def check_http(client, target, gateway, timeout):
    name, url, kind = target
    host = httpx.URL(url).host
    result = {'service': name, 'url': url, 'ok': False,
              'route': gateway.routes.group(host), 'stage': 'HTTPS'}
    started = time.monotonic()
    try:
        async with asyncio.timeout(timeout):
            async with client.stream('GET', url, headers={'Accept-Encoding': 'identity',
                                                          'User-Agent': 'SorryRKN-LiveCheck'}) as response:
                body = bytearray()
                async for chunk in response.aiter_raw():
                    body.extend(chunk[:131072-len(body)])
                    if len(body) >= 131072:
                        break
                encoding = response.headers.get('content-encoding', 'identity')
                inspected = bytes(body) if encoding in ('', 'identity') else b''
                state = _classify(response.status_code, response.headers, inspected)
                ok = (state not in ('challenge', 'regional_refusal', 'denied') and
                      expected_response(kind, response.status_code, inspected))
                result.update(http_status=response.status_code, state=state,
                              ok=ok,
                              bytes_examined=len(inspected))
                if ok:
                    result['state'] = 'verified_public_response'
                if len(body) == 131072:
                    result['body_read_limited'] = True
                if response.headers.get('cf-mitigated') == 'challenge':
                    result['browser_verification_required'] = True
                if encoding not in ('', 'identity'):
                    result['error'] = 'UnsupportedContentEncoding'
    except (httpx.HTTPError, OSError, ValueError, asyncio.TimeoutError) as error:
        result.update(state='transport_error', error=type(error).__name__)
    result['seconds'] = round(time.monotonic()-started, 3)
    return result


async def run(args, directory):
    processes = []
    gateway = None
    try:
        shutil.copyfile(ROOT/'app/src/main/assets/bundled-data.json', directory/'bundled-data.json')
        bridge_data.materialize(directory)
        routes = {'own_ip': args.ai_mode == 'own-ip', 'smart_dns': args.ai_mode == 'relay',
                  'builtin_extras': True}
        if args.byedpi:
            process, common = await start_native(Path(args.byedpi).resolve(), directory, args.profile, False)
            processes.append(process)
            process, extra = await start_native(Path(args.byedpi).resolve(), directory, args.profile, True)
            processes.append(process)
            routes.update(youtube=common, discord=common, instagram=extra, ai=extra)
        elif args.ai_mode == 'own-ip':
            raise ValueError('own-ip live check requires --byedpi')
        gateway = Gateway(port=0, directory=directory, routes=routes)
        await gateway.start()
        ai_route_check = await gateway.check_ai_route()
        transport = httpx.AsyncHTTPTransport(proxy=f'socks5://127.0.0.1:{gateway.port}',
                                             verify=verified_context(), trust_env=False,
                                             limits=httpx.Limits(max_connections=10, max_keepalive_connections=0))
        async with httpx.AsyncClient(transport=transport, trust_env=False, follow_redirects=False,
                                    timeout=args.timeout) as client:
            results = await asyncio.gather(*(check_http(client, target, gateway, args.timeout) for target in HTTP_TARGETS))
        address = await gateway.resolver.resolve('gateway.discord.gg')
        if address:
            discord = await check_gateway(gateway.port, address, timeout=args.timeout)
            discord.update(service='Discord WebSocket', route=gateway.routes.group('gateway.discord.gg'))
            results.append(discord)
        else:
            results.append({'service':'Discord WebSocket','ok':False,'stage':'DNS'})
        if args.telegram_port:
            from telegram_probe import check_telegram
            secret = os.environ.get(args.telegram_secret_env, '')
            if len(secret) != 32:
                raise ValueError('Telegram secret env must contain a 32-character hex secret')
            telegram = await asyncio.gather(*(check_telegram(args.telegram_port, secret, dc=dc,
                                                            timeout=args.timeout) for dc in range(1,6)))
            results.extend(dict(result, service='Telegram MTProto') for result in telegram)
        await asyncio.sleep(.05)  # Allow just-closed diagnostic relays to finish.
        return {'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'ai_mode':args.ai_mode, 'native_dpi':bool(args.byedpi), 'profile':args.profile,
                'ai_route_check':ai_route_check,
                'scope':{'android_tun':False,'authenticated_chatgpt':False,'youtube_playback':False,
                         'discord_voice':False,'telegram_mtproto':bool(args.telegram_port)},
                'results':results, 'gateway':dict(gateway.stats),
                'dns':{'normal':gateway.resolver.provider,
                       'ai':getattr(gateway.resolver.smart,'provider',None)}}
    finally:
        if gateway:
            await gateway.close()
        for process in processes:
            if process.poll() is None:
                process.terminate()
            try:
                await asyncio.to_thread(process.wait, timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait, timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--byedpi', help='Path to the host-native build/test-byedpi binary')
    parser.add_argument('--profile', default='bye-disorder')
    parser.add_argument('--ai-mode', choices=('relay','own-ip'), default='relay')
    parser.add_argument('--timeout', type=float, default=12)
    parser.add_argument('--telegram-port', type=int)
    parser.add_argument('--telegram-secret-env', default='SORRYRKN_TELEGRAM_TEST_SECRET')
    args = parser.parse_args()
    if not 1 <= args.timeout <= 30:
        parser.error('--timeout must be between 1 and 30 seconds')
    build = ROOT/'build'
    build.mkdir(exist_ok=True)
    # Restrict disposable state and cleanup to a new directory inside build.
    with tempfile.TemporaryDirectory(prefix='live-check-', dir=build) as tmp:
        directory = Path(tmp).resolve()
        if directory.parent != build.resolve():
            raise RuntimeError('unexpected temporary directory')
        report = asyncio.run(run(args, directory))
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
