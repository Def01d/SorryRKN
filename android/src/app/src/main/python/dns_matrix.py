"""Compare anonymous HTTPS responses through each DNS profile, without switching it."""
import asyncio
import datetime
import json
from pathlib import Path
import time

import httpx

from dns_profiles import CATALOG_URL, MAX_CATALOG, load_catalog, parse_catalog, providers
from doh import PinnedTransport, Resolver, verified_context
from service_probe import _classify, _error_stage

SERVICES = (
    ('chatgpt', 'ChatGPT', 'https://chatgpt.com/api/auth/providers'),
    ('claude', 'Claude', 'https://claude.ai/login'),
    ('gemini', 'Gemini', 'https://gemini.google.com/app'),
    ('grok', 'Grok', 'https://grok.com/'),
    ('copilot', 'Copilot', 'https://copilot.microsoft.com/'),
    ('deepseek', 'DeepSeek', 'https://chat.deepseek.com/'),
    ('perplexity', 'Perplexity', 'https://www.perplexity.ai/'),
    ('notebooklm', 'NotebookLM', 'https://notebooklm.google.com/'),
)


async def refresh_catalog(directory):
    target = Path(directory, 'dns-profiles.json')
    if target.is_file() and time.time() - target.stat().st_mtime < 86400:
        return
    try:
        async with httpx.AsyncClient(verify=verified_context(), trust_env=False,
                                    follow_redirects=False, timeout=4) as client:
            async with client.stream('GET', CATALOG_URL) as response:
                response.raise_for_status()
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_CATALOG:
                        raise ValueError('DNS catalog too large')
            incoming = parse_catalog(body)
            current = load_catalog(directory)
            merged = {p['id']: p for p in current['profiles']}
            merged.update((p['id'], p) for p in incoming['profiles'])
            if len(merged)>12:
                raise ValueError('DNS catalog merge too large')
            body = json.dumps(dict(incoming,profiles=list(merged.values())),ensure_ascii=False).encode()
            temporary = target.with_suffix('.part')
            temporary.write_bytes(body)
            temporary.replace(target)
    except (httpx.HTTPError, OSError, ValueError, TypeError):
        pass  # Retain the last validated catalog and bundled choices.


def classify(service_id, status, headers, body):
    state = _classify(status, headers, body)
    if state == 'regional_refusal' or state == 'challenge':
        return state
    if status == 429:
        return 'rate_limited'
    if status == 401:
        return 'login_unchecked'
    if service_id == 'chatgpt' and status == 200:
        try:
            provider = json.loads(body).get('openai', {})
            if provider.get('id') != 'openai' or provider.get('type') != 'oauth':
                return 'invalid_response'
        except (ValueError, AttributeError, TypeError, RecursionError):
            return 'invalid_response'
    return state


async def probe(profile, service):
    identifier, name, url = service
    host = httpx.URL(url).host
    result = {'service': identifier, 'name': name, 'state': 'dns_error',
              'authenticated_access': False}
    started = time.monotonic()
    resolver = Resolver(None, providers=providers(profile))
    try:
        async with asyncio.timeout(7):
            first = await resolver.resolve(host)
            addresses = resolver.last_addresses.get(host, ())[:3]
            if not first:
                return result
            for address in addresses:
                transport = PinnedTransport(httpx.AsyncHTTPTransport(
                    verify=verified_context(), trust_env=False, retries=0,
                    limits=httpx.Limits(max_connections=1, max_keepalive_connections=0)), {host: address})
                try:
                    async with httpx.AsyncClient(transport=transport, trust_env=False,
                                                follow_redirects=False, timeout=3) as client:
                        async with client.stream('GET', url, headers={
                            'User-Agent': 'SorryRKN-DNSCheck', 'Accept-Encoding': 'identity',
                            'Accept': 'text/html, application/json'}) as response:
                            body = bytearray()
                            async for chunk in response.aiter_raw():
                                body.extend(chunk[:32768-len(body)])
                                if len(body) >= 32768:
                                    break
                            encoded = response.headers.get('content-encoding', 'identity')
                            state = (classify(identifier, response.status_code, response.headers, bytes(body))
                                     if encoded in ('', 'identity') else 'invalid_response')
                            result.update(state=state, http_status=response.status_code, address=address)
                            if state in ('reachable_public', 'login_unchecked'):
                                break
                except (httpx.HTTPError, OSError, ValueError) as error:
                    result.update(state='transport_error', stage=_error_stage(error), error=type(error).__name__)
    except asyncio.TimeoutError:
        result.update(state='timeout')
    except (httpx.HTTPError, OSError, ValueError) as error:
        result.update(state='transport_error', stage=_error_stage(error), error=type(error).__name__)
    finally:
        await resolver.close()
        result['latency_ms'] = round((time.monotonic()-started)*1000)
    return result


async def scan(catalog, check=probe, deadline=60):
    semaphore = asyncio.Semaphore(8)
    rows = [{'id': p['id'], 'name': p['name'], 'results': [
        {'service': s[0], 'name': s[1], 'state': 'not_checked', 'authenticated_access': False}
        for s in SERVICES]} for p in catalog['profiles']]
    async def cell(profile_index, service_index):
        async with semaphore:
            try:
                result = await check(catalog['profiles'][profile_index], SERVICES[service_index])
                rows[profile_index]['results'][service_index] = result
            except asyncio.CancelledError:
                raise
            except Exception as error:
                rows[profile_index]['results'][service_index].update(state='transport_error', error=type(error).__name__)
    tasks = [asyncio.create_task(cell(i, j)) for i in range(len(rows)) for j in range(len(SERVICES))]
    try:
        await asyncio.wait_for(asyncio.gather(*tasks), deadline)
    except asyncio.TimeoutError:
        pass
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return {'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
            'scope': 'anonymous_public_https', 'account_checked': False,
            'profiles': rows, 'selection_changed': False}


def catalog_json(directory):
    return json.dumps(load_catalog(directory), ensure_ascii=False)


def scan_json(directory, refresh=True):
    async def run():
        if refresh:
            await refresh_catalog(directory)
        return await scan(load_catalog(directory))
    return json.dumps(asyncio.run(run()), ensure_ascii=False)
