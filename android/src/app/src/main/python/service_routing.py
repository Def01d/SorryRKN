"""Opt-in service routes. Anonymous checks never replay application traffic."""
import asyncio
import datetime
import hashlib
import json
from pathlib import Path
import time

from dns_profiles import load_catalog, selected_profile
from service_catalog import DEFINITIONS, SERVICES, service_for_host

RESULT_TTL = 1800


def selection(default='comss', services=None):
    services = services or {}
    if isinstance(services, str):
        services = json.loads(services)
    if not isinstance(services, dict) or len(services) > len(SERVICES):
        raise ValueError('Invalid service DNS choices')
    known = {s[0] for s in SERVICES}
    from re import fullmatch
    if any(k not in known or not isinstance(v, str) or
           v not in ('', 'auto') and not fullmatch(r'[a-z][a-z0-9-]{0,39}', v)
           for k, v in services.items()):
        raise ValueError('Invalid service DNS choice')
    return {'default': default or 'comss', 'services': dict(services)}


def selection_key(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:32]


def fresh(report, network_key, now=None):
    try:
        age = (now or time.time()) - datetime.datetime.fromisoformat(report['checked_at'].replace('Z', '+00:00')).timestamp()
        return bool(network_key) and report.get('network_key') == network_key and -60 <= age < RESULT_TTL
    except (ValueError, TypeError, KeyError, OverflowError,AttributeError):
        return False

def cache_fresh(report,network_key):
    if not fresh(report,network_key):return False
    checked=[c for row in report.get('profiles',()) for c in row.get('results',()) if c.get('state')!='not_checked']
    if report.get('coverage')=='full' and len(checked)==len(report.get('profiles',()))*len(SERVICES) and checked:return True
    if len(checked)>=len(SERVICES) and all(score(c)>0 for c in checked):return True
    when=datetime.datetime.fromisoformat(report['checked_at'].replace('Z','+00:00')).timestamp()
    return time.time()-when<120


def load_report(directory):
    try:
        path = Path(directory, 'dns-scan.json')
        if path.stat().st_size > 131072:
            return {}
        value = json.loads(path.read_text())
        if not isinstance(value,dict) or not isinstance(value.get('profiles'),list) or len(value['profiles'])>12:return {}
        for row in value['profiles']:
            if not isinstance(row,dict) or not isinstance(row.get('results'),list) or len(row['results'])>8:return {}
            if any(not isinstance(c,dict) for c in row['results']):return {}
            if not isinstance(row.get('id'),str):return {}
            if any(not isinstance(c.get('service'),str) or not isinstance(c.get('state'),str) for c in row['results']):return {}
        return value
    except (OSError, ValueError, TypeError):
        return {}


def score(cell):
    return {'reachable_public': 2, 'login_unchecked': 1}.get(cell.get('state'), 0)


def best_profile(report, identifier, preferred, catalog, network_key):
    if not fresh(report, network_key):
        return preferred
    known = {p['id'] for p in catalog['profiles']}
    best, best_score = preferred, 0
    for row in report.get('profiles', ()):
        for cell in row.get('results', ()):
            if cell.get('service') != identifier or row.get('id') not in known:
                continue
            if not fresh(dict(report, checked_at=cell.get('checked_at', report['checked_at'])), network_key):
                continue
            n = score(cell)
            if n > best_score or n > 0 and n == best_score and row['id'] == preferred:
                best, best_score = row['id'], n
    return best


class ServiceRouter:
    def __init__(self, default='comss', choices=None, directory=None, network_key='',allowed=None):
        self.selection = selection(default, choices)
        self.catalog = load_catalog(directory)
        self.default = selected_profile(default, directory)['id']
        report = load_report(directory) if directory else {}
        self.routes = {}
        self.enabled={s['id']:allowed(s['domains'][0]) if allowed else True for s in DEFINITIONS}
        for identifier, _, _ in SERVICES:
            mode = self.selection['services'].get(identifier, '')
            profile = (best_profile(report, identifier, self.default, self.catalog, network_key)
                       if mode == 'auto' else selected_profile(mode or self.default, directory)['id'])
            self.routes[identifier] = {'profile': profile, 'failures': 0, 'changes': 0,
                                       'changed': 0, 'state': ''}
        self.checked = 0
        self.checking = False
        self.cooldowns = {}

    def profile(self, host):
        return self.routes.get(service_for_host(host), {}).get('profile', self.default)

    def snapshot(self):
        return [dict(service=s['id'], name=s['name'], mode=(self.selection['services'].get(s['id']) or 'default'),
                     **{k: self.routes[s['id']][k] for k in ('profile', 'changes', 'state')}) for s in DEFINITIONS]

    async def recover(self, check=None):
        if self.checking or self.checked and time.monotonic() - self.checked < 60:
            return
        if check is None:
            from dns_matrix import probe
            check = probe
        self.checking, self.checked = True, time.monotonic()
        slots = asyncio.Semaphore(4)
        async def one(service):
            identifier = service[0]
            if self.selection['services'].get(identifier) != 'auto' or not self.enabled[identifier]:
                return
            async with slots:
                route = self.routes[identifier]
                current = next(p for p in self.catalog['profiles'] if p['id'] == route['profile'])
                result = await check(current, service)
                route['state'] = result['state']
                if score(result) or result['state'] in ('challenge', 'rate_limited'):
                    route['failures'] = 0
                    return
                route['failures'] += 1
                if route['failures'] < 2 or route['changed'] and time.monotonic() - route['changed'] < 300:
                    return
                for candidate in self.catalog['profiles']:
                    if candidate['id'] == route['profile']:
                        continue
                    key=(identifier,candidate['id'])
                    if self.cooldowns.get(key,0)>time.monotonic():continue
                    result = await check(candidate, service)
                    if score(result):
                        route.update(profile=candidate['id'], state=result['state'], failures=0,
                                     changes=route['changes'] + 1, changed=time.monotonic())
                        return
                    self.cooldowns[key]=time.monotonic()+300
                    return
        tasks = [asyncio.create_task(one(s)) for s in SERVICES]
        try:
            async with asyncio.timeout(35):
                await asyncio.gather(*tasks)
        except TimeoutError:
            pass
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.checking = False
