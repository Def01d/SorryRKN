"""Bundled service definitions shared with the Windows build; no remote code."""
import json
import pkgutil

_catalog = json.loads(pkgutil.get_data(__name__, 'services.json'))
assert _catalog['schema'] == 1 and len(_catalog['services']) == 8
DEFINITIONS = tuple(_catalog['services'])
SHARED_DOMAINS=tuple(_catalog.get('shared_domains',()))
SERVICES = tuple((s['id'], s['name'], s['url']) for s in DEFINITIONS)

def services_json():
    return json.dumps(DEFINITIONS,ensure_ascii=False)


def service_for_host(host):
    host = host.lower().rstrip('.')
    matches = [(len(d), s['id']) for s in DEFINITIONS for d in s['domains']
               if host == d or host.endswith('.' + d)]
    return max(matches, default=(0, ''))[1]
