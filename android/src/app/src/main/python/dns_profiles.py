"""Bounded declarative DNS catalog; selection is always a user's decision."""
import ipaddress
import json
import pkgutil
from pathlib import Path
import re
from urllib.parse import urlsplit

CATALOG_URL = 'https://raw.githubusercontent.com/Def01d/SorryRKN/main/dns-profiles.json'
MAX_CATALOG = 32768


def parse_catalog(data):
    if len(data) > MAX_CATALOG:
        raise ValueError('DNS catalog too large')
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError('Invalid DNS catalog')
    profiles = value.get('profiles')
    if type(value.get('schema')) is not int or value.get('schema') != 1 or not isinstance(profiles, list) or not 1 <= len(profiles) <= 12:
        raise ValueError('Invalid DNS catalog')
    seen = set()
    for profile in profiles:
        if not isinstance(profile, dict):
            raise ValueError('Invalid DNS profile')
        identifier, name = profile.get('id', ''), profile.get('name', '')
        if not isinstance(identifier,str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,39}', identifier) or identifier in seen:
            raise ValueError('Invalid DNS profile ID')
        seen.add(identifier)
        if not isinstance(name, str) or not 1 <= len(name) <= 60 or any(ord(c) < 32 for c in name):
            raise ValueError('Invalid DNS profile name')
        if not isinstance(profile.get('url'),str):
            raise ValueError('Invalid DNS HTTPS endpoint')
        url = urlsplit(profile['url'])
        if (url.scheme != 'https' or url.username or url.password or url.port not in (None, 443)
                or url.path != '/dns-query' or url.query or url.fragment or not url.hostname
                or not re.fullmatch(r'(?:[a-z0-9-]+\.)+[a-z]{2,}', url.hostname)):
            raise ValueError('Invalid DNS HTTPS endpoint')
        bootstrap = profile.get('bootstrap', [])
        if not isinstance(bootstrap, list) or len(bootstrap) > 4:
            raise ValueError('Invalid DNS bootstrap')
        if any(not isinstance(address,str) or not ipaddress.ip_address(address).is_global for address in bootstrap):
            raise ValueError('Non-public DNS bootstrap')
    if 'comss' not in seen:
        raise ValueError('Default DNS profile missing')
    return value


def load_catalog(directory=None):
    # Chaquopy loads modules from APK assets: use its loader for bundled data.
    bundled = parse_catalog(pkgutil.get_data(__name__, 'dns_profiles.json'))
    if directory:
        try:
            remote = parse_catalog(Path(directory, 'dns-profiles.json').read_bytes())
            # Preserve every bundled choice if an upstream update omits it.
            merged = {p['id']: p for p in bundled['profiles']}
            merged.update((p['id'], p) for p in remote['profiles'])
            if len(merged) <= 12:
                bundled = dict(remote, profiles=list(merged.values()))
        except (OSError, ValueError, TypeError, KeyError):
            pass
    return bundled


def selected_profile(identifier='comss', directory=None):
    profiles = load_catalog(directory)['profiles']
    return next((p for p in profiles if p['id'] == identifier), profiles[0])


def providers(profile):
    host = urlsplit(profile['url']).hostname
    return tuple((profile['name'], host, address) for address in (profile.get('bootstrap') or [None]))
