"""Bounded, thread-safe metadata about connection setup; never peer content.

Only fixed route/stage names, validated endpoint names/addresses and numeric
error fields are retained. Exception text, request paths, headers, payloads,
credentials and MTProto secrets must never be passed to this recorder.
"""
import ipaddress
import math
import re
import threading
import time
from collections import OrderedDict, deque

MAX_RECENT = 64
MAX_ACTIVE = 64
MAX_COOLDOWNS = 64
_ROUTES = {'dns', 'ws_direct', 'ws_local_socks', 'ws_fronting', 'native_tcp'}
_STAGES = {'dns', 'tcp', 'local_socket', 'local_socks', 'tls', 'http_upgrade',
           'native_tcp', 'native_init', 'mtproto_probe'}
_COUNTERS = {'native_tcp_backoff_skipped', 'native_tcp_wait_shared',
             'ws_race_selected', 'ws_race_lost', 'ws_refill_backoff_skipped', 'ws_refill_wait_shared'}
_FIELDS = {'errno': (-2147483648, 2147483647), 'verify_code': (0, 2147483647),
           'http_status': (0, 599), 'socks_reply': (0, 255), 'answers': (0, 256)}
_lock = threading.RLock()
_recent = deque(maxlen=MAX_RECENT)
_active = OrderedDict()
_cooldowns = OrderedDict()
_counts = {}
_generation = 0
_serial = 0


def _domain(value):
    if not isinstance(value, str) or not 1 < len(value) <= 253:
        return ''
    value = value.lower().rstrip('.')
    if '.' not in value:
        return ''
    return value if all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
                        for p in value.split('.')) else ''


def _ip(value):
    try:
        return str(ipaddress.ip_address(value)) if isinstance(value, str) and '%' not in value else ''
    except ValueError:
        return ''


def _port(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 < value <= 65535 else 0


def _numbers(values):
    return {key: value for key, value in values.items() if key in _FIELDS
            and isinstance(value, int) and not isinstance(value, bool)
            and _FIELDS[key][0] <= value <= _FIELDS[key][1]}


def _error(error):
    name = type(error).__name__
    result = {'error': name if re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,63}', name) else 'Exception'}
    seen = set()
    current = error
    for _ in range(8):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        for key, value in _numbers({key: getattr(current, key, None)
                                  for key in ('errno', 'verify_code', 'socks_reply', 'http_status')}).items():
            result.setdefault(key, value)
        current = current.__cause__ or current.__context__
    return result


def reset():
    """Forget history; already-running attempts cannot repopulate old data."""
    global _generation
    with _lock:
        _generation += 1
        _recent.clear()
        _active.clear()
        _cooldowns.clear()
        _counts.clear()


def increment(name):
    if name in _COUNTERS:
        with _lock:
            _counts[name] = _counts.get(name, 0) + 1


def cooldown(host, port, failures, until):
    ip, port = _ip(host), _port(port)
    if (not ip or not port or not isinstance(failures, int) or failures < 1
            or not isinstance(until, (int, float)) or not math.isfinite(until)):
        return
    with _lock:
        key = 'native_tcp', ip, port
        _cooldowns[key] = {'route': 'native_tcp', 'ip': ip, 'port': port, 'failures': failures, 'until': until}
        _cooldowns.move_to_end(key)
        while len(_cooldowns) > MAX_COOLDOWNS:
            _cooldowns.popitem(last=False)


def clear_cooldown(host=None, port=None):
    with _lock:
        if host is None:
            for key in list(_cooldowns):
                if key[0] == 'native_tcp':
                    _cooldowns.pop(key, None)
        else:
            _cooldowns.pop(('native_tcp', _ip(host), _port(port)), None)


def pool_cooldown(dc, media, test, failures, until):
    if (not isinstance(dc, int) or isinstance(dc, bool) or not 1 <= dc <= 32767
            or not isinstance(failures, int) or failures < 0
            or not isinstance(until, (int, float)) or not math.isfinite(until)):
        return
    with _lock:
        key = 'ws_pool', dc, bool(media), bool(test)
        _cooldowns[key] = {'route': 'ws_pool', 'dc': dc, 'media': bool(media),
                           'test': bool(test), 'failures': failures, 'until': until}
        _cooldowns.move_to_end(key)
        while len(_cooldowns) > MAX_COOLDOWNS:
            _cooldowns.popitem(last=False)


def clear_pool_cooldown(dc=None, media=False, test=False):
    with _lock:
        if dc is None:
            for key in list(_cooldowns):
                if key[0] == 'ws_pool':
                    _cooldowns.pop(key, None)
        else:
            _cooldowns.pop(('ws_pool', dc, bool(media), bool(test)), None)


def snapshot():
    """Detached JSON-safe copy, callable from Android's UI/Java thread."""
    now = time.monotonic()
    with _lock:
        active = []
        for value in _active.values():
            entry = {key: item for key, item in value.items() if key not in ('started', 'stage_started')}
            entry['duration_ms'] = max(0, round((now - value['stage_started']) * 1000))
            entry['elapsed_ms'] = max(0, round((now - value['started']) * 1000))
            active.append(entry)
        cooldowns = [dict({key: item for key, item in value.items() if key != 'until'},
                          remaining_ms=max(0, round((value['until'] - now) * 1000)))
                     for value in _cooldowns.values() if value['until'] > now]
        return {'recent': [dict(value) for value in _recent], 'active': active,
                'counts': dict(_counts), 'cooldowns': cooldowns}


class Attempt:
    def __init__(self, route, domain='', host='', port=0):
        global _serial
        if route not in _ROUTES:
            raise ValueError('Invalid diagnostic route')
        self.started = self.stage_started = time.monotonic()
        self.current = None
        self.completed = False
        with _lock:
            _serial += 1
            self.generation = _generation
            self.info = {'id': _serial, 'route': route, 'domain': _domain(domain),
                         'ip': _ip(host), 'port': _port(port)}

    def stage(self, name):
        if name not in _STAGES:
            raise ValueError('Invalid diagnostic stage')
        self.current, self.completed = name, False
        self.stage_started = time.monotonic()
        with _lock:
            if self.generation != _generation:
                return
            _active[self.info['id']] = dict(self.info, stage=name, started=self.started,
                                           stage_started=self.stage_started)
            _active.move_to_end(self.info['id'])
            while len(_active) > MAX_ACTIVE:
                _active.popitem(last=False)

    def _record(self, outcome, error=None, **values):
        if self.current is None or self.completed:
            return
        now = time.monotonic()
        entry = dict(self.info, stage=self.current, outcome=outcome,
                     duration_ms=max(0, round((now - self.stage_started) * 1000)),
                     elapsed_ms=max(0, round((now - self.started) * 1000)))
        entry.update(_numbers(values))
        if error is not None:
            entry.update(_error(error))
        with _lock:
            if self.generation == _generation:
                _recent.append(entry)
                key = self.info['route'] + ':' + self.current + ':' + outcome
                _counts[key] = _counts.get(key, 0) + 1
                _active.pop(self.info['id'], None)
        self.completed = True

    def success(self, **values):
        self._record('success', **values)

    def failure(self, error):
        self._record('failure', error)

    def cancel(self):
        self._record('cancelled')

    def finish(self):
        with _lock:
            if self.generation == _generation:
                _active.pop(self.info['id'], None)
