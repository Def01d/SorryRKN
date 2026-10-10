"""GitHub data only: pinned snapshots, bounded parsing and atomic last-good storage.

No downloaded file is executed. Windows desync options are never passed to tpws.
Only validated split positions are adapted; this is not winws equivalence.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import time
from urllib.parse import quote

import httpx

_lock = threading.RLock()
_update_lock = threading.Lock()
REPOS = ("Flowseal/zapret-discord-youtube", "Flowseal/tg-ws-proxy")
MAX_BYTES = 1024 * 1024
BASE = [
    {"id": "bye-disorder", "name": "ByeDPI / Disorder", "engine": "byedpi", "args": ["--disorder", "1"]},
    {"id": "bye-tls", "name": "ByeDPI / TLS", "engine": "byedpi", "args": ["--tlsrec", "1+s"]},
    {"id": "bye-disorder-tls", "name": "ByeDPI / Disorder + TLS", "engine": "byedpi", "args": ["--disorder", "1", "--tlsrec", "1+s"]},
    {"id": "bye-oob", "name": "ByeDPI / OOB", "engine": "byedpi", "args": ["--oob", "1+s"]},
    {"id": "bye-disoob", "name": "ByeDPI / DisOOB", "engine": "byedpi", "args": ["--disoob", "1+s"]},
    {"id": "bye-split", "name": "ByeDPI / Split SNI", "engine": "byedpi", "args": ["--split", "1+s", "--split", "0+sm"]},
    *[{"id": "bye-fake-" + str(ttl), "name": "ByeDPI / Fake TTL " + str(ttl), "engine": "byedpi",
       "args": ["--fake", "-1", "--ttl", str(ttl), "--fake-sni", "www.google.com"]} for ttl in (4, 6, 8, 10, 12)],
    {"id": "split", "name": "Split", "args": ["--split-pos=1,midsld", "--mss=1200"]},
    {"id": "tls", "name": "TLS", "args": ["--split-pos=1,midsld", "--tlsrec=sni", "--mss=1200"]},
    {"id": "disorder", "name": "Disorder", "args": ["--split-pos=1,midsld", "--disorder", "--mss=1200"]},
    {"id": "tls-mid", "name": "TLS / SLD", "args": ["--split-pos=midsld", "--tlsrec=snisld"]},
    {"id": "split-host", "name": "Split / Host", "args": ["--split-pos=1,host+1"]},
    {"id": "disorder-host", "name": "Disorder / Host", "args": ["--split-pos=1,host+1", "--disorder"]},
]
_domain = re.compile(r"(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])$")
_position = re.compile(r"(?:-?[1-9][0-9]{0,3}|(?:method|host|endhost|sld|endsld|midsld|sniext)(?:[+-][1-9][0-9]{0,3})?)$")


def domains(text, minimum=1, exact=False):
    if len(text.encode()) > MAX_BYTES:
        raise ValueError("Domain list too large")
    result = []
    seen = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        value = line[1:] if exact and line.startswith("^") else line
        if not _domain.fullmatch(value):
            raise ValueError("Invalid domain list")
        if line not in seen:
            seen.add(line)
            result.append(line)
    if not minimum <= len(result) <= 20000:
        raise ValueError("Incomplete domain list")
    return result


def split_positions(value):
    parts = value.split(",")
    if not 1 <= len(parts) <= 8 or any(not _position.fullmatch(p) for p in parts):
        raise ValueError("Unsupported split position")
    return value


def parse_strategies(scripts):
    result, seen = [], set()
    for filename, text in sorted(scripts.items()):
        if not re.fullmatch(r"general[^/\\]*\.bat", filename, re.I) or len(text) > 65536:
            raise ValueError("Invalid strategy source")
        # Join CMD continuations, then inspect individual winws profiles.
        for block in re.split(r"--new\b", text.replace("^\r\n", " ").replace("^\n", " ")):
            if not re.search(r"--filter-tcp=(?:[0-9]+,)*443(?:,|\s|$)", block):
                continue
            if not re.search(r'--hostlist="?[^\s"]*list-(?:general|google)\.txt', block):
                continue
            mode = re.search(r"--dpi-desync=([a-z,]+)(?:\s|$)", block)
            pos = re.search(r"--dpi-desync-split-pos=([^\s\"^]+)", block)
            if not mode or not pos:
                continue
            modes = mode[1].split(",")
            if not set(modes) & {"multisplit", "multidisorder", "split", "disorder"}:
                continue
            try:
                positions = split_positions(pos[1])
            except ValueError:
                continue  # Future markers require a new APK, not unchecked CLI.
            args = ["--split-pos=" + positions]
            disorder = bool(set(modes) & {"multidisorder", "disorder"})
            if disorder:
                args.append("--disorder")
            key = tuple(args)
            if key in seen:
                continue
            seen.add(key)
            digest = hashlib.sha256(" ".join(args).encode()).hexdigest()[:12]
            result.append({"id": "adapt-" + digest,
                           "name": ("Disorder" if disorder else "Split") + " / " + positions,
                           "source": filename, "args": args})
            if len(result) == 8:
                return result
    return result


def validate(data):
    if data.get("schema") != 1:
        raise ValueError("Unknown data schema")
    checked = data.get("checked", 0)
    if not isinstance(checked, int) or checked < 0 or checked > time.time() + 300:
        raise ValueError("Invalid update time")
    for field in ("hosts", "exclude"):
        if domains("\n".join(data[field]), exact=field == "hosts") != data[field]:
            raise ValueError("Noncanonical domains")
    domains("\n".join(data["cf"]), minimum=3)
    for repo in REPOS:
        if not re.fullmatch("[0-9a-f]{40}", data["commits"][repo]):
            raise ValueError("Invalid commit")
    profiles = data["profiles"]
    if len(profiles) > 8:
        raise ValueError("Too many profiles")
    for profile in profiles:
        args = profile["args"]
        if len(args) not in (1, 2) or not args[0].startswith("--split-pos="):
            raise ValueError("Invalid strategy")
        split_positions(args[0].split("=", 1)[1])
        if len(args) == 2 and args[1] != "--disorder":
            raise ValueError("Unknown strategy argument")
        expected = "adapt-" + hashlib.sha256(" ".join(args).encode()).hexdigest()[:12]
        if profile["id"] != expected or len(profile["name"]) > 100:
            raise ValueError("Invalid strategy identity")
    return data


def load(directory):
    root = Path(directory)
    with _lock:
        for path in (root / "github-data.json", root / "bundled-data.json"):
            try:
                if path.stat().st_size > 3 * MAX_BYTES:
                    continue
                return validate(json.loads(path.read_text()))
            except (OSError, ValueError, KeyError, TypeError):
                continue
    raise ValueError("No valid bundled data")


def catalog(directory):
    return json.dumps(BASE + load(directory)["profiles"], ensure_ascii=False)


def bye_args(profile_id, directory, adaptive=False,hosts_file='bye-hosts.txt'):
    profiles = [p for p in BASE if p.get("engine") == "byedpi"]
    selected = next(p for p in profiles if p["id"] == profile_id)
    if hosts_file not in ('bye-hosts.txt','bye-instagram-hosts.txt','bye-extras-hosts.txt'):raise ValueError('Invalid hosts file')
    hosts = str(Path(directory) / hosts_file)
    args = ["--timeout", "3", "--auto-mode", "o,s", "--hosts", hosts, *selected["args"]]
    if adaptive:
        # Triggered per destination, with a cache independent of the app's
        # network cache. Each group retains the host filter and sorting mode.
        for p in profiles:
            if p["id"] == selected["id"]:
                continue
            args += ["--auto=torst,ssl_err", "--auto-mode=o,s", "--hosts=" + hosts, *p["args"]]
    args += ["--auto=none"]  # unrelated hosts pass without desync
    return json.dumps(args)

def instagram_args(profile_id,directory,adaptive=True):
    from extra_sites import INSTAGRAM_HOSTS
    excluded=load(directory)['exclude']
    hosts=[h for h in INSTAGRAM_HOSTS if not any(h==e or h.endswith('.'+e) for e in excluded)]
    path=Path(directory,'bye-instagram-hosts.txt');temp=path.with_suffix('.tmp')
    temp.write_text('\n'.join(hosts)+'\n');os.replace(temp,path)
    return bye_args(profile_id,directory,adaptive,'bye-instagram-hosts.txt')


def extras_args(profile_id,directory,adaptive=True,geo_domains=(),direct_domains=(),builtins=True,telegram=False):
    """Local DPI only: canonical DNS destinations, no DNS relay endpoint.

    The gateway applies direct exclusions before forwarding to this listener.
    Its decision also covers a direct subdomain of a positive parent filter.
    Java callers may supply domain arrays as JSON strings.
    """
    from extra_sites import AI_HOSTS,INSTAGRAM_HOSTS,TELEGRAM_WS_HOSTS,matches
    from user_rules import DomainRules
    def values(value):
        value=json.loads(value) if isinstance(value,str) else value
        if not isinstance(value,(list,tuple)) or any(not isinstance(v,str) for v in value):
            raise ValueError('Invalid domain list')
        return value
    rules=DomainRules(values(geo_domains),values(direct_domains),bool(builtins))
    excluded=load(directory)['exclude']
    selected=[*(AI_HOSTS+INSTAGRAM_HOSTS if builtins else ()),*rules.geo,
              *(TELEGRAM_WS_HOSTS if telegram else ())]
    hosts=[h for h in dict.fromkeys(selected) if not rules.is_direct(h) and not matches(h,excluded)]
    path=Path(directory,'bye-extras-hosts.txt');temp=path.with_suffix('.tmp')
    temp.write_text('\n'.join(hosts)+'\n');os.replace(temp,path)
    return bye_args(profile_id,directory,adaptive,'bye-extras-hosts.txt')


def materialize(directory):
    data = load(directory)
    from extra_sites import YOUTUBE_HOSTS, DISCORD_HOSTS
    # Essential service roots survive stale remote lists. Exclusions still
    # take precedence in both native engines and gateway routing.
    data = dict(data, hosts=list(dict.fromkeys([*data['hosts'], *YOUTUBE_HOSTS, *DISCORD_HOSTS])))
    root = Path(directory)
    for name, field in (("hosts.txt", "hosts"), ("exclude.txt", "exclude")):
        temp = root / (name + ".tmp")
        temp.write_text("\n".join(data[field]) + "\n")
        os.replace(temp, root / name)
    # ByeDPI has a positive host filter. Build it from the same snapshot and
    # exclusions, removing tpws's exact-host prefix which ByeDPI doesn't parse.
    excluded = set(data["exclude"])
    hosts = [h.lstrip("^") for h in data["hosts"] if not any(
        h.lstrip("^") == e or h.lstrip("^").endswith("." + e) for e in excluded)]
    temp = root / "bye-hosts.tmp"
    temp.write_text("\n".join(hosts) + "\n")
    os.replace(temp, root / "bye-hosts.txt")
    return json.dumps({"commits": data["commits"], "profiles": BASE + data["profiles"]}, sort_keys=True)


def cf_domains(directory):
    return load(directory)["cf"]


def _fetch(client, url, *, json_payload=False):
    content = bytearray()
    with client.stream("GET", url) as response:
        response.raise_for_status()
        for chunk in response.iter_bytes():
            content.extend(chunk)
            if len(content) > MAX_BYTES:
                raise ValueError("GitHub response too large")
    text = content.decode("utf-8-sig", errors="strict")
    return json.loads(text) if json_payload else text


def update(directory, force=False, client=None, control=None):
    with _update_lock:
        previous = load(directory)
        if not force and time.time() - previous.get("checked", 0) < 86400:
            return json.dumps({"changed": False, "checked": previous.get("checked", 0),
                               "commits": previous["commits"]})
        owns_client = client is None
        if owns_client:
            client = httpx.Client(timeout=12, follow_redirects=False, trust_env=False,
                                  headers={"User-Agent": "GrayBridge/0.2", "Accept": "application/vnd.github+json"})
        begin = time.monotonic()
        def fetch(url, **kwargs):
            if time.monotonic() - begin > 90 or (control is not None and not control.keepRunning()):
                raise RuntimeError("Update cancelled or deadline exceeded")
            return _fetch(client, url, **kwargs)
        try:
            commits = {}
            for repo in REPOS:
                payload = fetch(f"https://api.github.com/repos/{repo}/commits/main", json_payload=True)
                commit = payload["sha"]
                if not re.fullmatch("[0-9a-f]{40}", commit):
                    raise ValueError("Invalid GitHub commit")
                commits[repo] = commit
            changed = commits != previous["commits"]
            if changed:
                zapret, tg = REPOS
                raw = f"https://raw.githubusercontent.com/{zapret}/{commits[zapret]}/"
                hosts = domains(fetch(raw + "lists/list-general.txt"), minimum=10, exact=True)
                hosts += domains(fetch(raw + "lists/list-google.txt"), minimum=5, exact=True)
                hosts = list(dict.fromkeys(hosts))
                exclude = domains(fetch(raw + "lists/list-exclude.txt"), minimum=1)
                from proxy.config import _dd
                encoded = fetch(f"https://raw.githubusercontent.com/{tg}/{commits[tg]}/.github/cfproxy-domains.txt")
                cf = domains("\n".join(_dd(s) for s in domains(encoded, minimum=3)), minimum=3)
                tree = fetch(f"https://api.github.com/repos/{zapret}/git/trees/{commits[zapret]}", json_payload=True)
                names = sorted(item["path"] for item in tree["tree"] if item.get("type") == "blob"
                               and re.fullmatch(r"general[^/\\]*\.bat", item["path"], re.I))
                if not 1 <= len(names) <= 32 or tree.get("truncated"):
                    raise ValueError("Unexpected strategy tree")
                scripts = {name: fetch(raw + quote(name, safe="")) for name in names}
                data = {"schema": 1, "commits": commits, "hosts": hosts, "exclude": exclude,
                        "cf": cf, "profiles": parse_strategies(scripts)}
            else:
                data = dict(previous)
            data["checked"] = int(time.time())
            validate(data)
            if control is not None and not control.keepRunning():
                raise RuntimeError("Update cancelled")
            path = Path(directory) / "github-data.json"
            temp = path.with_suffix(".tmp")
            with temp.open("w") as output:
                json.dump(data, output, ensure_ascii=False)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temp, path)  # readers always see a complete, validated snapshot
            return json.dumps({"changed": changed, "checked": data["checked"], "commits": commits})
        finally:
            if owns_client:
                client.close()
