#!/bin/sh
# SorryRKN server protocol 1. Run over pinned SSH on a Debian/Ubuntu VPS.
set -eu
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
dir=/etc/sorryrkn-https
units=/etc/systemd/system
vpn=sorryrkn-https.service
socks=sorryrkn-proxy.service
runtime=/usr/local/lib/sorryrkn-https
die() { printf 'SRKN_ERROR: %s\n' "$1" >&2; exit 1; }

check_unit() {
    path=$units/$1
    [ ! -L "$path" ] || die "A conflicting systemd unit already exists."
    if [ -f "$path" ]; then
        [ "$(head -n 1 "$path")" = '# Managed by SorryRKN HTTPS v1' ] &&
        [ "$(stat -c '%u:%a' "$path")" = 0:644 ] &&
        [ "$(systemctl show "$1" -p FragmentPath --value)" = "$path" ] &&
        [ -z "$(systemctl show "$1" -p DropInPaths --value)" ] || die "Refusing to change a foreign systemd unit or drop-in."
    elif [ "$(systemctl show "$1" -p LoadState --value)" != not-found ]; then
        die "A conflicting systemd unit already exists."
    fi
}
check_new_unit_paths() {
    [ -f "$units/$1" ] && return 0
    shift
    for slot do
        if [ -e "$slot" ] || [ -L "$slot" ]; then
            die "A service state or runtime path already exists. Refusing to take it over: $slot"
        fi
    done
}
unit_state() {
    if [ ! -f "$units/$1" ]; then echo missing
    elif systemctl is-active --quiet "$1"; then echo running
    else echo stopped
    fi
}
report() { printf 'SRKN1\tSTATUS\tvpn:%s\tsocks:%s\n' "$(unit_state "$vpn")" "$(unit_state "$socks")"; }

owned() {
    if [ ! -e "$1" ] && [ ! -L "$1" ]; then
        stage=$(mktemp -d "$(dirname "$1")/.srkn-https-XXXXXX")
        printf '1\n' > "$stage/managed-v1"
        chmod "$2" "$stage"
        mv -T "$stage" "$1"
    fi
    [ ! -L "$1" ] && [ "$(cat "$1/managed-v1" 2>/dev/null)" = 1 ] && [ "$(stat -c '%u:%a' "$1")" = "0:$2" ] || die "A managed path is occupied or unsafe."
}
write_unit() {
    dest=$(mktemp "$units/.sorryrkn-unit-XXXXXX")
    cat > "$dest"
    chmod 644 "$dest"
    mv "$dest" "$units/$1"
}
deps() {
    [ -r /etc/os-release ] && grep -Eq '^ID="?((debian)|(ubuntu))"?$' /etc/os-release || die "Supported systems are Debian and Ubuntu."
    for tool in curl openssl xz python3 ss iptables; do
        if ! command -v "$tool" >/dev/null; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get -o DPkg::Lock::Timeout=90 update >&2 </dev/null &&
            apt-get -y --no-install-recommends -o DPkg::Lock::Timeout=90 install ca-certificates curl openssl python3 iproute2 xz-utils iptables >&2 </dev/null || die "Cannot install packages. Check apt repositories, DNS and the package lock."
            break
        fi
    done
}

install_engine() {
    [ "$(uname -m)" = x86_64 ] || die "This verified Caddy Naive binary requires an x86-64 VPS."
    # Upstream release v2.11.7-naive2. Check the full archive before extracting
    # only its expected executable. Keep the verified engine on repeated setup.
    digest=c273dc07dd79c5919f97639cbdcb559d40ce90475dbd8aac80641b0a8c8065ff
    if [ ! -x "$runtime/caddy" ] || [ ! -s "$runtime/caddy.sha256" ] || ! (cd "$runtime" && sha256sum -c --status caddy.sha256); then
        curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --retry 2 --max-time 120 https://github.com/klzgrad/forwardproxy/releases/download/v2.11.7-naive2/caddy-forwardproxy-naive.tar.xz -o "$tmp/caddy.xz" || die "Cannot download the verified Caddy server from GitHub."
        printf '%s  %s\n' "$digest" "$tmp/caddy.xz" | sha256sum -c --status || die "Caddy archive digest mismatch."
        dest=$(mktemp "$runtime/.caddy-XXXXXX")
        tar xJOf "$tmp/caddy.xz" caddy-forwardproxy-naive/caddy > "$dest"
        chmod 755 "$dest"
        mv "$dest" "$runtime/caddy"
        (cd "$runtime" && sha256sum caddy > caddy.sha256)
    fi
}

init_identity(){
    if [ ! -s "$dir/identity" ]; then
        python3 - "$host" > "$tmp/identity" <<'PY'
import ipaddress,sys
host=sys.argv[1].lower()
try: ipaddress.ip_address(host); is_ip=True
except ValueError: is_ip=False
public_name=not is_ip and '.' in host and not host.endswith(('.local','.test','.localhost','.invalid','.internal'))
if public_name:
    print('public',host)
else:
    print('private',host)
PY
        mv "$tmp/identity" "$dir/identity"
    fi
    read -r mode sni < "$dir/identity"
    mkdir -p "$dir/clients"
    if [ ! -f "$dir/clients/$id" ]; then
        python3 -c 'import secrets;print(secrets.token_hex(24))' > "$tmp/credential"
        mv "$tmp/credential" "$dir/clients/$id"
    fi
}

configure_https(){
    {
        printf '{\n admin unix//run/sorryrkn-https/admin.sock\n auto_https disable_redirects\n skip_install_trust\n order forward_proxy before file_server\n servers {\n  protocols h1 h2\n }\n'
        if [ "$mode" = private ]; then printf ' default_sni %s\n' "$sni"; fi
        printf ' log {\n  level ERROR\n  exclude http.log.error\n }\n}\n'
        case "$sni" in *:*) site_host="[$sni]";; *) site_host=$sni;; esac
        printf ':443, https://%s {\n' "$site_host"
        if [ "$mode" = private ]; then printf ' tls internal\n'
        else printf ' tls {\n  issuer acme {\n   disable_http_challenge\n  }\n }\n'; fi
        printf ' forward_proxy {\n'
        for peer in "$dir"/clients/*; do
            printf '  basic_auth u%s %s\n' "$(basename "$peer")" "$(cat "$peer")"
        done
        printf '  hide_ip\n  hide_via\n  probe_resistance\n  acl {\n   deny 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 ::/128 ::1/128 fc00::/7 fe80::/10 ff00::/8\n   allow all\n  }\n }\n'
        printf ' root * %s/site\n file_server\n}\n' "$runtime"
    } > "$tmp/Caddyfile"
    "$runtime/caddy" adapt --config "$tmp/Caddyfile" --adapter caddyfile >/dev/null || die "Cannot validate the generated HTTPS configuration."
    cmp -s "$tmp/Caddyfile" "$dir/Caddyfile" || mv "$tmp/Caddyfile" "$dir/Caddyfile"
}

profile(){
    [ -f "$dir/clients/$id" ] || die "Set up HTTPS for this device first."
    python3 - "$dir" "$id" <<'PY'
import base64,pathlib,ssl,sys,urllib.parse
d=pathlib.Path(sys.argv[1]); peer=sys.argv[2]
mode,sni=(d/'identity').read_text().split()
query=dict(sni=sni)
if mode=='private':
    cert=pathlib.Path('/var/lib/sorryrkn-https/caddy/pki/authorities/local/root.crt')
    if not cert.exists(): sys.exit('SRKN_ERROR: The private certificate is not ready.')
    query['ca']=base64.urlsafe_b64encode(ssl.PEM_cert_to_DER_cert(cert.read_text())).decode().rstrip('=')
pw=(d/'clients'/peer).read_text().strip()
print('SRKN1\tHTTPS\tnaive+https://u'+peer+':'+pw+'@sorryrkn.invalid:443/?'+urllib.parse.urlencode(query)+'#SorryRKN')
PY
}

install_https(){
    deps
    if ! systemctl is-active --quiet "$vpn" && ss -Hlt 'sport = :443' | grep -q .; then die "TCP port 443 is already in use by another service."; fi
    install_engine
    init_identity
    mkdir -p -m 755 "$runtime/site"
    if [ ! -f "$runtime/site/index.html" ]; then
        # Use the same welcome page as an ordinary Caddy distribution. Keep
        # any site the owner has subsequently installed here.
        curl -fsSL --proto '=https' --proto-redir '=https' --retry 2 --max-time 30 https://raw.githubusercontent.com/caddyserver/dist/33ae08ff08d168572df2956ed14fbc4949880d94/welcome/index.html -o "$tmp/index.html" || die "Cannot download the standard Caddy welcome page."
        printf '%s  %s\n' 70a45d667679109cd6b25502554597f21536ee995ada0549251167bd171533b9 "$tmp/index.html" | sha256sum -c --status || die "Caddy welcome page digest mismatch."
        install -m 644 "$tmp/index.html" "$runtime/site/index.html"
    fi
    configure_https
    write_unit "$vpn" <<UNIT
# Managed by SorryRKN HTTPS v1
[Unit]
Description=SorryRKN HTTPS
After=network-online.target
Wants=network-online.target
[Service]
DynamicUser=yes
RuntimeDirectory=sorryrkn-https
RuntimeDirectoryMode=0700
StateDirectory=sorryrkn-https
StateDirectoryMode=0700
Environment=XDG_DATA_HOME=/var/lib/sorryrkn-https
Environment=XDG_CONFIG_HOME=/var/lib/sorryrkn-https
LoadCredential=Caddyfile:$dir/Caddyfile
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ExecStartPre=+/bin/sh -c '/usr/sbin/iptables -w 10 -C INPUT -p tcp --dport 443 -m comment --comment sorryrkn-https -j ACCEPT 2>/dev/null || /usr/sbin/iptables -w 10 -I INPUT -p tcp --dport 443 -m comment --comment sorryrkn-https -j ACCEPT'
ExecStart=$runtime/caddy run --config %d/Caddyfile --adapter caddyfile
ExecStopPost=+/bin/sh -c '/usr/sbin/iptables -w 10 -D INPUT -p tcp --dport 443 -m comment --comment sorryrkn-https -j ACCEPT 2>/dev/null || true'
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now "$vpn" >&2 || die "HTTPS did not start. Check journalctl -u sorryrkn-https and TCP 443."
    # SSH may have disconnected after the atomic rename but before reload.
    # Caddy compares with its live configuration and skips a redundant reload.
    ready=0
    for n in $(seq 1 20); do
        if [ -S /run/sorryrkn-https/admin.sock ]; then ready=1; break; fi
        sleep .25
    done
    [ "$ready" = 1 ] && "$runtime/caddy" reload --address unix//run/sorryrkn-https/admin.sock --config "$dir/Caddyfile" --adapter caddyfile >&2 || die "Cannot activate the authenticated HTTPS configuration."
    ready=0
    for n in $(seq 1 30); do
        if [ "$mode" = private ]; then
            ca=/var/lib/sorryrkn-https/caddy/pki/authorities/local/root.crt
            if [ -s "$ca" ] && curl --noproxy '*' -fsS --max-time 3 --cacert "$ca" --connect-to "$site_host:443:127.0.0.1:443" "https://$site_host/" 2>/dev/null | cmp -s "$runtime/site/index.html" -; then ready=1; break; fi
        elif curl --noproxy '*' -fsS --max-time 3 --connect-to "$site_host:443:127.0.0.1:443" "https://$site_host/" 2>/dev/null | cmp -s "$runtime/site/index.html" -; then ready=1; break; fi
        sleep 2
    done
    [ "$ready" = 1 ] || die "Cannot verify the HTTPS certificate and cover page. For a public hostname check DNS and inbound TCP 443, then retry."
    profile
}

install_socks() {
    head=127.0.0.1
    if ! systemctl is-active --quiet "$socks" && ss -Hlt 'sport = :11080' | grep -q .; then die "SOCKS port 11080 is occupied."; fi
    if [ ! -s "$dir/socks.credential" ]; then
        python3 -c 'import secrets;print(secrets.token_hex(24))' > "$tmp/credential"
        mv "$tmp/credential" "$dir/socks.credential"
    fi
    cat > "$tmp/socks.py" <<'PY'
"""Authenticated SOCKS5 CONNECT listener restricted to server loopback."""
import asyncio
import hmac
import os
import socket
import struct
import sys
from pathlib import Path

secret = (Path(os.environ['CREDENTIALS_DIRECTORY']) / 'password').read_bytes().strip()

async def negotiate(reader, writer):
    read = reader.readexactly
    version, count = await read(2)
    if version != 5 or 2 not in await read(count):
        writer.write(b'\x05\xff')
        return
    writer.write(b'\x05\x02')
    await writer.drain()
    version, length = await read(2)
    user = await read(length)
    passwd = await read((await read(1))[0])
    if version != 1 or user != b'sorryrkn' or not hmac.compare_digest(passwd, secret):
        writer.write(b'\x01\x01')
        return
    writer.write(b'\x01\x00')
    await writer.drain()
    ver, command, reserved, kind = await read(4)
    if (ver, command, reserved) != (5, 1, 0):
        writer.write(b'\x05\x07\x00\x01' + bytes(6))
        return
    if kind == 1:
        host = socket.inet_ntop(socket.AF_INET, await read(4))
    elif kind == 4:
        host = socket.inet_ntop(socket.AF_INET6, await read(16))
    elif kind == 3:
        host = (await read((await read(1))[0])).decode('ascii')
    else:
        writer.write(b'\x05\x08\x00\x01' + bytes(6))
        return
    port = struct.unpack('!H', await read(2))[0]
    try:
        stream = await asyncio.open_connection(host, port)
    except (OSError, ValueError):
        writer.write(b'\x05\x05\x00\x01' + bytes(6))
        return
    writer.write(b'\x05\x00\x00\x01' + bytes(6))
    return stream

async def copy(reader, writer):
    while True:
        data = await asyncio.wait_for(reader.read(65536), 300)
        if not data:
            if writer.can_write_eof():
                writer.write_eof()
            return
        writer.write(data)
        await writer.drain()

sessions = 0

async def handle(reader, writer):
    global sessions
    if sessions >= 100:
        writer.close()
        return
    sessions += 1
    upstream = None
    tasks = []
    try:
        stream = await asyncio.wait_for(negotiate(reader, writer), 15)
        if stream:
            remote, upstream = stream
            tasks = [asyncio.create_task(copy(reader, upstream)),
                     asyncio.create_task(copy(remote, writer))]
            await asyncio.gather(*tasks)
    except (OSError, ValueError, EOFError, asyncio.TimeoutError):
        pass
    finally:
        for task in tasks:
            task.cancel()
        if upstream:
            upstream.close()
        writer.close()
        sessions -= 1

async def main():
    server = await asyncio.start_server(handle, sys.argv[1], 11080)
    async with server:
        await server.serve_forever()

asyncio.run(main())
PY
    # DynamicUser needs access to the executable, but not the private state tree.
    lib=$runtime
    bin_tmp=$(mktemp "$lib/.socks-XXXXXX")
    install -m 644 "$tmp/socks.py" "$bin_tmp"
    mv "$bin_tmp" "$lib/socks.py"
    write_unit "$socks" <<UNIT
# Managed by SorryRKN HTTPS v1
[Unit]
Description=SorryRKN loopback SOCKS5 for SSH forwarding
[Service]
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
LoadCredential=password:$dir/socks.credential
ExecStart=/usr/bin/python3 -I $lib/socks.py $head
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now "$socks" >&2 || die "SOCKS5 did not start. Check journalctl -u sorryrkn-socks and systemd credential support."
    # Validate the actual listener and auth round trip before returning credentials.
    python3 - "$head" "$dir/socks.credential" <<'PY'
import socket, sys, time
from pathlib import Path
password = Path(sys.argv[2]).read_bytes().strip()
user = b'sorryrkn'
for attempt in range(20):
    try:
        with socket.create_connection((sys.argv[1],11080),timeout=1) as sock:
            reader = sock.makefile('rb')
            sock.sendall(b'\x05\x01\x02')
            assert reader.read(2) == b'\x05\x02'
            sock.sendall(b'\x01'+bytes([len(user)])+user+bytes([len(password)])+password)
            assert reader.read(2) == b'\x01\x00'
        break
    except (OSError, AssertionError):
        time.sleep(.2)
else:
    sys.exit('SRKN_ERROR: SOCKS5 did not pass the authentication check.')
PY
    printf 'SRKN1\tSOCKS\t%s\t11080\tsorryrkn\t%s\n' "$head" "$(cat "$dir/socks.credential")"
}

main(){
    [ "$(id -u)" = 0 ] && [ -d /run/systemd/system ] || die "Root or passwordless sudo on systemd Linux is required."
    action=$1; id=$2; host=$3
    case "$id" in ''|*[!0-9a-f]*) die "Invalid device ID.";; esac
    [ "$(printf %s "$id" | wc -c)" -eq 32 ] || die "Invalid device ID."
    case "$host" in ''|*[!a-zA-Z0-9_.:-]*) die "Invalid server hostname.";; esac
    [ "$(printf %s "$host" | wc -c)" -le 253 ] || die "Invalid server hostname."
    exec 9>/run/lock/sorryrkn-https.lock
    flock -w 90 9 || die "Another server operation is in progress."
    check_unit "$vpn"; check_unit "$socks"
    case "$action" in
        https-on) check_new_unit_paths "$vpn" /var/lib/sorryrkn-https /var/lib/private/sorryrkn-https /run/sorryrkn-https "/run/credentials/$vpn";;
        install-socks) check_new_unit_paths "$socks" "/run/credentials/$socks";;
    esac
    case "$action" in
        https-on|install-socks)
            owned "$dir" 700; owned "$runtime" 755
            tmp=$(mktemp -d "$dir/.stage-XXXXXX")
            trap 'rm -rf -- "$tmp"' EXIT;;
    esac
    case "$action" in
        https-on) install_https;;
        https-profile) profile;;
        https-start) [ -f "$units/$vpn" ] || die "Install HTTPS first."; systemctl enable --now "$vpn" >&2; report;;
        https-off) if [ -f "$units/$vpn" ]; then systemctl disable --now "$vpn" >&2; fi; report;;
        install-socks) deps; install_socks;;
        stop-socks) if [ -f "$units/$socks" ]; then systemctl disable --now "$socks" >&2; fi; report;;
        status|https-status) report;;
        *) die "Unknown server operation.";;
    esac
}
main "$@"
