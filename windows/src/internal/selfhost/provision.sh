#!/bin/sh
# SorryRKN server protocol 1. Sent over pinned SSH, never executed locally.
set -eu
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
dir=/etc/wireguard/sorryrkn-selfhost
units=/etc/systemd/system
vpn=sorryrkn-vpn.service
socks=sorryrkn-socks.service
die() { printf 'SRKN_ERROR: %s\n' "$1" >&2; exit 1; }

check_unit() {
    path=$units/$1
    [ ! -L "$path" ] || die "A conflicting systemd unit already exists."
    if [ -f "$path" ]; then
        grep -qxF '# Managed by SorryRKN v1' "$path" || die "Refusing to change a foreign systemd unit."
    elif [ "$(systemctl show "$1" -p LoadState --value)" != not-found ]; then
        die "A conflicting systemd unit already exists."
    fi
}

unit_state() {
    if [ ! -f "$units/$1" ]; then echo missing
    elif systemctl is-active --quiet "$1"; then echo running
    else echo stopped
    fi
}

report() {
    printf 'SRKN1\tSTATUS\tvpn:%s\tsocks:%s\n' "$(unit_state "$vpn")" "$(unit_state "$socks")"
}

init_state() {
    [ ! -L /etc/wireguard ] || die "The WireGuard configuration directory is a symbolic link."
    if [ ! -d /etc/wireguard ]; then mkdir -m 700 /etc/wireguard; fi
    if [ ! -e "$dir" ] && [ ! -L "$dir" ]; then
        stage=$(mktemp -d /etc/wireguard/.sorryrkn-selfhost-XXXXXX)
        printf '1\n' > "$stage/version"
        mv -T "$stage" "$dir"
    fi
    [ ! -L "$dir" ] && [ "$(cat "$dir/version" 2>/dev/null)" = 1 ] && [ "$(stat -c '%u:%a' "$dir")" = 0:700 ] || die "The SorryRKN state directory is occupied or unsafe."
}

dependencies() {
    [ -r /etc/os-release ] && grep -Eq '^ID="?((debian)|(ubuntu))"?$' /etc/os-release || die "Supported systems are Debian and Ubuntu with systemd."
    if ! command -v wg >/dev/null || ! command -v iptables >/dev/null || ! command -v python3 >/dev/null || ! command -v ip >/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get -o DPkg::Lock::Timeout=90 update >&2 </dev/null || die "Cannot refresh apt repositories. Check DNS, package mirrors and the dpkg lock."
        apt-get -y --no-install-recommends -o DPkg::Lock::Timeout=90 install wireguard-tools iproute2 iptables python3 >&2 </dev/null || die "Cannot install wireguard-tools, iproute2, iptables and python3. Check apt on the VPS."
    fi
}

init_network() {
    if [ ! -s "$dir/subnet" ]; then
        ip -j -4 route show table all > "$tmp/routes"
        python3 - "$tmp/routes" > "$tmp/subnet" <<'PY'
import ipaddress
import json
import sys
with open(sys.argv[1]) as stream:
    nets = [ipaddress.ip_network(r['dst'], strict=False) for r in json.load(stream)
            if r.get('dst') and r['dst'] != 'default']
for subnet in range(73, 256):
    prefix = f'10.197.{subnet}'
    if all(not net.overlaps(ipaddress.ip_network(prefix+'.0/24')) for net in nets):
        print(prefix)
        break
else:
    sys.exit('SRKN_ERROR: No unused SorryRKN private subnet.')
PY
        mv "$tmp/subnet" "$dir/subnet"
    fi
    subnet=$(cat "$dir/subnet")
    if [ ! -s "$dir/server.key" ]; then
        wg genkey > "$tmp/server.key"
        mv "$tmp/server.key" "$dir/server.key"
    fi
    mkdir -p "$dir/peers"
}

peer() {
    peer_dir=$dir/peers/$id
    if [ ! -d "$peer_dir" ]; then
        slot=2
        while grep -l -x -F "$slot" "$dir"/peers/*/slot >/dev/null 2>&1; do
            slot=$((slot+1))
        done
        [ "$slot" -le 254 ] || die "No available VPN client addresses."
        mkdir "$tmp/peer"
        printf '%s\n' "$slot" > "$tmp/peer/slot"
        wg genkey > "$tmp/peer/key"
        wg genpsk > "$tmp/peer/psk"
        mv "$tmp/peer" "$peer_dir"
    fi
}

firewall_script() {
    cat > "$tmp/firewall" <<'SH'
#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
dir=/etc/wireguard/sorryrkn-selfhost
subnet=$(cat "$dir/subnet")
out=$(cat "$dir/egress")
op=$1
rule() {
    table=$1; shift
    if [ "$op" = up ]; then
        iptables -w 10 -t "$table" -C "$@" 2>/dev/null || iptables -w 10 -t "$table" -I "$@"
    elif iptables -w 10 -t "$table" -C "$@" 2>/dev/null; then
        iptables -w 10 -t "$table" -D "$@"
    fi
}
if [ "$op" = up ]; then
    sysctl -q -w net.ipv4.ip_forward=1
    trap '"$0" down || true' EXIT
fi
rule filter INPUT -i "$out" -p udp --dport 51823 -m comment --comment sorryrkn-vpn -j ACCEPT
rule filter INPUT -i srkn0 -s "$subnet.0/24" -d "$subnet.1" -p tcp --dport 11080 -m comment --comment sorryrkn-socks -j ACCEPT
rule filter FORWARD -i srkn0 -o "$out" -s "$subnet.0/24" -m comment --comment sorryrkn-vpn -j ACCEPT
rule filter FORWARD -i "$out" -o srkn0 -d "$subnet.0/24" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment sorryrkn-vpn -j ACCEPT
rule nat POSTROUTING -s "$subnet.0/24" -o "$out" -m comment --comment sorryrkn-vpn -j MASQUERADE
trap - EXIT
SH
    chmod 700 "$tmp/firewall"
    mv "$tmp/firewall" "$dir/firewall"
}

write_config() {
    egress=$(ip -4 route get 1.1.1.1 | awk 'NR==1 {for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1);exit}}')
    case "$egress" in ''|*[!a-zA-Z0-9_.:-]*) die "No usable IPv4 default route.";; esac
    # A running interface still uses its recorded egress for rule cleanup.
    if ! systemctl is-active --quiet "$vpn" || [ ! -f "$dir/egress" ]; then
        printf '%s\n' "$egress" > "$tmp/egress"
        mv "$tmp/egress" "$dir/egress"
    fi
    {
        printf '[Interface]\nListenPort = 51823\nPrivateKey = %s\n' "$(cat "$dir/server.key")"
        for p in "$dir"/peers/*; do
            [ -d "$p" ] || continue
            printf '\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s.%s/32\n' "$(wg pubkey < "$p/key")" "$(cat "$p/psk")" "$subnet" "$(cat "$p/slot")"
        done
    } > "$tmp/srkn0.conf"
    mv "$tmp/srkn0.conf" "$dir/srkn0.conf"
    if systemctl is-active --quiet "$vpn"; then wg syncconf srkn0 "$dir/srkn0.conf"; fi
    cat > "$tmp/interface" <<'SH'
#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
dir=/etc/wireguard/sorryrkn-selfhost
case "$1" in
up)
    ip link add srkn0 type wireguard
    trap 'ip link del srkn0' EXIT
    ip link set srkn0 alias sorryrkn-selfhost-v1
    wg setconf srkn0 "$dir/srkn0.conf"
    ip addr add "$(cat "$dir/subnet").1/24" dev srkn0
    ip link set srkn0 mtu 1420 up
    "$dir/firewall" up
    trap - EXIT;;
down)
    [ "$(cat /sys/class/net/srkn0/ifalias 2>/dev/null)" = sorryrkn-selfhost-v1 ] || exit 1
    "$dir/firewall" down
    ip link del srkn0;;
*) exit 2;;
esac
SH
    chmod 700 "$tmp/interface"
    mv "$tmp/interface" "$dir/interface"
}

write_unit() {
    # Create the temporary file next to its destination for atomic replacement.
    dest=$(mktemp "$units/.sorryrkn-unit-XXXXXX")
    cat > "$dest"
    chmod 644 "$dest"
    mv "$dest" "$units/$1"
}

install_vpn() {
    dependencies
    if ! systemctl is-active --quiet "$vpn"; then
        if ip link show srkn0 >/dev/null 2>&1; then die "Interface srkn0 is already in use."; fi
        if ss -Hlun 'sport = :51823' | grep -q .; then die "UDP port 51823 is already in use."; fi
    fi
    init_network
    peer
    firewall_script
    write_config
    write_unit "$vpn" <<'UNIT'
# Managed by SorryRKN v1
[Unit]
Description=SorryRKN WireGuard
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/etc/wireguard/sorryrkn-selfhost/interface up
ExecStop=/etc/wireguard/sorryrkn-selfhost/interface down
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now "$vpn" >&2 || die "WireGuard did not start. Check journalctl -u sorryrkn-vpn and kernel WireGuard support."
    systemctl is-active --quiet "$vpn" && wg show srkn0 >/dev/null || die "WireGuard did not start. Check the server kernel and unit log."
    export_vpn
}

export_vpn() {
    p=$dir/peers/$id
    [ -s "$p/key" ] && [ -s "$p/psk" ] && [ -s "$p/slot" ] || die "Install a VPN peer for this device first."
    printf 'SRKN1\tVPN\t%s\t%s\t%s\t%s.%s\t51823\n' "$(cat "$p/key")" "$(wg pubkey < "$dir/server.key")" "$(cat "$p/psk")" "$(cat "$dir/subnet")" "$(cat "$p/slot")"
}

install_socks() {
    systemctl is-active --quiet "$vpn" || die "Start the SorryRKN VPN before installing SOCKS5."
    head=$(cat "$dir/subnet").1
    if [ ! -s "$dir/socks.credential" ]; then
        python3 -c 'import secrets;print(secrets.token_hex(24))' > "$tmp/credential"
        mv "$tmp/credential" "$dir/socks.credential"
    fi
    cat > "$tmp/socks.py" <<'PY'
"""Authenticated SOCKS5 CONNECT listener restricted to the WireGuard address."""
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
    lib=/usr/local/lib/sorryrkn-selfhost
    if [ ! -e "$lib" ]; then
        mkdir -m 755 "$lib"
        printf '1\n' > "$lib/managed-v1"
    fi
    [ ! -L "$lib" ] && [ "$(cat "$lib/managed-v1" 2>/dev/null)" = 1 ] && [ "$(stat -c '%u:%a' "$lib")" = 0:755 ] || die "The SOCKS runtime directory is occupied or unsafe."
    bin_tmp=$(mktemp "$lib/.socks-XXXXXX")
    install -m 644 "$tmp/socks.py" "$bin_tmp"
    mv "$bin_tmp" "$lib/socks.py"
    write_unit "$socks" <<UNIT
# Managed by SorryRKN v1
[Unit]
Description=SorryRKN authenticated SOCKS5 inside WireGuard
After=$vpn
BindsTo=$vpn
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
WantedBy=$vpn
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

main() {
    [ "$(id -u)" = 0 ] || die "Root or passwordless sudo is required."
    [ -d /run/systemd/system ] || die "This server must run systemd."
    action=$1
    id=$2
    case "$id" in *[!0-9a-f]*|'') die "Invalid client ID.";; esac
    [ "$(printf '%s' "$id" | wc -c)" -eq 32 ] || die "Invalid client ID."
    exec 9>/run/lock/sorryrkn-selfhost.lock
    flock -w 90 9 || die "Another SorryRKN server operation is in progress."
    check_unit "$vpn"
    check_unit "$socks"
    # Stage state and keys on the same filesystem so rename is atomic.
    case "$action" in
        install-vpn|install-socks)
            init_state
            tmp=$(mktemp -d "$dir/.stage-XXXXXX");;
        *) tmp=$(mktemp -d /run/sorryrkn-selfhost-XXXXXX);;
    esac
    trap 'rm -rf -- "$tmp"' EXIT
    case "$action" in
        install-vpn) install_vpn;;
        export-vpn) export_vpn;;
        start-vpn) [ -f "$units/$vpn" ] || die "Install the VPN first."; systemctl enable --now "$vpn" >&2; report;;
        stop-vpn) if [ -f "$units/$vpn" ]; then systemctl disable --now "$vpn" >&2; fi; report;;
        install-socks) install_socks;;
        stop-socks) if [ -f "$units/$socks" ]; then systemctl disable --now "$socks" >&2; fi; report;;
        status) report;;
        *) die "Unsupported action.";;
    esac
}

main "$@"
