#!/bin/sh
# Dedicated VLESS/REALITY service, invoked only over authenticated, pinned SSH.
set -eu
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
state=/etc/sorryrkn-reality
lib=/usr/local/lib/sorryrkn-reality
unit=sorryrkn-reality.service
unitfile=/etc/systemd/system/$unit
die() { printf 'SRKN_ERROR: %s\n' "$1" >&2; exit 1; }

[ "$(id -u)" = 0 ] && [ -d /run/systemd/system ] || die "Root and systemd on the VPS are required."
action=$1; id=$2
case "$id" in ''|*[!0-9a-f]*) die "Invalid device ID.";; esac
[ "${#id}" -eq 32 ] || die "Invalid device ID."
case "$action" in reality-on|reality-off|reality-profile|reality-status) :;; *) die "Invalid REALITY action.";; esac
exec 9>/run/lock/sorryrkn-reality.lock
flock -w 90 9 || die "Another SorryRKN REALITY operation is in progress."

# Check both the canonical unit file and systemd's effective fragment/drop-ins.
[ ! -L "$unitfile" ] || die "Conflicting REALITY service."
if [ -e "$unitfile" ]; then
    [ "$(stat -c '%u:%a' "$unitfile")" = 0:644 ] &&
        grep -Fxq '# Managed by SorryRKN REALITY v1' "$unitfile" &&
        [ "$(systemctl show "$unit" -p FragmentPath --value)" = "$unitfile" ] &&
        [ -z "$(systemctl show "$unit" -p DropInPaths --value)" ] || die "Refusing to modify a foreign systemd service."
else
    [ "$(systemctl show "$unit" -p LoadState --value)" = not-found ] || die "Conflicting REALITY service."
fi

status() {
    if [ ! -f "$unitfile" ]; then result=missing
    elif systemctl is-active --quiet "$unit"; then result=running
    else result=stopped
    fi
    printf 'SRKN1\tREALITY-STATUS\t%s\n' "$result"
}

owned() {
    [ ! -L "$1" ] && [ -d "$1" ] && [ "$(stat -c '%u:%a' "$1")" = "0:$2" ] &&
        [ ! -L "$1/managed-v1" ] && [ "$(cat "$1/managed-v1" 2>/dev/null)" = 1 ]
}
create_owned() {
    if [ ! -e "$1" ] && [ ! -L "$1" ]; then
        stage=$(mktemp -d "$(dirname "$1")/.srkn-reality-XXXXXX")
        printf '1\n' > "$stage/managed-v1"
        chmod "$2" "$stage"
        mv -T "$stage" "$1"
    fi
    owned "$1" "$2" || die "REALITY directory already exists or is unsafe."
}

profile() {
    owned "$state" 700 && [ -f "$state/config.json" ] && [ -f "$state/identity.json" ] ||
        die "Set up REALITY for this device first."
    python3 - "$state" "$id" <<'PY'
import json, sys, urllib.parse
from pathlib import Path
root, device = Path(sys.argv[1]), sys.argv[2]
identity = json.loads((root/'identity.json').read_text())
config = json.loads((root/'config.json').read_text())
peer = identity['devices'].get(device)
if not peer or peer['uuid'] not in {u['uuid'] for u in config['inbounds'][0]['users']}:
    sys.exit('SRKN_ERROR: Set up REALITY for this device first.')
query = urllib.parse.urlencode(dict(type='tcp', security='reality', encryption='none',
    flow='xtls-rprx-vision', fp='chrome', sni=identity['sni'], pbk=identity['public'],
    sid=peer['sid']))
print('SRKN1\tREALITY\tvless://'+peer['uuid']+'@sorryrkn.invalid:8443?'+query+'#SorryRKN-REALITY')
PY
}

case "$action" in
    reality-status) status; exit;;
    reality-off) if [ -f "$unitfile" ]; then systemctl disable --now "$unit" >&2; fi; status; exit;;
    reality-profile) profile; exit;;
esac

[ -f /etc/os-release ] && grep -Eq '^ID="?((debian)|(ubuntu))"?$' /etc/os-release ||
    die "REALITY setup supports Debian and Ubuntu with systemd."
export DEBIAN_FRONTEND=noninteractive
if ! command -v python3 >/dev/null || ! command -v curl >/dev/null || ! command -v ss >/dev/null || ! command -v iptables >/dev/null; then
    apt-get -o DPkg::Lock::Timeout=90 update >&2 </dev/null &&
    apt-get -y --no-install-recommends -o DPkg::Lock::Timeout=90 install ca-certificates python3 curl iproute2 iptables >&2 </dev/null ||
        die "Cannot install the required Debian/Ubuntu packages."
fi
active=0
if systemctl is-active --quiet "$unit"; then active=1
elif ss -Hlt 'sport = :8443' | grep -q .; then die "TCP port 8443 is occupied. Select a VPS with a free fallback port."; fi

create_owned "$state" 700
create_owned "$lib" 755
tmp=$(mktemp -d "$state/.stage-XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
version=1.14.4
case "$(uname -m)" in
    x86_64) arch=amd64; hash=699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968;;
    aarch64|arm64) arch=arm64; hash=436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26;;
    *) die "REALITY setup supports amd64 and arm64 Linux.";;
esac
engine=$lib/sing-box-$version
if [ ! -x "$engine" ]; then
    archive=sing-box-$version-linux-$arch
    curl -fSsL --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 180 --retry 2 \
        "https://github.com/SagerNet/sing-box/releases/download/v$version/$archive.tar.gz" -o "$tmp/engine.tar.gz" ||
        die "Cannot download the pinned sing-box release from GitHub."
    printf '%s  %s\n' "$hash" "$tmp/engine.tar.gz" | sha256sum -c - >&2 || die "VPN engine checksum mismatch."
    tar -xzf "$tmp/engine.tar.gz" -C "$tmp" "$archive/sing-box" "$archive/LICENSE"
    f=$(mktemp "$lib/.engine-XXXXXX")
    install -m 755 "$tmp/$archive/sing-box" "$f"; mv -f "$f" "$engine"
    install -m 644 "$tmp/$archive/LICENSE" "$lib/LICENSE"
fi
[ ! -L "$engine" ] && [ "$(stat -c '%u:%a' "$engine")" = 0:755 ] || die "Unsafe REALITY engine file."

# Verify the TLS target from the VPS. A root-only decoy.json can specify a chosen
# TLS 1.3 destination; the integration test uses a local, trusted TLS fixture.
python3 - "$state" "$tmp" "$engine" "$id" <<'PY'
import json, os, secrets, socket, ssl, subprocess, sys, uuid
from pathlib import Path

state, stage = map(Path, sys.argv[1:3])
engine, device = sys.argv[3:]
path = state/'identity.json'
if path.exists():
    identity = json.loads(path.read_text())
else:
    options = []
    custom = state/'decoy.json'
    if custom.exists():
        options.append(json.loads(custom.read_text()))
    else:
        options = [dict(sni=host, host=host, port=443) for host in ('www.microsoft.com','www.cloudflare.com')]
    for dest in options:
        try:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.set_alpn_protocols(['h2','http/1.1'])
            with socket.create_connection((dest['host'], int(dest['port'])), timeout=5) as conn:
                with ctx.wrap_socket(conn, server_hostname=dest['sni']):
                    pass
            break
        except (OSError, ValueError, KeyError):
            continue
    else:
        sys.exit('SRKN_ERROR: The VPS cannot reach a TLS 1.3 handshake target. Check DNS and outbound HTTPS.')
    keys = dict(line.split(': ',1) for line in subprocess.check_output([engine,'generate','reality-keypair'],text=True).strip().splitlines())
    identity = dict(private=keys['PrivateKey'], public=keys['PublicKey'], devices={}, **dest)
if device not in identity['devices']:
    if len(identity['devices']) >= 256: sys.exit('SRKN_ERROR: REALITY device limit reached.')
    identity['devices'][device] = dict(uuid=str(uuid.uuid4()),sid=secrets.token_hex(8))
devices = list(identity['devices'].values())
inbound = dict(type='vless',listen='::',listen_port=8443, users=[dict(uuid=u['uuid'],flow='xtls-rprx-vision') for u in devices],
    tls=dict(enabled=True,server_name=identity['sni'],reality=dict(enabled=True,
    handshake=dict(server=identity['host'],server_port=identity['port']),
    private_key=identity['private'],short_id=[u['sid'] for u in devices])))
config = dict(log=dict(level='warn'),inbounds=[inbound],outbounds=[dict(type='direct',tag='exit')],
              route=dict(final='exit',rules=[dict(ip_is_private=True,action='reject')]))
(stage/'identity.json').write_text(json.dumps(identity))
(stage/'config.json').write_text(json.dumps(config))
os.replace(stage/'identity.json',path)
PY
"$engine" check -c "$tmp/config.json" >&2 || die "The pinned engine rejected the REALITY configuration."

cat > "$tmp/firewall" <<'SH'
#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
op=$1
for fw in iptables ip6tables; do
    command -v "$fw" >/dev/null || continue
    "$fw" -w 5 -S INPUT >/dev/null 2>&1 || continue
    set -- INPUT -p tcp --dport 8443 -m comment --comment sorryrkn-reality -j ACCEPT
    if [ "$op" = up ]; then "$fw" -w 10 -C "$@" 2>/dev/null || "$fw" -w 10 -I "$@"
    elif "$fw" -w 10 -C "$@" 2>/dev/null; then "$fw" -w 10 -D "$@"; fi
done
SH
f=$(mktemp "$lib/.firewall-XXXXXX")
install -m 755 "$tmp/firewall" "$f"; mv -f "$f" "$lib/firewall"

cat > "$tmp/unit" <<UNIT
# Managed by SorryRKN REALITY v1
[Unit]
Description=SorryRKN VLESS REALITY
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
DynamicUser=yes
LoadCredential=config.json:$state/config.json
ExecStartPre=+$lib/firewall up
ExecStart=$engine run -c %d/config.json
ExecStopPost=+$lib/firewall down
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT

changed=0
if ! cmp -s "$tmp/unit" "$unitfile"; then
    f=$(mktemp /etc/systemd/system/.sorryrkn-reality-XXXXXX)
    install -m 644 "$tmp/unit" "$f"; mv -f "$f" "$unitfile"
    systemctl daemon-reload; changed=1
fi
if ! cmp -s "$tmp/config.json" "$state/config.json"; then
    if [ -f "$state/config.json" ]; then cp "$state/config.json" "$tmp/previous.json"; fi
    mv "$tmp/config.json" "$state/config.json"
    changed=1
fi
systemctl enable "$unit" >&2
if [ "$active" = 0 ] || [ "$changed" = 1 ]; then
    systemctl restart "$unit" >&2 || true
fi
# Type=simple reports active before it binds. Check the service PID and the
# actual listener to avoid attributing an unrelated process to SorryRKN.
for delay in 1 2 3 4 5 6 7 8 9 10; do
    pid=$(systemctl show "$unit" -p MainPID --value)
    if [ "$pid" -gt 1 ] && ss -Hltnp 'sport = :8443' | grep -Fq "pid=$pid," &&
        systemctl is-active --quiet "$unit"; then profile; exit; fi
    sleep .4
done
if [ "$active" = 1 ] && [ -f "$tmp/previous.json" ]; then
    mv "$tmp/previous.json" "$state/config.json"
    systemctl restart "$unit" >&2 || true
else
    systemctl disable --now "$unit" >&2 || true
fi
die "REALITY did not bind TCP 8443. Check journalctl -u sorryrkn-reality and the VPS firewall."
