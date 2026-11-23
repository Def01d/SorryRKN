#!/bin/sh
# Dedicated SRKN-Mirage v1 server service, invoked only over authenticated, pinned SSH.
set -eu
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
state=/etc/sorryrkn-mirage
lib=/usr/local/lib/sorryrkn-mirage
unit=sorryrkn-mirage.service
unitfile=/etc/systemd/system/$unit
release_tag=mirage-v1.0.0
die() { printf 'SRKN_ERROR: %s\n' "$1" >&2; exit 1; }

[ "$(id -u)" = 0 ] && [ -d /run/systemd/system ] || die "Root and systemd on the VPS are required."
action=$1; id=$2
case "$id" in ''|*[!0-9a-f]*) die "Invalid device ID.";; esac
[ "${#id}" -eq 32 ] || die "Invalid device ID."
case "$action" in mirage-on|mirage-off|mirage-profile|mirage-status|mirage-purge) :;; *) die "Invalid Mirage action.";; esac

exec 9>/run/lock/sorryrkn-mirage.lock
flock -w 90 9 || die "Another SorryRKN Mirage operation is in progress."

[ ! -L "$unitfile" ] || die "Conflicting Mirage service."
if [ -e "$unitfile" ]; then
    [ "$(stat -c '%u:%a' "$unitfile")" = 0:644 ] &&
        grep -Fxq '# Managed by SorryRKN MIRAGE v1' "$unitfile" &&
        [ "$(systemctl show "$unit" -p FragmentPath --value)" = "$unitfile" ] &&
        [ -z "$(systemctl show "$unit" -p DropInPaths --value)" ] || die "Refusing to modify a foreign systemd service."
else
    [ "$(systemctl show "$unit" -p LoadState --value)" = not-found ] || die "Conflicting Mirage service."
    if [ "$action" = mirage-on ] && { [ -e "/run/credentials/$unit" ] || [ -L "/run/credentials/$unit" ]; }; then
        die "Refusing to take over an existing Mirage credential runtime path."
    fi
fi

status() {
    if [ ! -f "$unitfile" ]; then result=missing
    elif systemctl is-active --quiet "$unit"; then result=running
    else result=stopped
    fi
    printf 'SRKN1\tMIRAGE-STATUS\t%s\n' "$result"
}

owned() {
    [ ! -L "$1" ] && [ -d "$1" ] && [ "$(stat -c '%u:%a' "$1")" = "0:$2" ] &&
        [ ! -L "$1/managed-v1" ] && [ "$(cat "$1/managed-v1" 2>/dev/null)" = 1 ]
}

create_owned() {
    if [ ! -e "$1" ] && [ ! -L "$1" ]; then
        stage=$(mktemp -d "$(dirname "$1")/.srkn-mirage-XXXXXX")
        printf '1\n' > "$stage/managed-v1"
        chmod "$2" "$stage"
        mv -T "$stage" "$1"
    fi
    owned "$1" "$2" || die "Mirage directory already exists or is unsafe."
}

profile() {
    owned "$state" 700 && [ -s "$state/secret" ] && [ -s "$state/pin" ] ||
        die "Set up Mirage on this server first."
    sec=$(tr -d '\r\n' < "$state/secret")
    pin=$(tr -d '\r\n' < "$state/pin")
    printf 'SRKN1\tMIRAGE\tmirage://%s@sorryrkn.invalid:2096?sni=edge-telemetry.local&pin=%s&fp=chrome&chaff=1#SorryRKN+Mirage\n' "$sec" "$pin"
}

case "$action" in
    mirage-status) status; exit;;
    mirage-off) if [ -f "$unitfile" ]; then systemctl disable --now "$unit" >&2; fi; status; exit;;
    mirage-profile) profile; exit;;
    mirage-purge)
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
        for fw in iptables ip6tables; do
            command -v "$fw" >/dev/null || continue
            "$fw" -w 10 -D INPUT -p tcp --dport 2096 -m comment --comment sorryrkn-mirage -j ACCEPT 2>/dev/null || true
        done
        rm -f "$unitfile"
        rm -rf -- "$state" "$lib"
        systemctl daemon-reload
        status
        exit;;
esac

[ -f /etc/os-release ] && grep -Eq '^ID="?((debian)|(ubuntu))"?$' /etc/os-release ||
    die "Mirage setup supports Debian and Ubuntu with systemd."
export DEBIAN_FRONTEND=noninteractive
if ! command -v curl >/dev/null || ! command -v ss >/dev/null || ! command -v iptables >/dev/null; then
    apt-get -o DPkg::Lock::Timeout=90 update >&2 </dev/null &&
    apt-get -y --no-install-recommends -o DPkg::Lock::Timeout=90 install ca-certificates curl iproute2 iptables >&2 </dev/null ||
        die "Cannot install required Debian/Ubuntu packages."
fi

active=0
if systemctl is-active --quiet "$unit"; then active=1
elif ss -Hlt 'sport = :2096' | grep -q .; then die "TCP port 2096 is occupied. Free it or pick another VPS."; fi

create_owned "$state" 700
create_owned "$lib" 755
tmp=$(mktemp -d "$state/.stage-XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT

case "$(uname -m)" in
    x86_64|amd64)
        arch=amd64
        digest=341a322ac44b9fffe370f7630fbe56ed5d4eb4c325c8c9a987fd31644dc053e7
        ;;
    aarch64|arm64)
        arch=arm64
        digest=8823a9873116185d394eb65b212e6fcc16d1be89c5da5ada670954f3e828f9b8
        ;;
    *) die "Unsupported VPS CPU architecture for Mirage.";;
esac

bin="$lib/sorryrkn-mirage"
if [ ! -x "$bin" ] || [ ! -s "$lib/engine.sha256" ] || ! (cd "$lib" && sha256sum -c --status engine.sha256); then
    url="https://github.com/Def01d/SorryRKN/releases/download/$release_tag/sorryrkn-mirage-linux-$arch.tar.gz"
    curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 180 --retry 2 "$url" -o "$tmp/mirage.tar.gz" ||
        die "Cannot download the SRKN-Mirage server binary."
    printf '%s  %s\n' "$digest" "$tmp/mirage.tar.gz" | sha256sum -c --status ||
        die "Mirage server archive checksum mismatch."
    tar -xzf "$tmp/mirage.tar.gz" -C "$tmp" sorryrkn-mirage
    f=$(mktemp "$lib/.mirage-XXXXXX")
    install -m 755 "$tmp/sorryrkn-mirage" "$f"
    mv -f "$f" "$bin"
    (cd "$lib" && sha256sum sorryrkn-mirage > engine.sha256)
fi

if [ ! -s "$state/secret" ] || [ ! -s "$state/pin" ] || [ ! -s "$state/cert.pem" ] || [ ! -s "$state/key.pem" ]; then
    "$bin" keygen --cn edge-telemetry.local --out-dir "$tmp/keys" >/dev/null
    chmod 644 "$tmp/keys/cert.pem" "$tmp/keys/pin"
    chmod 600 "$tmp/keys/key.pem" "$tmp/keys/secret"
    mv -f "$tmp/keys/cert.pem" "$state/cert.pem"
    mv -f "$tmp/keys/key.pem" "$state/key.pem"
    mv -f "$tmp/keys/secret" "$state/secret"
    mv -f "$tmp/keys/pin" "$state/pin"
fi

cat > "$tmp/firewall" <<'SH'
#!/bin/sh
set -eu
op=${1:?}
for fw in iptables ip6tables; do
    command -v "$fw" >/dev/null || continue
    "$fw" -w 5 -S INPUT >/dev/null 2>&1 || continue
    set -- INPUT -p tcp --dport 2096 -m comment --comment sorryrkn-mirage -j ACCEPT
    if [ "$op" = up ]; then "$fw" -w 10 -C "$@" 2>/dev/null || "$fw" -w 10 -I "$@"
    elif "$fw" -w 10 -C "$@" 2>/dev/null; then "$fw" -w 10 -D "$@"; fi
done
SH
f=$(mktemp "$lib/.firewall-XXXXXX")
install -m 755 "$tmp/firewall" "$f"; mv -f "$f" "$lib/firewall"

cat > "$tmp/unit" <<UNIT
# Managed by SorryRKN MIRAGE v1
[Unit]
Description=SorryRKN SRKN-Mirage v1 Anti-DPI Server
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
DynamicUser=yes
LoadCredential=cert.pem:$state/cert.pem
LoadCredential=key.pem:$state/key.pem
LoadCredential=secret:$state/secret
ExecStartPre=+$lib/firewall up
ExecStart=$bin server --listen :2096 --cert %d/cert.pem --key %d/key.pem --secret-file %d/secret --chaff=true
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
    f=$(mktemp /etc/systemd/system/.sorryrkn-mirage-XXXXXX)
    install -m 644 "$tmp/unit" "$f"; mv -f "$f" "$unitfile"
    systemctl daemon-reload; changed=1
fi
systemctl enable "$unit" >&2
if [ "$active" = 0 ] || [ "$changed" = 1 ]; then
    systemctl restart "$unit" >&2 || true
fi

for delay in 1 2 3 4 5 6 7 8 9 10; do
    pid=$(systemctl show "$unit" -p MainPID --value)
    if [ "$pid" -gt 1 ] && ss -Hltnp 'sport = :2096' | grep -Fq "pid=$pid," &&
        systemctl is-active --quiet "$unit"; then profile; exit; fi
    sleep .4
done
systemctl disable --now "$unit" >&2 || true
die "Mirage did not bind TCP 2096. Check journalctl -u sorryrkn-mirage and the VPS firewall."
