#!/bin/sh
# Multi-protocol VPN & SOCKS5 lifecycle manager for Debian/Ubuntu VPS over pinned SSH.
set -eu
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C

units=/etc/systemd/system
protolib=/usr/local/lib/sorryrkn-proto
engine=$protolib/sing-box-1.14.4
marker='# Managed by SorryRKN PROTO v1'

die() { printf 'SRKN_ERROR: %s\n' "$1" >&2; exit 1; }

[ "$(id -u)" = 0 ] && [ -d /run/systemd/system ] || die "Root and systemd on the VPS are required."
action=$1; id=$2
case "$id" in ''|*[!0-9a-f]*) die "Invalid device ID.";; esac
[ "${#id}" -eq 32 ] || die "Invalid device ID."

exec 9>/run/lock/sorryrkn-proto.lock
flock -w 90 9 || die "Another SorryRKN operation is in progress."

unit_state() {
    if [ ! -f "$units/$1" ]; then echo missing
    elif systemctl is-active --quiet "$1"; then echo running
    else echo stopped
    fi
}

check_proto_unit() {
    u=$1; path=$units/$1
    [ ! -L "$path" ] || die "Conflicting systemd unit $u."
    if [ -e "$path" ]; then
        [ "$(stat -c '%u:%a' "$path")" = 0:644 ] &&
            grep -Fxq "$marker" "$path" &&
            [ "$(systemctl show "$u" -p FragmentPath --value)" = "$path" ] &&
            [ -z "$(systemctl show "$u" -p DropInPaths --value)" ] || die "Refusing to modify foreign unit $u."
    elif [ "$(systemctl show "$u" -p LoadState --value)" != not-found ]; then
        die "Conflicting systemd unit $u."
    fi
}

owned_dir() {
    d=$1; mode=$2
    if [ ! -e "$d" ] && [ ! -L "$d" ]; then
        stage=$(mktemp -d "$(dirname "$d")/.srkn-proto-XXXXXX")
        printf '1\n' > "$stage/managed-v1"
        chmod "$mode" "$stage"
        mv -T "$stage" "$d"
    fi
    [ ! -L "$d" ] && [ -d "$d" ] && [ "$(stat -c '%u:%a' "$d")" = "0:$mode" ] &&
        [ ! -L "$d/managed-v1" ] && [ "$(cat "$d/managed-v1" 2>/dev/null)" = 1 ] ||
        die "Managed directory $d is occupied or unsafe."
}

fw_rule() {
    op=$1; proto=$2; port=$3; tag=$4
    for fw in iptables ip6tables; do
        command -v "$fw" >/dev/null || continue
        "$fw" -w 5 -S INPUT >/dev/null 2>&1 || continue
        set -- INPUT -p "$proto" --dport "$port" -m comment --comment "$tag" -j ACCEPT
        if [ "$op" = up ]; then "$fw" -w 10 -C "$@" 2>/dev/null || "$fw" -w 10 -I "$@"
        elif "$fw" -w 10 -C "$@" 2>/dev/null; then "$fw" -w 10 -D "$@"; fi
    done
}

install_deps() {
    [ -f /etc/os-release ] && grep -Eq '^ID="?((debian)|(ubuntu))"?$' /etc/os-release ||
        die "Supported systems are Debian and Ubuntu with systemd."
    export DEBIAN_FRONTEND=noninteractive
    if ! command -v python3 >/dev/null || ! command -v curl >/dev/null || ! command -v ss >/dev/null || ! command -v iptables >/dev/null || ! command -v openssl >/dev/null; then
        apt-get -o DPkg::Lock::Timeout=90 update >&2 </dev/null &&
        apt-get -y --no-install-recommends -o DPkg::Lock::Timeout=90 install ca-certificates openssl python3 curl iproute2 iptables >&2 </dev/null ||
            die "Cannot install required Debian/Ubuntu packages."
    fi
}

ensure_singbox() {
    owned_dir "$protolib" 755
    if [ -x "$engine" ] && [ -s "$protolib/engine.sha256" ] && (cd "$protolib" && sha256sum -c --status engine.sha256); then
        return 0
    fi
    case "$(uname -m)" in
        x86_64|amd64)
            archive=sing-box-1.14.4-linux-amd64
            digest=699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968
            ;;
        aarch64|arm64)
            archive=sing-box-1.14.4-linux-arm64
            digest=436441f7f5ab17078e2f0a5bd12be1618d8d6b235f398b66418b15f5e534a90d
            ;;
        *) die "Unsupported VPS CPU architecture.";;
    esac
    dl_tmp=$(mktemp -d "$protolib/.dl-XXXXXX")
    curl -fSsL --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 180 --retry 2 \
        "https://github.com/SagerNet/sing-box/releases/download/v1.14.4/$archive.tar.gz" -o "$dl_tmp/sb.tar.gz" ||
        { rm -rf -- "$dl_tmp"; die "Cannot download sing-box 1.14.4."; }
    if ! printf '%s  %s\n' "$digest" "$dl_tmp/sb.tar.gz" | sha256sum -c --status; then
        rm -rf -- "$dl_tmp"; die "sing-box checksum mismatch."
    fi
    tar -xzf "$dl_tmp/sb.tar.gz" -C "$dl_tmp" "$archive/sing-box" "$archive/LICENSE"
    f=$(mktemp "$protolib/.sb-XXXXXX")
    install -m 755 "$dl_tmp/$archive/sing-box" "$f"
    mv -f "$f" "$engine"
    install -m 644 "$dl_tmp/$archive/LICENSE" "$protolib/LICENSE"
    (cd "$protolib" && sha256sum sing-box-1.14.4 > engine.sha256)
    rm -rf -- "$dl_tmp"
}

write_singbox_unit() {
    u=$1; desc=$2; state=$3; fwtcp=$4; fwudp=$5; tag=$6
    fwscript=$state/firewall.sh
    tmpu=$(mktemp /etc/systemd/system/.srkn-proto-XXXXXX)
    cat > "$state/firewall.sh" <<SH
#!/bin/sh
set -eu
op=\${1:?}
for fw in iptables ip6tables; do
    command -v "\$fw" >/dev/null || continue
    "\$fw" -w 5 -S INPUT >/dev/null 2>&1 || continue
SH
    if [ -n "$fwtcp" ]; then
        cat >> "$state/firewall.sh" <<SH
    for p in $fwtcp; do
        set -- INPUT -p tcp --dport "\$p" -m comment --comment "$tag" -j ACCEPT
        if [ "\$op" = up ]; then "\$fw" -w 10 -C "\$@" 2>/dev/null || "\$fw" -w 10 -I "\$@"
        elif "\$fw" -w 10 -C "\$@" 2>/dev/null; then "\$fw" -w 10 -D "\$@"; fi
    done
SH
    fi
    if [ -n "$fwudp" ]; then
        cat >> "$state/firewall.sh" <<SH
    for p in $fwudp; do
        set -- INPUT -p udp --dport "\$p" -m comment --comment "$tag" -j ACCEPT
        if [ "\$op" = up ]; then "\$fw" -w 10 -C "\$@" 2>/dev/null || "\$fw" -w 10 -I "\$@"
        elif "\$fw" -w 10 -C "\$@" 2>/dev/null; then "\$fw" -w 10 -D "\$@"; fi
    done
SH
    fi
    cat >> "$state/firewall.sh" <<'SH'
done
SH
    chmod 755 "$fwscript"
    cat > "$tmpu" <<UNIT
$marker
[Unit]
Description=$desc
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
DynamicUser=yes
LoadCredential=config.json:$state/config.json
ExecStartPre=+$fwscript up
ExecStart=$engine run -c %d/config.json
ExecStopPost=+$fwscript down
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
    chmod 644 "$tmpu"
    mv -f "$tmpu" "$units/$u"
    systemctl daemon-reload
    systemctl enable "$u" >&2
    systemctl restart "$u" >&2 || die "$desc failed to start. Check journalctl -u $u."
}

wait_listener() {
    u=$1; kind=$2; port=$3
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
        pid=$(systemctl show "$u" -p MainPID --value)
        if [ "$pid" -gt 1 ] && ss -Hln"${kind}"p "sport = :$port" | grep -Fq "pid=$pid," && systemctl is-active --quiet "$u"; then
            return 0
        fi
        sleep .3
    done
    systemctl disable --now "$u" >&2 || true
    die "Service $u did not bind $kind port $port."
}

# ---- Hysteria2 + Salamander (UDP 8443) ----
hy2_state=/etc/sorryrkn-hy2
hy2_unit=sorryrkn-hy2.service

hy2_profile() {
    [ -s "$hy2_state/meta.json" ] || die "Set up Hysteria2 first."
    python3 - "$hy2_state/meta.json" <<'PY'
import json, sys, urllib.parse
m = json.loads(open(sys.argv[1]).read())
q = urllib.parse.urlencode(dict(
    sni=m['sni'], obfs='salamander', **{'obfs-password': m['obfs']},
    pinSHA256=m['cert_hex'], spki=m['spki_b64']
))
print(f"SRKN1\tHY2\thy2://{urllib.parse.quote(m['password'], safe='')}@sorryrkn.invalid:8443?{q}#SorryRKN+Hysteria2")
PY
}

hy2_on() {
    check_proto_unit "$hy2_unit"
    install_deps
    if ! systemctl is-active --quiet "$hy2_unit" && ss -Hlu 'sport = :8443' | grep -q .; then
        die "UDP port 8443 is occupied."
    fi
    ensure_singbox
    owned_dir "$hy2_state" 700
    tmp=$(mktemp -d "$hy2_state/.stage-XXXXXX")
    trap 'rm -rf -- "$tmp"' EXIT
    if [ ! -s "$hy2_state/cert.pem" ] || [ ! -s "$hy2_state/key.pem" ]; then
        openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/key.pem" 2>/dev/null
        openssl req -new -x509 -days 3650 -key "$tmp/key.pem" -out "$tmp/cert.pem" \
            -subj "/CN=edge.cloudflare.com" -addext "subjectAltName=DNS:edge.cloudflare.com" 2>/dev/null
        mv -f "$tmp/cert.pem" "$hy2_state/cert.pem"
        mv -f "$tmp/key.pem" "$hy2_state/key.pem"
    fi
    cert_hex=$(openssl x509 -in "$hy2_state/cert.pem" -outform DER | sha256sum | awk '{print $1}')
    spki_b64=$(openssl x509 -in "$hy2_state/cert.pem" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl enc -base64 -A)
    python3 - "$hy2_state" "$cert_hex" "$spki_b64" "$tmp/config.json" <<'PY'
import json, pathlib, secrets, sys
st = pathlib.Path(sys.argv[1])
cert_hex, spki_b64, cfg_out = sys.argv[2], sys.argv[3], pathlib.Path(sys.argv[4])
meta_path = st / 'meta.json'
if meta_path.exists():
    meta = json.loads(meta_path.read_text())
else:
    meta = dict(password=secrets.token_urlsafe(24), obfs=secrets.token_urlsafe(18), sni='edge.cloudflare.com')
meta['cert_hex'] = cert_hex
meta['spki_b64'] = spki_b64
meta_path.write_text(json.dumps(meta))
cert_pem = (st / 'cert.pem').read_text()
key_pem = (st / 'key.pem').read_text()
cfg = dict(
    log=dict(level='warn'),
    inbounds=[dict(
        type='hysteria2', tag='hy2-in', listen='::', listen_port=8443,
        obfs=dict(type='salamander', password=meta['obfs']),
        users=[dict(name='owner', password=meta['password'])],
        tls=dict(enabled=True, certificate=[cert_pem], key=[key_pem]),
    )],
    outbounds=[dict(type='direct', tag='exit')],
    dns=dict(servers=[dict(type='local', tag='local')], final='local'),
    route=dict(final='exit', default_domain_resolver='local', rules=[
        dict(action='resolve', server='local', strategy='prefer_ipv4'),
        dict(ip_is_private=True, action='reject'),
        dict(ip_cidr=['0.0.0.0/8','100.64.0.0/10','224.0.0.0/4','::/128','ff00::/8'], action='reject'),
    ]),
)
cfg_out.write_text(json.dumps(cfg))
PY
    "$engine" check -c "$tmp/config.json" >&2 || die "Invalid Hysteria2 configuration."
    mv -f "$tmp/config.json" "$hy2_state/config.json"
    write_singbox_unit "$hy2_unit" "SorryRKN Hysteria2" "$hy2_state" "" "8443" "sorryrkn-hy2"
    wait_listener "$hy2_unit" u 8443
    hy2_profile
}

# ---- VLESS + REALITY gRPC (TCP 2053) ----
grpc_state=/etc/sorryrkn-grpc
grpc_unit=sorryrkn-grpc.service

grpc_profile() {
    [ -s "$grpc_state/identity.json" ] && [ -s "$grpc_state/config.json" ] || die "Set up VLESS gRPC first."
    python3 - "$grpc_state" "$id" <<'PY'
import json, pathlib, sys, urllib.parse
st, dev = pathlib.Path(sys.argv[1]), sys.argv[2]
ident = json.loads((st / 'identity.json').read_text())
peer = ident['devices'].get(dev)
if not peer:
    sys.exit('SRKN_ERROR: Set up VLESS gRPC for this device first.')
q = urllib.parse.urlencode(dict(
    type='grpc', serviceName=ident['service'], security='reality', encryption='none',
    fp='chrome', sni=ident['sni'], pbk=ident['public'], sid=peer['sid']
))
print(f"SRKN1\tGRPC\tvless://{peer['uuid']}@sorryrkn.invalid:2053?{q}#SorryRKN-gRPC")
PY
}

grpc_on() {
    check_proto_unit "$grpc_unit"
    install_deps
    if ! systemctl is-active --quiet "$grpc_unit" && ss -Hlt 'sport = :2053' | grep -q .; then
        die "TCP port 2053 is occupied."
    fi
    ensure_singbox
    owned_dir "$grpc_state" 700
    tmp=$(mktemp -d "$grpc_state/.stage-XXXXXX")
    trap 'rm -rf -- "$tmp"' EXIT
    pair=""
    if [ ! -s "$grpc_state/identity.json" ]; then
        pair=$("$engine" generate reality-keypair)
    fi
    python3 - "$grpc_state" "$id" "$pair" "$tmp/config.json" <<'PY'
import json, pathlib, re, secrets, sys, uuid
st, dev, pair, cfg_out = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3], pathlib.Path(sys.argv[4])
ip = st / 'identity.json'
if ip.exists():
    ident = json.loads(ip.read_text())
else:
    priv = re.search(r'^PrivateKey:\s*(\S+)', pair, re.M).group(1)
    pub = re.search(r'^PublicKey:\s*(\S+)', pair, re.M).group(1)
    decoy = st / 'decoy.json'
    d = json.loads(decoy.read_text()) if decoy.exists() else dict(sni='www.microsoft.com', host='www.microsoft.com', port=443)
    ident = dict(private=priv, public=pub, sni=d['sni'], host=d['host'], port=int(d['port']),
                 service='srkn_' + secrets.token_hex(4), devices={})
ident['devices'].setdefault(dev, dict(uuid=str(uuid.uuid4()), sid=secrets.token_hex(8)))
ip.write_text(json.dumps(ident))
cfg = dict(
    log=dict(level='warn'),
    inbounds=[dict(
        type='vless', tag='grpc-in', listen='::', listen_port=2053,
        users=[dict(uuid=p['uuid']) for p in ident['devices'].values()],
        transport=dict(type='grpc', service_name=ident['service']),
        tls=dict(enabled=True, server_name=ident['sni'], reality=dict(
            enabled=True,
            handshake=dict(server=ident['host'], server_port=ident['port']),
            private_key=ident['private'],
            short_id=[p['sid'] for p in ident['devices'].values()],
        )),
    )],
    outbounds=[dict(type='direct', tag='exit')],
    dns=dict(servers=[dict(type='local', tag='local')], final='local'),
    route=dict(final='exit', default_domain_resolver='local', rules=[
        dict(action='resolve', server='local', strategy='prefer_ipv4'),
        dict(ip_is_private=True, action='reject'),
        dict(ip_cidr=['0.0.0.0/8','100.64.0.0/10','224.0.0.0/4','::/128','ff00::/8'], action='reject'),
    ]),
)
cfg_out.write_text(json.dumps(cfg))
PY
    "$engine" check -c "$tmp/config.json" >&2 || die "Invalid VLESS gRPC configuration."
    mv -f "$tmp/config.json" "$grpc_state/config.json"
    write_singbox_unit "$grpc_unit" "SorryRKN VLESS gRPC" "$grpc_state" "2053" "" "sorryrkn-grpc"
    wait_listener "$grpc_unit" t 2053
    grpc_profile
}

# ---- Shadowsocks 2022 (TCP+UDP 2083) ----
ss_state=/etc/sorryrkn-ss2022
ss_unit=sorryrkn-ss2022.service

ss2022_profile() {
    [ -s "$ss_state/meta.json" ] || die "Set up Shadowsocks 2022 first."
    python3 - "$ss_state/meta.json" <<'PY'
import base64, json, sys
m = json.loads(open(sys.argv[1]).read())
cred = base64.urlsafe_b64encode(f"{m['method']}:{m['password']}".encode()).decode().rstrip('=')
print(f"SRKN1\tSS2022\tss://{cred}@sorryrkn.invalid:2083#SorryRKN-SS2022")
PY
}

ss2022_on() {
    check_proto_unit "$ss_unit"
    install_deps
    if ! systemctl is-active --quiet "$ss_unit" && ss -Hltu 'sport = :2083' | grep -q .; then
        die "Port 2083 is occupied."
    fi
    ensure_singbox
    owned_dir "$ss_state" 700
    tmp=$(mktemp -d "$ss_state/.stage-XXXXXX")
    trap 'rm -rf -- "$tmp"' EXIT
    python3 - "$ss_state" "$tmp/config.json" <<'PY'
import base64, json, os, pathlib, sys
st, cfg_out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
mp = st / 'meta.json'
if mp.exists():
    m = json.loads(mp.read_text())
else:
    m = dict(method='2022-blake3-aes-256-gcm', password=base64.b64encode(os.urandom(32)).decode())
    mp.write_text(json.dumps(m))
cfg = dict(
    log=dict(level='warn'),
    inbounds=[dict(type='shadowsocks', tag='ss-in', listen='::', listen_port=2083,
                   method=m['method'], password=m['password'])],
    outbounds=[dict(type='direct', tag='exit')],
    dns=dict(servers=[dict(type='local', tag='local')], final='local'),
    route=dict(final='exit', default_domain_resolver='local', rules=[
        dict(action='resolve', server='local', strategy='prefer_ipv4'),
        dict(ip_is_private=True, action='reject'),
        dict(ip_cidr=['0.0.0.0/8','100.64.0.0/10','224.0.0.0/4','::/128','ff00::/8'], action='reject'),
    ]),
)
cfg_out.write_text(json.dumps(cfg))
PY
    "$engine" check -c "$tmp/config.json" >&2 || die "Invalid Shadowsocks 2022 configuration."
    mv -f "$tmp/config.json" "$ss_state/config.json"
    write_singbox_unit "$ss_unit" "SorryRKN Shadowsocks 2022" "$ss_state" "2083" "2083" "sorryrkn-ss2022"
    wait_listener "$ss_unit" t 2083
    ss2022_profile
}

# ---- Public Authenticated SOCKS5 (TCP 10808) ----
spub_state=/etc/sorryrkn-socks-pub
spub_unit=sorryrkn-socks-pub.service

spub_profile() {
    [ -s "$spub_state/meta.json" ] || die "Set up public SOCKS5 first."
    python3 - "$spub_state/meta.json" <<'PY'
import json, sys
m = json.loads(open(sys.argv[1]).read())
print(f"SRKN1\tSOCKS-PUB\t10808\t{m['user']}\t{m['password']}")
PY
}

spub_on() {
    check_proto_unit "$spub_unit"
    install_deps
    if ! systemctl is-active --quiet "$spub_unit" && ss -Hlt 'sport = :10808' | grep -q .; then
        die "TCP port 10808 is occupied."
    fi
    ensure_singbox
    owned_dir "$spub_state" 700
    tmp=$(mktemp -d "$spub_state/.stage-XXXXXX")
    trap 'rm -rf -- "$tmp"' EXIT
    python3 - "$spub_state" "$tmp/config.json" <<'PY'
import json, pathlib, secrets, sys
st, cfg_out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
mp = st / 'meta.json'
if mp.exists():
    m = json.loads(mp.read_text())
else:
    m = dict(user='srkn_' + secrets.token_hex(4), password=secrets.token_urlsafe(24))
    mp.write_text(json.dumps(m))
cfg = dict(
    log=dict(level='warn'),
    inbounds=[dict(type='socks', tag='socks-pub-in', listen='::', listen_port=10808,
                   users=[dict(username=m['user'], password=m['password'])])],
    outbounds=[dict(type='direct', tag='exit')],
    dns=dict(servers=[dict(type='local', tag='local')], final='local'),
    route=dict(final='exit', default_domain_resolver='local', rules=[
        dict(action='resolve', server='local', strategy='prefer_ipv4'),
        dict(ip_is_private=True, action='reject'),
        dict(ip_cidr=['0.0.0.0/8','100.64.0.0/10','224.0.0.0/4','::/128','ff00::/8'], action='reject'),
    ]),
)
cfg_out.write_text(json.dumps(cfg))
PY
    "$engine" check -c "$tmp/config.json" >&2 || die "Invalid public SOCKS5 configuration."
    mv -f "$tmp/config.json" "$spub_state/config.json"
    write_singbox_unit "$spub_unit" "SorryRKN Public SOCKS5" "$spub_state" "10808" "" "sorryrkn-socks-pub"
    wait_listener "$spub_unit" t 10808
    spub_profile
}

purge_single() {
    u=$1; st=$2; t=$3; p=$4; tag=$5
    systemctl disable --now "$u" >/dev/null 2>&1 || true
    [ -z "$t" ] || fw_rule down tcp "$t" "$tag"
    [ -z "$p" ] || fw_rule down udp "$p" "$tag"
    rm -f "$units/$u"
    rm -rf -- "$st"
    systemctl daemon-reload
}

purge_all() {
    for u in sorryrkn-https.service sorryrkn-relay.service sorryrkn-proxy.service sorryrkn-reality.service sorryrkn-mirage.service sorryrkn-hy2.service sorryrkn-grpc.service sorryrkn-ss2022.service sorryrkn-socks-pub.service; do
        systemctl disable --now "$u" >/dev/null 2>&1 || true
        rm -f "$units/$u"
    done
    fw_rule down tcp 443 sorryrkn-https
    fw_rule down tcp 8443 sorryrkn-reality
    fw_rule down tcp 2096 sorryrkn-mirage
    fw_rule down udp 8443 sorryrkn-hy2
    fw_rule down tcp 2053 sorryrkn-grpc
    fw_rule down tcp 2083 sorryrkn-ss2022
    fw_rule down udp 2083 sorryrkn-ss2022
    fw_rule down tcp 10808 sorryrkn-socks-pub
    rm -rf -- /etc/sorryrkn-* /usr/local/lib/sorryrkn-* /var/lib/sorryrkn-* /var/lib/private/sorryrkn-* /run/sorryrkn-*
    systemctl daemon-reload
    printf 'SRKN1\tPURGED\tall\n'
}

fleet_status() {
    printf 'SRKN1\tFLEET\thttps:%s\tmirage:%s\treality:%s\thy2:%s\tgrpc:%s\tss2022:%s\tsocks_ssh:%s\tsocks_pub:%s\n' \
        "$(unit_state sorryrkn-https.service)" \
        "$(unit_state sorryrkn-mirage.service)" \
        "$(unit_state sorryrkn-reality.service)" \
        "$(unit_state sorryrkn-hy2.service)" \
        "$(unit_state sorryrkn-grpc.service)" \
        "$(unit_state sorryrkn-ss2022.service)" \
        "$(unit_state sorryrkn-proxy.service)" \
        "$(unit_state sorryrkn-socks-pub.service)"
}

case "$action" in
    hy2-on) hy2_on;;
    hy2-profile) hy2_profile;;
    hy2-off) [ -f "$units/$hy2_unit" ] && systemctl disable --now "$hy2_unit" >&2 || true; printf 'SRKN1\tHY2-STATUS\t%s\n' "$(unit_state "$hy2_unit")";;
    hy2-status) printf 'SRKN1\tHY2-STATUS\t%s\n' "$(unit_state "$hy2_unit")";;
    hy2-purge) purge_single "$hy2_unit" "$hy2_state" "" "8443" "sorryrkn-hy2"; printf 'SRKN1\tHY2-STATUS\tmissing\n';;

    grpc-on) grpc_on;;
    grpc-profile) grpc_profile;;
    grpc-off) [ -f "$units/$grpc_unit" ] && systemctl disable --now "$grpc_unit" >&2 || true; printf 'SRKN1\tGRPC-STATUS\t%s\n' "$(unit_state "$grpc_unit")";;
    grpc-status) printf 'SRKN1\tGRPC-STATUS\t%s\n' "$(unit_state "$grpc_unit")";;
    grpc-purge) purge_single "$grpc_unit" "$grpc_state" "2053" "" "sorryrkn-grpc"; printf 'SRKN1\tGRPC-STATUS\tmissing\n';;

    ss2022-on) ss2022_on;;
    ss2022-profile) ss2022_profile;;
    ss2022-off) [ -f "$units/$ss_unit" ] && systemctl disable --now "$ss_unit" >&2 || true; printf 'SRKN1\tSS2022-STATUS\t%s\n' "$(unit_state "$ss_unit")";;
    ss2022-status) printf 'SRKN1\tSS2022-STATUS\t%s\n' "$(unit_state "$ss_unit")";;
    ss2022-purge) purge_single "$ss_unit" "$ss_state" "2083" "2083" "sorryrkn-ss2022"; printf 'SRKN1\tSS2022-STATUS\tmissing\n';;

    socks-pub-on) spub_on;;
    socks-pub-profile) spub_profile;;
    socks-pub-off) [ -f "$units/$spub_unit" ] && systemctl disable --now "$spub_unit" >&2 || true; printf 'SRKN1\tSOCKS-PUB-STATUS\t%s\n' "$(unit_state "$spub_unit")";;
    socks-pub-status) printf 'SRKN1\tSOCKS-PUB-STATUS\t%s\n' "$(unit_state "$spub_unit")";;
    socks-pub-purge) purge_single "$spub_unit" "$spub_state" "10808" "" "sorryrkn-socks-pub"; printf 'SRKN1\tSOCKS-PUB-STATUS\tmissing\n';;

    fleet-status) fleet_status;;
    purge-all) purge_all;;
    *) die "Unknown protocol action.";;
esac
