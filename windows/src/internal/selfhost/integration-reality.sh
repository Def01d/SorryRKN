#!/bin/bash
# Dedicated CI VM only. Starts an actual managed service and authenticates an
# explicit VLESS/REALITY request against a controlled, local TLS 1.3 decoy.
set -eu -o pipefail
[[ ${1:-} == --isolated-vm && $EUID == 0 ]] || { echo 'Requires --isolated-vm on a disposable Linux VM.' >&2; exit 2; }
script=$(dirname "$(realpath "$0")")/reality.sh
state=/etc/sorryrkn-reality
lib=/usr/local/lib/sorryrkn-reality
unit=sorryrkn-reality.service
device=89abcdef0123456789abcdef01234567
for path in "$state" "$lib" "/etc/systemd/system/$unit"; do [[ ! -e $path && ! -L $path ]] || { echo "Test requires a pristine VM"; exit 1; }; done
[[ -z $(ss -Htln 'sport = :8443') ]] || { echo 'Requires unused TCP port 8443'; exit 1; }
work=$(mktemp -d)
pids=()
cleanup() {
    rc=$?
    if [[ $rc != 0 ]]; then
        echo 'Failed fixture diagnostics (test endpoints only)'
        for log in client decoy origin; do
            if [[ -f "$work/$log.log" ]]; then tail -n 12 "$work/$log.log"; fi
        done
        journalctl --no-pager -u "$unit" -n 15
    fi
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    iptables -t nat -D OUTPUT -p tcp -d 93.184.216.34 --dport 24434 -j DNAT --to-destination 127.0.0.1:24434 2>/dev/null || true
    rm -f "/etc/systemd/system/$unit"
    systemctl daemon-reload
    rm -rf -- "$state" "$lib" "$work"
}
trap cleanup EXIT
# A scoped OUTPUT DNAT sends only our test address and port to the local origin in this disposable
# VM. The managed service refuses private destinations. No public site is contacted by the test relay.
iptables -t nat -I OUTPUT -p tcp -d 93.184.216.34 --dport 24434 -j DNAT --to-destination 127.0.0.1:24434
mkdir -m 700 "$state"
printf '1\n' > "$state/managed-v1"
printf '%s\n' '{"sni":"localhost","host":"127.0.0.1","port":24433}' > "$state/decoy.json"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost -addext subjectAltName=DNS:localhost \
    -keyout "$work/tls.key" -out "$work/tls.crt" >/dev/null 2>&1
cat /etc/ssl/certs/ca-certificates.crt "$work/tls.crt" > "$work/test-trust.pem"
export SSL_CERT_FILE="$work/test-trust.pem"
openssl s_server -accept 127.0.0.1:24433 -cert "$work/tls.crt" -key "$work/tls.key" -tls1_3 -alpn h2,http/1.1 -quiet -www >"$work/decoy.log" 2>&1 &
pids+=($!)
mkdir "$work/www"; printf 'sorryrkn-reality-fixture\n' > "$work/www/payload"
python3 -m http.server 24434 --bind 127.0.0.1 --directory "$work/www" >"$work/origin.log" 2>&1 &
pids+=($!)
# Verify a third-party listener on 8443 is left alone even in eager install mode.
python3 -m http.server 8443 --bind 127.0.0.1 --directory "$work/www" >"$work/occupied.log" 2>&1 &
occupied=$!; pids+=("$occupied")
for _ in {1..20}; do ss -Htln 'sport = :8443' | grep -q . && break; sleep .1; done
if sh "$script" reality-on "$device" >"$work/conflict" 2>"$work/conflict-error"; then echo 'Occupied port was accepted'; exit 1; fi
grep -q 'TCP port 8443 is occupied' "$work/conflict-error"
kill "$occupied"; wait "$occupied" || true
sh "$script" reality-on "$device" > "$work/profile"
sh "$script" reality-on "$device" > "$work/profile2"; cmp "$work/profile" "$work/profile2"
sh "$script" reality-profile "$device" | cmp - "$work/profile"
sh "$script" reality-status "$device" | grep -q $'SRKN1\tREALITY-STATUS\trunning'
second=76543210fedcba9876543210fedcba98
sh "$script" reality-on "$second" > "$work/second"
! cmp -s "$work/profile" "$work/second" || { echo 'Devices must have separate credentials'; exit 1; }
sh "$script" reality-profile "$device" | cmp - "$work/profile"
python3 - "$work" <<'PY'
from pathlib import Path
import json, sys, urllib.parse
work = Path(sys.argv[1])
record = (work/'profile').read_text().strip().split('\t')
assert len(record) == 3 and record[:2] == ['SRKN1','REALITY']
u = urllib.parse.urlsplit(record[2]); q = urllib.parse.parse_qs(u.query)
assert u.hostname == 'sorryrkn.invalid' and u.port == 8443
config = dict(inbounds=[dict(type='socks',listen='127.0.0.1',listen_port=24435)],outbounds=[dict(
    type='vless',server='127.0.0.1',server_port=8443,uuid=u.username,flow=q['flow'][0],
    tls=dict(enabled=True,server_name=q['sni'][0],utls=dict(enabled=True,fingerprint='chrome'),
    reality=dict(enabled=True,public_key=q['pbk'][0],short_id=q['sid'][0])))])
(work/'client.json').write_text(json.dumps(config))
PY
"$lib/sing-box-1.14.4" run -c "$work/client.json" >"$work/client.log" 2>&1 &
pids+=($!)
for _ in {1..25}; do grep -q 'sing-box started' "$work/client.log" && break; sleep .1; done
[[ $(curl -fsS --max-time 3 --noproxy '*' http://127.0.0.1:24434/payload) == sorryrkn-reality-fixture ]]
result=$(curl -fsS --max-time 10 --retry 2 --retry-all-errors --noproxy '' --proxy socks5h://127.0.0.1:24435 http://93.184.216.34:24434/payload)
[[ $result == sorryrkn-reality-fixture ]]
sh "$script" reality-off "$device" | grep -q $'SRKN1\tREALITY-STATUS\tstopped'
[[ -z $(ss -Htln 'sport = :8443') ]]
if iptables -C INPUT -p tcp --dport 8443 -m comment --comment sorryrkn-reality -j ACCEPT 2>/dev/null; then echo 'Firewall rule survived stop'; exit 1; fi
echo 'PASS: foreign TCP/8443 preserved, per-device profiles stable, TLS 1.3 REALITY relay delivered controlled payload, stopped service removed its listener and firewall rule.'
