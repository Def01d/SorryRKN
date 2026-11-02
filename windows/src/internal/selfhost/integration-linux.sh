#!/usr/bin/env bash
# Run only on a disposable root-access VM. Uses real systemd, kernel WireGuard,
# forwarding, SOCKS credentials and an isolated client network namespace.
set -euo pipefail
[[ $1 == --isolated-vm && $EUID == 0 ]] || { echo 'A disposable root VM is required.' >&2; exit 2; }
[[ ! -e /etc/wireguard/sorryrkn-selfhost && ! -e /etc/systemd/system/sorryrkn-vpn.service && ! -e /etc/systemd/system/sorryrkn-socks.service ]] || { echo 'VM is not clean.' >&2; exit 2; }
umask 077
dir=$(cd "$(dirname "$0")" && pwd)
mkdir -p -m 700 /etc/wireguard
work=$(mktemp -d /etc/wireguard/srkn-integration-XXXXXX)
ns=srkn-test-client
peer=01010101010101010101010101010101
other=02020202020202020202020202020202
run() { sh "$dir/provision.sh" "$1" "$2"; }
cleanup() {
    rc=$?
    if [[ $rc != 0 ]]; then
        journalctl --no-pager -n 40 -o cat -u sorryrkn-vpn.service -u sorryrkn-socks.service | sed -E 's#[A-Za-z0-9+/=]{32,}#[redacted]#g'
    fi
    if [[ -n $http_pid ]]; then kill "$http_pid" 2>/dev/null || true; fi
    ip netns del "$ns" 2>/dev/null || true
    systemctl stop sorryrkn-vpn.service 2>/dev/null || true
    rm -rf -- "$work"
}
http_pid=
trap cleanup EXIT

run status "$peer" > "$work/status"
grep -qx $'SRKN1\tSTATUS\tvpn:missing\tsocks:missing' "$work/status"
run install-vpn "$peer" > "$work/peer"
run install-vpn "$other" > "$work/other"
run install-vpn "$peer" > "$work/reinstall"
cmp "$work/peer" "$work/reinstall"
run export-vpn "$peer" > "$work/export"
cmp "$work/peer" "$work/export"
[[ $(cut -f6 "$work/peer") != "$(cut -f6 "$work/other")" ]]
[[ $(cut -f3 "$work/peer") != "$(cut -f3 "$work/other")" ]]
[[ $(wg show srkn0 peers | wc -l) == 2 ]]

# Birth namespace owns the UDP socket; the client namespace owns cleartext.
ip netns add "$ns"
ip link add srkn-client type wireguard
ip link set srkn-client netns "$ns"
cut -f3 "$work/peer" > "$work/key"
cut -f5 "$work/peer" > "$work/psk"
client_ip=$(cut -f6 "$work/peer")
vpn_ip=$(cat /etc/wireguard/sorryrkn-selfhost/subnet).1
ip netns exec "$ns" wg set srkn-client private-key "$work/key" peer "$(cut -f4 "$work/peer")" preshared-key "$work/psk" endpoint 127.0.0.1:51823 allowed-ips 0.0.0.0/0
ip -n "$ns" addr add "$client_ip/32" dev srkn-client
ip -n "$ns" link set srkn-client up
ip -n "$ns" route add default dev srkn-client
ip netns exec "$ns" ping -c 2 -W 3 "$vpn_ip" >/dev/null
wg show srkn0 latest-handshakes | awk '$2>0 {found=1} END {exit !found}'
echo 'Two independent peers, idempotent provisioning and actual WireGuard handshake passed.'

# This test leaves the root namespace via the server forwarding/NAT rules.
api_ip=$(getent ahostsv4 api.github.com | awk 'NR==1{v=$1} END{print v}')
ip netns exec "$ns" curl -4 -fsS --noproxy '*' --retry 2 --connect-timeout 8 --max-time 25 --resolve "api.github.com:443:$api_ip" https://api.github.com/zen -o /dev/null
echo 'IPv4 HTTPS through the full tunnel passed.'

run install-socks "$peer" > "$work/socks"
printf 'selfhost-proxy-check' > "$work/fixture"
# Only expose the single test file to this disposable loopback test origin.
mkdir "$work/public"
mv "$work/fixture" "$work/public/fixture"
python3 -m http.server 18664 --bind 127.0.0.1 --directory "$work/public" >/dev/null 2>&1 &
http_pid=$!
for ((i=0; i<20; i++)); do
    if curl -fsS --noproxy '*' http://127.0.0.1:18664/fixture -o /dev/null 2>/dev/null; then break; fi
    sleep .1
done
ip netns exec "$ns" python3 - "$work/socks" <<'PY'
from pathlib import Path
import socket, struct, sys
_, kind, host, port, user, password = Path(sys.argv[1]).read_text().strip().split('\t')
assert kind == 'SOCKS'
def check(password, expected):
    with socket.create_connection((host,int(port)),timeout=5) as sock:
        stream = sock.makefile('rb')
        sock.sendall(b'\x05\x01\x02')
        assert stream.read(2) == b'\x05\x02'
        u,p = user.encode(),password.encode()
        sock.sendall(b'\x01'+bytes([len(u)])+u+bytes([len(p)])+p)
        assert stream.read(2) == b'\x01'+bytes([expected])
        if expected: return
        sock.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',18664))
        assert stream.read(10) == b'\x05\x00\x00\x01'+bytes(6)
        sock.sendall(b'GET /fixture HTTP/1.0\r\n\r\n')
        assert stream.read().endswith(b'selfhost-proxy-check')
check('incorrect',1)
check(password,0)
PY
run stop-socks "$peer" | grep -q 'socks:stopped'
run install-socks "$peer" > "$work/retry-socks"
cmp "$work/socks" "$work/retry-socks"
run stop-vpn "$peer" | grep -q 'vpn:stopped'
run start-vpn "$peer" | grep -q 'vpn:running'
# Reconnect the client rather than waiting for its stale session to rekey.
ip netns exec "$ns" wg set srkn-client peer "$(cut -f4 "$work/peer")" remove
ip netns exec "$ns" wg set srkn-client peer "$(cut -f4 "$work/peer")" preshared-key "$work/psk" endpoint 127.0.0.1:51823 allowed-ips 0.0.0.0/0
ip netns exec "$ns" ping -c 2 -W 3 "$vpn_ip" >/dev/null
echo 'Authenticated SOCKS relay, credential preservation and service stop/start passed.'
