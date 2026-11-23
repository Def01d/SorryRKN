#!/bin/bash
# Dedicated CI VM only. Verifies SRKN-Mirage v1 (active-probe HTML cover + E2E client),
# multi-protocol provisioning (Hysteria2, VLESS gRPC, SS2022, Public SOCKS5), SSRF
# blocking, fleet-status reporting, and clean purge-all teardown.
set -eu -o pipefail
[[ ${1:-} == --isolated-vm && $EUID == 0 ]] || { echo 'Requires --isolated-vm on a disposable Linux VM.' >&2; exit 2; }

here=$(dirname "$(realpath "$0")")
mirage_sh=$here/mirage.sh
proto_sh=$here/protocols.sh
device=0123456789abcdef0123456789abcdef

for u in mirage hy2 grpc ss2022 socks-pub; do
    for path in "/etc/sorryrkn-$u" "/etc/systemd/system/sorryrkn-$u.service"; do
        [[ ! -e $path && ! -L $path ]] || { echo "Test requires a pristine VM ($path exists)"; exit 1; }
    done
done

work=$(mktemp -d)
pids=()
cleanup() {
    rc=$?
    if [[ $rc != 0 ]]; then
        echo 'Failed mirage/proto integration fixture diagnostics'
        for u in mirage hy2 grpc ss2022 socks-pub; do
            journalctl --no-pager -u "sorryrkn-$u.service" -n 20 || true
        done
        for log in client decoy origin; do
            [[ -f "$work/$log.log" ]] && tail -n 15 "$work/$log.log" || true
        done
    fi
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    sh "$proto_sh" purge-all "$device" >/dev/null 2>&1 || true
    iptables -t nat -D OUTPUT -p tcp -d 93.184.216.34 --dport 24434 -j DNAT --to-destination 127.0.0.1:24434 2>/dev/null || true
    rm -rf -- "$work"
}
trap cleanup EXIT

# Scoped OUTPUT DNAT routes only test IP 93.184.216.34:24434 to local HTTP origin.
iptables -t nat -I OUTPUT -p tcp -d 93.184.216.34 --dport 24434 -j DNAT --to-destination 127.0.0.1:24434
mkdir -p "$work/www"
printf 'sorryrkn-mirage-proto-ok\n' > "$work/www/payload"
python3 -m http.server 24434 --bind 127.0.0.1 --directory "$work/www" >"$work/origin.log" 2>&1 &
pids+=($!)

# Local TLS decoy for VLESS gRPC REALITY handshake verification.
mkdir -m 700 /etc/sorryrkn-grpc
printf '1\n' > /etc/sorryrkn-grpc/managed-v1
printf '%s\n' '{"sni":"localhost","host":"127.0.0.1","port":24433}' > /etc/sorryrkn-grpc/decoy.json
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost -addext subjectAltName=DNS:localhost \
    -keyout "$work/tls.key" -out "$work/tls.crt" >/dev/null 2>&1
openssl s_server -accept 127.0.0.1:24433 -cert "$work/tls.crt" -key "$work/tls.key" -tls1_3 -alpn h2,http/1.1 -quiet -www >"$work/decoy.log" 2>&1 &
pids+=($!)

# 1. Mirage install + active-probe cover check + E2E client tunnel + SSRF guard.
mirage_rec=$(sh "$mirage_sh" mirage-on "$device")
printf '%s\n' "$mirage_rec" | grep -q $'^SRKN1\tMIRAGE\tmirage://'
probe_html=$(curl -fsSk --max-time 4 https://127.0.0.1:2096/)
grep -q 'API Telemetry Endpoint' <<< "$probe_html"

mirage_uri=$(printf '%s' "$mirage_rec" | cut -f3 | sed 's/@sorryrkn\.invalid:/@127.0.0.1:/')
/usr/local/lib/sorryrkn-mirage/sorryrkn-mirage client --uri "$mirage_uri" --listen 127.0.0.1:24436 --socks-user cli --socks-pass pw >"$work/client.log" 2>&1 &
pids+=($!)
for _ in {1..30}; do ss -Htln 'sport = :24436' | grep -q . && break; sleep .1; done

got=$(curl -fsS --max-time 10 --noproxy '' --proxy socks5h://cli:pw@127.0.0.1:24436 http://93.184.216.34:24434/payload)
[[ $got == sorryrkn-mirage-proto-ok ]]
if curl -fsS --max-time 3 --noproxy '' --proxy socks5h://cli:pw@127.0.0.1:24436 http://127.0.0.1:24434/payload >/dev/null 2>&1; then
    echo 'Mirage SSRF guard failed on loopback'; exit 1
fi

# 2. Provision Hysteria2 + VLESS gRPC + SS2022 + Public SOCKS5.
hy2_rec=$(sh "$proto_sh" hy2-on "$device")
printf '%s\n' "$hy2_rec" | grep -q '^SRKN1	HY2	hy2://'
printf '%s\n' "$hy2_rec" | grep -q 'spki='

grpc_rec=$(sh "$proto_sh" grpc-on "$device")
printf '%s\n' "$grpc_rec" | grep -q '^SRKN1	GRPC	vless://'

ss_rec=$(sh "$proto_sh" ss2022-on "$device")
printf '%s\n' "$ss_rec" | grep -q '^SRKN1	SS2022	ss://'

spub_rec=$(sh "$proto_sh" socks-pub-on "$device")
IFS=$'\t' read -r hdr kind sp_port sp_user sp_pass <<< "$spub_rec"
[[ "$hdr" == SRKN1 && "$kind" == SOCKS-PUB && "$sp_port" == 10808 ]]
spub_got=$(curl -fsS --max-time 6 --noproxy '' --proxy "socks5h://$sp_user:$sp_pass@127.0.0.1:10808" http://93.184.216.34:24434/payload)
[[ $spub_got == sorryrkn-mirage-proto-ok ]]
if curl -fsS --max-time 3 --noproxy '' --proxy socks5h://127.0.0.1:10808 http://93.184.216.34:24434/payload >/dev/null 2>&1; then
    echo 'Unauthenticated SOCKS5 was accepted'; exit 1
fi
if curl -fsS --max-time 3 --noproxy '' --proxy "socks5h://$sp_user:$sp_pass@127.0.0.1:10808" http://127.0.0.1:24434/payload >/dev/null 2>&1; then
    echo 'Public SOCKS5 SSRF guard failed on loopback'; exit 1
fi

# 3. Fleet status must reflect all running services accurately.
fleet=$(sh "$proto_sh" fleet-status "$device")
for token in 'mirage:running' 'hy2:running' 'grpc:running' 'ss2022:running' 'socks_pub:running'; do
    grep -q "$token" <<< "$fleet" || { echo "Missing $token in fleet: $fleet"; exit 1; }
done

# 4. Purge all must cleanly delete units, directories, and iptables rules.
sh "$proto_sh" purge-all "$device" | grep -q '^SRKN1	PURGED	all$'
for u in mirage hy2 grpc ss2022 socks-pub; do
    [[ ! -e "/etc/sorryrkn-$u" && ! -e "/etc/systemd/system/sorryrkn-$u.service" ]] || { echo "Leftover $u after purge-all"; exit 1; }
done
[[ -z $(iptables -S INPUT | grep 'sorryrkn-' || true) ]]
echo 'PASS: Mirage E2E + cover HTML + Hysteria2/gRPC/SS2022/PublicSOCKS5 + purge-all verified.'
