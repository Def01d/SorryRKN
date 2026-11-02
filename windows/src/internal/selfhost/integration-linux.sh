#!/bin/bash
# Full server integration. Run only on a fresh disposable Linux VM.
set -Eeuo pipefail
trap 'echo "Fixture failed at line $LINENO (status $?)" >&2' ERR
[[ $1 == --isolated-vm && $EUID == 0 ]] || exit 2
dir=$(dirname "$(realpath "$0")"); script=$dir/provision.sh
[[ ! -e /etc/sorryrkn-https && ! -e /usr/local/lib/sorryrkn-https && ! -e /etc/systemd/system/sorryrkn-https.service ]] || { echo 'Requires a fresh VM'; exit 1; }
umask 077
work=$(mktemp -d)
unit=sorryrkn-https.service
id=01010101010101010101010101010101
id2=02020202020202020202020202020202
run(){ sh "$script" "$1" "$2" 127.0.0.1; }
cleanup(){
    rc=$?
    if [[ $rc != 0 ]]; then
        journalctl --no-pager -n 30 -o cat -u "$unit" -u sorryrkn-proxy.service | sed -E 's#[A-Za-z0-9+/=]{28,}#[redacted]#g'
    fi
    systemctl disable --now "$unit" 2>/dev/null || true
    systemctl disable --now sorryrkn-proxy.service 2>/dev/null || true
    rm -rf -- "$work"
}
trap cleanup EXIT
run status "$id" | grep -q $'vpn:missing\tsocks:missing'
# Refuse both existing directories and broken symlinks *before* creating a
# managed unit or allowing systemd to change ownership, permissions or content.
mkdir -m 751 /var/lib/sorryrkn-https
printf 'owner sentinel\n' > /var/lib/sorryrkn-https/sentinel
if run https-on "$id" >"$work/foreign-out" 2>"$work/foreign-err"; then exit 1; fi
grep -q 'Refusing to take it over' "$work/foreign-err"
[[ $(stat -c '%u:%a' /var/lib/sorryrkn-https) == 0:751 && $(cat /var/lib/sorryrkn-https/sentinel) == 'owner sentinel' ]]
rm -- /var/lib/sorryrkn-https/sentinel; rmdir /var/lib/sorryrkn-https
ln -s "$work/absent" /run/sorryrkn-https
if run https-on "$id" >"$work/foreign-out" 2>"$work/foreign-err"; then exit 1; fi
grep -q 'Refusing to take it over' "$work/foreign-err"
[[ $(readlink /run/sorryrkn-https) == "$work/absent" && ! -e /etc/systemd/system/sorryrkn-https.service ]]
rm -- /run/sorryrkn-https
run https-on "$id" > "$work/first"
cp /etc/sorryrkn-https/Caddyfile "$work/before-second"
run https-on "$id2" > "$work/second"
run https-profile "$id" > "$work/export"
run https-on "$id" > "$work/reinstall"
cmp "$work/first" "$work/export"; cmp "$work/first" "$work/reinstall"
! cmp -s "$work/first" "$work/second" || { echo 'Duplicate per-device credential'; exit 1; }
python3 - "$work" <<'PY'
import base64,pathlib,ssl,sys,urllib.parse
w=pathlib.Path(sys.argv[1]); record=(w/'second').read_text().strip().split('\t')
assert record[:2]==['SRKN1','HTTPS']
u=urllib.parse.urlsplit(record[2]); q=urllib.parse.parse_qs(u.query)
assert u.hostname=='sorryrkn.invalid' and u.port==443 and q['sni']==['127.0.0.1']
der=base64.urlsafe_b64decode(q['ca'][0]+'===')
(w/'ca.pem').write_text(ssl.DER_cert_to_PEM_cert(der))
(w/'curl.conf').write_text('proxy = "https://127.0.0.1:443"\nproxy-user = "'+u.username+':'+u.password+'"\n')
PY
# Simulate interruption after adding the second peer on disk but before the
# running service activated it. It must fail to authenticate until reconciled.
/usr/local/lib/sorryrkn-https/caddy reload --address unix//run/sorryrkn-https/admin.sock --config "$work/before-second" --adapter caddyfile >/dev/null 2>&1
if curl --config "$work/curl.conf" --proxy-http2 --proxy-cacert "$work/ca.pem" --noproxy '' --fail --silent --max-time 6 https://api.github.com/zen >/dev/null 2>&1; then
    echo 'The missing device unexpectedly authenticated before recovery' >&2; exit 1
fi
run https-on "$id2" > "$work/recovered"
cmp "$work/second" "$work/recovered"
# Validate the genuine IP SAN without sending any TLS SNI.
openssl s_client -noservername -connect 127.0.0.1:443 -CAfile "$work/ca.pem" -verify_ip 127.0.0.1 -verify_return_error </dev/null >/dev/null 2>&1
curl -fsS --cacert "$work/ca.pem" https://127.0.0.1/ > "$work/cover"
cmp "$work/cover" /usr/local/lib/sorryrkn-https/site/index.html
python3 - "$work" <<'PY'
from pathlib import Path
import socket, ssl, sys
w=Path(sys.argv[1]); tls=ssl.create_default_context(cafile=str(w/'ca.pem'))
for auth in (b'',b'Proxy-Authorization: Basic d3Jvbmc6d3Jvbmc=\r\n'):
    with socket.create_connection(('127.0.0.1',443),timeout=5) as raw:
        with tls.wrap_socket(raw,server_hostname='127.0.0.1') as s:
            s.sendall(b'CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n'+auth+b'Connection: close\r\n\r\n')
            out=b''
            while len(out)<65536:
                data=s.recv(65536)
                if not data: break
                out+=data
    assert b'proxy-authenticate:' not in out.lower() and not out.startswith(b'HTTP/1.1 407'), 'proxy challenge on unauthorized probe'
    # The stock file_server canonicalizes this empty-path CONNECT request to
    # "/", exactly as it does without forward_proxy. It cannot relay traffic.
    assert out.startswith(b'HTTP/1.1 308 ') and b'\r\nLocation: /\r\n' in out, 'unexpected response to unauthenticated CONNECT'
PY
# libcurl negotiates HTTP/2 with the HTTPS proxy, authenticates CONNECT, and
# validates the public origin's TLS certificate through the tunnel.
result=$(curl --config "$work/curl.conf" --proxy-http2 --proxy-cacert "$work/ca.pem" --noproxy '' --fail --silent --verbose --max-time 25 --retry 2 -o "$work/response" -w '%{http_code}' https://api.github.com/zen 2>"$work/private-trace")
# %{http_connect} reports 000 for a successful HTTP/2 CONNECT in libcurl.
# Verify the negotiated HTTP/2 CONNECT and origin independently. Never emit
# verbose traffic or Proxy-Authorization from the private temporary trace.
if [[ "$result" != 200 || ! -s "$work/response" ]] || ! grep -Eiq '(Establish HTTP/2 proxy tunnel|\[:method: CONNECT\]|^> CONNECT [^[:space:]]+ HTTP/2)' "$work/private-trace"; then
    echo "Authenticated HTTP2 CONNECT or HTTPS origin check failed (origin $result)" >&2
    exit 1
fi
if curl --config "$work/curl.conf" --proxy-http2 --noproxy '' --fail --silent --max-time 5 https://api.github.com/zen >/dev/null 2>&1; then echo 'Untrusted private CA was accepted'; exit 1; fi
# Preserve owner content on reinstall and observe it on the actual TLS site.
printf '<html><title>Owner site</title></html>\n' >/usr/local/lib/sorryrkn-https/site/index.html
run https-on "$id" >/dev/null
curl -fsS --cacert "$work/ca.pem" https://127.0.0.1/ | grep -q 'Owner site'
echo 'HTTPS: private CA/IP SAN without SNI, ordinary cover, wrong and missing auth, authenticated HTTP2 relay and idempotent peers passed.'
run https-off "$id" | grep -q 'vpn:stopped'
run install-socks "$id" > "$work/socks"
grep -q $'SRKN1\tSOCKS\t127.0.0.1\t11080\t' "$work/socks"
python3 - "$work/socks" <<'PY'
from pathlib import Path
import socket,sys
_,_,host,port,user,password=Path(sys.argv[1]).read_text().strip().split('\t')
for passwd,expected in (('wrong',1),(password,0)):
    with socket.create_connection((host,int(port)),timeout=5) as s:
        r=s.makefile('rb'); s.sendall(b'\x05\x01\x02'); assert r.read(2)==b'\x05\x02'
        u,p=user.encode(),passwd.encode()
        s.sendall(b'\x01'+bytes([len(u)])+u+bytes([len(p)])+p);assert r.read(2)==b'\x01'+bytes([expected])
        if not expected:
            domain=b'api.github.com'
            s.sendall(b'\x05\x01\x00\x03'+bytes([len(domain)])+domain+b'\x01\xbb')
            assert r.read(10)==b'\x05\x00\x00\x01'+bytes(6)
PY
run stop-socks "$id" | grep -q 'socks:stopped'
run install-socks "$id" > "$work/socks2"; cmp "$work/socks" "$work/socks2"
run https-start "$id" | grep -q 'vpn:running'
for n in {1..20}; do curl -fsS --cacert "$work/ca.pem" https://127.0.0.1/ 2>/dev/null | grep -q 'Owner site' && break; sleep .3; done
curl -fsS --cacert "$work/ca.pem" https://127.0.0.1/ | grep -q 'Owner site'
echo 'Independent loopback SOCKS authentication/connect, credential preservation, HTTPS stop/start passed.'
