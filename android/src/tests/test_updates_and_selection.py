"""Last-good rollback, untrusted upstream parsing and real TLS over native SOCKS."""
import asyncio
import contextlib
import datetime
import json
import ipaddress
from pathlib import Path
import shutil
import socket
import ssl
import subprocess

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import bridge_data as data
import strategy_probe as probe

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40


@pytest.fixture
def store(tmp_path):
    shutil.copy(ROOT / "app/src/main/assets/bundled-data.json", tmp_path)
    return tmp_path


def github_transport(*, bad_cf=False, unchanged=False, dangerous=False):
    calls = []
    bundled = json.loads((ROOT / "app/src/main/assets/bundled-data.json").read_text())
    def handle(request):
        url = str(request.url)
        calls.append(url)
        if "/commits/main" in url:
            repo = url.split("/repos/")[1].split("/commits/")[0]
            return httpx.Response(200, json={"sha": bundled["commits"][repo] if unchanged else SHA})
        if "/git/trees/" in url:
            return httpx.Response(200, json={"tree": [{"type": "blob", "path": "general (ALT2).bat"}]})
        assert f"/{SHA}/" in url, "All raw files must be pinned to the same commit"
        if "list-general.txt" in url:
            return httpx.Response(200, text="\n".join(f"site{i}.com" for i in range(12)))
        if "list-google.txt" in url:
            return httpx.Response(200, text="\n".join(f"google{i}.com" for i in range(6)))
        if "list-exclude.txt" in url:
            return httpx.Response(200, text="exclude.com")
        if "cfproxy-domains.txt" in url:
            return httpx.Response(200, text="evil;rm -rf /" if bad_cf else "virkgj.com\nvmmzovy.com\nmkuosckvso.com")
        if "general%20%28ALT2%29.bat" in url:
            pos = "2;$(touch /tmp/injected)" if dangerous else "2,host+1"
            return httpx.Response(200, text=f'--filter-tcp=443 --hostlist="%LISTS%list-general.txt" '
                                  f'--dpi-desync=fake,multisplit --dpi-desync-split-pos={pos} --dpi-desync-fooling=badseq')
        return httpx.Response(404)
    return httpx.MockTransport(handle), calls


def test_pinned_update_atomic_failure_and_offline_fallback(store):
    transport, calls = github_transport()
    with httpx.Client(transport=transport) as client:
        result = json.loads(data.update(store, True, client))
    assert result["changed"] and len(calls) == 8
    snapshot = data.load(store)
    assert snapshot["profiles"][0]["args"] == ["--split-pos=2,host+1"]
    assert snapshot["cf"] != ["virkgj.com", "vmmzovy.com", "mkuosckvso.com"]
    prepared = json.loads(data.materialize(store))
    assert prepared["commits"] == snapshot["commits"]
    assert (store / "hosts.txt").read_text().splitlines() == snapshot["hosts"]
    previous = (store / "github-data.json").read_bytes()
    # Force a new upstream revision whose CF payload is broken.
    transport, _ = github_transport(bad_cf=True)
    snapshot["commits"] = {repo: "b" * 40 for repo in data.REPOS}
    (store / "github-data.json").write_text(json.dumps(snapshot))
    previous = (store / "github-data.json").read_bytes()
    with httpx.Client(transport=transport) as client, pytest.raises(ValueError):
        data.update(store, True, client)
    assert (store / "github-data.json").read_bytes() == previous
    (store / "github-data.json").write_text("{broken")
    assert data.load(store)["commits"] != snapshot["commits"]


def test_unchanged_commits_and_daily_throttle(store):
    transport, calls = github_transport(unchanged=True)
    with httpx.Client(transport=transport) as client:
        assert not json.loads(data.update(store, True, client))["changed"]
        assert not json.loads(data.update(store, False, client))["changed"]
    assert len(calls) == 2  # no file downloads; second check is entirely offline


def test_untrusted_bat_cannot_supply_cli_or_execute_commands(store):
    transport, _ = github_transport(dangerous=True)
    with httpx.Client(transport=transport) as client:
        data.update(store, True, client)
    assert data.load(store)["profiles"] == []
    with pytest.raises(ValueError):
        data.domains("ok.com\n--hostlist=/sdcard/file")
    with pytest.raises(ValueError):
        data.split_positions("1,--daemon")
    snapshot = data.load(store)
    snapshot["profiles"] = [{"id": "adapt-test", "name": "evil", "args": ["--split-pos=1", "--daemon"]}]
    (store / "github-data.json").write_text(json.dumps(snapshot))
    assert data.load(store)["profiles"] != snapshot["profiles"]


def test_oversized_response_and_redirect_keep_previous(store):
    original = data.load(store)
    for response in (httpx.Response(200, content=b"x" * (data.MAX_BYTES + 1)),
                     httpx.Response(302, headers={"Location": "https://evil.invalid/payload"})):
        with httpx.Client(transport=httpx.MockTransport(lambda _: response), follow_redirects=False) as client:
            with pytest.raises((ValueError, httpx.HTTPError)):
                data.update(store, True, client)
        assert data.load(store) == original
        assert not (store / "github-data.json").exists()


class Control:
    def __init__(self, running=True): self.running = running
    def keepRunning(self): return self.running


@pytest.mark.asyncio
async def test_block_page_and_wrong_discord_response_are_not_success():
    def handle(request):
        if request.url.host == "www.youtube.com":
            return httpx.Response(200, text="Доступ ограничен")
        return httpx.Response(200, json={"url": "wss://blocking.invalid"})
    result = await probe.probe_async(1082, Control(), httpx.MockTransport(handle))
    assert result["passed"] == 0 and not result["complete"]
    transport = httpx.MockTransport(lambda r: httpx.Response(204) if "youtube" in r.url.host
                                    else httpx.Response(200, json={"url": "wss://gateway.discord.gg"}))
    assert (await probe.probe_async(1082, Control(), transport))["complete"]


@pytest.mark.asyncio
async def test_cancel_in_flight_probe_closes_tasks():
    finished = []
    async def hanging(request):
        try:
            await asyncio.Future()
        finally:
            finished.append(request.url.host)
    control = Control()
    task = asyncio.create_task(probe.probe_async(1082, control, httpx.MockTransport(hanging)))
    await asyncio.sleep(.1)
    control.running = False
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, .5)
    assert len(finished) == 2


@pytest.mark.asyncio
async def test_all_native_profiles_real_socks_tls_and_certificate_check(store, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
            .not_valid_after(now+datetime.timedelta(days=1)).add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False).sign(key, hashes.SHA256()))
    cert_path, key_path = store / "test-cert.pem", store / "test-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ssl.load_cert_chain(cert_path, key_path)
    client_ssl = ssl.create_default_context(cafile=str(cert_path))
    async def https(reader, writer):
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            if b"/youtube " in request:
                writer.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            else:
                body = b'{"url":"wss://gateway.discord.gg"}'
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
                             + b"\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(OSError): await writer.wait_closed()
    server = await asyncio.start_server(https, "127.0.0.1", 0, ssl=server_ssl)
    tls_port = server.sockets[0].getsockname()[1]
    server6 = await asyncio.start_server(https, "::1", tls_port, ssl=server_ssl)
    monkeypatch.setattr(probe, "TARGETS", (("YouTube", f"https://localhost:{tls_port}/youtube", 204),
                                         ("Discord", f"https://localhost:{tls_port}/discord", 200)))
    profiles = json.loads(data.catalog(store))
    data.materialize(store)
    (store / "bye-hosts.txt").write_text("localhost\n")
    async with server, server6:
        for profile in profiles:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
            if profile.get("engine") == "byedpi":
                command = [str(ROOT / "build/test-byedpi"), "--ip", "127.0.0.1", f"--port={port}",
                           *json.loads(data.bye_args(profile["id"], store, False))]
            else:
                command = [str(ROOT / "build/test-tpws"), "--socks", "--bind-addr=127.0.0.1",
                           f"--port={port}", *profile["args"]]
            native = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    try:
                        reader, writer = await asyncio.open_connection("127.0.0.1", port)
                        writer.close(); await writer.wait_closed(); break
                    except OSError:
                        await asyncio.sleep(.01)
                else: pytest.fail("Native profile rejected: " + profile["name"])
                if profile["id"].startswith("bye-fake-"):
                    # TTL fakes must expire before reaching the server. Loopback
                    # has no intervening hops: only startup/CLI can be verified.
                    continue
                result = await probe.probe_async(port, Control(), verify=client_ssl, bootstrap=False)
                assert result["complete"], (profile["name"], result)
                if profile == profiles[0]:
                    # Untrusted self-signed certificate MUST fail under production defaults.
                    assert not (await probe.probe_async(port, Control(), bootstrap=False))["complete"]
            finally:
                native.terminate(); native.wait(timeout=3)


        faults = {"blocked": 0, "accepted": 0}
        def block_first_handshakes(connection, hostname, context):
            if faults["blocked"] < 2:
                faults["blocked"] += 1
                return ssl.ALERT_DESCRIPTION_ACCESS_DENIED
            faults["accepted"] += 1
        server_ssl.set_servername_callback(block_first_handshakes)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0)); retry_port=sock.getsockname()[1]
        native = subprocess.Popen([str(ROOT / "build/test-byedpi"), "--ip", "127.0.0.1", f"--port={retry_port}",
                                   *json.loads(data.bye_args("bye-disorder",store,True)), "--debug", "1"],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1",retry_port)
                    writer.close(); await writer.wait_closed(); break
                except OSError: await asyncio.sleep(.01)
            else: pytest.fail("Adaptive proxy failed to start")
            result = await probe.probe_async(retry_port,Control(),verify=client_ssl,bootstrap=False)
            assert result["complete"], result
            assert faults["blocked"] == 2 and faults["accepted"] >= 2
        finally:
            native.terminate()
            output = native.communicate(timeout=3)[0].decode(errors="replace")
            server_ssl.set_servername_callback(None)
        import re
        assert re.search(r"desync TCP: group=[1-9],",output), output


def test_byedpi_adaptive_native_configuration_and_host_exclusions(store):
    snapshot = data.load(store)
    snapshot["hosts"] += ["excluded.com", "sub.excluded.com", "keep.example.com"]
    snapshot["exclude"] += ["excluded.com"]
    (store / "github-data.json").write_text(json.dumps(snapshot))
    data.materialize(store)
    hosts = (store / "bye-hosts.txt").read_text().splitlines()
    assert "excluded.com" not in hosts and "sub.excluded.com" not in hosts
    assert "keep.example.com" in hosts and not any(h.startswith("^") for h in hosts)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0)); port=sock.getsockname()[1]
    args = json.loads(data.bye_args("bye-disorder",store,True))
    assert args.count("--auto=torst,ssl_err") == 10
    assert args[-1] == "--auto=none"
    native = subprocess.Popen([str(ROOT / "build/test-byedpi"), "--ip", "127.0.0.1", f"--port={port}", *args],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import time
    try:
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=.1): break
            except OSError: time.sleep(.01)
        else: pytest.fail("Native adaptive ByeDPI configuration rejected")
        assert native.poll() is None
    finally:
        native.terminate(); native.wait(timeout=3)
