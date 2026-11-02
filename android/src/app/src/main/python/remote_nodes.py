"""Convert subscription data to vetted Xray outbounds. Never execute provider JSON."""
import base64
import binascii
import json
import uuid
from urllib.parse import parse_qs, unquote, urlsplit

MAX_CONTENT = 1024 * 1024
MAX_NODES = 256


def decode64(value):
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True).decode()


def address(host, port):
    if not host or len(host) > 253 or any(ch.isspace() or ch in "/?#@" or ord(ch) < 32 for ch in host):
        raise ValueError("Invalid host")
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    return {"address": host, "port": port}


def stream(params):
    net = params.get("type", "tcp")
    if net not in ("tcp", "raw", "ws", "grpc"):
        raise ValueError("Unsupported transport")
    security = params.get("security", "none") or "none"
    if security not in ("tls", "reality", "none"):
        raise ValueError("Unsupported security")
    if params.get("allowInsecure", "").lower() in ("true", "1"):
        raise ValueError("Invalid TLS policy")
    result = {"network": net, "security": security}
    if security == "tls":
        settings = {"serverName": params.get("sni", ""), "allowInsecure": False}
        if params.get("alpn"):
            settings["alpn"] = params["alpn"].split(",")
        if params.get("fp"):
            settings["fingerprint"] = params["fp"]
        result["tlsSettings"] = settings
    elif security == "reality":
        if not params.get("pbk") or not params.get("sni"):
            raise ValueError("Incomplete REALITY")
        result["realitySettings"] = {"serverName": params["sni"], "fingerprint": params.get("fp", "chrome"),
                                      "publicKey": params["pbk"], "shortId": params.get("sid", ""),
                                      "spiderX": params.get("spx", "")}
    if net == "ws":
        result["wsSettings"] = {"path": params.get("path") or "/", "host": params.get("host", "")}
    elif net == "grpc":
        result["grpcSettings"] = {"serviceName": params.get("serviceName", ""), "multiMode": params.get("mode") == "multi"}
    elif params.get("headerType", "none") not in ("", "none"):
        raise ValueError("Unsupported TCP header")
    return result


def parse_node(line):
    if len(line) > 16384 or any(ord(ch) < 32 for ch in line):
        raise ValueError("Invalid node")
    link = urlsplit(line)
    protocol = link.scheme
    params = {name: values[-1] for name, values in parse_qs(link.query, max_num_fields=64).items()}
    label = unquote(link.fragment)
    if protocol == "vmess":
        obj = json.loads(decode64(line.split("://", 1)[1].split("#")[0]))
        peer = address(obj["add"], obj["port"])
        peer["users"] = [{"id": str(uuid.UUID(obj["id"])), "security": obj.get("scy") or "auto", "alterId": int(obj.get("aid") or 0)}]
        params = {"type": obj.get("net") or "tcp", "security": obj.get("tls") or "none",
                  "sni": obj.get("sni") or obj.get("host", ""), "host": obj.get("host", ""), "path": obj.get("path", ""),
                  "headerType": obj.get("type", "none"), "serviceName": obj.get("path", ""), "alpn": obj.get("alpn", ""),
                  "fp": obj.get("fp", ""), "allowInsecure": str(obj.get("allowInsecure", ""))}
        label = obj.get("ps", "")
        settings = {"vnext": [peer]}
    elif protocol == "ss":
        if params.get("plugin"):
            raise ValueError("Unsupported plugin")
        ssurl = link
        if not link.username:
            ssurl = urlsplit("ss://" + decode64(line.split("://", 1)[1].split("#")[0].split("?")[0]))
        if ssurl.password is not None:
            method, password = unquote(ssurl.username), unquote(ssurl.password)
        else:
            method, password = decode64(unquote(ssurl.username)).split(":", 1)
        if not password or method not in ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
                                          "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"):
            raise ValueError("Unsupported cipher")
        peer = address(ssurl.hostname, ssurl.port)
        settings = {"servers": [{**peer, "method": method, "password": password}]}
        protocol = "shadowsocks"
    elif protocol in ("trojan", "vless"):
        peer = address(link.hostname, link.port)
        if not link.username:
            raise ValueError("Missing credentials")
        identity = unquote(link.username)
        if protocol == "vless":
            peer["users"] = [{"id": str(uuid.UUID(identity)), "encryption": params.get("encryption", "none"),
                              "flow": params.get("flow", "")}]
            settings = {"vnext": [peer]}
        else:
            params.setdefault("security", "tls")
            settings = {"servers": [{**peer, "password": identity}]}
    else:
        raise ValueError("Unsupported protocol")
    outbound = {"tag": "remote", "protocol": protocol, "settings": settings, "streamSettings": stream(params)}
    title = str(label or peer["address"])
    title = "".join(ch for ch in title if ch.isprintable())[:100]
    return {"name": title, "outbound": outbound}


def parse_subscription(content):
    if not content or len(content.encode()) > MAX_CONTENT:
        raise ValueError("Subscription size")
    content = content.strip()
    if "://" not in content:
        content = decode64("".join(content.split()))
    nodes, rejected = [], 0
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if len(nodes) + rejected >= MAX_NODES:
            raise ValueError("Too many nodes")
        try:
            nodes.append(parse_node(line))
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, binascii.Error):
            rejected += 1
    if not nodes:
        raise ValueError("No supported nodes")
    return json.dumps({"nodes": nodes, "skipped": rejected}, ensure_ascii=False)

