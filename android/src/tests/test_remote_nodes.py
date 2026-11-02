import base64
import json
import unittest
from remote_nodes import parse_subscription

UUID = "6e020466-ae7a-414f-bbd2-57310593a90c"
VLESS = f"vless://{UUID}@example.test:8443?security=reality&sni=cover.test&pbk=pub&fp=chrome&flow=xtls-rprx-vision#First"


class RemoteNodesTests(unittest.TestCase):
    def test_subscription_preserves_reality_and_reports_unknown_links(self):
        text = VLESS + "\nunsupported://not-imported"
        result = json.loads(parse_subscription(base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")))
        node = result["nodes"][0]
        self.assertEqual((node["name"], result["skipped"]), ("First", 1))
        stream = node["outbound"]["streamSettings"]
        self.assertEqual((stream["security"], stream["realitySettings"]["publicKey"]), ("reality", "pub"))
        self.assertEqual(node["outbound"]["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision")

    def test_terminal_unsafe_or_unknown_settings_are_rejected(self):
        for link in (VLESS.replace("security=reality", "security=other"), VLESS + "\r\n",
                     "trojan://pw@host.test:443?security=tls&allowInsecure=1"):
            if link == VLESS + "\r\n":
                self.assertEqual(len(json.loads(parse_subscription(link))["nodes"]), 1)
            else:
                with self.assertRaises(ValueError):
                    parse_subscription(link)
        with self.assertRaises(ValueError):
            parse_subscription('{"outbounds":[{"protocol":"freedom"}]}')

    def test_sip002_ss_and_vmess_websocket(self):
        key = base64.urlsafe_b64encode(b"aes-256-gcm:hello").decode().rstrip("=")
        ss = json.loads(parse_subscription(f"ss://{key}@127.0.0.1:5050#Node"))["nodes"][0]["outbound"]
        self.assertEqual(ss["settings"]["servers"][0]["password"], "hello")
        obj = {"add":"example.test","port":"443","id":UUID,"net":"ws","tls":"tls","path":"/ws","host":"cdn.test","sni":"cdn.test"}
        link = "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()
        vm = json.loads(parse_subscription(link))["nodes"][0]["outbound"]
        self.assertEqual(vm["streamSettings"]["wsSettings"]["path"], "/ws")
        self.assertFalse(vm["streamSettings"]["tlsSettings"]["allowInsecure"])

