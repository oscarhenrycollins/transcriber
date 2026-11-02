"""Box-peer gate of the shared MCP front (wizard-os issue 386, card 5).

Runs the real front (mcp/front.py + mcp/tools.py, exactly as mcp/inline.py assembles it) as a subprocess in front of
a stub upstream, and talks raw HTTP to it. Synthetic keys only, generated per run.
Run: python3 -m unittest discover -s tests -v
"""
import hashlib
import http.client
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEEN = []


class Upstream(BaseHTTPRequestHandler):
    def do_GET(self):
        SEEN.append({k.lower(): v for k, v in self.headers.items()})
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.end_headers()
            return
        body = json.dumps({"path": self.path, "data": []}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FrontGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.up = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=cls.up.serve_forever, daemon=True).start()
        cls.tmp = tempfile.TemporaryDirectory()
        src = (ROOT / "mcp" / "front.py").read_text() + "\n\n" + (ROOT / "mcp" / "tools.py").read_text()
        src += "\n\nif __name__ == \"__main__\":\n    asyncio.run(main())\n"
        cls.script = Path(cls.tmp.name) / "front_run.py"
        cls.script.write_text(src)
        cls.procs = []

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            p.kill()
            p.wait()
        cls.up.shutdown()
        cls.tmp.cleanup()

    def start(self, **env):
        port = free_port()
        e = {"PATH": os.environ.get("PATH", ""), "WIZARD_APP": "front-test", "FRONT_PORT": str(port),
             "UPSTREAM_HOST": "127.0.0.1", "UPSTREAM_PORT": str(self.up.server_address[1]), "PYTHONDONTWRITEBYTECODE": "1"}
        e.update({k: v for k, v in env.items() if v is not None})
        p = subprocess.Popen([sys.executable, str(self.script)], env=e, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.procs.append(p)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                return port
            except OSError:
                time.sleep(0.05)
        self.fail("front did not start: %s" % p.stdout.read1(4096))

    def grants_file(self, incoming, enforce=False, raw=None):
        f = Path(self.tmp.name) / ("grants-%s.json" % secrets.token_hex(4))
        f.write_text(raw if raw is not None else json.dumps({"outgoing": {}, "incoming": incoming, "enforce": enforce}))
        return str(f)

    def req(self, port, path, method="GET", headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data

    def mcp(self, port, headers=None):
        msg = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
        return self.req(port, "/mcp", "POST", {"Content-Type": "application/json", **(headers or {})}, msg)

    # ---- default-off: today's behaviour is unchanged ----
    def test_boundary_off_keeps_todays_behaviour(self):
        port = self.start(WIZARD_GATEWAY_KEY=secrets.token_hex(32))
        self.assertEqual(self.mcp(port)[0], 200)
        self.assertEqual(self.req(port, "/json/version")[0], 200)

    # ---- /mcp answers only the gateway ----
    def test_mcp_needs_the_gateway_key(self):
        key = secrets.token_hex(32)
        port = self.start(WIZARD_BROWSER_BOUNDARY="1", WIZARD_GATEWAY_KEY=key)
        self.assertEqual(self.mcp(port)[0], 403)                                             # box peer, no key
        self.assertEqual(self.mcp(port, {"X-Wizard-Grant": secrets.token_hex(32)})[0], 403)  # wrong key
        status, body = self.mcp(port, {"X-Wizard-Grant": key})
        self.assertEqual(status, 200)
        self.assertIn("tools", json.loads(body)["result"])

    def test_mcp_refuses_browser_and_network_markers_even_with_the_key(self):
        key = secrets.token_hex(32)
        port = self.start(WIZARD_BROWSER_BOUNDARY="1", WIZARD_GATEWAY_KEY=key)
        for h in ({"Origin": "http://127.0.0.1"}, {"Origin": "null"}, {"Cookie": "a=b"}, {"Referer": "http://x/"},
                  {"Sec-Fetch-Site": "same-origin"}, {"Tailscale-User-Login": "owner@example.com"},
                  {"X-Forwarded-For": "100.64.0.9"}, {"Forwarded": "for=100.64.0.9"}):
            self.assertEqual(self.mcp(port, {"X-Wizard-Grant": key, **h})[0], 403, h)

    def test_mcp_fails_closed_without_a_configured_key(self):
        port = self.start(WIZARD_BROWSER_BOUNDARY="1")
        self.assertEqual(self.mcp(port, {"X-Wizard-Grant": secrets.token_hex(32)})[0], 503)

    def test_mcp_accepts_a_spec_host_agent_service_row_but_not_an_app_row(self):
        gw, app = secrets.token_hex(32), secrets.token_hex(32)
        rows = [{"from": "host:agent-service", "sha256": hashlib.sha256(gw.encode()).hexdigest()},
                {"from": "wisdom", "sha256": hashlib.sha256(app.encode()).hexdigest()}]
        port = self.start(WIZARD_BROWSER_BOUNDARY="1", WIZARD_GRANTS_FILE=self.grants_file(rows))
        self.assertEqual(self.mcp(port, {"X-Wizard-Grant": gw})[0], 200)
        self.assertEqual(self.mcp(port, {"X-Wizard-Grant": app})[0], 403)  # an app grant carries no agent authority

    # ---- the app behind the front ----
    def test_require_mode_admits_only_key_holders_and_hides_the_key_from_upstream(self):
        gw, app = secrets.token_hex(32), secrets.token_hex(32)
        rows = [{"from": "defleur-video", "sha256": hashlib.sha256(app.encode()).hexdigest()}]
        port = self.start(WIZARD_BROWSER_BOUNDARY="1", WIZARD_GATEWAY_KEY=gw, WIZARD_PEER_GATE="require",
                          WIZARD_GRANTS_FILE=self.grants_file(rows))
        self.assertEqual(self.req(port, "/json/version")[0], 403)
        self.assertEqual(self.req(port, "/json/version", headers={"X-Wizard-Grant": secrets.token_hex(32)})[0], 403)
        SEEN.clear()
        self.assertEqual(self.req(port, "/json/version", headers={"X-Wizard-Grant": app})[0], 200)
        self.assertEqual(self.req(port, "/json/version", headers={"X-Wizard-Grant": gw})[0], 200)
        self.assertTrue(SEEN and all("x-wizard-grant" not in h for h in SEEN))
        self.assertEqual(self.req(port, "/json/version", headers={"X-Wizard-Grant": app, "Origin": "http://evil.example"})[0], 403)

    def test_require_mode_gates_websocket_upgrades(self):
        app = secrets.token_hex(32)
        rows = [{"from": "defleur-video", "sha256": hashlib.sha256(app.encode()).hexdigest()}]
        port = self.start(WIZARD_BROWSER_BOUNDARY="1", WIZARD_GATEWAY_KEY=secrets.token_hex(32),
                          WIZARD_PEER_GATE="require", WIZARD_GRANTS_FILE=self.grants_file(rows))
        ws = {"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
              "Sec-WebSocket-Version": "13"}

        def upgrade(extra):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(("GET /devtools/browser/x HTTP/1.1\r\nHost: 127.0.0.1\r\n" +
                       "".join("%s: %s\r\n" % kv for kv in {**ws, **extra}.items()) + "\r\n").encode())
            line = s.recv(4096).split(b"\r\n", 1)[0]
            s.close()
            return line

        self.assertIn(b" 403 ", upgrade({}))
        self.assertIn(b" 101 ", upgrade({"X-Wizard-Grant": app}))

    def test_grants_mode_follows_the_enforce_flag(self):
        rows = []
        port = self.start(WIZARD_BROWSER_BOUNDARY="1", WIZARD_GATEWAY_KEY=secrets.token_hex(32),
                          WIZARD_GRANTS_FILE=self.grants_file(rows, enforce=False))
        self.assertEqual(self.req(port, "/v1/models")[0], 200)                 # logged, served (rollout step)
        self.assertEqual(self.req(port, "/v1/models", headers={"Origin": "http://x"})[0], 403)
        port = self.start(WIZARD_BROWSER_BOUNDARY="1", WIZARD_GATEWAY_KEY=secrets.token_hex(32),
                          WIZARD_GRANTS_FILE=self.grants_file(rows, enforce=True))
        self.assertEqual(self.req(port, "/v1/models")[0], 403)
        port = self.start(WIZARD_BROWSER_BOUNDARY="1", WIZARD_GATEWAY_KEY=secrets.token_hex(32),
                          WIZARD_GRANTS_FILE=self.grants_file(None, raw="{not json"))
        self.assertEqual(self.req(port, "/v1/models")[0], 403)                 # configured but malformed: closed

    def test_health_stays_open_for_box_probes(self):
        port = self.start(WIZARD_BROWSER_BOUNDARY="1", WIZARD_GATEWAY_KEY=secrets.token_hex(32), WIZARD_PEER_GATE="require")
        self.assertEqual(self.req(port, "/health")[0], 200)
        self.assertEqual(self.req(port, "/health", headers={"Tailscale-User-Login": "x@example.com"})[0], 403)


class Recipe(unittest.TestCase):
    def test_compose_wires_the_gate_default_off_and_stays_box_only(self):
        text = (ROOT / "runtipi" / "docker-compose.yml").read_text()
        self.assertIn("WIZARD_BROWSER_BOUNDARY: ${WIZARD_BROWSER_BOUNDARY:-0}", text)
        self.assertIn("WIZARD_GATEWAY_KEY: ${WIZARD_GATEWAY_KEY:-}", text)
        for line in text.splitlines():
            s = line.strip().strip("-").strip().strip("'\"")
            if s.count(":") >= 2 and "${APP_PORT}" in s:
                self.assertTrue(s.startswith("127.0.0.1:"), line)   # published, if at all, on loopback only
        manifest = (ROOT / "wizard.md").read_text().split("---")[1]
        self.assertNotIn("\nview:", manifest)                     # no view = no Tailscale Serve route

    def test_inlined_front_is_current(self):
        r = subprocess.run([sys.executable, str(ROOT / "mcp" / "inline.py"), "--check"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
