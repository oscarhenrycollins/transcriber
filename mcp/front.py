"""Wizard MCP front: serves this app's MCP tools at /mcp and passes every other request,
byte for byte, to the app behind it (HTTP, streaming and WebSockets alike).
Stdlib only, so it runs on a stock python image with no build step.
Generated from the app repo's mcp/ folder; edit there, then run mcp/inline.py."""
import asyncio
import contextvars
import base64
import hashlib
import hmac
import json
import os
import socket
import struct
import time
import urllib.parse
import urllib.request
import uuid

APP = os.environ.get("WIZARD_APP", "app")
VERSION = os.environ.get("APP_VERSION", "0")
PORT = int(os.environ.get("FRONT_PORT", "8080"))
UP_HOST = os.environ.get("UPSTREAM_HOST", "")
UP_PORT = int(os.environ.get("UPSTREAM_PORT", str(PORT)))
MCP_PATH = "/mcp"
MCP_TOKEN = os.environ.get("MCP_TOKEN", "")  # when set, /mcp needs Authorization: Bearer <token>
# Box-peer gate (wizard-os issue 386, card 5), default-off: only with WIZARD_BROWSER_BOUNDARY=1.
#   - Every route refuses browser markers (Origin, Cookie, Referer, Sec-Fetch-Site/Dest/User) and network-identity
#     markers (Tailscale-User-*, X-Forwarded-*, Forwarded, X-Real-IP). This listener has no view and no Serve route:
#     only box processes and granted containers are legitimate callers, and they send none of these.
#   - /mcp answers only the Agent Service gateway: X-Wizard-Grant equal to WIZARD_GATEWAY_KEY (the per-installation
#     key App Manager writes into this app's user env and into the gateway's grants/agent-service.json), or a key
#     whose SHA-256 is a host:agent-service row in WIZARD_GRANTS_FILE. No key configured = refused (fail closed).
#   - Every other route (the app behind this front) needs X-Wizard-Grant too: the gateway key or a granted app's
#     key (an `incoming` row of WIZARD_GRANTS_FILE). WIZARD_PEER_GATE=require refuses everyone else; the default
#     (grants) follows the grants file's own `enforce` flag (log-and-serve while false, as spec PERMISSIONS.md says).
BOUNDARY = os.environ.get("WIZARD_BROWSER_BOUNDARY") == "1"
GATEWAY_KEY = os.environ.get("WIZARD_GATEWAY_KEY", "").strip()
GRANTS_FILE = os.environ.get("WIZARD_GRANTS_FILE", "")
PEER_GATE = os.environ.get("WIZARD_PEER_GATE", "grants")
OPEN_PATHS = ("/health",)  # no owner data; box health probes carry no key
BROWSER_MARKERS = ("origin", "cookie", "referer", "sec-fetch-site", "sec-fetch-dest", "sec-fetch-user")
NETWORK_MARKERS = ("tailscale-user-login", "tailscale-user-name", "tailscale-user-profile-pic", "tailscale-app-capabilities",
                   "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded", "x-real-ip")
STRIP_UPSTREAM = ("x-wizard-grant", "x-wizard-agent", "x-wizard-agent-label")
MAX_HEAD = 65536
MAX_BODY = 1 << 20
TOOLS = {}
REQUEST = contextvars.ContextVar("request", default={})  # headers of the current /mcp call


def tool(name, description, props=None, required=()):
    def deco(fn):
        schema = {"type": "object", "properties": props or {}, "required": list(required)}
        TOOLS[name] = ({"name": name, "description": description, "inputSchema": schema}, fn)
        return fn
    return deco


def up_addr():
    try:
        return socket.gethostbyname(UP_HOST)
    except OSError:
        return UP_HOST


def http(method, path, body=None, headers=None, timeout=60):
    url = "http://%s:%d%s" % (up_addr(), UP_PORT, path)
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def err(i, code, message):
    return {"jsonrpc": "2.0", "id": i, "error": {"code": code, "message": message}}


def rpc(msg):
    m, i, p = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if m == "initialize":
        r = {"protocolVersion": p.get("protocolVersion", "2025-06-18"), "capabilities": {"tools": {}},
             "serverInfo": {"name": APP, "version": VERSION}}
    elif m == "tools/list":
        r = {"tools": [t[0] for t in TOOLS.values()]}
    elif m == "tools/call":
        name, args = p.get("name"), p.get("arguments") or {}
        if name not in TOOLS:
            return err(i, -32602, "unknown tool %s" % name)
        try:
            out = TOOLS[name][1](**args)
            if isinstance(out, dict) and "_content" in out:
                r = {"content": out["_content"]}
            else:
                text = out if isinstance(out, str) else json.dumps(out, indent=2)
                r = {"content": [{"type": "text", "text": text[:200000]}]}
        except Exception as e:  # tool errors go back to the agent, not the transport
            r = {"content": [{"type": "text", "text": "%s: %s" % (type(e).__name__, e)}], "isError": True}
    elif m == "ping":
        r = {}
    elif i is None:
        return None  # notification
    else:
        return err(i, -32601, "unknown method %s" % m)
    return {"jsonrpc": "2.0", "id": i, "result": r}


def parse_headers(rest):
    headers = {}
    for line in rest.decode("latin-1").split("\r\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers


_GRANTS = {"stamp": None, "doc": None}


def grants():
    """WIZARD_GRANTS_FILE as {'incoming': [...], 'enforce': bool}; None when unset; 'bad' when configured but unreadable."""
    if not GRANTS_FILE:
        return None
    try:
        st = os.stat(GRANTS_FILE)
        stamp = (st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino)
        if stamp != _GRANTS["stamp"]:
            with open(GRANTS_FILE, "rb") as f:
                doc = json.loads(f.read(65537)[:65536])
            rows = doc.get("incoming") if isinstance(doc, dict) else None
            if not isinstance(rows, list) or not isinstance(doc.get("enforce", False), bool):
                raise ValueError("malformed grants file")
            _GRANTS.update(stamp=stamp, doc={"incoming": [r for r in rows if isinstance(r, dict)],
                                             "enforce": doc.get("enforce", False)})
        return _GRANTS["doc"]
    except (OSError, ValueError):
        _GRANTS.update(stamp=None, doc=None)
        return "bad"


def grant_caller(headers, gateway_only=False):
    """Who presented X-Wizard-Grant: 'host:agent-service', a granted app id, or '' (none / unknown)."""
    key = headers.get("x-wizard-grant", "")
    if not key:
        return ""
    if GATEWAY_KEY and hmac.compare_digest(key.encode(), GATEWAY_KEY.encode()):
        return "host:agent-service"
    g = grants()
    if not isinstance(g, dict):
        return ""
    digest = hashlib.sha256(key.encode()).hexdigest()
    for row in g["incoming"]:
        if hmac.compare_digest(str(row.get("sha256", "")).encode(), digest.encode()):
            who = str(row.get("from", ""))
            if not gateway_only or who == "host:agent-service":
                return who
    return ""


def peer_refusal(path, headers):
    """None to serve, else (status, reason). Only called with the boundary on."""
    marked = [h for h in BROWSER_MARKERS + NETWORK_MARKERS if h in headers]
    if marked:
        return 403, "box-only service: refused a request carrying %s" % marked[0]
    if path == MCP_PATH:
        if MCP_TOKEN and hmac.compare_digest(headers.get("authorization", "").encode(), ("Bearer " + MCP_TOKEN).encode()):
            return None
        if not GATEWAY_KEY and not isinstance(grants(), dict):
            return 503, "MCP gateway key not configured"
        return None if grant_caller(headers, gateway_only=True) else (403, "MCP answers only the Wizard agent gateway")
    if path in OPEN_PATHS or grant_caller(headers):
        return None
    if PEER_GATE == "require":
        return 403, "this service needs X-Wizard-Grant from a granted app"
    g = grants()
    if g == "bad" or (isinstance(g, dict) and g["enforce"]):
        return 403, "this service needs X-Wizard-Grant from a granted app"
    print("wizard-front: unknown caller served (grants not enforced) %s" % path, flush=True)
    return None


REASONS = {200: "OK", 202: "Accepted", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
           401: "Unauthorized", 413: "Payload Too Large", 502: "Bad Gateway", 503: "Service Unavailable"}


async def respond(writer, code, obj=None, extra=""):
    body = b"" if obj is None else json.dumps(obj).encode()
    head = "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n%s\r\n" % (
        code, REASONS.get(code, "OK"), len(body), extra)
    writer.write(head.encode() + body)
    try:
        await writer.drain()
    finally:
        writer.close()


async def mcp(reader, writer, method, rest):
    headers = parse_headers(rest)
    if MCP_TOKEN and not BOUNDARY:
        if not hmac.compare_digest(headers.get("authorization", "").encode(), ("Bearer " + MCP_TOKEN).encode()):
            return await respond(writer, 401, {"error": "this MCP needs Authorization: Bearer <token>"}, 'WWW-Authenticate: Bearer\r\n')
    if method != "POST":
        return await respond(writer, 405, {"error": "use POST %s" % MCP_PATH}, "Allow: POST\r\n")
    n = int(headers.get("content-length") or 0)
    if n > MAX_BODY:
        return await respond(writer, 413, {"error": "request too large"})
    body = await reader.readexactly(n) if n else b""
    try:
        msg = json.loads(body or b"{}")
    except ValueError:
        return await respond(writer, 400, err(None, -32700, "parse error"))
    REQUEST.set(headers)
    batch = msg if isinstance(msg, list) else [msg]
    results = await asyncio.gather(*(asyncio.to_thread(rpc, x) for x in batch if isinstance(x, dict)))
    out = [x for x in results if x]
    if not out:
        return await respond(writer, 202)
    await respond(writer, 200, out if isinstance(msg, list) else out[0])


async def pipe(r, w):
    try:
        while True:
            data = await r.read(65536)
            if not data:
                break
            w.write(data)
            await w.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def handle(reader, writer):
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
        writer.close()
        return
    line, _, rest = head.partition(b"\r\n")
    parts = line.decode("latin-1").split(" ")
    path = parts[1].split("?", 1)[0] if len(parts) >= 3 else ""
    if BOUNDARY:
        refused = peer_refusal(path, parse_headers(rest))
        if refused:
            return await respond(writer, refused[0], {"error": refused[1]})
    if path == MCP_PATH:
        return await mcp(reader, writer, parts[0], rest)
    if not UP_HOST:
        return await respond(writer, 404, {"error": "not found"})
    try:
        ur, uw = await asyncio.open_connection(UP_HOST, UP_PORT)
    except OSError:
        return await respond(writer, 502, {"error": "%s is starting or not reachable" % APP})
    # One request per proxied connection (unless it is an upgrade such as a WebSocket), so a
    # later /mcp request can never ride an upstream keep-alive connection.
    lines = [l for l in head.decode("latin-1").split("\r\n") if l.split(":", 1)[0].strip().lower() not in STRIP_UPSTREAM]
    head = "\r\n".join(lines).encode("latin-1")
    if not any(l.lower().startswith("upgrade:") for l in lines):
        lines = [l for l in lines if l and not l.lower().startswith(("connection:", "keep-alive:"))]
        head = ("\r\n".join(lines) + "\r\nConnection: close\r\n\r\n").encode("latin-1")
    uw.write(head)
    await uw.drain()
    await asyncio.gather(pipe(reader, uw), pipe(ur, writer))


async def main():
    srv = await asyncio.start_server(handle, "0.0.0.0", PORT, limit=MAX_HEAD)
    async with srv:
        await srv.serve_forever()
