"""wiretap core: a faithful local reverse proxy, a capture store and the web UI server.

Standard library only. Requests are forwarded byte-for-byte to ONE configured
upstream; the only header changed is Host (and hop-by-hop headers, which by
HTTP rules belong to a single connection). Nothing is sent anywhere else.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import gzip
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import webbrowser
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlsplit

from . import NAME, TAGLINE, __version__
from . import analyze as A

HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization",
              "te", "trailer", "trailers", "transfer-encoding", "upgrade", "expect"}
UI_PREFIX = "/__" + NAME
MAX_CAPTURE_BODY = 16 * 1024 * 1024  # bytes of response kept for analysis (stream is always passed through in full)

AGENTS = {
    # name: (default upstream, env line template, note)
    "claude": ("https://api.anthropic.com", "ANTHROPIC_BASE_URL={base} claude", "Claude Code"),
    "codex": ("https://api.openai.com", "OPENAI_BASE_URL={base}/v1 codex", "Codex CLI (API-key mode; untested)"),
    "openai": ("https://api.openai.com", "OPENAI_BASE_URL={base}/v1 <your-openai-client>", "OpenAI-compatible clients"),
    "gemini": ("https://generativelanguage.googleapis.com", "<point your Gemini client's base URL at> {base}", "Gemini API clients (untested)"),
}


# --------------------------------------------------------------------------
# capture store
# --------------------------------------------------------------------------


class Store:
    def __init__(self, maxlen: int = 200, save_dir: Optional[str] = None, ident: Optional[A.LocalIdentity] = None):
        self.lock = threading.RLock()
        self.items: "collections.OrderedDict[int, Dict[str, Any]]" = collections.OrderedDict()
        self.maxlen = maxlen
        self.next_id = 1
        self.rev = 0
        self.endpoints: Dict[str, Dict[str, Any]] = {}
        self.ident = ident
        self.worker = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix=NAME + "-analyze")
        self.save_path = None
        if save_dir:
            Path(save_dir).mkdir(parents=True, exist_ok=True)
            self.save_path = Path(save_dir) / ("%s-%s.jsonl" % (NAME, time.strftime("%Y%m%d-%H%M%S")))

    def _bump(self):
        self.rev += 1

    def new(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            rec["id"] = self.next_id
            self.next_id += 1
            self.items[rec["id"]] = rec
            while len(self.items) > self.maxlen:
                self.items.popitem(last=False)
            key = "%s %s%s" % (rec["method"], rec["upstream_host"], rec["path"].split("?")[0])
            e = self.endpoints.setdefault(key, {"endpoint": key, "count": 0, "bytes_out": 0, "bytes_in": 0})
            e["count"] += 1
            e["bytes_out"] += rec["req_bytes"]
            self._bump()
        return rec

    def update(self, rec: Dict[str, Any], **kw):
        with self.lock:
            rec.update(kw)
            if "resp_bytes" in kw:
                key = "%s %s%s" % (rec["method"], rec["upstream_host"], rec["path"].split("?")[0])
                if key in self.endpoints:
                    self.endpoints[key]["bytes_in"] += kw["resp_bytes"] or 0
            self._bump()

    def previous_for(self, rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        p = rec["path"].split("?")[0]
        with self.lock:
            for oid in reversed(self.items):
                o = self.items[oid]
                if oid < rec["id"] and o["path"].split("?")[0] == p and o.get("api") == rec.get("api") and "decoded" in o:
                    return o
        return None

    def get(self, cid: int) -> Optional[Dict[str, Any]]:
        with self.lock:
            return self.items.get(cid)

    def clear(self):
        with self.lock:
            self.items.clear()
            self.endpoints.clear()
            self._bump()

    def listing(self) -> List[Dict[str, Any]]:
        with self.lock:
            return [brief(r) for r in reversed(self.items.values())]

    def persist(self, rec: Dict[str, Any]):
        if not self.save_path:
            return
        line = json.dumps(rec, ensure_ascii=False, default=str)
        with self.lock:
            fd = os.open(str(self.save_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(line + "\n")


def brief(r: Dict[str, Any]) -> Dict[str, Any]:
    s = r.get("summary") or {}
    resp = r.get("response") or {}
    return {
        "id": r["id"], "ts": r["ts"], "method": r["method"], "path": r["path"], "state": r.get("state"),
        "status": r.get("status"), "req_bytes": r["req_bytes"], "resp_bytes": r.get("resp_bytes"),
        "duration_ms": r.get("duration_ms"), "api": r.get("api"), "model": r.get("model"),
        "stream": r.get("stream"), "tool_count": s.get("tool_count"), "system_tokens": s.get("system_tokens"),
        "message_count": s.get("message_count"),
        "hidden_warn": (r.get("hidden") or {}).get("warn"), "hidden_total": (r.get("hidden") or {}).get("total"),
        "pii_total": (r.get("pii") or {}).get("total"), "usage": resp.get("usage"), "error": r.get("error"),
    }


# --------------------------------------------------------------------------
# analysis jobs (run on a single worker thread so diffs see the previous capture)
# --------------------------------------------------------------------------


def _decode_body(raw: bytes, encoding: str) -> Optional[bytes]:
    enc = (encoding or "").lower().strip()
    try:
        if not enc or enc == "identity":
            return raw
        if enc == "gzip":
            return gzip.decompress(raw)
        if enc == "deflate":
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return zlib.decompress(raw, -zlib.MAX_WBITS)
    except Exception:
        return None
    return None  # br / zstd: not in the standard library


def analyze_request_job(store: Store, rec: Dict[str, Any], body: bytes, content_encoding: str):
    try:
        plain = _decode_body(body, content_encoding)
        if plain is None:
            store.update(rec, analysis_note="request body is %s-encoded; not decoded" % content_encoding)
            return
        res = A.analyze_request(rec["path"], plain, store.ident)
        store.update(rec, **res)
        prev = store.previous_for(rec)
        store.update(rec, diff=A.diff_requests(prev, rec))
    except Exception as e:  # never let analysis affect the proxy
        store.update(rec, analysis_error=repr(e))


def analyze_response_job(store: Store, rec: Dict[str, Any], raw: bytes, ctype: str, cenc: str, truncated: bool):
    try:
        plain = _decode_body(raw, cenc)
        if plain is None:
            resp = {"kind": "encoded", "note": "response is %s-encoded; passed through untouched but not decoded for display" % cenc,
                    "usage": {}, "text": "", "tool_calls": [], "events": 0, "event_types": {}}
        else:
            resp = A.parse_response(ctype, plain)
        resp["truncated_for_display"] = truncated
        store.update(rec, response=resp, state="done")
    except Exception as e:
        store.update(rec, response={"error": repr(e)}, state="done")
    store.persist(rec)


# --------------------------------------------------------------------------
# HTTP handlers
# --------------------------------------------------------------------------

UI_HTML_PATH = Path(__file__).with_name("ui.html")


class Ctx:
    """Shared runtime config, attached to both servers."""

    def __init__(self, upstream: str, store: Store, timeout: float = 600.0, ui_base: str = "", proxy_base: str = ""):
        u = urlsplit(upstream)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("upstream must look like https://host[:port][/base/path]")
        self.upstream = upstream.rstrip("/")
        self.scheme = u.scheme
        self.host = u.hostname
        self.port = u.port or (443 if u.scheme == "https" else 80)
        self.netloc = u.netloc
        self.base_path = u.path.rstrip("/")
        self.store = store
        self.timeout = timeout
        self.ssl_ctx = ssl.create_default_context()
        self.ui_base = ui_base
        self.proxy_base = proxy_base

    def connect(self) -> http.client.HTTPConnection:
        if self.scheme == "https":
            return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.ssl_ctx)
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)


LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}


def _host_ok(handler: BaseHTTPRequestHandler) -> bool:
    """DNS-rebinding guard for the UI: only answer to local Host names."""
    host = (handler.headers.get("Host") or "").strip()
    name = host.rsplit(":", 1)[0] if not host.endswith("]") else host
    if name in LOCAL_HOSTS:
        return True
    try:
        return ipaddress.ip_address(name.strip("[]")).is_loopback or name.strip("[]") == handler.server.server_address[0]
    except ValueError:
        return False


def _json(handler, obj, status=200, extra_headers=()):
    data = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    for k, v in extra_headers:
        handler.send_header(k, v)
    handler.end_headers()
    if handler.command != "HEAD":
        handler.wfile.write(data)


def _text(handler, text, ctype, status=200, extra_headers=()):
    data = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    for k, v in extra_headers:
        handler.send_header(k, v)
    handler.end_headers()
    if handler.command != "HEAD":
        handler.wfile.write(data)


def serve_ui(handler: BaseHTTPRequestHandler, ctx: Ctx, path: str):
    if not _host_ok(handler):
        return _text(handler, "forbidden host", "text/plain", 403)
    u = urlsplit(path)
    p = u.path
    store = ctx.store
    if handler.command == "POST" and p == "/api/clear":
        store.clear()
        return _json(handler, {"ok": True})
    if p in ("", "/", "/index.html"):
        html = UI_HTML_PATH.read_text(encoding="utf-8")
        return _text(handler, html, "text/html; charset=utf-8", extra_headers=[
            ("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"),
            ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer")])
    if p == "/api/info":
        return _json(handler, {"name": NAME, "version": __version__, "tagline": TAGLINE, "upstream": ctx.upstream,
                               "proxy": ctx.proxy_base, "ui": ctx.ui_base,
                               "save": str(store.save_path) if store.save_path else None, "max": store.maxlen})
    if p == "/api/captures":
        q = parse_qs(u.query)
        if q.get("rev") and q["rev"][0] == str(store.rev):
            return _json(handler, {"rev": store.rev, "unchanged": True})
        return _json(handler, {"rev": store.rev, "items": store.listing(),
                               "endpoints": sorted(store.endpoints.values(), key=lambda e: -e["count"])})
    m = re.match(r"^/api/captures/(\d+)(\.json|\.md)?$", p)
    if m:
        rec = store.get(int(m.group(1)))
        if not rec:
            return _json(handler, {"error": "not found"}, 404)
        with store.lock:
            snap = json.loads(json.dumps(rec, default=str))
        if m.group(2) == ".md":
            return _text(handler, A.markdown_report(snap, NAME), "text/markdown; charset=utf-8",
                         extra_headers=[("Content-Disposition", 'attachment; filename="%s-%s.md"' % (NAME, rec["id"]))])
        if m.group(2) == ".json":
            return _json(handler, snap, extra_headers=[("Content-Disposition", 'attachment; filename="%s-%s.json"' % (NAME, rec["id"]))])
        return _json(handler, snap)
    return _json(handler, {"error": "not found"}, 404)


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = NAME + "/" + __version__
    ctx: Ctx = None  # type: ignore

    def log_message(self, fmt, *args):  # quiet; the UI is the log
        if os.environ.get("WIRETAP_DEBUG"):
            sys.stderr.write("[%s] %s\n" % (NAME, fmt % args))


class UIHandler(_Base):
    def do_GET(self):
        serve_ui(self, self.ctx, self.path)

    do_HEAD = do_GET
    do_POST = do_GET


class ProxyHandler(_Base):
    def _read_body(self) -> bytes:
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            out = bytearray()
            while True:
                line = self.rfile.readline(65537)
                size = int(line.split(b";", 1)[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline(65537) not in (b"\r\n", b"\n", b""):
                        pass
                    break
                out += self.rfile.read(size)
                self.rfile.readline(3)
            return bytes(out)
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _handle(self):
        if self.path.startswith(UI_PREFIX):
            return serve_ui(self, self.ctx, self.path[len(UI_PREFIX):] or "/")
        ctx = self.ctx
        t0 = time.time()
        body = self._read_body()
        req_headers = [(k, v) for k, v in self.headers.items()]
        rec = ctx.store.new({
            "ts": t0, "method": self.command, "path": A.redact_path(self.path),
            "upstream": ctx.upstream, "upstream_host": ctx.netloc,
            "req_headers": A.redact_headers(req_headers), "req_bytes": len(body), "state": "in_flight",
        })
        ctx.store.worker.submit(analyze_request_job, ctx.store, rec, body, self.headers.get("Content-Encoding", ""))

        conn = None
        sent_any = False
        try:
            conn = ctx.connect()
            conn.putrequest(self.command, ctx.base_path + self.path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", ctx.netloc)
            had_len = False
            for k, v in req_headers:
                lk = k.lower()
                if lk in HOP_BY_HOP or lk == "host":
                    continue
                if lk == "content-length":
                    had_len = True
                    v = str(len(body))
                conn.putheader(k, v)
            if body and not had_len:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body if body else None)
            resp = conn.getresponse()
            ttfb = time.time()

            resp_headers = resp.getheaders()
            ctx.store.update(rec, status=resp.status, resp_headers=A.redact_headers(resp_headers),
                             ttfb_ms=int((ttfb - t0) * 1000), state="streaming")
            ctype, cenc = resp.getheader("Content-Type", ""), resp.getheader("Content-Encoding", "")

            self.send_response_only(resp.status, resp.reason)
            has_len = resp.getheader("Content-Length") is not None
            no_body = self.command == "HEAD" or resp.status in (204, 304) or 100 <= resp.status < 200
            chunked = not has_len and not no_body
            for k, v in resp_headers:
                if k.lower() in HOP_BY_HOP:
                    continue
                self.send_header(k, v)
            if chunked:
                self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            sent_any = True

            captured = bytearray()
            stats = {"total": 0, "truncated": False}
            client_gone = None
            read = getattr(resp, "read1", None) or resp.read
            if not no_body:
                while True:
                    chunk = read(65536)
                    if not chunk:
                        break
                    stats["total"] += len(chunk)
                    if len(captured) < MAX_CAPTURE_BODY:
                        captured += chunk[: MAX_CAPTURE_BODY - len(captured)]
                    else:
                        stats["truncated"] = True
                    try:
                        if chunked:
                            self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                        else:
                            self.wfile.write(chunk)
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError) as e:
                        client_gone = "client disconnected mid-response: %s" % e.__class__.__name__
                        self.close_connection = True
                        break
                if chunked and not client_gone:
                    try:
                        self.wfile.write(b"0\r\n\r\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        self.close_connection = True
            t1 = time.time()
            upd = dict(resp_bytes=stats["total"], duration_ms=int((t1 - t0) * 1000), state="analyzing")
            if client_gone:
                upd["error"] = client_gone
            ctx.store.update(rec, **upd)
            ctx.store.worker.submit(analyze_response_job, ctx.store, rec, bytes(captured), ctype, cenc, stats["truncated"])
        except (BrokenPipeError, ConnectionResetError) as e:
            ctx.store.update(rec, state="done", error="client disconnected: %s" % e.__class__.__name__,
                             duration_ms=int((time.time() - t0) * 1000))
            self.close_connection = True
        except Exception as e:
            msg = "%s: %s" % (e.__class__.__name__, e)
            ctx.store.update(rec, state="done", status=rec.get("status") or 502, error="upstream error: " + msg,
                             duration_ms=int((time.time() - t0) * 1000), resp_bytes=rec.get("resp_bytes") or 0)
            if not sent_any:
                try:
                    _json(self, {"type": "error", "error": {"type": NAME + "_upstream_error", "message": msg}}, 502)
                except Exception:
                    pass
            self.close_connection = True
        finally:
            if conn is not None:
                conn.close()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _handle


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            return  # clients hanging up is normal
        super().handle_error(request, client_address)


def make_servers(host: str, port: int, ui_port: int, upstream: str, store: Store, timeout: float = 600.0):
    disp = "[%s]" % host if ":" in host else host
    ctx = Ctx(upstream, store, timeout)
    ph = type("Proxy", (ProxyHandler,), {"ctx": ctx})
    proxy = _Server((host, port), ph)
    ctx.proxy_base = "http://%s:%d" % (disp, proxy.server_address[1])
    ui = None
    if ui_port >= 0:
        uh = type("UI", (UIHandler,), {"ctx": ctx})
        ui = _Server((host, ui_port), uh)
        ctx.ui_base = "http://%s:%d" % (disp, ui.server_address[1])
    else:
        ctx.ui_base = ctx.proxy_base + UI_PREFIX + "/"
    return ctx, proxy, ui


def start_in_threads(*servers):
    threads = []
    for s in servers:
        if s is None:
            continue
        t = threading.Thread(target=s.serve_forever, daemon=True)
        t.start()
        threads.append(t)
    return threads


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _c(code, s):
    return "\033[%sm%s\033[0m" % (code, s) if sys.stdout.isatty() and not os.environ.get("NO_COLOR") else s


def banner(ctx: Ctx, agent: str, store: Store) -> str:
    _, env_tpl, label = AGENTS.get(agent, AGENTS["claude"])
    env_line = env_tpl.format(base=ctx.proxy_base)
    lines = [
        "",
        "  %s %s  %s" % (_c("1;35", NAME), __version__, _c("2", TAGLINE)),
        "",
        "  proxy   %s  ->  %s" % (_c("1", ctx.proxy_base), ctx.upstream),
        "  web UI  %s" % _c("1;36", ctx.ui_base),
        "",
        "  Now run your agent through it, in another terminal (%s):" % label,
        "",
        "    " + _c("1;32", env_line),
        "",
        "  captures: %s" % ("in memory (last %d) + JSONL at %s" % (store.maxlen, store.save_path) if store.save_path
                            else "in memory only (last %d); nothing written to disk. --save DIR to keep them." % store.maxlen),
        "  API keys and tokens are forwarded to the upstream but never shown or saved.",
        "  Ctrl+C to stop.",
        "",
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=NAME, description=TAGLINE + " A local proxy + web UI for coding-agent API traffic.")
    p.add_argument("--port", type=int, default=int(os.environ.get("WIRETAP_PORT", 8787)), help="proxy port (default 8787)")
    p.add_argument("--ui-port", type=int, default=int(os.environ.get("WIRETAP_UI_PORT", 8788)),
                   help="web UI port (default 8788; -1 = serve UI on the proxy port under %s/)" % UI_PREFIX)
    p.add_argument("--agent", choices=sorted(AGENTS), default="claude", help="preset for upstream + printed env line (default claude)")
    p.add_argument("--upstream", default=None, help="real API base URL to forward to (default from --agent; claude: https://api.anthropic.com)")
    p.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1; keep it local)")
    p.add_argument("--save", metavar="DIR", default=None, help="also append redacted captures as JSONL in DIR (off by default)")
    p.add_argument("--max", type=int, default=200, help="captures kept in memory (default 200)")
    p.add_argument("--timeout", type=float, default=600.0, help="upstream timeout seconds (default 600)")
    p.add_argument("--open", action="store_true", help="open the web UI in your browser")
    p.add_argument("--version", action="version", version="%s %s" % (NAME, __version__))
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    upstream = args.upstream or AGENTS[args.agent][0]
    try:
        if not ipaddress.ip_address(args.host).is_loopback:
            print("  warning: binding to %s exposes captured prompts to your network." % args.host, file=sys.stderr)
    except ValueError:
        pass
    store = Store(maxlen=args.max, save_dir=args.save, ident=A.LocalIdentity())
    try:
        ctx, proxy, ui = make_servers(args.host, args.port, args.ui_port, upstream, store, args.timeout)
    except OSError as e:
        print("%s: could not bind: %s (try --port / --ui-port)" % (NAME, e), file=sys.stderr)
        return 2
    except ValueError as e:
        print("%s: %s" % (NAME, e), file=sys.stderr)
        return 2
    print(banner(ctx, args.agent, store), flush=True)
    start_in_threads(proxy, ui)
    if args.open:
        webbrowser.open(ctx.ui_base)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n  bye.")
    finally:
        proxy.shutdown()
        if ui:
            ui.shutdown()
    return 0
