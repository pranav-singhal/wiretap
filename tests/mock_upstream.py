"""A tiny fake Anthropic-style API for tests and demos.

POST /v1/messages with "stream": true  -> Claude-style SSE stream (chunked, flushed per event)
POST /v1/messages without stream        -> JSON message
Every request is recorded (method, path, headers, body) so tests can check fidelity.
Synthetic data only; it says nothing about what a real API returns beyond the public event shapes.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SSE_EVENTS = [
    ("message_start", {"type": "message_start", "message": {"id": "msg_mock", "type": "message", "role": "assistant", "model": "mock-model", "content": [], "stop_reason": None, "usage": {"input_tokens": 1234, "output_tokens": 1}}}),
    ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
    ("ping", {"type": "ping"}),
    ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "O"}}),
    ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "K"}}),
    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
    ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 2}}),
    ("message_stop", {"type": "message_stop"}),
]


def sse_bytes():
    return b"".join(("event: %s\ndata: %s\n\n" % (e, json.dumps(d))).encode() for e, d in SSE_EVENTS)


class MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    received = None  # set per server
    event_delay = 0.0

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        self.received.append({"method": self.command, "path": self.path, "headers": list(self.headers.items()), "body": body})
        try:
            req = json.loads(body or b"{}")
        except ValueError:
            req = {}
        if self.path.startswith("/v1/fail"):
            data = b'{"type":"error","error":{"type":"overloaded_error","message":"mock overloaded"}}'
            self.send_response(529)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if req.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Mock-Header", "kept")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for e, d in SSE_EVENTS:
                chunk = ("event: %s\ndata: %s\n\n" % (e, json.dumps(d))).encode()
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
                if self.event_delay:
                    time.sleep(self.event_delay)
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        else:
            data = json.dumps({"id": "msg_mock", "type": "message", "role": "assistant", "model": "mock-model",
                               "content": [{"type": "text", "text": "OK"}], "stop_reason": "end_turn",
                               "usage": {"input_tokens": 1234, "output_tokens": 2}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Mock-Header", "kept")
            self.end_headers()
            self.wfile.write(data)

    def do_GET(self):
        self.received.append({"method": "GET", "path": self.path, "headers": list(self.headers.items()), "body": b""})
        data = b'{"data":[{"id":"mock-model"}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def start(port=0, event_delay=0.0):
    received = []
    h = type("H", (MockHandler,), {"received": received, "event_delay": event_delay})
    srv = ThreadingHTTPServer(("127.0.0.1", port), h)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, received


if __name__ == "__main__":
    import sys
    srv, _ = start(int(sys.argv[1]) if len(sys.argv) > 1 else 9999, event_delay=0.05)
    print("mock upstream on http://127.0.0.1:%d" % srv.server_address[1], flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
