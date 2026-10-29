import http.client
import json
import time
import unittest

from wiretap import analyze as A
from wiretap import core
from tests import mock_upstream

FAKE_KEY = "sk-ant-api03-" + "x" * 40


def sample_request(user_text="Reply OK", extra_system=""):
    return {
        "model": "mock-model", "max_tokens": 64, "stream": True,
        "system": [{"type": "text", "text": "You are a helpful assistant." + extra_system}],
        "tools": [
            {"name": "Read", "description": "Read a file", "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}}},
            {"name": "Bash", "description": "Run a command " + "x" * 500, "input_schema": {"type": "object", "properties": {"cmd": {"type": "string"}}}},
        ],
        "messages": [{"role": "user", "content": [{"type": "text", "text": user_text}]}],
    }


class Harness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock, cls.received = mock_upstream.start(event_delay=0.02)
        up = "http://127.0.0.1:%d" % cls.mock.server_address[1]
        ident = A.LocalIdentity(username="alice", hostname="alice-mbp.local", home="/Users/alice", git_email="alice@example.com", git_name="Alice Example", auto=False)
        cls.store = core.Store(maxlen=50, ident=ident)
        cls.ctx, cls.proxy, cls.ui = core.make_servers("127.0.0.1", 0, 0, up, cls.store)
        core.start_in_threads(cls.proxy, cls.ui)
        cls.pport = cls.proxy.server_address[1]
        cls.uport = cls.ui.server_address[1]

    @classmethod
    def tearDownClass(cls):
        for srv in (cls.proxy, cls.ui, cls.mock):
            srv.shutdown(); srv.server_close()

    def post(self, path, body, headers=None, port=None):
        c = http.client.HTTPConnection("127.0.0.1", port or self.pport, timeout=10)
        h = {"Content-Type": "application/json", "x-api-key": FAKE_KEY, "anthropic-version": "2023-06-01"}
        h.update(headers or {})
        c.request("POST", path, body=body if isinstance(body, bytes) else json.dumps(body).encode(), headers=h)
        self.addCleanup(c.close)
        r = c.getresponse()
        return r, r.read(), c

    def ui_get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.uport, timeout=10)
        self.addCleanup(c.close)
        c.request("GET", path)
        r = c.getresponse()
        return r, r.read()

    def wait_done(self, cid, timeout=5):
        end = time.time() + timeout
        while time.time() < end:
            rec = self.store.get(cid)
            if rec and rec.get("state") == "done" and "summary" in rec:
                return rec
            time.sleep(0.02)
        self.fail("capture %s not analyzed" % cid)

    def last_id(self):
        return max(self.store.items)


class TestForwarding(Harness):
    def test_body_and_headers_forwarded_byte_for_byte(self):
        raw = json.dumps(sample_request("hi \u200b there")).encode()
        n = len(self.received)
        r, data, _ = self.post("/v1/messages?beta=true", raw, {"anthropic-beta": "x-1", "X-Custom": "Keep Me"})
        self.assertEqual(r.status, 200)
        got = self.received[n]
        self.assertEqual(got["body"], raw)
        self.assertEqual(got["path"], "/v1/messages?beta=true")
        h = {k.lower(): v for k, v in got["headers"]}
        self.assertEqual(h["x-api-key"], FAKE_KEY)  # auth passes through to the upstream
        self.assertEqual(h["x-custom"], "Keep Me")
        self.assertEqual(h["anthropic-beta"], "x-1")
        self.assertEqual(h["host"], "127.0.0.1:%d" % self.mock.server_address[1])

    def test_raw_header_order_and_case_preserved(self):
        import socket
        body = b'{"model":"m","messages":[{"role":"user","content":"x"}]}'
        hdrs = [("User-Agent", "test/1.0"), ("X-Api-Key", FAKE_KEY), ("anthropic-version", "2023-06-01"),
                ("Content-Type", "application/json"), ("X-Dup", "a"), ("X-Dup", "b"), ("Content-Length", str(len(body)))]
        raw = "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n" % self.pport
        raw += "".join("%s: %s\r\n" % kv for kv in hdrs) + "Connection: close\r\n\r\n"
        n = len(self.received)
        s = socket.create_connection(("127.0.0.1", self.pport), timeout=10)
        self.addCleanup(s.close)
        s.sendall(raw.encode() + body)
        resp = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
        self.assertTrue(resp.startswith(b"HTTP/1.1 200"))
        got = self.received[n]
        self.assertEqual(got["body"], body)
        self.assertEqual([kv for kv in got["headers"] if kv[0].lower() != "host"], hdrs)

    def test_sse_passthrough_identical_and_incremental(self):
        c = http.client.HTTPConnection("127.0.0.1", self.pport, timeout=10)
        c.request("POST", "/v1/messages", body=json.dumps(sample_request()).encode(),
                  headers={"Content-Type": "application/json", "x-api-key": FAKE_KEY})
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        self.assertIn("text/event-stream", r.getheader("Content-Type"))
        self.assertEqual(r.getheader("X-Mock-Header"), "kept")
        first = r.read1(65536)
        self.assertTrue(first.startswith(b"event: message_start"), first[:60])
        self.assertLess(len(first), len(mock_upstream.sse_bytes()))  # streamed, not buffered
        rest = r.read()
        self.assertEqual(first + rest, mock_upstream.sse_bytes())
        rec = self.wait_done(self.last_id())
        resp = rec["response"]
        self.assertEqual(resp["kind"], "sse")
        self.assertEqual(resp["text"], "OK")
        self.assertEqual(resp["usage"]["input_tokens"], 1234)
        self.assertEqual(resp["usage"]["output_tokens"], 2)
        self.assertEqual(resp["stop_reason"], "end_turn")
        self.assertEqual(resp["event_types"]["content_block_delta"], 2)

    def test_client_disconnect_mid_stream_is_recorded(self):
        import socket
        body = json.dumps(sample_request()).encode()
        s = socket.create_connection(("127.0.0.1", self.pport), timeout=10)
        s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
        self.assertIn(b"200", s.recv(200))
        s.close()
        cid = self.last_id()
        end = time.time() + 5
        while time.time() < end and self.store.get(cid).get("state") != "done":
            time.sleep(0.05)
        rec = self.store.get(cid)
        self.assertEqual(rec["status"], 200)
        self.assertIn("disconnected", rec.get("error", ""))

    def test_json_response_and_keepalive(self):
        body = sample_request(); body["stream"] = False
        r, data, conn = self.post("/v1/messages", body)
        self.assertEqual(json.loads(data)["content"][0]["text"], "OK")
        conn.request("GET", "/v1/models", headers={"x-api-key": FAKE_KEY})  # same connection again
        r2 = conn.getresponse()
        self.assertEqual(r2.status, 200)
        self.assertIn(b"mock-model", r2.read())

    def test_error_status_passthrough(self):
        r, data, _ = self.post("/v1/fail", sample_request())
        self.assertEqual(r.status, 529)
        self.assertIn(b"overloaded_error", data)

    def test_upstream_down_gives_502(self):
        store = core.Store()
        ctx, proxy, _ = core.make_servers("127.0.0.1", 0, -1, "http://127.0.0.1:9", store)
        core.start_in_threads(proxy)
        try:
            r, data, _ = self.post("/v1/messages", sample_request(), port=proxy.server_address[1])
            self.assertEqual(r.status, 502)
            self.assertIn(b"upstream_error", data)
        finally:
            proxy.shutdown(); proxy.server_close()


class TestRedaction(Harness):
    def test_keys_never_in_ui_or_exports(self):
        body = sample_request("my key is %s and token ghp_%s" % (FAKE_KEY, "a" * 36))
        self.post("/v1/messages", body, {"Authorization": "Bearer " + FAKE_KEY})
        cid = self.last_id()
        self.wait_done(cid)
        for path in ("/api/captures", "/api/captures/%d" % cid, "/api/captures/%d.json" % cid, "/api/captures/%d.md" % cid):
            r, data = self.ui_get(path)
            self.assertEqual(r.status, 200, path)
            self.assertNotIn(FAKE_KEY.encode(), data, path)
            self.assertNotIn(b"ghp_" + b"a" * 36, data, path)
        rec = json.loads(self.ui_get("/api/captures/%d" % cid)[1])
        hdr = {k.lower(): v for k, v in rec["req_headers"]}
        self.assertTrue(hdr["x-api-key"].startswith("[REDACTED"))
        self.assertTrue(hdr["authorization"].startswith("Bearer [REDACTED"))
        self.assertIn("secret", rec["pii"]["counts"])

    def test_redact_helpers(self):
        self.assertNotIn("sk-ant", A.redact_text("x " + FAKE_KEY))
        self.assertEqual(A.redact_path("/v1/x?key=AIzaSECRET&alt=sse"), "/v1/x?key=[REDACTED]&alt=sse")
        self.assertTrue(A.is_sensitive_header("X-Goog-Api-Key"))
        self.assertFalse(A.is_sensitive_header("anthropic-version"))

    def test_save_jsonl_is_redacted(self):
        import tempfile, os
        d = tempfile.mkdtemp()
        store = core.Store(save_dir=d)
        up = "http://127.0.0.1:%d" % self.mock.server_address[1]
        ctx, proxy, _ = core.make_servers("127.0.0.1", 0, -1, up, store)
        core.start_in_threads(proxy)
        try:
            self.post("/v1/messages", sample_request("key " + FAKE_KEY), port=proxy.server_address[1])
            end = time.time() + 5
            while time.time() < end and not (store.save_path.exists() and store.save_path.stat().st_size):
                time.sleep(0.05)
            text = store.save_path.read_text()
            self.assertIn('"summary"', text)
            self.assertNotIn(FAKE_KEY, text)
            if os.name == "posix":
                self.assertEqual(oct(os.stat(store.save_path).st_mode & 0o777), "0o600")
        finally:
            proxy.shutdown(); proxy.server_close()


class TestHidden(unittest.TestCase):
    def test_categories(self):
        tag = "".join(chr(0xE0000 + ord(c)) for c in "hi")
        s = "a\u200bb \u202egnp.exe c\u00a0d s" + tag + "e \u0440aypal \ufeff x\x07"
        h = A.scan_hidden({"system": s})
        for cat in ("zero_width", "bidi", "tag", "unusual_space", "homoglyph", "control"):
            self.assertIn(cat, h["counts"], cat)
        self.assertEqual(h["counts"]["tag"], 2)
        self.assertEqual(h["tag_runs"][0]["decoded"], "hi")
        self.assertEqual(h["counts"]["zero_width"], 2)  # U+200B and U+FEFF
        self.assertTrue(any(f["codepoint"] == "U+202E" for f in h["findings"]))

    def test_clean_text_and_emoji(self):
        self.assertEqual(A.scan_hidden({"a": "plain ascii\n\ttext", "b": "caf\u00e9 \u4f60\u597d"})["total"], 0)
        h = A.scan_hidden("\U0001F468\u200d\U0001F4BB")  # emoji ZWJ sequence
        self.assertEqual(h["warn"], 0)
        self.assertEqual(h["counts"]["zero_width"], 1)

    def test_variation_selectors(self):
        # single VS16 after an emoji / keycap is fine
        h = A.scan_hidden({"a": "\u2764\ufe0f ok 1\ufe0f\u20e3"})
        self.assertEqual(h["warn"], 0)
        self.assertEqual(h["counts"]["variation_selector"], 2)
        # a run of selectors smuggles bytes: warn and decode
        payload = "".join(chr(0xFE00 + b) if b < 16 else chr(0xE0100 + b - 16) for b in b"hi")
        h = A.scan_hidden({"a": "look \U0001F600" + payload + " here"})
        self.assertEqual(h["warn"], 2)
        self.assertTrue(any(r["kind"] == "variation_selectors" and r["decoded"] == "hi" for r in h["tag_runs"]))
        # stray selector on plain Latin text warns
        self.assertEqual(A.scan_hidden("abc\ufe0fdef")["warn"], 1)
        self.assertEqual(A.scan_hidden("abc\U000E0101def")["warn"], 1)

    def test_apostrophe_lookalikes_but_not_curly(self):
        self.assertEqual(A.scan_hidden("Today\u2019s date is 2026-10-29")["total"], 0)
        for cp in ("\u02bc", "\u02b9"):
            h = A.scan_hidden("Today" + cp + "s date is 2026-10-29")
            self.assertEqual(h["warn"], 1, cp)
            self.assertIn("apostrophe_lookalike", h["counts"])

    def test_cyrillic_inside_latin_word(self):
        h = A.scan_hidden("please run \u0440ip install and \u0430dmin")  # Cyrillic er, a
        self.assertEqual(h["counts"].get("homoglyph"), 2)
        # all-Cyrillic words next to Latin words are fine
        self.assertEqual(A.scan_hidden("\u041c\u043e\u0441\u043a\u0432\u0430 and London")["total"], 0)

    def test_legit_emoji_and_indic_joiners(self):
        texts = ["\U0001F469\u200d\U0001F4BB", "\U0001F44D\U0001F3FD", "\u2764\ufe0f\u200d\U0001F525",
                 "\U0001F3F3\ufe0f\u200d\U0001F308",
                 "\u0915\u094d\u200d\u0937",   # Devanagari half-form with ZWJ
                 "\u0915\u094d\u200c\u0937",   # Devanagari with ZWNJ
                 "\u0d28\u0d4d\u200d",          # Malayalam chillu
                 "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645"]  # Persian ZWNJ
        for t in texts:
            self.assertEqual(A.scan_hidden(t)["warn"], 0, ascii(t))
        self.assertEqual(A.scan_hidden("ign\u200dore")["warn"], 1)
        scotland = "\U0001F3F4" + "".join(chr(0xE0000 + ord(c)) for c in "gbsct") + "\U000E007F"
        h = A.scan_hidden("flag " + scotland)
        self.assertEqual(h["warn"], 0)
        self.assertEqual(h["tag_runs"], [])

    def test_end_to_end_flag(self):
        r = A.analyze_request("/v1/messages", json.dumps(sample_request("he\u200bllo")).encode())
        self.assertEqual(r["hidden"]["warn"], 1)
        self.assertEqual(r["hidden"]["findings"][0]["path"], "$.messages[0].content[0].text")


class TestPII(unittest.TestCase):
    ident = A.LocalIdentity(username="alice", hostname="alice-mbp.local", home="/Users/alice", git_email="alice@example.com", git_name="Alice Example", auto=False)

    def test_patterns_and_local_identity(self):
        txt = ("Working dir: /Users/alice/code/app on host alice-mbp; contact bob@corp.io; "
               "remote git@github.com:alice/app.git and https://github.com/alice/app ip 10.0.0.12 "
               "author Alice Example <alice@example.com>")
        p = A.find_pii({"system": txt}, self.ident)
        c = p["counts"]
        self.assertEqual(c["email"], 2)
        self.assertEqual(c["home_path_username"], 1)
        self.assertGreaterEqual(c["local_username"], 1)
        self.assertEqual(c["local_hostname"], 1)
        self.assertEqual(c["local_home_dir"], 1)
        self.assertEqual(c["git_email"], 1)
        self.assertEqual(c["git_name"], 1)
        self.assertEqual(c["git_remote"], 2)
        self.assertEqual(c["ip_address"], 1)

    def test_username_word_boundary(self):
        p = A.find_pii({"t": "malice and alicent are not alice"}, self.ident)
        self.assertEqual(p["counts"].get("local_username"), 1)

    def test_windows_path(self):
        p = A.find_pii({"t": r"C:\Users\Bob\proj"}, None)
        self.assertEqual(p["items"][0]["value"], "Bob")

    def test_clean(self):
        self.assertEqual(A.find_pii({"t": "nothing here"}, self.ident)["total"], 0)


class TestDecodersAndDiff(unittest.TestCase):
    def test_anthropic_summary(self):
        r = A.analyze_request("/v1/messages", json.dumps(sample_request()).encode())
        s = r["summary"]
        self.assertEqual(r["api"], "anthropic.messages")
        self.assertEqual(s["tool_count"], 2)
        self.assertEqual(s["biggest"][0]["label"], "Bash")
        self.assertEqual(s["last_user_text"], "Reply OK")
        self.assertEqual(s["last_user_bytes"], 8)
        self.assertGreater(s["amplification"], 10)

    def test_openai_chat_and_responses_and_gemini(self):
        chat = {"model": "m", "messages": [{"role": "system", "content": "S"}, {"role": "user", "content": "U"}],
                "tools": [{"type": "function", "function": {"name": "f", "description": "d", "parameters": {}}}]}
        r = A.analyze_request("/v1/chat/completions", json.dumps(chat).encode())
        self.assertEqual((r["api"], len(r["decoded"]["system"]), r["decoded"]["tools"][0]["name"]), ("openai.chat", 1, "f"))
        resp = {"model": "m", "instructions": "I", "input": [{"role": "user", "content": [{"type": "input_text", "text": "hey"}]}], "tools": [{"type": "function", "name": "g"}]}
        r = A.analyze_request("/v1/responses", json.dumps(resp).encode())
        self.assertEqual((r["api"], r["decoded"]["system"][0]["text"], r["decoded"]["tools"][0]["name"]), ("openai.responses", "I", "g"))
        gem = {"systemInstruction": {"parts": [{"text": "SI"}]}, "contents": [{"role": "user", "parts": [{"text": "q"}]}],
               "tools": [{"functionDeclarations": [{"name": "h", "description": ""}]}]}
        r = A.analyze_request("/v1beta/models/x:streamGenerateContent", json.dumps(gem).encode())
        self.assertEqual((r["api"], r["decoded"]["system"][0]["text"], r["decoded"]["tools"][0]["name"]), ("gemini", "SI", "h"))

    def test_non_json_body(self):
        r = A.analyze_request("/x", b"\x00\x01binary")
        self.assertFalse(r["is_json"])

    def test_diff(self):
        a = sample_request("first")
        b = sample_request("first", extra_system="\nToday is X.")
        b["messages"] += [{"role": "assistant", "content": "ok"}, {"role": "user", "content": "second"}]
        b["tools"].append({"name": "Write", "input_schema": {}})
        ra = A.analyze_request("/v1/messages", json.dumps(a).encode()); ra["id"] = 1
        rb = A.analyze_request("/v1/messages", json.dumps(b).encode())
        d = A.diff_requests(ra, rb)
        self.assertTrue(d["system_changed"])
        self.assertEqual(d["tools_added"], ["Write"])
        self.assertEqual(d["messages_common_prefix"], 1)
        self.assertEqual(len(d["new_messages"]), 2)
        self.assertFalse(d["history_rewritten"])
        self.assertTrue(any(l.startswith("+Today is X.") for l in d["system_diff"]))

    def test_report_has_no_text_or_pii(self):
        r = A.analyze_request("/v1/messages", json.dumps(sample_request("email me at bob@corp.io")).encode())
        r.update(id=7, method="POST", path="/v1/messages", status=200, duration_ms=5, req_headers=[["x-api-key", "[REDACTED]"]])
        md = A.markdown_report(r)
        self.assertIn("| `Bash` |", md)
        self.assertIn("email: 1", md)
        self.assertNotIn("bob@corp.io", md)
        self.assertNotIn("helpful assistant", md)


class TestUI(Harness):
    def test_index_and_api(self):
        r, html = self.ui_get("/")
        self.assertEqual(r.status, 200)
        self.assertIn(b"<title>wiretap</title>", html)
        self.assertNotIn(b"https://", html.split(b"<script>")[0])  # no external assets
        info = json.loads(self.ui_get("/api/info")[1])
        self.assertEqual(info["name"], "wiretap")
        self.post("/v1/messages", sample_request("Reply OK"))
        cid = self.last_id()
        self.wait_done(cid)
        lst = json.loads(self.ui_get("/api/captures")[1])
        self.assertEqual(lst["items"][0]["id"], cid)
        self.assertTrue(any("/v1/messages" in e["endpoint"] for e in lst["endpoints"]))
        unchanged = json.loads(self.ui_get("/api/captures?rev=%d" % lst["rev"])[1])
        self.assertTrue(unchanged.get("unchanged"))

    def test_ui_on_proxy_port_and_host_guard(self):
        c = http.client.HTTPConnection("127.0.0.1", self.pport, timeout=5)
        c.request("GET", "/__wiretap/api/info")
        self.assertEqual(c.getresponse().status, 200)
        c = http.client.HTTPConnection("127.0.0.1", self.uport, timeout=5)
        c.request("GET", "/api/captures", headers={"Host": "evil.example.com"})
        self.assertEqual(c.getresponse().status, 403)


if __name__ == "__main__":
    unittest.main()
