#!/usr/bin/env python3
"""Run wiretap against a local mock upstream and send SYNTHETIC traffic.

For screenshots/GIFs and for trying the UI without an API key. Nothing here
is real agent traffic; the payloads are made up and labelled as such.

    python3 scripts/demo.py            # UI on http://127.0.0.1:8788
"""
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tests import mock_upstream  # noqa: E402
from wiretap import analyze as A, core  # noqa: E402

PORT = int(os.environ.get("DEMO_PORT", 8787))
UI_PORT = int(os.environ.get("DEMO_UI_PORT", 8788))

SYSTEM = ("SYNTHETIC DEMO PAYLOAD (not captured from any real agent).\n"
          "You are a coding assistant. Working directory: /Users/demo/projects/acme-app\n"
          "Git remote: git@github.com:demo/acme-app.git\n"
          "Commit author: Demo User <demo@example.com>\n"
          "Platform: darwin. Shell: zsh.\u200b\n" + "Follow the style guide.\n" * 120)


def tool(name, desc, props, pad=0):
    return {"name": name, "description": desc + (" More detail." * pad),
            "input_schema": {"type": "object", "properties": {p: {"type": "string", "description": "the " + p} for p in props}}}


TOOLS = [tool("run_shell", "Run a shell command.", ["command", "cwd", "timeout"], 140),
         tool("edit_file", "Replace text in a file.", ["path", "old", "new"], 90),
         tool("read_file", "Read a file.", ["path", "offset", "limit"], 40),
         tool("search", "Search the codebase.", ["pattern", "glob"], 60),
         tool("web_fetch", "Fetch a URL.", ["url"], 25),
         tool("todo", "Track tasks.", ["items"], 30)]


def send(messages, system=SYSTEM):
    body = {"model": "mock-model", "max_tokens": 1024, "stream": True,
            "system": [{"type": "text", "text": system}], "tools": TOOLS, "messages": messages}
    req = urllib.request.Request("http://127.0.0.1:%d/v1/messages" % PORT, data=json.dumps(body).encode(),
                                 headers={"content-type": "application/json", "x-api-key": "sk-ant-demo-" + "0" * 30,
                                          "anthropic-version": "2023-06-01", "user-agent": "demo-client/0.0"})
    with urllib.request.urlopen(req) as r:
        r.read()


def main():
    mock, _ = mock_upstream.start(0, event_delay=0.01)
    ident = A.LocalIdentity(username="demo", hostname="demo-laptop", home="/Users/demo", git_email="demo@example.com", git_name="Demo User", auto=False)
    store = core.Store(ident=ident)
    ctx, proxy, ui = core.make_servers("127.0.0.1", PORT, UI_PORT, "http://127.0.0.1:%d" % mock.server_address[1], store)
    core.start_in_threads(proxy, ui)
    print(core.banner(ctx, "claude", store))
    m1 = [{"role": "user", "content": [{"type": "text", "text": "Reply OK"}]}]
    send(m1)
    m2 = m1 + [{"role": "assistant", "content": [{"type": "text", "text": "OK"}]},
               {"role": "user", "content": [{"type": "text", "text": "Now list the files in /Users/demo/projects/acme-app"}]}]
    send(m2, SYSTEM + "\nThe current date is (synthetic).")
    m3 = [{"role": "user", "content": [{"type": "text", "text": "Reply OK"}]}]
    send(m3)
    print("  sent 3 synthetic requests. UI: %s   (Ctrl+C to stop)" % ctx.ui_base, flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
