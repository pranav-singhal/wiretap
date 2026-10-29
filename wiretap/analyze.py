"""Pure analysis functions: decoders, hidden-character scan, PII finder,
redaction, diffs, response parsing and the shareable report.

Everything here works only on captured data. Nothing is assumed about what
any particular agent sends; if a field is not in the capture it is not shown.
"""
from __future__ import annotations

import difflib
import getpass
import json
import os
import re
import socket
import subprocess
import unicodedata
from typing import Any, Callable, Dict, List, Optional

# --------------------------------------------------------------------------
# sizes / token estimates
# --------------------------------------------------------------------------


def jbytes(obj: Any) -> int:
    """UTF-8 size of obj as compact JSON (strings: raw UTF-8 size)."""
    if isinstance(obj, str):
        return len(obj.encode("utf-8", "surrogatepass"))
    return len(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "surrogatepass"))


def est_tokens(nbytes: int) -> int:
    """Rough token estimate (~4 bytes per token). Labelled as an estimate in the UI."""
    return (nbytes + 3) // 4


# --------------------------------------------------------------------------
# secret redaction
# --------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}")),
    ("openai-key", re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}")),
    ("github-token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"xox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=:+/]{16,}")),
]

SENSITIVE_HEADER_EXACT = {
    "authorization", "proxy-authorization", "x-api-key", "api-key", "cookie",
    "set-cookie", "x-goog-api-key", "anthropic-api-key", "openai-api-key",
}
SENSITIVE_HEADER_WORDS = ("token", "secret", "key", "auth", "cookie", "session", "password", "credential")
SENSITIVE_QUERY = re.compile(r"(?i)([?&](?:key|api_key|apikey|token|access_token|auth|sig|signature)=)[^&#]*")


def redact_text(s: str) -> str:
    for label, pat in SECRET_PATTERNS:
        s = pat.sub(lambda m, l=label: "[REDACTED %s, %d chars]" % (l, len(m.group(0))), s)
    return s


def redact_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    return obj


def is_sensitive_header(name: str) -> bool:
    n = name.lower()
    if n in SENSITIVE_HEADER_EXACT:
        return True
    return any(w in n for w in SENSITIVE_HEADER_WORDS)


def redact_headers(headers) -> List[List[str]]:
    """headers: iterable of (name, value). Returns [[name, redacted_value], ...]."""
    out = []
    for k, v in headers:
        if is_sensitive_header(k):
            parts = v.split(" ", 1)
            if len(parts) == 2 and parts[0].lower() in ("bearer", "basic", "token"):
                v = "%s [REDACTED, %d chars]" % (parts[0], len(parts[1]))
            else:
                v = "[REDACTED, %d chars]" % len(v)
        else:
            v = redact_text(v)
        out.append([k, v])
    return out


def redact_path(path: str) -> str:
    return SENSITIVE_QUERY.sub(lambda m: m.group(1) + "[REDACTED]", path)


# --------------------------------------------------------------------------
# decoders (one small function per API shape; see CONTRIBUTING.md)
# --------------------------------------------------------------------------


def _blocks_text(content: Any) -> str:
    """Flatten message content (string or list of blocks) into readable text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        content = [content]
    parts = []
    for b in content if isinstance(content, list) else [content]:
        if isinstance(b, str):
            parts.append(b)
        elif isinstance(b, dict):
            t = b.get("type")
            if isinstance(b.get("text"), str):
                parts.append(b["text"])
            elif t in ("tool_use", "function_call"):
                parts.append("[%s %s] %s" % (t, b.get("name", ""), json.dumps(b.get("input", b.get("arguments")), ensure_ascii=False)))
            elif t in ("tool_result", "function_call_output"):
                inner = b.get("content", b.get("output"))
                parts.append("[%s] %s" % (t, _blocks_text(inner)))
            elif t in ("thinking", "redacted_thinking"):
                parts.append("[%s] %s" % (t, b.get("thinking", "")))
            elif t == "image" or t == "image_url" or "inline_data" in b or "inlineData" in b:
                parts.append("[image, %d bytes]" % jbytes(b))
            elif "functionCall" in b or "functionResponse" in b:
                parts.append(json.dumps(b, ensure_ascii=False))
            else:
                parts.append("[%s] %s" % (t or "block", json.dumps(b, ensure_ascii=False)[:2000]))
    return "\n".join(parts)


def _kinds(content: Any) -> List[str]:
    if isinstance(content, list):
        return [b.get("type", "?") if isinstance(b, dict) else type(b).__name__ for b in content]
    return ["text"] if isinstance(content, str) else []


def _sys_item(label: str, text: str) -> Dict[str, Any]:
    b = jbytes(text)
    return {"label": label, "text": text, "bytes": b, "tokens": est_tokens(b)}


def _tool_item(name: str, description: str, obj: Any) -> Dict[str, Any]:
    b = jbytes(obj)
    return {"name": name or "?", "description": description or "", "bytes": b, "tokens": est_tokens(b), "json": obj}


def _msg_item(role: str, content: Any) -> Dict[str, Any]:
    b = jbytes(content)
    return {"role": role or "?", "text": _blocks_text(content), "bytes": b, "tokens": est_tokens(b), "kinds": _kinds(content)}


def _other(body: dict, used: set) -> Dict[str, Any]:
    return {k: v for k, v in body.items() if k not in used}


def decode_anthropic(body: dict) -> Dict[str, Any]:
    system = []
    s = body.get("system")
    if isinstance(s, str):
        system.append(_sys_item("system", s))
    elif isinstance(s, list):
        for i, blk in enumerate(s):
            text = blk.get("text", "") if isinstance(blk, dict) else str(blk)
            system.append(_sys_item("system[%d]" % i, text))
    tools = [_tool_item(t.get("name", t.get("type", "?")), t.get("description", ""), t) for t in body.get("tools") or [] if isinstance(t, dict)]
    messages = [_msg_item(m.get("role"), m.get("content")) for m in body.get("messages") or [] if isinstance(m, dict)]
    return {"system": system, "tools": tools, "messages": messages,
            "other": _other(body, {"system", "tools", "messages"})}


def decode_openai_chat(body: dict) -> Dict[str, Any]:
    system, messages = [], []
    for i, m in enumerate(body.get("messages") or []):
        if not isinstance(m, dict):
            continue
        if m.get("role") in ("system", "developer"):
            system.append(_sys_item("%s[%d]" % (m["role"], i), _blocks_text(m.get("content"))))
        else:
            messages.append(_msg_item(m.get("role"), m.get("content") if m.get("content") is not None else m.get("tool_calls")))
    tools = []
    for t in body.get("tools") or []:
        if isinstance(t, dict):
            f = t.get("function", t)
            tools.append(_tool_item(f.get("name", t.get("type")), f.get("description", ""), t))
    return {"system": system, "tools": tools, "messages": messages,
            "other": _other(body, {"messages", "tools"})}


def decode_openai_responses(body: dict) -> Dict[str, Any]:
    system, messages = [], []
    if isinstance(body.get("instructions"), str):
        system.append(_sys_item("instructions", body["instructions"]))
    inp = body.get("input")
    if isinstance(inp, str):
        messages.append(_msg_item("user", inp))
    elif isinstance(inp, list):
        for i, m in enumerate(inp):
            if not isinstance(m, dict):
                continue
            role = m.get("role") or m.get("type")
            if role in ("system", "developer"):
                system.append(_sys_item("%s[%d]" % (role, i), _blocks_text(m.get("content"))))
            else:
                messages.append(_msg_item(role, m.get("content", m)))
    tools = [_tool_item(t.get("name", t.get("type")), t.get("description", ""), t) for t in body.get("tools") or [] if isinstance(t, dict)]
    return {"system": system, "tools": tools, "messages": messages,
            "other": _other(body, {"instructions", "input", "tools"})}


def decode_gemini(body: dict) -> Dict[str, Any]:
    system = []
    si = body.get("systemInstruction") or body.get("system_instruction")
    if isinstance(si, dict):
        system.append(_sys_item("systemInstruction", _blocks_text(si.get("parts"))))
    tools = []
    for t in body.get("tools") or []:
        if not isinstance(t, dict):
            continue
        decls = t.get("functionDeclarations") or t.get("function_declarations")
        if decls:
            for d in decls:
                tools.append(_tool_item(d.get("name"), d.get("description", ""), d))
        else:
            tools.append(_tool_item(",".join(t.keys()), "", t))
    messages = [_msg_item(c.get("role", "user"), c.get("parts")) for c in body.get("contents") or [] if isinstance(c, dict)]
    return {"system": system, "tools": tools, "messages": messages,
            "other": _other(body, {"systemInstruction", "system_instruction", "tools", "contents"})}


def decode_generic(body: Any) -> Dict[str, Any]:
    return {"system": [], "tools": [], "messages": [],
            "other": body if isinstance(body, dict) else {"body": body}}


# (name, matcher(path, body) -> bool, decoder). First match wins. Add yours here.
DECODERS: List[tuple] = [
    ("anthropic.messages", lambda p, b: "/messages" in p and "messages" in b, decode_anthropic),
    ("openai.responses", lambda p, b: p.split("?")[0].endswith("/responses") or ("input" in b and "model" in b and "messages" not in b), decode_openai_responses),
    ("openai.chat", lambda p, b: "/chat/completions" in p or ("messages" in b and isinstance(b.get("messages"), list) and any(isinstance(m, dict) and m.get("role") in ("system", "developer") for m in b["messages"])), decode_openai_chat),
    ("gemini", lambda p, b: "contents" in b or ":generateContent" in p or ":streamGenerateContent" in p, decode_gemini),
    ("anthropic.messages", lambda p, b: "messages" in b, decode_anthropic),
]


def decode_request(path: str, body: Any) -> Dict[str, Any]:
    if not isinstance(body, dict):
        d = decode_generic(body)
        d["api"] = "unknown"
        return d
    for name, match, fn in DECODERS:
        try:
            if match(path, body):
                d = fn(body)
                d["api"] = name
                return d
        except Exception:  # a broken decoder must never break the proxy
            continue
    d = decode_generic(body)
    d["api"] = "unknown"
    return d


# --------------------------------------------------------------------------
# hidden / unusual characters
# --------------------------------------------------------------------------

ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x180E, 0x034F}
BIDI = {0x200E, 0x200F, 0x061C, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
LATIN = re.compile(r"[A-Za-z]")
WORD = re.compile(r"[^\W\d_]+", re.UNICODE)


def char_category(cp: int) -> Optional[str]:
    if cp in ZERO_WIDTH:
        return "zero_width"
    if cp in BIDI:
        return "bidi"
    if 0xE0000 <= cp <= 0xE007F:
        return "tag"
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        return "variation_selector"
    ch = chr(cp)
    cat = unicodedata.category(ch)
    if cat == "Cc" and ch not in "\t\n\r":
        return "control"
    if cat == "Co":
        return "private_use"
    if cat == "Cf":
        return "format"
    if cat == "Zs" and cp != 0x20:
        return "unusual_space"
    if cat in ("Zl", "Zp"):
        return "unusual_space"
    return None


def _cname(cp: int) -> str:
    try:
        return unicodedata.name(chr(cp))
    except ValueError:
        if 0xE0000 <= cp <= 0xE007F:
            return "TAG CHARACTER"
        return "UNNAMED"


def _is_emoji_neighbour(s: str, i: int) -> bool:
    for j in (i - 1, i + 1):
        if 0 <= j < len(s) and unicodedata.category(s[j]) in ("So", "Sk"):
            return True
    return False


def _walk_strings(obj: Any, path: str = "$"):
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, "%s[%d]" % (path, i))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                yield from _walk_strings(k, "%s.<key>" % path)
            yield from _walk_strings(v, "%s.%s" % (path, k))


def _context(s: str, i: int, width: int = 24) -> str:
    a, b = max(0, i - width), min(len(s), i + width + 1)
    out = []
    for k in range(a, b):
        cp = ord(s[k])
        if k == i or char_category(cp):
            out.append("\u27e6U+%04X\u27e7" % cp)
        else:
            out.append(s[k])
    return "".join(out).replace("\n", "\u21b5")


def scan_hidden(obj: Any, limit: int = 500) -> Dict[str, Any]:
    """Find zero-width, bidi, tag, variation-selector, control, private-use,
    format and unusual-space characters plus mixed-script (homoglyph-ish)
    words in every string in obj."""
    counts: Dict[str, int] = {}
    findings: List[Dict[str, Any]] = []
    tag_runs: List[Dict[str, str]] = []

    def add(cat, path, s, i, severity="warn"):
        counts[cat] = counts.get(cat, 0) + 1
        if len(findings) < limit:
            cp = ord(s[i])
            findings.append({"category": cat, "path": path, "index": i, "codepoint": "U+%04X" % cp,
                             "name": _cname(cp), "severity": severity, "context": redact_text(_context(s, i))})

    for path, s in _walk_strings(obj):
        if s.isascii():
            continue
        run = []
        for i, ch in enumerate(s):
            cp = ord(ch)
            cat = char_category(cp)
            if cat == "tag":
                run.append(chr(cp - 0xE0000) if 0x20 <= cp - 0xE0000 < 0x7F else "")
            elif run:
                tag_runs.append({"path": path, "decoded": "".join(run)})
                run = []
            if cat:
                sev = "info" if cat in ("zero_width", "variation_selector") and _is_emoji_neighbour(s, i) else "warn"
                if cat == "unusual_space" and cp in (0xA0, 0x202F):
                    sev = "info"
                add(cat, path, s, i, sev)
        if run:
            tag_runs.append({"path": path, "decoded": "".join(run)})
        for m in WORD.finditer(s):
            w = m.group(0)
            if LATIN.search(w):
                for k, ch in enumerate(w):
                    cp = ord(ch)
                    if 0x0370 <= cp <= 0x03FF or 0x0400 <= cp <= 0x04FF or 0xFF21 <= cp <= 0xFF5A:
                        add("homoglyph", path, s, m.start() + k)
    total = sum(counts.values())
    warn = sum(1 for f in findings if f["severity"] == "warn")
    return {"total": total, "warn": warn, "counts": counts, "findings": findings, "tag_runs": tag_runs}


# --------------------------------------------------------------------------
# personal data finder
# --------------------------------------------------------------------------

EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}(?![A-Za-z0-9:\-])")
HOME_PATH = re.compile(r"(?:/Users/|/home/)([A-Za-z0-9._\-]+)|[A-Za-z]:\\+Users\\+([^\\/\"\s]+)")
GIT_REMOTE = re.compile(r"git@[\w.\-]+:[\w\-/]+(?:\.[\w\-]+)*|https?://(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)/[\w.\-]+/[\w.\-]+")
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


class LocalIdentity:
    """Strings that identify *this* machine, gathered locally once and only
    used for matching. Never sent anywhere."""

    def __init__(self, username=None, hostname=None, home=None, git_email=None, git_name=None, auto=True):
        def safe(fn):
            try:
                return fn()
            except Exception:
                return None

        def git(key):
            out = subprocess.run(["git", "config", "--global", key], capture_output=True, text=True, timeout=2)
            return out.stdout.strip() or None

        self.username = username if username is not None else (safe(getpass.getuser) if auto else None)
        hn = hostname if hostname is not None else (safe(socket.gethostname) if auto else None)
        self.hostname = hn
        self.home = home if home is not None else (safe(lambda: os.path.expanduser("~")) if auto else None)
        self.git_email = git_email if git_email is not None else (safe(lambda: git("user.email")) if auto else None)
        self.git_name = git_name if git_name is not None else (safe(lambda: git("user.name")) if auto else None)

    def needles(self) -> List[tuple]:
        out = []
        for kind, val in (("local_username", self.username), ("local_hostname", self.hostname),
                          ("local_home_dir", self.home), ("git_email", self.git_email), ("git_name", self.git_name)):
            if val and len(val) >= 3 and val not in ("/", "root", "localhost"):
                out.append((kind, val))
        if self.hostname and "." in self.hostname:
            short = self.hostname.split(".")[0]
            if len(short) >= 3:
                out.append(("local_hostname", short))
        return out


def find_pii(obj: Any, ident: Optional[LocalIdentity] = None) -> Dict[str, Any]:
    found: Dict[tuple, Dict[str, Any]] = {}

    def add(kind, value, path):
        key = (kind, value)
        f = found.setdefault(key, {"type": kind, "value": value, "count": 0, "paths": []})
        f["count"] += 1
        if len(f["paths"]) < 5 and path not in f["paths"]:
            f["paths"].append(path)

    needles = ident.needles() if ident else []
    for path, s in _walk_strings(obj):
        for m in EMAIL.finditer(s):
            add("email", m.group(0), path)
        for m in HOME_PATH.finditer(s):
            add("home_path_username", m.group(1) or m.group(2), path)
        for m in GIT_REMOTE.finditer(s):
            add("git_remote", m.group(0), path)
        for m in IPV4.finditer(s):
            add("ip_address", m.group(0), path)
        for label, pat in SECRET_PATTERNS:
            for m in pat.finditer(s):
                add("secret", "[REDACTED %s]" % label, path)
        if "[REDACTED " in s:
            for m in re.finditer(r"\[REDACTED ([a-z\-]+), \d+ chars\]", s):
                add("secret", "[REDACTED %s]" % m.group(1), path)
        for kind, val in needles:
            if kind in ("local_username", "git_name", "local_hostname"):
                pat = re.compile(r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9])" % re.escape(val))
                n = len(pat.findall(s))
            else:
                n = s.count(val)
            for _ in range(n):
                add(kind, val, path)
    items = sorted(found.values(), key=lambda f: (-f["count"], f["type"]))
    counts: Dict[str, int] = {}
    for f in items:
        counts[f["type"]] = counts.get(f["type"], 0) + f["count"]
    return {"total": sum(counts.values()), "counts": counts, "items": items}


# --------------------------------------------------------------------------
# summary, diff
# --------------------------------------------------------------------------


def summarize(decoded: Dict[str, Any], total_bytes: int) -> Dict[str, Any]:
    sb = sum(x["bytes"] for x in decoded["system"])
    tb = sum(x["bytes"] for x in decoded["tools"])
    mb = sum(x["bytes"] for x in decoded["messages"])
    ob = jbytes(decoded["other"]) if decoded["other"] else 0
    items = []
    for x in decoded["system"]:
        items.append({"kind": "system", "label": x["label"], "bytes": x["bytes"]})
    for x in decoded["tools"]:
        items.append({"kind": "tool", "label": x["name"], "bytes": x["bytes"]})
    for i, x in enumerate(decoded["messages"]):
        items.append({"kind": "message", "label": "#%d %s" % (i, x["role"]), "bytes": x["bytes"]})
    items.sort(key=lambda x: -x["bytes"])
    last_user = None
    for m in reversed(decoded["messages"]):
        if m["role"] == "user" and "tool_result" not in m["kinds"]:
            last_user = m
            break
    lut = None
    if last_user is not None:
        # The user's own words: text blocks only, without injected reminder blocks we can't distinguish -> show all text
        lut = last_user["text"]
    lub = jbytes(lut) if lut is not None else None
    return {
        "total_bytes": total_bytes,
        "system_bytes": sb, "system_tokens": est_tokens(sb), "system_blocks": len(decoded["system"]),
        "tools_bytes": tb, "tools_tokens": est_tokens(tb), "tool_count": len(decoded["tools"]),
        "messages_bytes": mb, "messages_tokens": est_tokens(mb), "message_count": len(decoded["messages"]),
        "other_bytes": ob, "total_tokens_est": est_tokens(total_bytes),
        "last_user_text": (lut[:2000] if lut else lut), "last_user_bytes": lub,
        "amplification": (round(total_bytes / lub, 1) if lub else None),
        "biggest": items[:12],
    }


def diff_requests(prev: Optional[Dict[str, Any]], cur: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """prev/cur are capture dicts with 'decoded' and 'summary'."""
    if not prev or "decoded" not in prev or "decoded" not in cur:
        return None
    pd, cd = prev["decoded"], cur["decoded"]
    ps, cs = prev["summary"], cur["summary"]
    psys = "\n\n".join(x["text"] for x in pd["system"])
    csys = "\n\n".join(x["text"] for x in cd["system"])
    sysdiff = []
    if psys != csys:
        sysdiff = [l if len(l) <= 400 else l[:400] + " \u2026 (+%d chars)" % (len(l) - 400)
                   for l in difflib.unified_diff(psys.splitlines(), csys.splitlines(), "previous", "current", n=1, lineterm="")][:400]
    ptools = {t["name"]: t for t in pd["tools"]}
    ctools = {t["name"]: t for t in cd["tools"]}
    changed = [{"name": n, "delta": ctools[n]["bytes"] - ptools[n]["bytes"]}
               for n in ctools if n in ptools and ctools[n]["json"] != ptools[n]["json"]]
    pm, cm = pd["messages"], cd["messages"]
    prefix = 0
    for a, b in zip(pm, cm):
        if a["role"] == b["role"] and a["text"] == b["text"]:
            prefix += 1
        else:
            break
    new_msgs = [{"index": i, "role": m["role"], "bytes": m["bytes"], "preview": m["text"][:300]} for i, m in enumerate(cm[prefix:], prefix)]
    other_changed = sorted(k for k in set(pd["other"]) | set(cd["other"]) if pd["other"].get(k) != cd["other"].get(k))
    return {
        "previous_id": prev.get("id"),
        "bytes_delta": cs["total_bytes"] - ps["total_bytes"],
        "system_changed": psys != csys, "system_diff": sysdiff,
        "system_bytes_delta": cs["system_bytes"] - ps["system_bytes"],
        "tools_added": sorted(set(ctools) - set(ptools)), "tools_removed": sorted(set(ptools) - set(ctools)),
        "tools_changed": changed, "tools_bytes_delta": cs["tools_bytes"] - ps["tools_bytes"],
        "messages_prev": len(pm), "messages_cur": len(cm), "messages_common_prefix": prefix,
        "history_rewritten": prefix < len(pm), "new_messages": new_msgs[:50],
        "other_changed": other_changed,
    }


# --------------------------------------------------------------------------
# responses (JSON or SSE)
# --------------------------------------------------------------------------


def _collect_from_event(data: Any, acc: Dict[str, Any]):
    if not isinstance(data, dict):
        return
    t = data.get("type")
    # Anthropic
    if t == "message_start" and isinstance(data.get("message"), dict):
        acc["model"] = data["message"].get("model") or acc.get("model")
        acc["usage"].update(data["message"].get("usage") or {})
    elif t == "message_delta":
        acc["usage"].update(data.get("usage") or {})
        if isinstance(data.get("delta"), dict) and data["delta"].get("stop_reason"):
            acc["stop_reason"] = data["delta"]["stop_reason"]
    elif t == "content_block_start" and isinstance(data.get("content_block"), dict):
        cb = data["content_block"]
        if cb.get("type") == "tool_use":
            acc["tool_calls"].append(cb.get("name"))
    elif t == "content_block_delta" and isinstance(data.get("delta"), dict):
        d = data["delta"]
        if d.get("type") == "text_delta":
            acc["text"].append(d.get("text", ""))
        elif d.get("type") == "thinking_delta":
            acc["thinking"].append(d.get("thinking", ""))
    # OpenAI responses API
    elif t == "response.output_text.delta":
        acc["text"].append(data.get("delta", ""))
    elif t in ("response.completed", "response.done") and isinstance(data.get("response"), dict):
        acc["usage"].update(data["response"].get("usage") or {})
        acc["model"] = data["response"].get("model") or acc.get("model")
    elif t is None:
        # OpenAI chat chunk / Gemini chunk / non-stream bodies
        for ch in data.get("choices") or []:
            d = ch.get("delta") or ch.get("message") or {}
            if isinstance(d.get("content"), str):
                acc["text"].append(d["content"])
            for tc in d.get("tool_calls") or []:
                n = (tc.get("function") or {}).get("name")
                if n:
                    acc["tool_calls"].append(n)
            if ch.get("finish_reason"):
                acc["stop_reason"] = ch["finish_reason"]
        for c in data.get("candidates") or []:
            for p in (c.get("content") or {}).get("parts") or []:
                if isinstance(p.get("text"), str):
                    acc["text"].append(p["text"])
        if isinstance(data.get("usage"), dict):
            acc["usage"].update(data["usage"])
        if isinstance(data.get("usageMetadata"), dict):
            acc["usage"].update(data["usageMetadata"])
        if data.get("model"):
            acc["model"] = data["model"]
        if data.get("type") is None and isinstance(data.get("content"), list):  # Anthropic non-stream
            for b in data["content"]:
                if isinstance(b, dict) and b.get("type") == "text":
                    acc["text"].append(b.get("text", ""))
                elif isinstance(b, dict) and b.get("type") == "tool_use":
                    acc["tool_calls"].append(b.get("name"))
    if t == "message" and isinstance(data.get("content"), list):  # Anthropic non-stream message
        for b in data["content"]:
            if isinstance(b, dict) and b.get("type") == "text":
                acc["text"].append(b.get("text", ""))
            elif isinstance(b, dict) and b.get("type") == "tool_use":
                acc["tool_calls"].append(b.get("name"))
        acc["usage"].update(data.get("usage") or {})
        acc["model"] = data.get("model") or acc.get("model")
        acc["stop_reason"] = data.get("stop_reason")


def parse_response(content_type: str, raw: bytes, max_text: int = 200_000) -> Dict[str, Any]:
    acc: Dict[str, Any] = {"usage": {}, "text": [], "thinking": [], "tool_calls": [], "model": None, "stop_reason": None}
    ct = (content_type or "").lower()
    text = raw.decode("utf-8", "replace")
    out: Dict[str, Any] = {"kind": "other", "events": 0, "event_types": {}}
    if "text/event-stream" in ct or text.startswith("event:") or text.startswith("data:"):
        out["kind"] = "sse"
        for block in re.split(r"\r?\n\r?\n", text):
            ev, datas = None, []
            for line in block.splitlines():
                if line.startswith("event:"):
                    ev = line[6:].strip()
                elif line.startswith("data:"):
                    datas.append(line[5:].lstrip())
            if not datas and not ev:
                continue
            payload = "\n".join(datas)
            try:
                data = json.loads(payload) if payload and payload != "[DONE]" else None
            except ValueError:
                data = None
            name = ev or (data.get("type") if isinstance(data, dict) and data.get("type") else ("[DONE]" if payload == "[DONE]" else "data"))
            out["events"] += 1
            out["event_types"][name] = out["event_types"].get(name, 0) + 1
            _collect_from_event(data, acc)
    elif "json" in ct or text[:1] in "{[":
        out["kind"] = "json"
        try:
            data = json.loads(text)
            if isinstance(data, list):
                for d in data:
                    _collect_from_event(d, acc)
            else:
                _collect_from_event(data, acc)
                if isinstance(data, dict) and "error" in data:
                    out["error"] = redact_obj(data["error"])
        except ValueError:
            out["kind"] = "text"
    out["text"] = redact_text("".join(acc["text"]))[:max_text]
    out["thinking_chars"] = sum(len(x) for x in acc["thinking"])
    out["tool_calls"] = acc["tool_calls"]
    out["usage"] = acc["usage"]
    out["model"] = acc["model"]
    out["stop_reason"] = acc["stop_reason"]
    out["raw_preview"] = redact_text(text[:20000])
    return out


# --------------------------------------------------------------------------
# full request analysis
# --------------------------------------------------------------------------


def analyze_request(path: str, body_bytes: bytes, ident: Optional[LocalIdentity] = None) -> Dict[str, Any]:
    try:
        body = json.loads(body_bytes.decode("utf-8")) if body_bytes else None
        is_json = True
    except (ValueError, UnicodeDecodeError):
        body, is_json = body_bytes.decode("utf-8", "replace"), False
    # hidden chars + PII are scanned on the *unredacted* body (secrets get counted, never shown)
    hidden = scan_hidden(body)
    pii = find_pii(body, ident)
    safe = redact_obj(body)
    decoded = decode_request(path, safe if is_json else {})
    if not is_json:
        decoded["other"] = {}
    summary = summarize(decoded, len(body_bytes))
    return {
        "is_json": is_json,
        "body": safe if is_json else (safe[:200_000] if isinstance(safe, str) else safe),
        "api": decoded.pop("api"),
        "model": safe.get("model") if isinstance(safe, dict) else None,
        "stream": safe.get("stream") if isinstance(safe, dict) else None,
        "decoded": decoded,
        "summary": summary,
        "hidden": hidden,
        "pii": pii,
    }


# --------------------------------------------------------------------------
# shareable markdown report (redacted: no prompt text, no PII values)
# --------------------------------------------------------------------------


def _fmt(n: Optional[int]) -> str:
    return "-" if n is None else "{:,}".format(n)


def markdown_report(cap: Dict[str, Any], name: str = "wiretap") -> str:
    s = cap.get("summary") or {}
    L = []
    L.append("# %s capture #%s" % (name, cap.get("id")))
    L.append("")
    L.append("Measured locally by %s from one captured request. Token counts marked ~ are estimates (bytes / 4); "
             "\"reported\" numbers come from the API's own usage field in the response." % name)
    L.append("")
    L.append("| | |")
    L.append("|---|---|")
    L.append("| Endpoint | `%s %s` |" % (cap.get("method"), cap.get("path")))
    L.append("| API shape | %s |" % cap.get("api"))
    L.append("| Model | %s |" % (cap.get("model") or "-"))
    L.append("| Request size | %s bytes (~%s tokens) |" % (_fmt(s.get("total_bytes")), _fmt(s.get("total_tokens_est"))))
    L.append("| System prompt | %s bytes in %s block(s) (~%s tokens) |" % (_fmt(s.get("system_bytes")), s.get("system_blocks"), _fmt(s.get("system_tokens"))))
    L.append("| Tool schemas | %s tools, %s bytes (~%s tokens) |" % (s.get("tool_count"), _fmt(s.get("tools_bytes")), _fmt(s.get("tools_tokens"))))
    L.append("| Messages | %s messages, %s bytes (~%s tokens) |" % (s.get("message_count"), _fmt(s.get("messages_bytes")), _fmt(s.get("messages_tokens"))))
    if s.get("last_user_bytes"):
        L.append("| Your last message | %s bytes; whole request was %sx that |" % (_fmt(s["last_user_bytes"]), s.get("amplification")))
    resp = cap.get("response") or {}
    if resp.get("usage"):
        L.append("| Reported usage | `%s` |" % json.dumps(resp["usage"], sort_keys=True))
    L.append("| Status | %s in %s ms |" % (cap.get("status"), cap.get("duration_ms")))
    L.append("")
    dec = cap.get("decoded") or {}
    if dec.get("tools"):
        L.append("## Tool schemas by size")
        L.append("")
        L.append("| Tool | Bytes | ~Tokens |")
        L.append("|---|---:|---:|")
        for t in sorted(dec["tools"], key=lambda t: -t["bytes"]):
            L.append("| `%s` | %s | %s |" % (t["name"], _fmt(t["bytes"]), _fmt(t["tokens"])))
        L.append("")
    h = cap.get("hidden") or {}
    L.append("## Unusual characters")
    L.append("")
    if h.get("total"):
        for k, v in sorted(h["counts"].items()):
            L.append("- %s: %d" % (k, v))
        if h.get("tag_runs"):
            L.append("- decoded tag-character runs: %d (contents omitted)" % len(h["tag_runs"]))
    else:
        L.append("None found.")
    L.append("")
    p = cap.get("pii") or {}
    L.append("## Personal-data matches (values omitted)")
    L.append("")
    if p.get("total"):
        for k, v in sorted(p["counts"].items()):
            L.append("- %s: %d" % (k, v))
    else:
        L.append("None found.")
    L.append("")
    L.append("## Request headers (names only)")
    L.append("")
    L.append(", ".join("`%s`" % k for k, _ in cap.get("req_headers") or []))
    L.append("")
    L.append("_Prompt text, message content and personal values are not included in this report._")
    return "\n".join(L) + "\n"
