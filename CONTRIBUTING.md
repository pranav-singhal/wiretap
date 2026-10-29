# Contributing to wiretap

Thanks for helping. The ground rules are the same as the product's: **show only what was measured**, never send data anywhere, never display a credential.

## Dev setup

```bash
git clone https://github.com/pranav-singhal/wiretap && cd wiretap
python3 -m unittest -v          # or: pytest
python3 scripts/demo.py         # UI with synthetic traffic on http://127.0.0.1:8788
python3 -m wiretap --upstream http://127.0.0.1:9999   # with: python3 tests/mock_upstream.py 9999
```

No dependencies. Please keep it that way for the core; Python 3.9+.

## Layout

| File | What |
|---|---|
| `wiretap/__init__.py` | `NAME`, version, tagline: the one place to rename the project |
| `wiretap/core.py` | proxy, capture store, UI/API server, CLI |
| `wiretap/analyze.py` | pure functions: decoders, hidden chars, personal data, redaction, diff, response parsing, Markdown report |
| `wiretap/ui.html` | the whole UI: one file, vanilla JS, no build step, no external assets |
| `tests/mock_upstream.py` | fake Anthropic-style API (JSON + SSE) used by tests and the demo |

## Adding a decoder (new agent / API shape)

A decoder turns a request body into the common shape the UI understands:

```python
{"system": [{"label", "text", "bytes", "tokens"}],
 "tools": [{"name", "description", "bytes", "tokens", "json"}],
 "messages": [{"role", "text", "bytes", "tokens", "kinds"}],
 "other": {...remaining top-level keys...}}
```

1. Write `decode_<api>(body: dict) -> dict` in `analyze.py` using the `_sys_item`, `_tool_item`, `_msg_item` helpers.
2. Register it in `DECODERS` with a matcher `(path, body) -> bool`. Put specific matchers before generic ones.
3. If the API streams, teach `_collect_from_event` its event shapes (text deltas, tool calls, usage).
4. Add a test in `tests/test_wiretap.py` with a minimal **synthetic** body. Base shapes on the provider's public API docs, not on guesses about what an agent sends.

## Adding detectors

- Hidden characters: `char_category()` in `analyze.py`, and mirror the class in the `HIDDEN` regex in `ui.html`.
- Personal data: add a regex next to `EMAIL` / `HOME_PATH` and handle it in `find_pii()`.
- Secrets: add to `SECRET_PATTERNS`; they are redacted everywhere and counted as `secret`.

Every detector needs a positive and a negative test.

## Rules for PRs

- No network calls except forwarding to the configured upstream. No CDNs, fonts or analytics in the UI.
- Never display, log or persist a credential; add a test if you touch redaction.
- Don't change request bytes. Forwarding fidelity tests must keep passing.
- Wording in the UI and docs states measurements, not motives.
- Never commit real captures; use synthetic fixtures.

## Renaming the project

Change `NAME` in `wiretap/__init__.py` (banner, UI title, `/__<name>` path, filenames), then rename the `wiretap/` package directory and update `pyproject.toml` (`name`, `[project.scripts]`, package lists) and the README.
