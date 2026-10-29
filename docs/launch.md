# Launch kit (drafts)

Rules for every post: state what the tool measures; no claims about any company's intent; no numbers we haven't measured ourselves on a real run. Fill the `[ ]` brackets only with numbers from your own capture, and say they're from your machine.

## X / Twitter

**Post 1 (with the hero GIF):**

> I wanted to know exactly what my coding agent sends to the API when I type "Reply OK".
>
> So I built wiretap: a local proxy + UI that shows every byte. System prompt, every tool schema ranked by size, full history, hidden Unicode characters, and anything that looks like my personal data.
>
> One command, zero deps, nothing leaves your machine.
>
> github.com/OWNER/wiretap

**Reply 1:**

> How it works: point your agent at it with one env var
>
> ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude
>
> It forwards requests unmodified to the real API and redacts your API key everywhere it displays or saves anything.

**Reply 2 (only with your own measured numbers):**

> On my machine, typing "Reply OK" (8 bytes) sent a [ ] KB request: [ ] KB system prompt, [ ] tools totalling [ ] KB. Try it on yours and post your number.

**Reply 3:**

> It also flags zero-width / bidi / tag characters and highlights your username, home path, git email and remotes wherever they appear in the payload, so you can decide what you're comfortable with.
>
> Export a redacted Markdown report to share sizes without sharing your prompts.

## Show HN

**Title:** Show HN: Wiretap – see every byte your coding agent sends to the API

**Text:**

> I kept wondering what actually goes over the wire when I use Claude Code, so I built a small local proxy with a web UI.
>
> You run `wiretap`, then start the agent with `ANTHROPIC_BASE_URL=http://127.0.0.1:8787`. Requests are forwarded unmodified (only Host and hop-by-hop headers change) to the real API, streaming included, and the UI shows:
>
> - request size split into system prompt / tool schemas / messages, with the biggest items
> - each tool schema ranked by size
> - the full history re-sent each turn, and a diff against the previous request
> - hidden or unusual Unicode (zero-width, bidi, tag characters decoded, homoglyph-ish words)
> - strings that look like personal data, including your own username, hostname, home dir and git identity
> - the API's own reported token usage from the streamed response
>
> It's Python standard library only (3.9+), binds to 127.0.0.1, has no telemetry, and redacts API keys anywhere it displays or saves data. Captures stay in memory unless you pass `--save`.
>
> Limits: it only sees traffic sent to the base URL you point at it, so other hosts the agent talks to aren't covered. Token counts per section are estimates (bytes/4); the exact totals come from the API's usage field. Codex/OpenAI and Gemini decoders exist but I've mostly used it with Claude Code.
>
> I'd love decoders for more agents, and to hear what you find.

## Reddit (r/ClaudeAI, r/LocalLLaMA, r/programming)

**Title:** I built a local proxy that shows every byte Claude Code sends to the API (open source, zero deps)

Body: reuse the Show HN text, lead with the GIF.

## Pre-launch checklist

- [ ] Test end to end with real Claude Code on macOS and Linux; note the version in the README
- [ ] Test Codex CLI in API-key mode; update the agents table
- [ ] Record the hero GIF from a real session; scrub personal data first
- [ ] Replace `OWNER` in README, pyproject, CONTRIBUTING
- [ ] Publish `agent-wiretap` to PyPI so `pipx install` / `uvx` work
- [ ] Add repo topics: claude-code, codex, ai-agents, llm, privacy, proxy, devtools
- [ ] Pin 3 "good first issue" decoder tasks
