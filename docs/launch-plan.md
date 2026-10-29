# wiretap launch plan

Researched 29 Oct 2026. Counts and rules were read on that day and change often: re-check each one the day you post. Anything marked **(unverified)** I could not confirm from a primary source.

**Ground rules for every post:** say what the tool measures, not what any company intends. Only use numbers you measured on your own machine, and say so. Never claim Claude watermarks its replies. Lead with the "Reply OK" moment. Say plainly that you built it and that it's free and MIT.

---

## 0. Pre-launch checklist (do all of this before day 1)

- [ ] Push the repo, then **pin it** on your profile.
- [ ] Add a description (the tagline) and these topics: `claude-code codex ai-agents llm proxy debugging observability prompt-injection security mcp developer-tools`.
- [x] **Hero GIF recorded from synthetic demo data**: `docs/demo.gif` (+ `docs/demo.mp4` for X), regenerate with `scripts/record_gif.sh`. It is already the README hero.
  - Optional: a real-session clip later. **Before recording, open the Personal data tab and check what's on screen**; a real session contains your email, username, home path and memory file contents. Use a throwaway directory or demo `~/.claude` setup, or crop.
- [ ] Fill numbers only from real measurements. For the X post you need from one fresh `Reply OK` run: request size, system prompt size, number of tools, tools size, Claude Code version (`claude --version`). Write them down with the date.
- [ ] Run the hidden-character demo for real: put a file with a tag-character line in a scratch repo, ask Claude Code to read it, screenshot the Hidden chars tab. (`scripts/demo.py` shows how the synthetic one is built.) Only claim what you saw.
- [ ] Test Codex CLI in API-key mode if you can; otherwise the agents table already says "untested".
- [ ] Open 5–6 **good first issues** from the README list, labelled `good first issue` (Codex/Gemini/Aider/Cline verification, session view, cost estimate, `wiretap report`, Homebrew formula, translations).
- [ ] Enable private vulnerability reporting (Settings → Security) to match `SECURITY.md`.
- [ ] Tag and release **v0.1.0** with a 5-line changelog and the GIF.
- [ ] Optional: publish to PyPI as `agent-wiretap` so `pipx install agent-wiretap` works (`wiretap` is taken on PyPI).
- [ ] Clear 4 hours after each big post to answer every comment. Response speed matters more than the hour you pick.

## 1. Order and timing

US clocks go back on **1 Nov 2026**, so from then on: IST = UTC+5:30, US Eastern = UTC−5, US Pacific = UTC−8.

| # | When (IST) | UTC | US Eastern / Pacific | Where |
|---|---|---|---|---|
| 1 | **Sun 8 Nov, 9:30 PM** | 16:00 | 11:00 AM / 8:00 AM | **X thread** with the GIF |
| 2 | **Sun 8 Nov, 10:00 PM** | 16:30 | 11:30 AM / 8:30 AM | **Show HN** (stay up until ~2 AM IST answering) |
| 3 | Mon 9 Nov, 7:30 PM | 14:00 | 9:00 AM / 6:00 AM | r/ClaudeCode, then r/ClaudeAI 30 min later |
| 4 | Tue 10 Nov, 7:30 PM | 14:00 | 9:00 AM / 6:00 AM | r/LocalLLaMA |
| 5 | Tue 10 Nov, evening | | | dev.to article (cross-post to Hashnode) |
| 6 | Wed 11 Nov | | | r/IndiaTech, r/SideProject, r/commandline (only if ≥30 days old by then: it won't be, so skip or wait) |
| 7 | Wed–Fri | | | Newsletters (emails/forms below) |
| 8 | After ~100 stars **and** 14 days old | | | awesome-list submissions |
| 9 | Week 2 | | | Reel / short video; a netsec-style write-up |

Why these times: an analysis of 216,816 HN posts (Mar–Oct 2026) found 15:00–16:00 UTC the best hour for replies and Sunday the best day; for Show HN, 00:00 UTC and 16:00–17:00 UTC were the two best hours ([Syften](https://syften.com/blog/best-time-to-post-on-hacker-news/)). A separate study of 188k Show HNs found Monday 00:00 UTC best for reaching 50+ points (10.8%) and about 1.4 GitHub stars per HN point within 48 h ([Daniel King](https://danfking.github.io/blog/2026/04/23/show-hn-by-the-numbers/)). Monday 00:00 UTC is 5:30 AM IST, so I picked the 16:00 UTC slot you can actually staff. If you'd rather do the early-morning slot, post Show HN **Mon 9 Nov 5:30 AM IST** (Sun 7 PM ET).

## 2. X (main channel)

Visual: the hero GIF. Typing "Reply OK" (8 bytes), then the overview showing how many KB actually went out. That's the before/after: what you typed vs. what left your laptop.

**Post 1 (GIF attached):**
> I typed "Reply OK" into Claude Code.
>
> [N] KB left my laptop.
>
> I built wiretap to see exactly what: the system prompt, all [N] tool schemas, the full history, any personal data and hidden Unicode in it.
>
> One command, zero dependencies, runs locally. Free + MIT.
>
> github.com/pranav-singhal/wiretap

**Reply 1:** how it works
> Point your agent at it with one env var:
> ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude
> It forwards every request untouched and never shows or saves your API key.

**Reply 2:** hidden characters (screenshot of a real capture only)
> It also decodes invisible Unicode. Text the model reads but you can't see: tag characters, zero-width, variation-selector smuggling, lookalike apostrophes. Here's an instruction hidden in a README my agent read: [screenshot]

**Reply 3:** personal data
> And it highlights what about you goes along with every request: email, username, home path, git remote. Mine had [what you saw, described without the values].

**Reply 4:** ask
> Try it on your machine and post your "Reply OK" number. PRs for Codex / Gemini / Aider support welcome.

**Who to tag** (handles verified to exist on 29 Oct 2026; tag 1–2 in a reply, not in the first post, and only where relevant):

| Handle | Why | Followers |
|---|---|---|
| @badlogicgames (Mario Zechner) | built claude-trace, the closest prior art; credit him | 78k |
| @simonw (Simon Willison) | wrote up claude-trace and cares about prompt internals | 247k |
| @wunderwuzzi23 (Johann Rehberger) | ASCII-smuggling / hidden Unicode research | 12k |
| @rez0__ (Joseph Thacker) | early analysis of tag-character injection | 75k |
| @dotey (宝玉) | large Chinese dev audience that shares Claude Code internals | 263k |


## 3. Hacker News: Show HN

Rules ([Show HN guidelines](https://news.ycombinator.com/showhn.html)): it must be something people can try; no landing-page-only posts; title starts with "Show HN:"; don't ask anyone to upvote; plain factual title.

**Title:** `Show HN: Wiretap – see every byte your coding agent sends to the API`

**Text:**
> I wanted to know what actually goes over the wire when I type "Reply OK" into Claude Code, so I built a small local proxy with a web UI.
>
> Run `python3 -m wiretap --open`, start the agent with `ANTHROPIC_BASE_URL=http://127.0.0.1:8787`, and it forwards requests untouched (streaming included) while showing:
> - request size split into system prompt / tool schemas / messages, biggest items first
> - every tool schema ranked by size, and a diff against the previous turn
> - hidden Unicode the model reads but you can't see (tag characters decoded, variation-selector runs decoded, zero-width, bidi, lookalike apostrophes, Cyrillic inside Latin words), without flagging normal emoji or Indic text
> - things that look like your personal data, including your own username, home dir and git identity
> - the API's own reported token usage
>
> Python standard library only, binds to 127.0.0.1, no telemetry, never displays or saves your key. Claude Code is the only agent I've tested; Codex and Gemini decoders exist but are untested.
>
> Prior art: Mario Zechner's claude-trace records sessions to a log viewer. wiretap is a live proxy for any agent with a base URL, focused on byte accounting and auditing.
>
> On my machine, "Reply OK" sent [N] KB. I'd like to hear what yours sends.

First comment from you: the technical note on how hidden-character detection avoids false positives (single VS16 after emoji, ZWJ in emoji/Indic, curly apostrophe U+2019 never flagged).

## 4. Reddit

| Sub | Rule that matters (read 29 Oct 2026) | Plan |
|---|---|---|
| r/ClaudeCode | Self-promo in the weekly showcase thread; standalone posts need the "Built with Claude Code" flair and a real write-up of what you built and how ([mod post](https://www.reddit.com/r/ClaudeCode/comments/1vdcl09/small_rclaudecode_cleanup_new_flairs_rules_filters/), [showcase](https://www.reddit.com/r/ClaudeCode/comments/1v7vewn/weekly_showcase_thread_show_us_what_you_built/)) | Post with the flair; also comment in the weekly thread |
| r/ClaudeAI | Rule 7: built by you with or for Claude, explain how Claude helped, say it's free, minimal promo language, **feed posts need OP karma > 100**, otherwise use the Project Showcase megathread ([rules summary](https://threadfox.vip/rules/claudeai)) | Check your karma. "Built with Claude" flair |
| r/LocalLLaMA | Self-promo ≤ 10% of your activity; no sensational title; link straight to GitHub; flair "Resources" or "I Built A Thing", never "News"; 5 sub karma needed ([summary](https://spacestationlabs.ai/subreddits/localllama)) | Angle: works with any OpenAI-compatible base URL, including local servers |
| r/IndiaTech | Has a FOSS exception to the self-promo rule ([mod post](https://www.reddit.com/r/IndiaTech/comments/1lw6tye/exception_to_selfpromotion_rule_for_foss_projects/)) | "Built in India" angle |
| r/SideProject | Built for project posts **(rules unverified)** | Short post plus GIF |
| r/commandline | Projects must be notable and **at least 30 days old** ([summary](https://threadfox.vip/rules/commandline)) | Wait until December |
| r/netsec | No direct links to tool repos; tools go in the monthly discussion/tool thread; standalone only for a real technical write-up ([thread](https://www.reddit.com/r/netsec/comments/1jzrx4g/rnetsec_monthly_discussion_tool_thread/)) | Monthly thread only, or a write-up on hidden Unicode in agent traffic |
| r/programming | **No** self-promotion or "I made this" posts ([summary](https://leadsrover.io/subreddits/r/programming)) | Skip |
| r/opensource | 2026 rules exclude AI-focused projects and require ~1 year of maintenance ([Tom's Hardware](https://www.tomshardware.com/tech-industry/artificial-intelligence/reddits-r-opensource-bans-ai-made-and-ai-focused-projects-also-bans-non-english-speakers-sweeping-new-rules-spark-backlash-over-linux-kernel-contributions-and-solo-developers)) | Skip |

**Title (r/ClaudeCode / r/ClaudeAI):** `I built a local proxy that shows every byte Claude Code sends when you type "Reply OK" (free, open source, zero deps)`
Body: 3 lines on why, the GIF, two commands, what it shows, what it doesn't do (other hosts, untested agents), and "built with Claude Code: [one honest sentence on how]". Don't post to more than two subs on the same day.

## 5. Other channels

- **Lobsters:** invite-only; new accounts can't use the `show` tag for their first 70 days, and self-promotion should be under a quarter of your activity ([summary](https://syften.com/blog/lobsters-hacker-news-alternative/)). Only if someone with an account posts it. Don't ask for invites in public.
- **dev.to / Hashnode:** a write-up titled "What Claude Code sends when you type 'Reply OK'". Use your real numbers, the hidden-Unicode section with sources, and the repo link at the end. Tags: `ai`, `claude`, `opensource`, `security`.
- **Product Hunt: no** (for now). It's a terminal dev tool with no signup and no account to convert, and the payoff needs a day of campaigning. Reconsider for a v1 with a desktop app.
- **Discords/Slacks:** Latent Space Discord, Claude/Anthropic developer community, MCP community **(invite links unverified; use the official links from their sites)**. Post only in #show-and-tell style channels.

## 6. Newsletters

| Newsletter | How | Status |
|---|---|---|
| Console.dev | email `hello@console.dev`; they pick developer tools that are self-service and maintained; pre-1.0 must be labelled beta ([criteria](https://console.dev/selection-criteria)) | verified |
| Changelog News | [changelog.com/news/submit](https://changelog.com/news/submit): URL, headline, why it matters | verified |
| Latent Space | `tips@latent.space` ([about](https://www.latent.space/about)) | verified |
| PyCoder's Weekly | [pycoders.com/submissions](https://pycoders.com/submissions) (it's pure stdlib Python) | page exists |
| TLDR (AI / InfoSec / Dev) | a "submit a link" form is linked from tldr.tech | **URL unverified** |
| Hacker Newsletter | picks from HN automatically | n/a |

Send these on Wed–Thu after launch, with the one real number and the GIF link.

## 7. awesome-lists (after ~100 stars and 14 days)

| List | Stars (29 Oct 2026) | How |
|---|---|---|
| [hesreallyhim/awesome-claude-code](https://github.com/hesreallyhim/awesome-claude-code) | 56.8k | **Issue form only, no PRs**, human-written; repo must be ≥ 14 days old with ongoing commits **or** have ≥ 100 stars; one resource at a time; description not a pitch, no emoji ([CONTRIBUTING](https://github.com/hesreallyhim/awesome-claude-code/blob/main/CONTRIBUTING.md)). Section: Observability & Monitoring |
| [punkpeye/awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) | 97.0k | Only fits if you add an MCP mode; skip for now |
| [e2b-dev/awesome-ai-agents](https://github.com/e2b-dev/awesome-ai-agents) | 30.7k | PR, dev-tools section **(fit unverified)** |
| [tensorchord/Awesome-LLMOps](https://github.com/tensorchord/Awesome-LLMOps) | 6.0k | PR under observability |
| [jamesmurdza/awesome-ai-devtools](https://github.com/jamesmurdza/awesome-ai-devtools) | 4.0k | PR |
| [rohitg00/awesome-claude-code-toolkit](https://github.com/rohitg00/awesome-claude-code-toolkit) | 2.8k | PR |
| [corca-ai/awesome-llm-security](https://github.com/corca-ai/awesome-llm-security) | 1.7k | PR, tools section (hidden-Unicode angle); last push Aug 2025 |
| [karanb192/awesome-claude-code-mods](https://github.com/karanb192/awesome-claude-code-mods) | 0.8k | PR |

Suggested one-line description: `wiretap - Local proxy and web UI that shows the bytes a coding agent sends: system prompt, tool schemas, history, hidden Unicode and personal data.`

## 8. Short video / reels

Earlier research suggested itr-wala got stars from reels **(unverified)**. A 20-second vertical video: (1) type "Reply OK" (2) cut to wiretap: "8 bytes typed, [N] KB sent" (3) scroll the tool list (4) Hidden chars tab decoding a planted instruction (5) "github.com/pranav-singhal/wiretap". Post on Instagram Reels, YouTube Shorts and X. The hook line: "Your AI agent sends [N]× more than you type."

## 9. What could go wrong

- **Prior art.** [claude-trace](https://github.com/badlogic/lemmy/tree/main/apps/claude-trace) (Mario Zechner, covered by [Simon Willison](https://simonwillison.net/2025/Jun/2/claude-trace/)), its [proxy-mode fork](https://github.com/hanqunfeng/claude-trace), and OrcaReplay already capture Claude Code traffic. Expect "this exists" on HN. Credit them up front, and differentiate on live view, any agent, byte accounting, hidden-character and personal-data auditing, and zero dependencies.
- **Anthropic terms and proxy detection.** `ANTHROPIC_BASE_URL` is a documented setting for gateways, and you're inspecting your own traffic. But Claude Code has behaved differently behind a custom base URL before (the 2.1.91–2.1.196 date marker), so say "what's sent when proxied". Don't encourage extracting OAuth tokens or reselling access. Don't speculate about Anthropic's motives.
- **Personal data in your own launch assets.** This is the biggest real risk. Check every GIF and screenshot frame.
- **Name collisions.** `wiretap` is taken on PyPI (hence `agent-wiretap`). On GitHub, [sandialabs/wiretap](https://github.com/sandialabs/wiretap) (1.1k★, a WireGuard proxy) and [pb33f/wiretap](https://github.com/pb33f/wiretap) (236★, an API validation proxy) share the name. It's fine for a repo, but say "wiretap for coding agents" in titles. Have `agent-wiretap` ready if anyone objects.
- **"Wiretap" sounds like surveillance.** Some readers may assume it spies on others. The first line should make clear it's your own traffic on your own machine.
- **Security reports.** A proxy holding your key will attract scrutiny. `SECURITY.md` asks for private reports; respond within 48 h, fix fast, credit reporters.
- **False positives in hidden-char detection.** If someone's Hindi or emoji text gets flagged, fix it the same day and add a test. That's a good-first-issue magnet.
- **Untested agents.** The Codex and Gemini rows say "untested". Keep it that way until someone verifies.
