# Security

wiretap sits between your agent and its API and sees your prompts, so security bugs matter here.

**Please don't open a public issue for a vulnerability.** Use GitHub's private vulnerability reporting on this repository (Security tab → "Report a vulnerability").

In scope, for example:

- a credential (API key, OAuth token, cookie) shown in the UI, an export, a saved file or a log
- the UI or API reachable from anything other than the local machine
- request or response bytes altered in transit
- any network call other than forwarding to the configured upstream

Please include steps to reproduce with synthetic data. Never send real captures.
