# Security Policy

## Status

The current default branch is an open-source **release candidate**. There is no
independent security certification, uptime guarantee, or production support SLA.

Guardian's policy evaluation is not an enforced sandbox unless a separately
controlled runtime makes it an unavoidable boundary. Do not treat this project
as a complete AI security product.

## Reporting vulnerabilities

Do **not** disclose exploits, credentials, tokens or personal data in a public
GitHub issue. Use private GitHub Security Advisories:

https://github.com/twinthos/ai-sec-sentinel/security/advisories/new

Please include affected code version, minimal reproduction instructions, impact,
and safe redacted logs. We welcome coordinated disclosure, but have not
committed to guaranteed response or remediation deadlines.

## Security model

- All live alert channels must be explicitly configured and tested.
- `--dry-run` never sends alerts or mutates alert-deduplication state.
- A failed source fetch causes a nonzero one-shot result.
- Guardian evaluation and dashboard HTTP APIs require authentication and bind
  to loopback by default; place them behind a separate authenticated,
  TLS-terminating gateway if access beyond localhost is needed.
- Guardian logs should not contain raw tool parameters. Runtime state must be
  stored in restricted persistent storage.
- The local ledger is a hash chain, **not** immutable or externally anchored.
- CI uses synthetic fixtures and cannot certify live integrations or compliance.

Scope: this GitHub repository only, not the commercial Twinthos service or
third-party software. See README.md for what this project does and does not do.
