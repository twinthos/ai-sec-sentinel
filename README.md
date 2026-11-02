# Twinthos Sentinel

**A small, inspectable AI security project: threat monitoring + a scoped tool-execution demonstration.**

[![CI](https://github.com/twinthos/ai-sec-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/twinthos/ai-sec-sentinel/actions/workflows/ci.yml)
[Security policy](SECURITY.md) · [Threat model](docs/THREAT_MODEL.md) · [Engineering evidence](docs/EVIDENCE.md) · [Twinthos](https://twinthos.com/engineering/)

This repository focuses on two **different** tasks. The threat-intelligence scanner collects security information and sends notifications. The Guardian experiment evaluates proposed agent actions; a separate, **read-only reference adapter** proves a few specific tool restrictions can be enforced before a file is accessed.

**Maturity:** open-source reference / release candidate. Not independently audited, not certified, not a universal agent firewall or a substitute for runtime isolation.

## New: enforce one MCP tool and triage ARTEX-era cloud signals

The [minimal read-only MCP server](docs/AGENT-BOUNDARY-DEMO.md) implements an actual local JSON-RPC tool boundary with negative tests. It has **no shell, network or write tools**. The [ARTEX defence note](docs/ARTEX-DEFENSE.md) links primary incident research and an offline, privacy-conscious log triage example. Neither component claims to secure every agent or detect all attacks.

```sh
python3 -m unittest discover -s tests -v
```

## See the security boundary work — one command

```sh
python3 reference_adapter.py --demo
```

Expected on a compatible POSIX filesystem:

```text
PASS: Scoped file read allowed.
PASS: File deletion denied before execution; file unchanged.
PASS: Evidence ledger verified; contents not logged.
Scope: this read-only adapter only; NOT a universal agent firewall.
```

The adapter deliberately supports **only** bounded UTF-8 file reads within an explicitly configured workspace. It has no shell, write or network API. It rejects unknown operations, parent-directory traversal and symlinks, treats `ask` as denied, and records a decision before returning file contents. It uses POSIX directory file descriptors and no-follow flags to avoid relying on string path checks alone.

The reference adapter does **not** automatically protect Hermes, Orgo, MCP clients or any general AI agent. Those systems need a real integration with an unavoidable tool boundary and no alternate routes to the same privileges.

Run the full offline test suite:

```sh
python3 -m unittest discover -s tests -v
```

The suite includes authorized/unauthorized calls, ledger integrity, sensitive-content redaction, symlink traversal, delivery retries and dry-run state. CI uses synthetic fixtures; it does not constitute independent penetration testing.

## Threat monitor — what actually works

- Pulls a primary CVE feed and enriches findings with CISA KEV and FIRST EPSS when those sources are available.
- Filters by AI-related terms and optionally matches monitored suppliers. These are **heuristic relevance filters**, not guarantees of detection.
- Optionally reviews specifically supported pinned AI dependency versions using OSV; unpinned packages and unsupported lockfile formats cannot be verified.
- Sends notifications via Telegram or approved Slack/Discord webhook destinations, records acknowledged items, and retries notifications that failed.
- Provides dry-run mode without sending alerts or changing deduplication state; checks the freshness of a successful live scan separately from whether the process is alive.

Not supported: comprehensive SCA, full SBOM assurance, ransomware prevention, vulnerability remediation, live process isolation, all-platform threat coverage, guaranteed alert delivery or compliance certification.

### Install / verify

Requires Python 3.10+ and Internet access for live feed scans.

```sh
git clone https://github.com/twinthos/ai-sec-sentinel.git
cd ai-sec-sentinel
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
python3 ai_sec_sentinel.py --dry-run --since-hours 24
```

The dry run previews alert formatting and queries live feeds. The sample configuration disables optional RSS news monitoring until you explicitly set `news.enabled=true` in `sentinel_config.json`; it does not monitor X accounts or cloud infrastructure. Network errors should produce a nonzero status rather than a misleading clean result.

### Configure a live notification destination

Use environment variables, not committed credentials.

```sh
# Telegram
export TELEGRAM_BOT_TOKEN="YOUR_TOKEN"
export TELEGRAM_CHAT_ID="YOUR_CHAT_ID"

# Or use an approved Slack/Discord webhook
# export SENTINEL_WEBHOOK_URL="https://hooks.slack.com/services/..."
# export SENTINEL_WEBHOOK_PLATFORM="slack"

python3 ai_sec_sentinel.py --test-alert  # prove every configured channel acknowledges a test
python3 ai_sec_sentinel.py --since-hours 24
python3 ai_sec_sentinel.py --daemon --interval 60
```

Without a delivery destination, live monitoring fails visibly. Set up monitoring of nonzero exits and the health check; a running daemon alone is not evidence of functioning alerts.

### Local lockfile check

```sh
python3 ai_sec_sentinel.py --check-only --lockfile requirements.txt --ecosystem python
```

A reported finding exits nonzero, as does incomplete strict coverage. Only supported, exactly pinned dependency versions are assessed. A lack of findings does **not** assert that an entire application has no vulnerabilities. For complete dependency auditing use a dedicated, maintained SCA tool.

### Operations and deployment

```sh
python3 ai_sec_sentinel.py --health
docker compose up --build -d
```

The Docker image runs as a non-root user and stores runtime data in the `/data` volume. Configure a notification destination before starting a live service. The health command checks freshness of the last successful live scan; it is not a guarantee that every alert was received.

The optional `guardian_gate.py` API and `dashboard.py` are **separate processes**, loopback-only by default, and require their own secrets. Guardian registration requires a distinct admin key. Do not expose either service directly to the Internet.

## Reproducible security and portfolio review

See [the evidence-led case study](docs/SECURITY-AND-CAREER.md) for an honest threat-to-test mapping, the limits of the demo, and what a security hiring manager can reproduce. Guardian Gate now requires \`GUARDIAN_AGENT_ID\` (a host-set identity) before answering evaluation or passport requests. An authenticated API decision is **not** a substitute for enforcement at the real tool boundary.

## What the project does not prove

**An allow/deny API response is not enforcement.** The model may still be able to reach tools by another path. `reference_adapter.py` shows what enforcement looks like for one deliberately limited capability; it does not secure an unrestricted runtime.

The evidence ledger verifies local record hashes and chaining, but an administrator with write access could replace the full history. There is no independent log anchoring, signing or immutable store.

Permission scopes, response accuracy and company-specific applicability must be verified before production. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for protected assets, assumptions, bypasses and remaining work.

## Technical review / contributing

Start at [docs/EVIDENCE.md](docs/EVIDENCE.md) for the proof checklist, then inspect [reference_adapter.py](reference_adapter.py), [tests/test_reference_adapter.py](tests/test_reference_adapter.py), [ai_sec_sentinel.py](ai_sec_sentinel.py) and [tests/test_runtime_safety.py](tests/test_runtime_safety.py).

Reproduce the tests; review the negative cases; open an issue with a minimal sanitized reproduction. Report security vulnerabilities **privately** using [GitHub Security Advisories](https://github.com/twinthos/ai-sec-sentinel/security/advisories/new). Never post tokens, private logs or credentials in issues.

Licensed under [MIT](LICENSE). The project is maintained by Twinthos; there is no implied endorsement by OWASP, GitHub or external security vendors.
