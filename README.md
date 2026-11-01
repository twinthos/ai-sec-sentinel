# Twinthos Sentinel

**AI vulnerability monitoring with explicit delivery and failure reporting.**

Sentinel watches public vulnerability intelligence and selected RSS sources, filters AI-related findings, enriches CVEs with CISA KEV / FIRST EPSS, and sends alerts through Telegram or Slack/Discord webhooks. It also offers a limited pinned-dependency OSV check.

**Status: release candidate, not independently production-certified.** Source code and automated tests are available for review. Do not rely on this alone to secure a company or AI agent.

## What works and what doesn't

| Capability | Status | Boundary |
| --- | --- | --- |
| cve.now CVE feed + AI keyword filter | Implemented | Keyword matching is not proof a package is installed or exploitable |
| CISA KEV / FIRST EPSS enrichment | Implemented | Upstream outages cause failures; EPSS is a prediction, not observed exploitation |
| Telegram / Slack / Discord notifications | Implemented | Delivery requires credentials and an actual acknowledgement |
| News RSS monitoring | Implemented | Selected feeds only; failed deliveries remain retryable |
| OSV dependency scan | Limited | Supports exactly pinned AI dependencies in Python requirements, npm package-lock, and Go sums; not a full SCA/SBOM solution |
| Persistent scan history, Docker health | Implemented | Health checks scan freshness, not security posture |
| Guardian policy evaluation | **Experimental** | Cannot block agents with independent access to tools |
| Agent passport, replay, MCP probes, compliance | **Demonstrations / partial** | No certification, runtime sandbox, independent proof ledger, or comprehensive protection |

A green unit-test badge proves test cases ran. It does not establish production safety, 24/7 availability, complete threat coverage, or exploit prevention.

## Quick start: safe preview

Requires Python **3.11+**. Run these commands from the repository root:

```bash
git clone https://github.com/twinthos/ai-sec-sentinel.git
cd ai-sec-sentinel
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python3 ai_sec_sentinel.py --dry-run --since-hours 24
```

Preview mode performs a feed scan **without sending notifications or changing alert deduplication state**. It is not a background monitor.

## Set up real alerts

Choose **one** of these delivery routes:

**Telegram:**

```bash
export TELEGRAM_BOT_TOKEN="your-private-bot-token"
export TELEGRAM_CHAT_ID="your-chat-id"
```

**Slack:**

```bash
export SENTINEL_WEBHOOK_PLATFORM="slack"
export SENTINEL_WEBHOOK_URL="https://hooks.slack.com/services/your-private-webhook"
```

**Discord:** set `SENTINEL_WEBHOOK_PLATFORM=discord` and use a `https://discord.com/api/webhooks/...` URL.

Never commit credentials or send them in issues, screenshots or agent prompts.

Verify the real notification path:

```bash
python3 ai_sec_sentinel.py --test-alert
```

**Only continue once the alert appears in the intended channel.** The command exits with code 2 on missing or failed configured destinations. A receiver HTTP acknowledgement does not prove a human saw the message.

Then run a live scan:

```bash
python3 ai_sec_sentinel.py --since-hours 24
python3 ai_sec_sentinel.py --health
```

Continuous operation:

```bash
python3 ai_sec_sentinel.py --daemon --interval 60
```

If an upstream source is unavailable, a live scan fails visibly and does not update `last_successful_run`. A daemon may retry on the next interval; its health check turns unhealthy when successful scans become stale. No alerts are delivered unless a relevant finding occurs.

## Check an AI dependency lockfile

```bash
python3 ai_sec_sentinel.py --check-only --lockfile ./requirements.txt --ecosystem python
```

This sends *package names and exact versions* to OSV. It does not upload the whole lockfile under the default configuration.

Exit codes: **0** = no reported vulnerabilities in the packages it could check; **1** = reported vulnerabilities; **2** = invalid input, unsupported parser, unpinned AI package, OSV failure or incomplete coverage.

Only exactly pinned AI dependencies are in scope. Other dependencies, different ecosystems, non-AI packages, optional dependencies, installed runtime differences and unknown packages may be unassessed. This tool is **not** a substitute for comprehensive SCA tools.

## Containers

Build locally and provide credentials through your container/orchestrator secret management:

```bash
docker compose build
docker compose up -d
docker compose ps
```

The Compose deployment uses a persistent named Docker volume at `/data` with `SENTINEL_DATA_DIR=/data`. Protect and back up the volume; do not commit runtime data. A missing notification destination prevents useful live monitoring. The Kubernetes manifest is an **example**, with a deliberately invalid image placeholder until you supply a tested image pinned by digest. It does not run Guardian or the dashboard.

## State, logs and access

- Runtime data includes `sentinel_state.json`, `sentinel_feedback.json`, and optional Guardian logs/ledger. Mount `SENTINEL_DATA_DIR` on persistent, restricted storage.
- The dashboard is optional, **read-only**, local-only by default, and requires `DASHBOARD_API_KEY` (24+ characters). It has no remote scan-trigger endpoint.
- Guardian Gate is a **policy evaluation API**, not an interception layer. It requires `GUARDIAN_API_KEY` for evaluations and a separate `GUARDIAN_ADMIN_API_KEY` for registration; both should be strong and never reused. An agent with direct access to shells, network or connectors can bypass the evaluator.
- A Guardian hash chain detects some local file modifications but is not signed or independently anchored. Protect evidence externally before treating it as audit-grade proof.
- The repo does not remediate dependencies, prove the absence of prompt injection, run live agent penetration tests, or certify legal compliance.

## Tests and evidence

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q .
```

GitHub CI covers deterministic fixtures, policy/ledger behavior and alert-delivery state with mocked integrations. **CI does not hold your Telegram or webhook credentials, and it cannot prove real live delivery**. Run `--test-alert` yourself after configuring channels.

Coverage limitations: only a bounded, recent CVE feed window is scanned; keyword matching and news sentiment are heuristic; unsupported packages and unavailable feeds cannot be reported as clean; overlapping daemon instances may interfere with local state and should not share the same data directory.

## Vulnerability reporting

Please use [GitHub private security advisories](https://github.com/twinthos/ai-sec-sentinel/security/advisories/new), not a public issue. See [SECURITY.md](SECURITY.md). License: MIT.

Maintained by [Twinthos](https://twinthos.com). No affiliation with source feed vendors.
