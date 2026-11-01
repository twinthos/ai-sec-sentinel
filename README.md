# Twinthos Sentinel

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12345/badge)](https://www.bestpractices.dev/projects/12345)

> OSPS Baseline Level 1 — in progress. See SECURITY.md for disclosure policy.

Continuous threat intelligence for organisations running AI agents and automation.

## Alert channels

| Channel | Cost | Setup |
|---------|------|-------|
| Telegram | Free | @BotFather token + chat ID |
| Slack | Free | Webhook URL |
| Discord | Free | Webhook URL |
| iMessage (Sendblue) | Paid (~$20/mo) | Sendblue API key + secret + recipient number |

## What it does (working features)

- **CVE monitoring**: Fetches NVD, CISA KEV, and GitHub Security Advisories. Filters to your stack via keyword matching.
- **Telegram alerts**: Delivers findings with retry queue (SQLite-backed, WAL mode). Failed alerts survive restarts.
- **Lockfile scanning**: Queries OSV.dev for known vulnerabilities in your dependencies. Uses proper version comparison (packaging library), not lexical string comparison.
- **Risk scoring**: Heuristic 0-100 score based on severity, KEV status, EPSS, asset criticality. Labelled as heuristic, not authoritative.
- **Compliance mapping**: Indicative mapping to OWASP, EU AI Act, GDPR, FCA, MHRA, SRA. Not certified compliance.
- **News monitoring**: RSS feed scanning with deduplication and state persistence.
- **Webhook alerts**: Slack and Discord webhook delivery with retry.
- **Guardian (experimental)**: Safety control plane with OBSERVE/UNDERSTAND/CONTROL/PROVE layers. Policy engine, agent passports, blast radius map, evidence ledger. These are prototypes, not production integrations.
- **Dashboard**: Stdlib-only web dashboard on port 8099 with API key auth.
- **Agent security tests**: Canary prompt definitions, tool permission audit, exfiltration detection patterns. These are definitions, not live tests against real agents.

## What it does NOT do

- Does NOT enforce agent permissions in production. Guardian is a prototype policy engine requiring integration at a trusted tool-execution boundary.
- Does NOT automatically remediate vulnerabilities. Fix commands are suggestions with disclaimers.
- Does NOT guarantee security or zero incidents.
- Does NOT provide certified compliance. Compliance mapping is indicative only.
- Does NOT perform real-time detection. Monitoring is periodic (configurable interval).
- Does NOT learn autonomously. Feedback is stored and heuristic suggestions are generated.
- Does NOT verify all CVE claims independently. Case studies are labelled as simulations where applicable.

## Installation

```bash
git clone https://github.com/twinthos/ai-sec-sentinel.git
cd ai-sec-sentinel
pip install -r requirements.txt
cp sentinel_config.example.json sentinel_config.json
# Edit sentinel_config.json with your Telegram bot token and chat ID
python ai_sec_sentinel.py --demo
```

## Quick start (isolated example)

```bash
# Dry run (no alerts sent)
python ai_sec_sentinel.py --dry-run --since-hours 24

# Scan a lockfile
python ai_sec_sentinel.py --check-only --lockfile requirements.txt

# Run Guardian demo
python ai_sec_sentinel.py --guardian

# Run dashboard
python dashboard.py
```

## Testing

```bash
python -m unittest tests.test_sentinel_core tests.test_comprehensive -v
```

## Architecture

See ARCHITECTURE.md for system design. See THREAT_MODEL.md for security analysis.

## Version

v1.4.1 — see CHANGELOG.md for history.

## OpenSSF Compliance

This project is working towards OpenSSF OSPS Baseline Level 1 compliance.
Controls met: SECURITY.md, dependabot, CI tests, README, LICENSE, CONTRIBUTING.md, CODE_OF_CONDUCT.md, CHANGELOG.md, pinned dependencies, branch protection.

Pending: MFA on GitHub account, signed releases, SBOM generation in CI.

Badge registration: https://www.bestpractices.dev

## License

MIT
