# Twinthos Sentinel

**Continuous threat intelligence for organizations.**

A self-driving monitor that scrapes, filters, and alerts on threats that could actually harm your company — AI threats today, brand threats tomorrow. Runs wherever your infrastructure runs.

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Status](https://img.shields.io/badge/status-autonomous-success)

---

## What this is

This repository is the **reference implementation** of Twinthos Sentinel — the same engine that powers the managed Twinthos digital employee. It runs on your infrastructure, scans your dependencies, and sends alerts to your team channel.

**This is NOT the Twinthos managed service.** The managed service at [twinthos.com](https://twinthos.com) includes hosted operation, 24/7 monitoring, and dedicated support. This repo lets you run the core scanner yourself.

---

## The problem

- Generic threat feeds are 90% noise. You get alerts about WordPress plugins while your AI stack, supply chain, or brand reputation is under attack.
- CISA KEV tells you what's actively exploited — but not what matters to YOUR stack, YOUR suppliers, or YOUR market.
- By the time you hear about an AI agent escape, a supply-chain compromise, or a brand-threatening leak on social media, it's already in the wild.

## What it does

- **Threat-intelligence scraper** — continuously pulls CVE feeds, CISA KEV, exploit databases, and news sources
- **Organization-aware filter** — only alerts on threats that match YOUR stack, YOUR suppliers, and YOUR industry
- **AI-first, not AI-only** — AI/agent/MCP threats are the current focus because that's where the active exploitation is
- **CISA KEV + FIRST EPSS** — cross-references every alert against known exploited vulnerabilities and exploit prediction scores
- **Lockfile-aware** — scans your actual `requirements.txt` / `package-lock.json` / `go.sum` against threat feeds
- **Continuous daemon** — runs 24/7, scans every N minutes, self-heals on errors
- **Feedback learning** — mark alerts as `ignored` or `useful`; the monitor adapts
- **Telegram/Discord/webhook** — formatted alerts with CVSS, EPSS, CISA KEV flag, fix version
- **Deduplication** — remembers alerted threats across runs; never spam you twice

## 30-second install

```bash
git clone https://github.com/twinthos/ai-sec-sentinel.git
cd ai-sec-sentinel
pip install -r requirements.txt
python3 ai_sec_sentinel.py --since-hours 24
```

**Docker:**
```bash
docker run -v $(pwd)/data:/data twinthos/ai-sec-sentinel:latest
```

**Daemon mode:**
```bash
python3 ai_sec_sentinel.py --daemon --interval 60
```

**Lockfile check:**
```bash
python3 ai_sec_sentinel.py --lockfile requirements.txt --ecosystem python
```

**Give feedback:**
```bash
python3 ai_sec_sentinel.py --feedback CVE-2026-63377 useful
python3 ai_sec_sentinel.py --feedback CVE-2026-119712 ignored
```

## How it works

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│ Threat feeds│────▶│ Stack-aware  │────▶│ CISA KEV +  │
│ (CVE, KEV,  │     │ filter       │     │ EPSS enrich  │
│ EPSS, news) │     │ AI, infra,   │     │ CVSS, EPSS,  │
│             │     │ suppliers,   │     │ KEV flag     │
└─────────────┘     │ brand risks  │     └──────┬───────┘
                    └──────────────┘            │
                                                 ▼
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│ Lockfile    │────▶│ Dedup +      │────▶│ Telegram /   │
│ scanner     │     │ feedback     │     │ Discord /    │
│ YOUR actual │     │ learning     │     │ webhook      │
│ dependencies│     │              │     │ alert        │
└─────────────┘     └──────────────┘     └──────────────┘
```

## Configuration

`sentinel_config.json` controls everything:

```json
{
  "scan_interval_minutes": 60,
  "alert_min_severity": 2,
  "alert_on_medium": false,
  "auto_remediate": false,
  "feedback_enabled": true,
  "learn_from_actions": true,
  "lockfile": "requirements.txt",
  "ecosystem": "python",
  "telegram": {
    "enabled": false,
    "parse_mode": "HTML"
  }
}
```

## Autonomous operation

| Mode | Command | Use case |
|------|---------|----------|
| One-shot | `python3 ai_sec_sentinel.py` | CI/CD, manual scans |
| Daemon | `python3 ai_sec_sentinel.py --daemon --interval 60` | 24/7 monitoring |
| Lockfile only | `python3 ai_sec_sentinel.py --lockfile requirements.txt --ecosystem python --check-only` | Dependency audit |
| Cron | `bash install_cron.sh` | Hourly scheduled |

## Competition

| Tool | Type | AI-only filter | CISA KEV | EPSS | Lockfile | Daemon | Feedback | Local |
|------|------|---------------|----------|------|----------|--------|----------|-------|
| **This** | Monitor | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| cve.now | Feed + MCP | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ |
| Lakera Guard | Cloud SaaS | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| Protect AI | Cloud SaaS | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |

**What others miss:** generic CVEs drown out AI signals; no one combines CISA KEV + EPSS + lockfile + feedback learning + news/supplier monitoring in a continuous daemon.

## What's new in v1.2.0

- **News scanner** — RSS/news monitoring for brand, supplier, and industry threats
- **Supplier watch** — get alerted when YOUR suppliers are breached
- **Telegram inline buttons** — 👍 Useful / 👎 Ignore directly from alerts
- **Offline lockfile fallback** — works even when cve.now API is down
- **Repositioned** — from "AI Security Sentinel" to "Twinthos Sentinel": continuous threat intelligence for organizations

## Roadmap

- [ ] Cloud provider polling (AWS Bedrock, Azure OpenAI, Vertex AI)
- [ ] Kubernetes pod scanner
- [ ] SaaS AI tracker (Slack/Teams shadow AI)
- [ ] Agent egress monitoring
- [ ] Behavioural baseline for misalignment detection
- [ ] Web UI (Streamlit)
- [ ] MCP server mode — query sentinel state from Claude Code
- [ ] Docker image on Docker Hub
- [ ] Slack/Discord native integrations
- [ ] Auto-PR for vulnerable dependencies
- [ ] MITRE ATT&CK mapping for AI threats

## Contributing

PRs welcome. See `CONTRIBUTING.md`.

## License

MIT — see `LICENSE`.

## Author

**Tyson Mandela** — [twinthos.com](https://twinthos.com) · [github.com/twinthos](https://github.com/twinthos) · [Humanitai CIC](https://humanitai.org)
