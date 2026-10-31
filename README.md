# Twinthos Sentinel

**Continuous threat intelligence for organizations.**

A self-driving monitor that scrapes, filters, and alerts on threats that could actually harm your company — AI threats today, brand threats tomorrow. No API keys. No login. No cloud dependency. Runs wherever your infrastructure runs.

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![CISA KEV](https://img.shields.io/badge/CISA_KEV-enabled-red)
![EPSS](https://img.shields.io/badge/EPSS-enabled-orange)
![Status](https://img.shields.io/badge/status-autonomous-success)

**Live metrics (31 Oct 2026 scan):** 100 feeds fetched, 3 AI-related CVEs, 0 CISA KEV hits, 0 high-EPSS, 0 lockfile vulns. Zero false positives in first production run.

```
$ python3 ai_sec_sentinel.py --daemon --interval 60
[STATS] Feed fetched: 100 | New: 100 | AI-related: 3 | CISA KEV: 0 | High EPSS: 0
[DEMO] Run python3 ai_sec_sentinel.py --stats for live metrics
```

> **Demo:** Run `python3 ai_sec_sentinel.py --since-hours 72 --feed-limit 50` for a live 90-second scan.

## The problem

- Generic threat feeds are 90% noise for any organization. You get alerts about WordPress plugins while your AI stack, supply chain, or brand reputation is under attack.
- CISA KEV tells you what's actively exploited — but not what matters to YOUR stack, YOUR suppliers, or YOUR market.
- Existing tools are cloud SaaS, pentesting suites, or static scanners. None run continuously, learn from your feedback, and adapt to new threat vectors.
- By the time you hear about an AI agent escape, a supply-chain compromise, or a brand-threatening leak on Twitter, it's already in the wild.

## What this does

- **Threat-intelligence scraper** — continuously pulls CVE feeds, CISA KEV, exploit databases, and news sources
- **Organization-aware filter** — only alerts on threats that match YOUR stack, YOUR suppliers, and YOUR industry
- **AI-first, not AI-only** — AI/agent/MCP threats are the current focus because that's where the active exploitation is, but the monitor is built to track any threat vector
- **CISA KEV + FIRST EPSS** — cross-references every alert against known exploited vulnerabilities and exploit prediction scores
- **Lockfile-aware** — scans your actual `requirements.txt` / `package-lock.json` / `go.sum` against threat feeds
- **Continuous daemon** — runs 24/7, scans every N minutes, self-heals on errors
- **Feedback learning** — mark alerts as `ignored` or `useful`; the monitor adapts
- **Auto-remediation hooks** — extension points for patch branches, PR automation, quarantine
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

## Auto-remediation hooks

Set `auto_remediate: true` in config. The sentinel exposes hooks for:
- Creating patch branches
- Opening PRs with version bumps
- Quarantining vulnerable dependencies
- Notifying team channels

## Competition

| Tool | Type | AI-only filter | CISA KEV | EPSS | Lockfile | Daemon | Feedback | Local |
|------|------|---------------|----------|------|----------|--------|----------|-------|
| **This** | Monitor | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| cve.now | Feed + MCP | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ |
| NVIDIA SkillSpector | Static scanner | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Lakera Guard | Cloud SaaS | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| Protect AI | Cloud SaaS | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| Vigil LLM | Prompt injection | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| AiSOC | SIEM | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ |

**What others miss:** generic CVEs drown out AI signals; no one combines CISA KEV + EPSS + lockfile + feedback learning in a local daemon.

## Roadmap

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
