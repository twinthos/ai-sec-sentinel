# Twinthos AI Security Sentinel

**Autonomous. Continuous. Adaptive.**

A self-driving AI vulnerability monitor that doesn't just alert — it learns, adapts, and can auto-remediate. No API key. No login. No cloud dependency.

## What it does

- **Continuous daemon mode:** runs 24/7, scans every N minutes, never sleeps
- **CISA KEV:** cross-references every alert against CISA's Known Exploited Vulnerabilities catalog
- **FIRST EPSS:** enriches alerts with exploit probability scores
- **Lockfile-aware:** scans your actual dependencies against cve.now's catalog
- **Feedback learning:** mark alerts as ignored/useful; the sentinel adapts its thresholds
- **Auto-remediation hooks:** extension points for patch/PR automation
- **Config-driven:** `sentinel_config.json` controls everything — no hardcoded secrets
- **Telegram/Discord/webhook alerts:** formatted alerts with CVSS, EPSS, CISA KEV flag, fix version
- **Deduplication:** remembers alerted CVEs across runs in `sentinel_state.json`

## What's novel

cve.now already exists as a feed + MCP server. This bot adds:
1. **AI-only filtering** — generic CVEs are noise; this only alerts on LangChain, MCP, Claude Code, OpenAI, Anthropic, agent frameworks, prompt injection, etc.
2. **CISA KEV + EPSS scoring** — prioritizes by real-world exploitation likelihood, not just CVSS
3. **Lockfile-aware** — checks YOUR actual dependencies, not just the global feed
4. **Actionable output** — tells you the exact package and version to upgrade to
5. **Local + scheduled** — runs on your machine, no cloud service, no SaaS signup
6. **Autonomous daemon** — continuous scanning without cron
7. **Feedback learning** — adapts to what you ignore
8. **Auto-remediation ready** — hooks for patch/PR automation

## Files

- `ai_sec_sentinel.py` — main bot, ~320 lines
- `sentinel_config.json` — configuration file
- `run_sentinel.sh` — one-liner runner
- `requirements.txt` — requests only
- `sentinel_state.json` — deduplication state (auto-created)
- `sentinel_feedback.json` — user feedback store (auto-created)

## Usage

```bash
# One-shot scan
python3 ai_sec_sentinel.py

# Continuous daemon mode — scans every 60 minutes, 24/7
python3 ai_sec_sentinel.py --daemon --interval 60

# Check a specific lockfile
python3 ai_sec_sentinel.py --lockfile requirements.txt --ecosystem python

# Lockfile only, no feed
python3 ai_sec_sentinel.py --lockfile package-lock.json --ecosystem npm --check-only

# Alert on medium+ instead of high/critical only
python3 ai_sec_sentinel.py --alert-on-everything

# Give feedback — teach the sentinel what matters
python3 ai_sec_sentinel.py --feedback CVE-2026-119712 ignored
python3 ai_sec_sentinel.py --feedback CVE-2026-63377 useful
```

## Telegram setup

Set env vars or pass flags:
```bash
export TELEGRAM_BOT_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"
python3 ai_sec_sentinel.py
```

## Configuration

`sentinel_config.json` controls behavior:
```json
{
  "scan_interval_minutes": 60,
  "alert_min_severity": 2,
  "alert_on_medium": false,
  "auto_remediate": false,
  "feedback_enabled": true,
  "learn_from_actions": true,
  "lockfile": "requirements.txt",
  "ecosystem": "python"
}
```

## Autonomous operation

**Daemon mode:**
```bash
python3 ai_sec_sentinel.py --daemon --interval 60
```
Runs continuously, scans every 60 minutes, self-heals on errors.

**Feedback learning:**
```bash
python3 ai_sec_sentinel.py --feedback CVE-2026-119712 ignored
```
Mark alerts as ignored or useful. The sentinel tracks patterns and can adjust thresholds.

**Auto-remediation hooks:**
Set `auto_remediate: true` in config. The sentinel exposes hooks for:
- Creating patch branches
- Opening PRs with version bumps
- Quarantining vulnerable dependencies
- Notifying team channels

## Cron

```bash
bash install_cron.sh
# Runs hourly. Logs to /var/log/ai-sec-sentinel.log
```

## Live test result (31 Oct 2026)

- Fetched 50 entries from cve.now
- Found 3 AI-related in last 72h
- 1 critical alert ready: CVE-2026-119712 (PipesHub SSRF via image URLs)
- CISA KEV cross-check: 1,766 KEV entries loaded
- Deduplication: second run with same window = 0 duplicate alerts
- Alert format: severity emoji, clean CVE ID, title, CVSS, EPSS, CISA KEV flag, cve.now link, suggested fix version

## Sources

- **cve.now** by Sazabi — free, public, no login. Merges CVE List, GitHub Advisory Database, OSV, NVD, CISA KEV, FIRST EPSS, Exploit-DB.
- **CISA KEV** — Known Exploited Vulnerabilities catalog.
- **FIRST EPSS** — Exploit Prediction Scoring System.
