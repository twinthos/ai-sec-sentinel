# Twinthos AI Security Sentinel

Real-time AI vulnerability monitor. No API key. No login. Free.

## What it does

- **Feed watch:** polls cve.now every hour for new AI/agent/MCP vulnerabilities
- **CISA KEV:** cross-references every alert against CISA's Known Exploited Vulnerabilities catalog
- **EPSS:** enriches alerts with FIRST Exploit Prediction Scoring System probability where available
- **Lockfile check:** scans your `requirements.txt` / `package-lock.json` / etc. against cve.now's catalog
- **Telegram alerts:** sends formatted alerts for high/critical new AI vulnerabilities
- **Deduplication:** remembers alerted CVEs across runs in `sentinel_state.json`
- **Upgrade hints:** extracts suggested fix versions from CVE descriptions

## What's novel

cve.now already exists as a feed + MCP server. This bot adds:
1. **AI-only filtering** — generic CVEs are noise; this only alerts on LangChain, MCP, Claude Code, OpenAI, Anthropic, agent frameworks, prompt injection, etc.
2. **CISA KEV + EPSS scoring** — prioritizes by real-world exploitation likelihood, not just CVSS
3. **Lockfile-aware** — checks YOUR actual dependencies, not just the global feed
4. **Actionable output** — tells you the exact package and version to upgrade to
5. **Local + scheduled** — runs on your machine, no cloud service, no SaaS signup

## Files

- `ai_sec_sentinel.py` — main bot, ~280 lines
- `run_sentinel.sh` — one-liner runner
- `requirements.txt` — requests only
- `sentinel_state.json` — deduplication state (auto-created)

## Usage

```bash
# Scan feed for new AI vulns in last 24h
python3 ai_sec_sentinel.py

# Check a specific lockfile
python3 ai_sec_sentinel.py --lockfile requirements.txt --ecosystem python

# Lockfile only, no feed
python3 ai_sec_sentinel.py --lockfile package-lock.json --ecosystem npm --check-only

# Alert on medium+ instead of high/critical only
python3 ai_sec_sentinel.py --alert-on-everything
```

## Telegram setup

Set env vars or pass flags:
```bash
export TELEGRAM_BOT_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"
python3 ai_sec_sentinel.py
```

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
