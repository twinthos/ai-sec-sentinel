# Contributing to Twinthos Sentinel

## Scope and responsible use

This is a defensive, open-source **reference** tool. Do not submit live customer records, exploit payloads, passwords, access tokens or confidential infrastructure details. Report vulnerabilities privately using [GitHub Security Advisories](https://github.com/twinthos/ai-sec-sentinel/security/advisories/new), not a public issue.

## Local development

Requires Python **3.11+**. The scoped file adapter uses POSIX directory file descriptors and is tested on Linux. The scanner uses the dependencies declared in `requirements.txt`.

```sh
git clone https://github.com/twinthos/ai-sec-sentinel.git
cd ai-sec-sentinel
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
python3 examples/proof.py
python3 defensive_event_triage.py --input examples/fixtures/synthetic_cloud_events.jsonl
```

These commands use synthetic fixtures. **Do not run live monitoring mode in CI or a PR.** Live monitoring needs an explicitly configured and tested alert destination. A preview (`python3 ai_sec_sentinel.py --dry-run --since-hours 24`) may fetch public feeds but does not send notifications.

## Changes

- Add negative tests for every new permission or tool.
- Keep the MCP reference boundary closed to shell, writes, network and unknown operations unless a separate, reviewed threat model justifies expansion.
- Demonstrate actual tool enforcement rather than trusting an API response or an AI model's refusal.
- Support public claims with dated source material. Distinguish synthetic examples from field evidence and ensure tests are reproducible.
- Do not claim production protection, compliance certification, real-world detection efficacy or exploit prevention from this repository.
- Never include sensitive logs in public GitHub issues, PR bodies or screenshots.

A reviewable PR describes the threat, the specific permitted and denied behaviours, the tests, and residual risk.
