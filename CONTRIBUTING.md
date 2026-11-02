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

## Choose a focused contribution

Read [the roadmap](docs/ROADMAP.md) and [ecosystem context](docs/ECOSYSTEM.md). For a new integration, name the client, protocol version, platform and permissions it needs. For a bug, include a minimal synthetic reproduction and the expected exit status. The GitHub issue forms guide these details.

Useful first contributions include clearer error messages, documentation verified on your platform, and regression tests for malformed inputs. Discuss changes to the privileged tool surface before implementing them.

## Troubleshooting the first run

- **Missing `requests` or `feedparser`:** activate `.venv` and run `python -m pip install -r requirements.txt`. The bare `python examples/proof.py` demonstration needs only the standard library.
- **Unsupported filesystem or native Windows:** use Linux, WSL or a compatible POSIX environment. The boundary depends on directory file descriptors and no-follow flags; do not replace them with weaker string-only checks.
- **Unhealthy scanner after a demo:** expected. The synthetic demo does not record a successful live monitoring scan.
- **Network failure during a preview:** check access to the documented feed destinations and configured CA trust. Do not disable TLS verification.
- **Private details in a reproduction:** reduce it to invented files and data before opening an issue. Do not attach your environment file or full logs.

## Before a pull request

```sh
python tools/check_repo_exposure.py
python -B -m unittest discover -s tests -v
python ai_sec_sentinel.py --quickstart
git diff --check
```

The exposure checker scans tracked files and has limited pattern coverage. Also inspect new files and the full diff yourself. A clean scan does not guarantee that a document contains no private information.
