# Contributing to Twinthos Sentinel

## Ground rules

- No secrets in PRs. No API keys, tokens, passwords, credentials.
- Keep it simple. One feature per PR. Under 200 lines changed if possible.
- Python 3.9+ only. No external dependencies beyond `requests`.
- Tests: run `python3 ai_sec_sentinel.py --since-hours 1 --feed-limit 5` before submitting.

## Dev setup

```bash
git clone https://github.com/twinthos/ai-sec-sentinel.git
cd ai-sec-sentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 ai_sec_sentinel.py --help
```

## Adding keywords

Edit `AI_KEYWORDS` in `ai_sec_sentinel.py`. Keep the list tight — false positives kill trust.

## Adding a source

1. Add fetch function following the pattern of `fetch_cisa_kev()` or `fetch_epss_scores()`.
2. Integrate into `run_scan()`.
3. Add a CLI flag if it needs configuration.

## Feedback

Found a bug? Open an issue with:
- Python version
- OS
- Command run
- Full output
