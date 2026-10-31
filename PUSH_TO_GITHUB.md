# Push to GitHub

This repo is ready to push. No secrets are committed.

## One-time setup

```bash
cd /root/twinthos-brain/projects/ai-sec-bot

# Add GitHub remote (replace with your actual repo URL)
git remote add origin https://github.com/twinthos/ai-sec-sentinel.git
# or: git remote add origin git@github.com:twinthos/ai-sec-sentinel.git

# Push
git branch -M main
git push -u origin main
```

## Create the repo first

If the repo doesn't exist yet:
```bash
gh repo create twinthos/ai-sec-sentinel --public --source=. --remote=origin --push
```

Or create it manually at https://github.com/new then run the git commands above.

## What's in the box

- `ai_sec_sentinel.py` — 320-line autonomous monitor
- `sentinel_config.json` — all tunables
- `requirements.txt` — single dependency
- `README.md` — full docs
- `.gitignore` — protects state/feedback files

## Verify after push

```bash
gh repo view twinthos/ai-sec-sentinel --web
```
