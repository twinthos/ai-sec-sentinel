---
on:
  schedule: daily
  workflow_dispatch:
permissions:
  contents: read
  issues: read
  pull-requests: read
safe-outputs:
  create-issue:
    title-prefix: "[sentinel-report] "
    labels: [automation, security-review]
engine: copilot
---

# Sentinel repository health brief

Produce an evidence-linked repository operations brief for maintainers.

1. Inspect recent commits, open pull requests, open issues, and available GitHub Actions results.
2. Summarise only facts linked to a commit, issue, pull request, workflow run, or file.
3. Separate confirmed findings from hypotheses. An absent alert is not evidence that a system is secure.
4. Highlight failed or missing CI checks, stale open work, unreviewed security-sensitive changes, and documentation claims broader than demonstrated tests.
5. Do not modify source files, merge PRs, close issues, change settings, access secrets, or contact external services.
6. Create at most one issue only for a genuinely useful new finding; check for duplicates first.
7. Include "Evidence and limitations" with exact GitHub URLs. Never include credentials, customer data, private logs, or secret values.
8. If there is no useful new finding, create nothing.
