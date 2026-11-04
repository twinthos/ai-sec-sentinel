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
    title-prefix: "[sentinel-report-review] "
    labels: [automation, security-review]
engine: copilot
---

# Sentinel repository health brief — review required

Produce a concise, evidence-linked repository operations brief for maintainers.

1. Inspect recent commits, open pull requests, open issues, and available GitHub Actions results.
2. Summarise only facts linked to a commit, issue, pull request, workflow run, or file.
3. Separate confirmed findings from hypotheses. An absent alert is not evidence that a system is secure.
4. Highlight failed or missing CI checks, stale open work, unreviewed security-sensitive changes, and documentation claims broader than demonstrated tests.
5. Do not modify source files, merge PRs, close issues, change settings, access secrets, or contact external services.
6. Never include credentials, customer data, private logs, tokens, or secret values. Do not reproduce sensitive code or security details that could create a new exposure.
7. Check for duplicate reports first. If there is no useful new finding, create nothing.
8. If a report is useful, create one issue clearly marked as a **human-review draft**, containing only high-level findings, exact public repository links, and evidence limitations. Do not assign severity beyond what the available evidence supports.
9. The issue is a review queue item, not an incident declaration or an automated remediation request.
