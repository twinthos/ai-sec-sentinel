---
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
permissions:
  contents: read
  issues: read
  pull-requests: read
safe-outputs:
  add-comment:
    max: 1
engine: copilot
---

# Sentinel pull request risk review

Review this pull request as a cautious security engineer. Do not change code.

1. Identify changed files and classify impact areas: network access, authentication, authorization, filesystem access, subprocesses, secrets, logging, persistence, dependency management, CI permissions, and deployment.
2. Read relevant implementation, tests, threat model, and security documentation.
3. Check whether each security-sensitive behaviour has positive and negative tests.
4. Distinguish a demonstrated defect from a question, missing test, or design trade-off.
5. Do not claim exploitability without a reproducible path and concrete impact.
6. Do not claim a vulnerability is absent just because no issue was found.
7. Check whether README and PR claims match actual test scope. Explicitly flag model/runtime integrations that have not been tested.
8. Report findings with severity rationale, affected path and line references, reproduction steps if established, and a recommended test or fix.
9. Do not run external network scans, inspect secrets, use production credentials, modify files, approve or merge the PR.
10. Post at most one concise review comment. If there is no evidence-backed finding, say so and list material uncertainties.
