---
on:
  pull_request:
    types: [opened, synchronize, reopened]
permissions:
  contents: read
  pull-requests: read
  issues: read
safe-outputs:
  add-comment:
    max: 1
engine: copilot
---

# Dependency change review

Review dependency changes in this pull request without modifying files.

1. Identify dependency manifests and lockfiles changed in this PR.
2. Extract package names, ecosystems, old versions and new versions only where the diff establishes them.
3. Check whether versions are pinned and whether lockfile coverage is complete.
4. Review repository-provided automated dependency scan results when present. Do not invent advisory status or claim a live vulnerability lookup was performed unless a configured tool and cited result establish it.
5. Flag unsupported ecosystems, unpinned dependencies, incomplete manifests, and manifest/lockfile discrepancies.
6. Recommend exact deterministic CI commands or tests needed to verify uncertain items.
7. Never update dependencies, execute install scripts, contact package registries, access secrets, or merge changes.
8. Post one concise comment with evidence and explicit limitations only when dependency files changed.
