# Twinthos GitHub automation roadmap

This roadmap is a proposal, not a statement that the features are currently enabled.

## Stage 0 — establish the baseline

- Keep existing deterministic CI authoritative.
- Confirm current workflow status, artifact contents and dependency audit results.
- Keep PR #15 as a draft research/evidence design until its own CI has run and its claims have been reviewed.

## Stage 1 — read-only repository triage

- Pilot advisory issue classification on a small set of non-sensitive issues.
- Compare suggested classifications against human review.
- Never auto-close or auto-label security reports.
- Do not connect customer support, prospect data or private security disclosures.

## Stage 2 — CI failure explanation

- Trigger only on failed runs.
- Read workflow/job summaries and sanitised log excerpts.
- Propose reproduction steps; no autonomous code modification or reruns.
- Human reviewer decides whether to create an issue or patch.

## Stage 3 — Sentinel security evidence pipeline

- Keep security tests and offline MCP proof as deterministic Actions jobs.
- Publish version-pinned JSON evidence artifacts, with secrets and customer data excluded.
- Have any agentic summary quote artifact identifiers and preserve fail status.
- A summary must never turn a failed or missing test into a pass.

## Stage 4 — explicit MCP integration

- Add Sentinel MCP to a workflow only after the server is packaged reproducibly and tool definitions are reviewed.
- Keep its tools read-only and task-scoped where possible.
- Explicitly list allowed network endpoints and pin image/dependency digests.
- Do not interpret an MCP response as proof that other host tools are protected.

## Stage 5 — external event dispatch

- Only after a concrete external system is selected, define a narrow repository_dispatch event schema.
- Authenticate the sender with a dedicated, short-lived/scoped credential or supported app identity.
- Validate event type and payload schema; reject oversized payloads and untrusted instructions.
- Store credentials in the sending system's secret store; never in issue content or repository files.
- Do not use a broad long-lived PAT by default.

## Cost and outcome metrics

Track per workflow: Actions minutes, provider inference cost, run duration, failures, human correction rate and useful time saved. AIC/usage estimates are useful for observability but must be reconciled with provider billing. Set engine-side and repository/organization budgets before expanding usage.
