# GitHub agentic operations for Twinthos Sentinel

**Status:** design note. This repository has not been initialized with GitHub Agentic Workflows (gh-aw). No agentic workflow has been enabled by this document.

## Why use GitHub Agentic Workflows here?

GitHub Agentic Workflows (gh-aw) are an optional layer on top of GitHub Actions. An author writes a Markdown workflow with YAML frontmatter, compiles it with the gh-aw CLI into a checked-in `.lock.yml`, reviews both files, and runs it through Actions. The Markdown supplies agent instructions; the frontmatter supplies triggers, permissions, tools, network policy and safe outputs.

They are useful for repository tasks that require interpretation, such as issue triage, CI failure summaries and draft documentation. They do not replace normal deterministic tests or CI.

Official references:
- https://docs.github.com/en/copilot/how-tos/github-agentic-workflows/creating-github-agentic-workflows
- https://github.github.com/gh-aw/guides/mcps/
- https://github.github.com/gh-aw/reference/faq/

## What the feature does — and does not mean

- Markdown is an authoring interface, not an absence of configuration. YAML frontmatter remains, and compilation generates a conventional Actions lock workflow.
- Agentic workflows run on GitHub Actions. They require Actions enabled, a supported AI engine and its billing/credentials configuration.
- GitHub MCP is built in; custom MCP servers can be configured. A custom MCP tool is only available to the workflow when explicitly configured and its network/dependency requirements are satisfied.
- Read-only permissions are the default baseline; writes should be restricted to declared safe outputs and reviewed. Do not grant broad repository write permissions just to make an automation work.
- Cost has at least two parts: GitHub Actions runner minutes and model inference billed by the selected engine/provider. AIC estimates are not a guaranteed invoice total; compare them with provider billing.
- Triggers and integrations must be explicitly configured. A service does not automatically trigger an agentic workflow merely because it exists in the toolchain.
- Agentic workflows do not make an external Sentinel service authoritative over an agent's shell, browser, local extensions or other MCP servers.

## Proposed Sentinel use cases (not yet implemented)

### 1. Issue triage — read-only analysis, then human-reviewed safe output

Trigger: a new issue or manual dispatch.

The agent may inspect the issue and relevant repository docs, classify it as bug / question / security report / feature request, propose severity with a short rationale, find likely duplicate issues, and draft a response. It should not close issues, change code, access secrets, or make vulnerability claims. Any write action should be a constrained safe output and explicitly reviewed.

### 2. CI failure summary — read logs, propose next checks

Trigger: workflow failure.

The agent may summarise failed job names and relevant log excerpts, identify the failing test and suggest a reproducer. It must not modify code, rerun workflows automatically, change branch protection, suppress a test, or claim a fix has been validated.

### 3. Evidence freshness — deterministic, not agentic

Use ordinary GitHub Actions scripts to run the offline proof, unit tests, dependency audit and evidence-schema checks. Upload machine-readable artifacts. If a narrative summary is helpful, a separate read-only agentic workflow can summarise those artifacts; it must not replace or reinterpret the underlying test exit codes.

## Sentinel versus GitHub

GitHub Agentic Workflows orchestrate repository-level tasks: triggers, runner execution, logs, artifact retention, configured MCP tools and constrained repository outputs.

Sentinel is a separate security project with two distinct components:
1. Threat-intelligence monitoring (CVE/KEV/EPSS and supported dependency checks, plus notifications).
2. A limited reference tool-enforcement demonstration: a real local MCP subprocess exposes a single bounded read operation and denies shell, path escape and selected sensitive paths in synthetic tests.

Sentinel's Guardian policy API/task-context precheck is not an unavoidable interceptor for every tool in Hermes, Mirror or Orgo. A trusted host integration must mediate each privileged execution path. If another shell, browser, extension or MCP server can reach the same resource directly, the narrow Sentinel MCP boundary does not protect that path.

Therefore, GitHub automation does not replace Sentinel, and Sentinel does not replace GitHub Actions. They solve different problems and can be connected only through explicit, least-privilege interfaces.

## Recommended acceptance criteria before enabling any workflow

- Actions enabled and supported engine availability/billing confirmed by the repository owner.
- Workflow permissions reviewed; default to read-only.
- Only required MCP servers, toolsets and network destinations configured.
- Any write uses a narrow safe output, with human review before merge or irreversible action.
- No production credentials, customer data or private incident reports in prompts or public artifacts.
- CI tests remain deterministic and authoritative; an LLM summary is advisory.
- Cost and retention limits documented; artifact contents checked for secrets and personal data.
- Workflow lockfile reviewed after compilation and pinned dependencies inspected.
- At least one test with adversarial issue content to check prompt-injection resistance of the workflow itself.

## First safe rollout

Start with issue triage on a low-risk repository event and read-only permissions. Measure classification accuracy against a human-labelled sample, false-positive security severity, duplicate detection precision, and review time saved. Do not connect Sentinel production notifications or prospect research to this workflow until the repository-only pilot is understood.
