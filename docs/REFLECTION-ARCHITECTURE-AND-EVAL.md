# Reflection AI / Beam — architecture-led evaluation brief

**Research date:** 2026-11-03. **Status:** research + an offline Sentinel boundary proof. **NOT a Beam/Mirror/Hermes evaluation.** This document reverse-engineers a credible *research question*, not an alleged vulnerability or a product pitch claiming Reflection lacks security.

## 1. Source-verified architecture

Reflection describes an open intelligence stack: Beam model weights and hosted inference; integrations with independent harnesses; its own Mirror CLI; evaluation, deployment and customization tooling. Beam is a sparse MoE text model (501B total, 23B active parameters) aimed at agentic coding and tool use.

Mirror is Reflection's coding harness. Its Python frontend manages UI, instructions, skills and extensions; a Rust worker/core drives the model and agent loop. It supports MCP integrations and shell/file tools. Mirror was used to run the company's prompt-injection benchmarks. Beam can ALSO run with Nous Research's Hermes and other harnesses; model behavior is not the same as harness security.

**Critical boundary, from Mirror's published README:** ordinarily its local tools run as the user's account, and approvals are not isolation. Mirror also provides **optional microsandbox/microVM workspaces** for file and shell tools, with allowlisted HTTPS egress and no host credentials. Extensions and local MCP servers run on the host even when a sandbox workspace is used. That is a documented trust distinction, **not evidence of an exploitable vulnerability**. Never assert that Mirror lacks a sandbox or that Sentinel automatically secures its built-in shell.

The two valid integration shapes are:
- **Host-scoped MCP path:** Mirror/Hermes -> explicitly exposed read-only Sentinel MCP tool -> bounded local executor -> evidence. Other tools require *independent* isolation. This repo already demonstrates this narrow path.
- **Potential deeper integration:** trusted agent host/runtime intercepts *all* selected tool dispatches; applies per-task policy; enforces consequences in the actual OS/network executor. **Not implemented or verified in Mirror/Hermes here.**

```text
User task -> Beam model -> Mirror (Python CLI / Rust agent core) -> selected tools
                        |                                  |
                        |                     host shell / files / extensions
                        |                     or optional microsandbox
                        +-> MCP client -> Sentinel bounded MCP server -> local read executor
                                         (only this explicitly exposed tool)
```

### What Reflection already evaluates

Reflection's Beam Safety Technical Report describes **MirrorDojo and MirrorDyn**, its adaptations of AgentDojo and AgentDyn. Each attacked episode contains a legitimate task and injected tool-result instructions. It measures **task utility** and **attacker goal success** independently. Its tested Mirror developer-prompt mitigation reduced the reported Beam attack success rate from **3.1% to 0.3% (MirrorDojo)** and **3.6% to 0% (MirrorDyn)** on fixed, non-adaptive attacks. These are **Reflection-reported results**, not results from Sentinel, and 0% means no success in that sample, not invulnerability. The report says MirrorDojo used 949 and MirrorDyn 560 attacked episodes per model/setting. Compare only when protocols and harnesses truly match.

Reflection separately evaluates loss-of-control properties (**monitorability, evaluability, controllability**) and has a Beam Verifier for live endpoint API conformance and benchmark checks. Sentinel's MCP tool proof is neither a replacement for Beam Verifier nor an improvement to those published numbers.

### Primary sources

- [Beam release; model, Mirror architecture, Hermes compatibility](https://reflection.ai/blog/beam-is-available)
- [Beam Safety Technical Report; prompt injection and loss of control](https://reflection.ai/beam-safety-report)
- [Mirror CLI README; host permissions, optional microsandbox, MCP caveat](https://github.com/reflection-oss/mirror/blob/main/mirror-cli/README.md)
- [Mirror MCP configuration and tool exposure](https://developers.reflection.ai/mirror-mcp)
- [Beam Verifier; API/tool protocol conformance](https://developers.reflection.ai/beam-verifier)
- [Reflection current open roles, including London evaluations and safety infrastructure](https://reflection.ai/careers)

## 2. SWOT — supported facts versus hypotheses

| Lens | Grounded assessment | Consequence for our demo |
| --- | --- | --- |
| **Strengths** | Reflection has Beam, an open model ecosystem, Mirror, established evaluation methodology, and optional sandbox workspaces. | Do not introduce a toy gate as if it invented agent safety or replaced Reflection's evaluations. |
| **Weaknesses / explicit scope limits** | Mirror's default local permissions are not a sandbox; optional microsandbox does not place every host extension/MCP server inside the VM. Fixed prompt-injection tests do not cover all adaptive attacks. | Test independently enforced boundaries and trace their exact scope. Do not call a documented design tradeoff a discovered bug. |
| **Opportunities (hypotheses)** | Portable, open, reproducible comparisons across Mirror, Hermes and tool adapters could complement existing model-centric safety work. | Pair malicious attempted actions with legitimate tasks; report security outcomes, utility and auditability. Seek feedback before claiming buyer value. |
| **Threats to differentiation** | Existing sandbox/evaluation systems may already handle the same cases; unrestricted alternate tools bypass a narrow gate; benchmark and harness changes invalidate comparison. | Publish negative results and limitations, pin versions, prohibit unsupported competitive claims. |

## 3. Reverse-engineered research question

**Does a host-owned, independently enforced tool boundary reduce unauthorized *executed* actions while preserving the user's benign task completion, compared with the same harness configuration without that boundary?**

This is *not* a claim Reflection needs Sentinel. It is a falsifiable engineering experiment a safety/evaluation engineer can critique.

### Objections translated into measurements

| Likely technical objection | Required evidence | Current status |
| --- | --- | --- |
| Is there real execution, not a mock policy response? | Real MCP subprocess, allow and deny outcomes, unchanged protected file. | Covered only by local synthetic MCP proof. |
| Does legitimate work continue? | Benign task completion and false block rate on matched tasks. | One permitted read in local proof; **no Beam task-completion rate**. |
| Can agent instructions override boundaries? | Attempted calls and executed outcomes, injected tool-result variants, independent authorization. | Forced forbidden MCP calls are denied; **no live model prompt-injection evaluation**. |
| Can other tools bypass it? | Enumerated execution paths, controlled egress, sandbox/tool inventory, adversarial bypass tests. | **Not demonstrated** for Mirror/Hermes/Orgo. |
| Does it improve Reflection's existing safeguards? | Matched A/B runs with version pins, predeclared grading, uncertainty. | **Not measured**. |
| Does it damage useful work? | Clean/under-attack utility, false positives, p50/p95 latency overhead. | **Not measured**. |
| Is evidence independent and reproducible? | One-command rerun, fixed checks, source SHA-256, CI logs, failure exit status. | Local evidence wrapper provided; CI results must be checked separately. |
| Are results honest and secure? | No real secrets/customer data; distinguish model decisions from executor permissions. | Synthetic fixture only; no production security claim. |

## 4. Demonstration structure — disciplined order

**Phase A (implemented here):** Run `python3 examples/reflection_boundary_evidence.py`. It invokes the existing `examples/proof.py` real stdio MCP subprocess, verifies **all 10 expected boolean checks**, refuses missing, added or contradictory claims, and prints a JSON evidence report with SHA-256 fingerprints. Test with `python3 -m unittest tests.test_reflection_boundary_evidence -v`. This shows only a bounded read-only MCP enforcement mechanism. This is not a model benchmark.

**Phase B (not done):** Use a trusted isolated machine/VM with synthetic workspace and no production credentials. Pin Beam model version, Mirror release/commit, Hermes version, exact tool inventory, sandbox configuration, prompts, scenarios, grader, timeouts and seeds. Record the agent's **proposed tool call** separately from the **effect that actually occurred**. Validate that every available execution path is mapped; isolate shell/browser/other MCP connectors or exclude them from the security claim.

**Phase C (not done):** Run paired scenarios through the same harness in comparably configured arms: native approvals/prompt policy; native optional sandbox (where supported); then the same configuration with a host-controlled Sentinel boundary. For a separate cross-harness study, repeat in Hermes and report it **separately**, not as if Mirror's official benchmark scores were reproduced. Pre-register legitimate task success, attacker objective success, unauthorized attempted calls, unauthorized executed actions, denial correctness, audit evidence coverage, false blocks and latency. Report denominators, trial counts, confidence bounds and all failures. Never publish a claimed 0% vulnerability rate.

**Phase D (not done):** Present a 3-minute client demonstration of one permitted task, one attempted prohibited action, unchanged protected data and the evidence report; attach technical reproducibility instructions. Reflection engineering reviewers should receive the full method and failure cases, not a promotional video in place of data.

## 5. Meaning of current results

The existing narrow Sentinel MCP server can enforce its **own** tool's file-read permissions. Even an injected document cannot grant shell or network capabilities *through that server*, because such operations are not exposed. This is an execution-boundary property, not proof that Beam ignores instructions in hostile documents. An agent with separate unrestricted shell, browser, cloud credentials or MCP tools remains outside this demonstration.

**No Beam API requests, Reflection/Nous credentials, customer records or live Mirror/Hermes sessions were used.** There is currently no evidence that Sentinel improves Beam's safety outcomes against Reflection's existing mitigations, and the dossier must never imply otherwise. The next decision is whether engineering a **cross-harness paired evaluation** yields a contribution beyond their already published work.

## 6. What to say to Reflection

> I studied your Beam safety report and Mirror design rather than assuming you lacked guardrails. I built a small reproducible tool-boundary proof and documented its limits. I would like feedback on a paired evaluation measuring *attempted vs executed* unauthorized actions, legitimate-task utility and evidence portability across harnesses. I have not run a Beam or Mirror model benchmark yet and do not claim better results than yours.

**No vendor name in a demo title implies endorsement or affiliation.** Keep all interpretations linked to sources, versions and actual test output.
