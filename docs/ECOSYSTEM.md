# Agent security: current context and Sentinel's role

Reviewed **2 November 2026** against the primary project documentation linked below. These are documentation observations, not independent deployment verification, market-share estimates or comparative security benchmarks. Recheck maintenance status before adopting a dependency.

## What the available tools cover

| Project / guidance | Current documented focus | Implication for Sentinel |
| --- | --- | --- |
| [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk/blob/main/README.md) | Official client/server SDK; current README links v2 documentation and requires Python 3.11+ | Test Sentinel with an official client. Its hand-written stdio subset is not evidence of complete MCP compatibility. |
| [Promptfoo](https://github.com/promptfoo/promptfoo/blob/main/README.md) | Model/prompt evaluations, red teaming, vulnerability scanning and code scanning | Complement execution-boundary tests with evaluations when a real agent integration exists. Do not claim equivalent evaluation coverage. |
| [NVIDIA garak](https://github.com/NVIDIA/garak/blob/main/README.md) | Probes LLM-backed applications for weaknesses including leakage, prompt injection and jailbreaks | Model probes and deterministic tool-denial tests answer different questions. Both matter for a deployed system. |
| [Microsoft PyRIT](https://github.com/microsoft/PyRIT/blob/main/README.md) | Open-source framework for identifying generative-AI risks | Use its current Microsoft repository; the [old Azure repository](https://github.com/Azure/PyRIT/blob/main/README.md) announces the move. |
| [LLM Guard](https://github.com/protectai/llm-guard/blob/main/README.md) | Input/output scanning; README now explicitly announces archival and no active maintenance | Do not add it as a new maintained dependency on the strength of older recommendations. Existing users should assess their own maintenance plan. |
| [OWASP AI Agent Security Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/AI_Agent_Security_Cheat_Sheet.md) | Least privilege, execution-side authorization, exact-action approvals, memory isolation, exfiltration controls and adversarial tests | Keep permissions outside model-controlled text. Test bypasses and failures; do not mistake a permission decision for an unavoidable boundary. |

These repositories show concrete tools and integration patterns available today. Their README claims, badges and popularity do not establish how widely they are deployed or how safe a particular deployment is. No customer or usage statistics were independently verified in this review.

## Product decisions

1. **Lead with one reproducible result.** The standard-library demo exercises a real MCP subprocess without asking for a model key or personal files.
2. **Make scope visible.** Separate the restricted file reader, offline event triage and online feed monitor. Each has different data flows and assurance.
3. **Prefer evidence over badges.** Link negative tests and explain what a passing result proves. CI status is not a security certification.
4. **Treat interoperability as unfinished work.** The MCP ecosystem is moving; a home-grown protocol test cannot substitute for an official-client compatibility check.
5. **Make privacy part of contribution design.** Ask for synthetic reproductions, not uploaded environments, personal logs or broad diagnostic bundles.
6. **Make production claims wait for production evidence.** A real isolated host, removal of alternate tools, delivery tests and external review remain necessary.

## What would justify stronger claims?

See the [roadmap](ROADMAP.md). A claim that Sentinel protects a particular agent needs a versioned integration, a clear trusted computing base, tests that attempt alternate tool access, and recovery behavior under failure. A claim about real-world adoption needs attributable usage evidence. Neither follows from a local demo or a GitHub star count.
