# Sentinel: security evidence, not a product pitch

Updated 2 November 2026. Scope: public `twinthos/ai-sec-sentinel` repository.

## The real security problem

An AI agent can read untrusted emails, webpages, documents and MCP tool descriptions **and** act with someone else's privileges. A prompt saying “do not do dangerous things” cannot enforce a file, network or payment boundary. Defence requires a trusted identity, least-privilege execution path, independent approval for sensitive actions, reliable evidence, and repeatable adversarial testing.

Useful current frameworks: [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html), [OWASP Agentic Applications Top 10](https://genai.owasp.org/initiatives/agentic-security-initiative/), and [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/).

## Reproduce the evidence in two commands

Requires Python 3.11+ and a POSIX/Linux system for the descriptor-based file security example.

```sh
python3 reference_adapter.py --demo
python3 -m unittest discover -s tests -v
```

Both commands are meant to run with synthetic local data without credentials or network access. These commands should fail visibly if a security regression breaks the test.

## What these tests actually demonstrate

| Question | Reproduce | Result supported by code | Boundary |
| --- | --- | --- | --- |
| Can an unknown tool delete a file? | `tests/test_reference_adapter.py::test_unknown_tool_cannot_delete_file` | The adapter refuses the action before execution | It only controls calls made via this adapter |
| Can `../` or symlinks escape an allowed workspace? | `test_parent_path_traversal_is_denied`, `test_symlink_to_outside_is_denied` | File descriptor traversal rejects these attempts | POSIX/Linux; access via other tools bypasses it |
| What if the ledger cannot write? | `test_fails_closed_when_ledger_cannot_write` | The adapter withholds content | Ledger is locally hash-chained, not immutable |
| Can a caller claim another agent's identity? | `tests/test_gate_identity.py` | The API refuses an agent ID different from its trusted host binding | One identity per Gate API key; not integrated with a real runtime |
| Is a missing policy treated as permission? | `test_no_policy_means_no_reads` | The read is denied | Does not prove wider model alignment |
| What if a security feed or alert delivery fails? | `tests/test_runtime_safety.py` | Mocked failure handling is tested | Not a live notification SLA |

## Honest coverage against current threats

| Threat | Evidence in this repo | Missing for a real enterprise deployment |
| --- | --- | --- |
| Prompt injection / goal hijack | The read-only adapter cannot execute arbitrary injected tool requests | A tested and unavoidable tool broker for the actual LLM host |
| Excessive tool permissions | Fixed operation list, deny by default in one adapter | Principal-to-tool mapping for every real integration |
| Cross-agent impersonation | Guardian Gate binds the evaluation identity to a host-set ID | Per-session cryptographic identity and authentication upstream |
| Path traversal / unsafe file reads | OS descriptor-based confinement and negative tests | Windows support, additional capabilities, and sandboxing |
| Data exfiltration | Read-only bounded local capability limits one avenue | Egress firewall, DLP, secret isolation and end-to-end red-team tests |
| Poisoned external content or memory | Threat-model documentation | Untrusted-content and memory-scoping integration tests |
| Evidence manipulation | Hash chain detects local edits in the example | Independent log anchoring, signatures and privileged-user threat model |
| Vulnerability intelligence | CVE / KEV / EPSS source code, alert retry tests | Production uptime, live alert receipts, complete SBOM/SCA |
| CI / release safety | Multi-version Python tests and container build | Artifact provenance, threat-modelled releases and external audit |

**Do not infer** any certification, production monitoring uptime, prevented attack count, customer deployment, guaranteed detection rate or real-world security assurance from this repository.

## Real job-readiness checklist

A hiring reviewer should be able to:

1. Clone the repo and run the demo plus full test suite.
2. See a permitted action and at least three prohibited actions fail.
3. Follow the trust boundary from API credentials through policy to actual file access.
4. Read the negative tests, understand why `ask` is not an approval, and reproduce a denial.
5. Identify what is out of scope without needing to reverse-engineer marketing copy.
6. See green CI on the **default branch** after the change.
7. Inspect a real end-to-end integration and a written security review **before** making production claims.

This project is evidence of applied Python, security engineering and communication. It does **not** by itself establish professional security experience or guarantee a job. Suitable applications can include junior AI-security testing, security automation, application-security support, cyber threat-intelligence engineering, or responsible AI assurance. Present this project as a scoped reference and monitoring tool rather than an enterprise firewall.

## Next work that would have disproportionate value

1. Implement an optional example MCP/agent host adapter where all tool access is brokered and alternatives are explicitly disabled.
2. Add adversarial tests that feed untrusted data to the actual agent and assert forbidden actions never reach executors.
3. Add scoped egress controls and an approved high-risk-action flow with expiring, signed human approval.
4. Run external review and publish a reproducible demo/video and release digest.
5. Measure live scanning source coverage and successful notification acknowledgements, with alerts for missed runs.

## Vulnerability disclosure

Please report vulnerabilities privately through [GitHub Security Advisories](https://github.com/twinthos/ai-sec-sentinel/security/advisories/new). Never put customer records, tokens or exploits containing secrets in public issues.
