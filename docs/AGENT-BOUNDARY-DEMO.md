# A real, deliberately narrow MCP security boundary

## What this does

`mcp_reference_server.py` implements the MCP **stdio** JSON-RPC handshake and exposes exactly one tool: `sentinel_read_workspace`. Every tool call is mapped to the existing `GuardedWorkspace.execute("file_read", ...)` operation, whose host-supplied policy must return literal `allow`. It uses descriptor-relative file access and denies symlink/path escape. A local evidence record is written before content returns. A denied call returns an MCP `isError` response without its requested path or secrets.

No arbitrary code, shell, network, writing, delegation, or wildcard tool dispatch exists in this server. This is a functioning tool-execution path, **not** a mere “allow” message from a model.

## Run it locally

Requires Python 3.11+ and a POSIX/Linux runtime with `O_NOFOLLOW`. Run from a checkout of this repository. Put the trusted policy and evidence ledger **outside** the readable workspace:

```sh
mkdir -p /tmp/sentinel-demo/docs /tmp/sentinel-demo/control
printf '%s\n' 'This is a public sample, not a customer record.' > /tmp/sentinel-demo/docs/example.md
printf '%s\n' '[{"tool":"file_read","action":"allow","condition":"always","agent":"demo-agent"}]' > /tmp/sentinel-demo/control/policy.json
python3 mcp_reference_server.py \
  --workspace /tmp/sentinel-demo/docs \
  --policy /tmp/sentinel-demo/control/policy.json \
  --ledger /tmp/sentinel-demo/control/evidence.jsonl \
  --agent-id demo-agent
```

This process is a **stdio server**; connect it through an MCP client's local subprocess configuration, supplying the command and arguments above from the trusted host, not from model instructions. Do not expose it as a network server. The host must remove or isolate all other shell, file, browser and network tools; otherwise they bypass this particular boundary.

## One-command, observable security demonstration

```sh
python3 examples/proof.py
```

This starts an actual MCP stdio subprocess with temporary synthetic files, then verifies a permitted read, denied shell request, denied traversal, denied hidden-file access, redacted evidence and a clean shutdown. It prints machine-readable true/false results and returns a failure exit code when a check fails. The JSON is computed from real local actions, not marketing figures.

## Test without an LLM, credentials or a customer machine

```sh
python3 -m unittest discover -s tests -p 'test_mcp_reference_server.py' -v
python3 reference_adapter.py --demo
```

The first suite checks handshake, exposed tools, a real stdio subprocess, successful authorised reads, malicious tool names, prompt injection inside a document, path traversal, hidden files, symlinks, oversized data, fail-closed policy and failed evidence storage. This tests **tool enforcement**, not whether an LLM can be persuaded to *try* a forbidden call. The test harness deliberately sends forbidden tool calls directly, making failure observable and deterministic.

## Security boundary and limitations

- `GUARDIAN_AGENT_ID` and the Guardian Gate are **separate**, decision-only facilities. This MCP server instead uses its own host-set `--agent-id` with local `GuardedWorkspace`. Do not claim the API automatically intercepts the MCP stream.
- Only `.md` / `.txt` files without hidden or secret-like path components are eligible. The adapter also rejects file content matching a small set of credential and personal-data patterns; the absence of a match is **not** a confidentiality guarantee. Content may still contain confidential information if an operator places it in an allowed document. **Do not put real customer data into the example workspace.**
- The content of any allowed file is **untrusted data**. A model could still obey a malicious sentence in a retrieved file, but it cannot execute shell/write/network operations *through this MCP server*. Alternative tools must be independently isolated.
- Ledger is locally hash chained, not signed, externally anchored or protected from a compromised administrator. Log storage and the model process should have separate permissions in production.
- This server does not provide client authentication beyond a trusted local process launcher or end-to-end identity attestation. It is not production-hardened against a compromised host.
- The test is not a live adversary simulation, deployment assessment, compliance certificate or prevention claim for ARTEX.

## Security interview demonstration

A credible five-minute interview should show (1) one allowed read, (2) a denied deletion, (3) a path escape that fails, (4) untrusted content that cannot grant extra tools, (5) redacted evidence, and (6) the relevant source and tests. Then explicitly describe why an unrestricted secondary tool or network connection would break the safety argument.

Reference: [OWASP AI Agent Security](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) and [OWASP AI Agent & MCP Security](https://owasp.github.io/DevSecOpsGuideline/2-Process/2-2-Develop/2-2-5-AI-Agent-and-MCP-Security/).
