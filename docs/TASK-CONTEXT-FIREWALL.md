# Task-scoped Context Firewall — reference policy precheck

This is a narrow implementation of the highest-priority **runtime access / context
firewall** idea. It is an optional host-controlled addition to the authenticated
Guardian `/evaluate` API, not a network proxy or a universal AI-agent firewall.

## What was built

When `GUARDIAN_TASK_POLICY_FILE` is configured, every `/evaluate` request
must pass **both** the task-context precheck and Guardian's existing explicit
policy evaluation. The task-context layer rejects:

- Wrong agent or unknown task;
- Missing, too-short or incorrect task capability;
- Tasks outside their explicit UTC validity interval;
- Unlisted tools (including shell, file write and plugin installation);
- File-read paths outside exact approved directory prefixes, including simple
  traversal and encoded path anomalies;
- HTTPS destinations outside the exact host allowlist, non-standard ports,
  IP literals, user-info URL smuggling and insecure schemes;
- Invalid, oversized, symlinked or non-private host policy files.

The host policy is reloaded per evaluation so removing a task immediately
revokes its capability for future evaluations. A denial creates a *minimal*
ledger event with tool and reason code, not the credential or raw parameters.
A ledger write failure itself blocks evaluation.

**Scope:** This is a *precheck* before existing Guardian decisions. An external
agent runtime must enforce the final decision at the one actual execution
boundary and remove bypassing tools; this repository does **not** show a live
Hermes/Orgo deployment doing so.

## Safe deployment shape

Store the task policy **outside the public repository** in a host-owned,
regular POSIX file with permission mode `0600`. The policy has this shape
(placeholders only; do not commit generated capability values):

```json
{
  "version": 1,
  "tasks": [{
    "task_id": "support-case-1",
    "agent_id": "support-agent",
    "capability_sha256": "<64-lowercase-hex-sha256-digest>",
    "not_before": "2026-11-03T09:00:00+00:00",
    "expires_at": "2026-11-03T09:20:00+00:00",
    "tools": {
      "file_read": {"path_prefixes": ["approved/"]},
      "http_request": {"hosts": ["api.example.com"]}
    }
  }]
}
```

Issue a random token from trusted host infrastructure. Use a cryptographic
random generator (e.g. Python `secrets.token_urlsafe(32)`). Store only its
SHA-256 hex digest under `capability_sha256` in the policy. The raw token must
remain in a trusted sidecar or adapter, **never** in model prompt/context,
untrusted web content, GitHub, public logs, or a Telegram/Slack chat. Do not
pretend this is a one-use token: the capability can be reused until revoked or
expired. Use short lifetimes, trusted distribution and rotation.

Run Guardian Gate with `GUARDIAN_AGENT_ID` matching the task `agent_id`,
a host-set `GUARDIAN_API_KEY`, and
`GUARDIAN_TASK_POLICY_FILE=/absolute/private/tasks.json`. The trusted tool
adapter injects these headers into each internal request:

- `Authorization: Bearer <host API credential>`;
- `X-Sentinel-Task-Capability: <host-issued task capability>`.

The request body includes `agent_id`, `task_id`, `tool`, and `params`.
`file_read` accepts only a `path` under a configured prefix.
`http_request` accepts only a `url` with an approved HTTPS host. The task
scope does not grant the tool by itself; Guardian's own policy must also
explicitly allow it.

If `GUARDIAN_TASK_POLICY_FILE` is **unset**, legacy Guardian behaviour
remains and the response explicitly marks `task_scope: not_configured`.
Do not advertise this as task-context enforcement. If it is set but policy is
missing, inaccessible, malformed or insecure, the API returns an error and
**does not allow the action**.

## What this does *not* protect

- Does not execute or intercept tool calls, issue/revoke upstream cloud tokens,
  enforce network routing, prevent DNS rebinding/redirects or verify MCP tool
  origins. Restrict egress with independent network controls.
- Does not protect alternate shell, file, browser, plugin or network paths.
- Does not inspect AI intent, natural-language prompts, tool descriptions or
  MCP server code; it is a strict metadata and parameter gate only.
- Does not detect shadow AI, build a governance dashboard, implement autonomous
  remediation, or satisfy sector compliance by itself.
- Directory-prefix validation is *not* a safe filesystem operation. The real
  executor must enforce no-symlink, no-traversal and read/write rules using
  trusted OS primitives (see `reference_adapter.py`).
- The policy file must be created and distributed by a trusted component; an
  agent able to edit it can forge task permissions.

## Reproduce the scope tests

```sh
python3 -m unittest tests.test_task_context -v
python3 -m unittest discover -s tests -v
```

Tests use only temporary files and synthetic tokens. No customer environment,
network request, real agent account or production credential is involved.

## Why this direction

The internal strategy briefing identified tool vetting, moment-of-use access
decisions and task-specific permissions as high-priority ideas. This scoped
prototype implements part of that architecture without adopting unverified
competitive, market-size, pricing or delivery-date claims.

External background:
- Fortune's 2026–27 Cyber 60 was announced **28 October 2026** and includes
  **60** companies across three stages, not 20 total:
  https://fortune.com/ranking/cyber/
- OWASP Agentic Top 10 identifies tool misuse and identity/privilege abuse:
  https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
- OWASP Q3 2026 research recommends independently enforced network boundaries
  and per-run credentials, not just a model-side request to behave:
  https://genai.owasp.org/2026/10/08/genai-and-agentic-ai-exploit-roundup-q3-2026/

**Evidence standard:** a passing offline test suite demonstrates only those
scenarios. It does not certify deployment safety or vendor-level equivalence.
