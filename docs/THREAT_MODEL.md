# Sentinel reference adapter — threat model

**Status:** scoped, executable teaching/reference component. Not a universal security control.

## Security objective

Before reading a trusted workspace file, a tool request must pass:
1. Tool name exists in the adapter's exposed list.
2. Policy evaluation returns literal `allow`.
3. The requested path is relative, bounded, contains no `..` components, and resolves by descriptor-based traversal without symlinks.
4. The target is a regular file whose contents fit within the configured byte cap.
5. An enforcement decision is durably written before data is returned.

Any failure must refuse the action, not fall through to a weaker execution route.

## Trusted computing base

The local Python process, its OS user, trusted policy file, the root directory descriptor, Python standard library and storage backend. Caller agent identity must be supplied by the host's trusted adapter configuration, **not** by model text or a public API parameter.

## Assets at risk

Files outside the permitted root; workspace file contents; tool permissions; local evidence; credentials or sensitive data that may be found in filenames and logs.

## Threat scenarios and expected behaviour

| Scenario | Expected adapter behaviour | Reproducible evidence |
|---|---|---|
| An AI agent requests a deleted file | No delete tool is exported; request rejected | `test_unknown_tool_cannot_delete_file` |
| Parent-directory traversal | Reject path before file operation | `test_parent_path_traversal_is_denied` |
| Final or intermediate symlink escape | OS file-descriptor access with `O_NOFOLLOW`; deny | `test_symlink_to_outside_is_denied`, `test_intermediate_symlink_is_denied` |
| Unapproved read or approval requested | Deny unless literal policy `allow` | `test_no_policy_means_no_reads`, `test_ask_does_not_execute` |
| Ledger write unavailable | Do not return file contents | `test_fails_closed_when_ledger_cannot_write` |
| Large, non-regular, undecodable content | Deny | `test_binary_or_oversized_file_denied` |
| Successful permitted read | Return only bounded file content; record redacted decision | `test_permitted_read_returns_exact_content` |

## Out-of-scope and bypasses

- An agent with **another** shell, file API, broader filesystem permission or network channel can bypass the adapter. Integration requires removing alternate paths.
- Files in the allowed workspace may contain sensitive data; path confinement alone is not data classification or DLP.
- A compromised OS user, process or policy administrator can modify files or falsify local ledger history.
- No hardware-based identity, signed logs, MFA, remote attestation, cross-process authorization, immutable event store, distributed locking or high availability.
- API Guardian registration is descriptive; it is not cryptographic attestation.
- Security monitoring is not exploit prevention; feed completeness and freshness vary.

## Required before production integration

Specify the actual agent runtime, isolate it at OS/container boundaries, map every tool to a brokered operation, remove direct access, establish cryptographic principal identity, implement signed one-time approval with expiry, conduct adversarial tests and external review, monitor delivery failures, and test recovery and rollback.

This threat model is intentionally narrow so that the tested assurance is not overstated.
