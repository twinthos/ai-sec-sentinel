# Reproducible engineering evidence

**Question:** can the code demonstrate a security property, not merely report one?

## Quick verification

```sh
python3 reference_adapter.py --demo
python3 -m unittest discover -s tests -v
```

These commands run locally without cloud credentials for the reference adapter and offline unit tests. Network-based threat-intelligence previews are a separate path:

```sh
python3 -m pip install -r requirements.txt
python3 ai_sec_sentinel.py --dry-run --since-hours 24
```

The live feed preview requires Internet access; nonzero errors are meaningful and should not be ignored.

## Evidence map

| Property | Implementation | Tests | Limits |
|---|---|---|---|
| Explicit allow before file access | `GuardedWorkspace.execute` | `test_permitted_read_returns_exact_content`, `test_no_policy_means_no_reads` | Only this adapter |
| Prohibited tool never reaches an executor | Fixed operation dispatch | `test_unknown_tool_cannot_delete_file` | Other host tools may exist |
| Path confinement | Descriptor-relative POSIX open, no-follow | `test_parent_path_traversal_is_denied`, symlink tests | POSIX/Linux scope |
| Refuse unapproved `ask` | Policy decision gate | `test_ask_does_not_execute` | No approval UI provided |
| Avoid leaked data in evidence | Redacted ledger entry | `test_permitted_read_returns_exact_content` | Host logs are separate |
| Fail when evidence cannot be written | Durable decision before return | `test_fails_closed_when_ledger_cannot_write` | Not immutable |
| Notification retry and dry-run isolation | Scanner delivery/seen logic | `test_runtime_safety.py` | External channel receipt not guaranteed |
| Source health visibility | Nonzero one-shot errors and freshness check | `test_runtime_safety.py` | CI mocks not live coverage |

## What reviewers should inspect

The secure boundary is implemented at the **tool-execution adapter** (not inside the LLM). Re-run the negative tests; replace an allow rule with `ask`; try an outside symlink; make the ledger directory unwritable; verify that content does not return.

## Engineering decisions

**Why not add hundreds of tools?** Every tool expands attack surface. One audited, bounded capability is a stronger proof than a broad allowlist without enforcement.

**Why not put raw tool inputs in the ledger?** Inputs may contain secrets. Evidence stores tool, outcome and reason—not file contents or path values. This sacrifices forensic detail in favour of less sensitive logs.

**Why not silently skip feed failures?** A monitoring system is misleading if all sources fail and its process still claims healthy operation. Failures must be visible to the scheduler/operator.

**Why does CI not prove production safety?** Tests use synthetic fixtures. Real-time authorization, identity, deployment isolation and monitoring require integration and independent assessment.

No external certification, benchmark performance, customer deployment or employer endorsement is asserted.
