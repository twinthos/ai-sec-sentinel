# Sentinel security review — 2026-11-03

## Scope and evidence

This review covers the **public** `twinthos/ai-sec-sentinel` source repository and its
offline tests, not an inspected production Hermes/Orgo deployment. The agent
policy demo is separate from the vulnerability monitor. CI success is evidence
that the covered tests pass, **not** proof of total security or live alert delivery.

## Findings and repairs

| Finding | Risk | Mitigation | Verification |
| --- | --- | --- | --- |
| Severity evaluated before missing CVSS is retrieved | High-risk CVEs silently omitted | Enrich before applying severity threshold; do not drop KEV solely because its score is missing | `test_unscored_critical_entry_is_enriched_before_filtering`, `test_known_exploited_entry_is_not_discarded_when_unscored` |
| A later CISA KEV listing is not a newly published CVE | New active exploitation can be missed | Independently track *dateAdded* for AI-related or explicitly watched suppliers; maintain separate KEV acknowledgement state | `tests/test_kev_updates.py` |
| Telegram callback trusts any authenticated platform sender | Other participants may suppress alert feedback | Require both an expected chat and explicitly listed human operator IDs; validate callback action and CVE | `test_feedback_requires_both_chat_and_sender_identity` |
| Network errors may print webhook URLs or bot tokens | Credential exposure in logs | Emit exception types, not exception URLs; turn off HTTP redirects for outbound notifications | `test_telegram_exception_never_logs_token`, `test_webhook_must_not_follow_redirects` |
| Old pinned Requests dependency | Known package advisories | Update to Requests 2.34.2 and retain Dependabot | CI installation; `test_requests_version_contains_2026_security_fixes` |
| Preview workflow receives production messaging secrets | Unnecessary credential access by a no-send job | Remove secrets from preview and restrict GitHub Actions content permission | `test_ci_dry_run_receives_no_message_secrets` |

## Operator requirements

Set `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`,
`TELEGRAM_WEBHOOK_SECRET` (at least 24 characters), and
`TELEGRAM_ALLOWED_USER_IDS` (comma-separated numeric Telegram user IDs).
For example, `TELEGRAM_ALLOWED_USER_IDS=111111,222222` permits only those
two operator accounts to submit feedback from the configured chat. Never
commit these values or paste real tokens into public issues or Slack channels.

Configure `suppliers` in `sentinel_config.json` with genuinely used vendor
or product names. Newly added CISA KEV records are monitored by **catalog
date** and may include part of the previous day because the feed has no
time-of-day precision. The scanner is **not** a comprehensive inventory,
and relevance matching is approximate.

## Fresh context

- [OWASP 2026 agentic application risks](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) highlight goal hijack, tool misuse, identity/privilege abuse and agentic supply-chain risk.
- [OWASP AI agent security cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) recommends explicit tool boundaries, limiting permissions, and inspecting untrusted inputs and persistent memory.
- [Microsoft 2026 red-team findings](https://www.microsoft.com/en-us/security/blog/2026/06/04/updating-taxonomy-failure-modes-agentic-ai-systems-year-red-teaming-taught-us/) identify human-approval bypass, cross-domain prompt injection and memory poisoning as recurring failure modes.
- [CISA BOD 26-04 summary](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/430d404) emphasises risk-based prioritisation of known exploited vulnerabilities, particularly exposed critical assets.
- [Requests release history](https://pypi.org/project/requests/) confirms newer patched releases than the previous 2.31.0 pin.

These sources guide threat prioritisation; they do **not** attest to Sentinel's
security or substantiate any vendor/customer claim.

## Remaining risks and next experiments

1. **Real runtime integration:** prove the Hermes/Orgo agent has no bypass around
   the tool broker. Local, isolated MCP tests alone cannot establish this.
2. **Source correctness:** validate cve.now as an external intermediary; compare
   independent authoritative vulnerability sources (CVE/NVD/OSV/CISA), with
   explicit feed freshness and missing-source outcomes. EPSS is probability,
   not proof of active exploitation.
3. **Actual delivery:** run `--test-alert` with a dedicated test destination,
   then simulate Telegram, Slack, DNS and feed outages; observe failed-state
   retries, alarms and health checks.
4. **Human approval:** test approvals over multi-step actions, replay,
   identity swapping and malicious tool descriptions; never treat a policy
   recommendation as enforcement.
5. **Supply chain and data boundaries:** add an inventory/SBOM, review dependency
   updates, verify credential rotation, prevent unsafe memory writes, and
   exercise prompt-injection cases using safe synthetic fixtures.
6. **External review:** obtain independent security review before making strong
   customer-facing protection claims.

**Truth rule:** No component should be described as `impossible to break`,
`certified`, `production-proven`, or `protecting Twinthos clients` without
relevant external evidence.
