# ARTEX and agentic intrusions — defensive engineering note

**Updated 2 November 2026.** This page is **public threat intelligence, not operational attribution** by Twinthos. Source confidence and scope matter.

## What primary sources confirm

- [Microsoft Security Research, 21 October 2026](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/): Microsoft linked ARTEX usage to Storm-0940 and a cloud application / supply-chain incident, including automated sign-in activity against more than 2,250 downstream tenants and follow-on app permission abuse. A reported 151,000+ failed password-spray sign-ins did **not** establish successful authentication in that sub-campaign.
- [CrowdStrike Intelligence, 7 October 2026](https://www.crowdstrike.com/en-us/blog/unknown-threat-actor-uses-artex-to-target-south-korean-finance/): Researchers found ARTEX configuration and agent session material associated with attacks on South Korean financial organisations.
- [Google Threat Intelligence Group, 30 October 2026](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks): Researchers observed ARTEX and other agentic frameworks in incidents, including a reported fastest path to deep system access of approximately 15 minutes in a case. That is **not** a universal compromise time.

The previously circulated number **“140 breached organisations in 11 days” is not treated as verified** here. ARTEX is model-agnostic and cannot accurately be described solely as a DeepSeek-based tool.

## What a defender should measure

The practical threat is often abuse of **existing privileges and applications**, amplified by faster automation. A host agent-security control cannot prevent a compromised enterprise OAuth application from being abused elsewhere. Different sensors are needed.

1. **At the agent tool boundary:** deny unrestricted shell, outbound network and unauthorised file or identity operations even when instructions are persuasive. Sentinel's `mcp_reference_server.py` demonstrates just one read-only capability and its limits.
2. **At identity and SaaS telemetry:** monitor unusual authentication failures across accounts/tenants and track application-credential, OAuth-grant and privileged-role changes. Correlate with deployment approvals and known administrators.
3. **At the dependency boundary:** pin and review MCP servers, tools, packages and workflows. A GitHub repo deletion or fork is **not** proof that a package is malicious.
4. **At the response boundary:** revoke leaked app credentials, contain compromised identities, preserve logs and involve authorised incident responders. Sentinel does not perform these actions automatically.

## Reproduce safe offline cloud-log triage

`defensive_event_triage.py` accepts **normalised local JSONL** with UTC timestamps and the keys `event`, `result`, `source_ip`, `account_id`, `tenant_id`. Relevant event values: `sign_in`, `user_sign_in`, `app_credential_added`, `oauth_permission_granted`, `privileged_role_granted`.

Start with the included **synthetic, public demonstration dataset** (not customer logs). Run:

```sh
python3 defensive_event_triage.py --input examples/fixtures/synthetic_cloud_events.jsonl
python3 -m unittest discover -s tests -p 'test_defensive_event_triage.py' -v
```

The signal is a sliding five-minute cluster of 20+ failed sign-ins covering at least five accounts and two tenants from one source address, or one high-impact permission/credential change. The report omits source IPs, account IDs, tenant IDs and raw payloads. This is a **heuristic**, not evidence an attack is ARTEX or a person is malicious. NAT, imperfect event normalization, missing audit data and split traffic can produce false positives or negatives.

**No Microsoft Graph/Defender connector, live feed collection, automated containment or real-time alert delivery is implemented by this module.** Do not describe it as a deployed detection on a customer tenancy. Export/normalize only logs you are authorised to handle, and use vendor-supported APIs or SIEM rules for production.

## What could become useful to security teams

An initial paid engagement could review an organisation's **approved** AI agent tool boundaries, MCP inventory and identity permission scopes, run synthetic abuse tests, and deliver a remediation plan. Real access requires agreed scope, data processing terms and credentials scoped by the client. An independently reviewable engagement report is more convincing than an unsupported “impossible to breach” claim.

This is defensive education and safe offline engineering, not an offensive ARTEX replication.
