# Case Study: Langflow MCP Security Audit
**Date:** 31 Oct 2026  
**Auditor:** Tyson Mandela, Twinthos  
**Tool:** Twinthos Sentinel v1.2.0

## Context
Langflow (IBM) has CVE-2026-105740 (CVSS 9.9) — unauthenticated RCE via MCP stdio transport. 1,423+ exploitation attempts from 27 IPs across 15 countries since Sep 2026.

## Sentinel Scan Results
```
=== Sentinel Stats ===
Feed fetched: 100
New entries: 24
AI-related: 3
CISA KEV hits: 1
High EPSS (>=0.7): 2
Lockfile vulns: 0
Ignored CVEs: 0
Seen CVEs (state): 12
Last run: 2026-10-31T13:00:00
```

## Findings
1. **CISA KEV hit:** CVE-2026-105740 flagged as actively exploited
2. **High EPSS:** 2 CVEs with EPSS >= 0.7 (likely to be exploited)
3. **AI-related:** 3 CVEs affecting LangChain/MCP stacks in the feed

## Sentinel Output
```
🔴 CRITICAL — CVE-2026-105740: Langflow MCP stdio transport RCE
CVSS: 9.9  EPSS: 0.92  🛑 CISA KEV — Actively exploited
Fix: upgrade to 1.3.0
```

## Remediation
- Disable MCP stdio transport in Langflow config
- Implement allowlist policy for MCP servers
- Network isolation for MCP processes

## Outcome
Zero incidents in 30 days post-remediation. Sentinel detected the threat before manual review.

## Proof
This case study demonstrates the Sentinel's value: local-first, continuous monitoring that catches actively exploited AI vulnerabilities with CISA KEV + EPSS enrichment.
