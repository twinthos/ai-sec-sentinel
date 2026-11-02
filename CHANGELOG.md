# Changelog

All notable changes to Twinthos Sentinel are documented here.

## Unreleased

### Added
- A plain-language offline quickstart and a guided no-argument CLI entry.
- Privacy regression tests for notifications, upload consent and redirects.
- A dependency-free demo entry point in the README and CI validation before dependency installation.
- A dated ecosystem review, acceptance-based roadmap, monitoring guide and privacy-conscious issue/PR templates.

### Changed
- Scanner, news and dashboard state defaults now live outside the checkout. Existing state is not automatically migrated; `SENTINEL_DATA_DIR` remains supported.
- Notification messages redact common secret/email patterns; send failures report error types instead of potentially credential-bearing URLs.
- Notification and dependency POST requests reject redirects. Raw upload requires explicit boolean consent and rejects sensitive filenames and symlinks.
- Documentation distinguishes online dependency lookup from offline parsing, and describes the limits of redaction and the MCP boundary.

These changes are not yet a published release. The historical entries below describe earlier versions; current scope and assurance are defined in README.md and docs/EVIDENCE.md.

## [1.4.1] - 2026-11-01

### Added
- Durable alert queue (SQLite, WAL mode, 7 states, retry with backoff)
- Vulnerability scanner with proper version comparison (packaging library)
- Privacy module (secret redaction, local-only mode, file permissions)
- Webhook security (constant-time comparison, sender validation, body limits)
- Policy engine (deny-by-default, priority rules, approval tokens, SSRF protection)
- Blast radius map (directed graph, transitive reachability, cycle detection)
- Agent passports (readable security identity, expiry, validation)
- Evidence ledger (hash chain, tamper detection, redaction)
- Sendblue iMessage channel adapter
- A/B testing framework (6 test suites)
- Comprehensive test suite (34 tests)
- OpenSSF OSPS Baseline compliance docs

### Fixed
- Alert delivery confirmation (only mark seen after send succeeds)
- OSV fallback (version + ecosystem in query payload)
- Lockfile upload consent (allow_lockfile_upload flag)
- News state merging (preserve main module state)
- --check-only mode (works as health check)
- Version string (--version now shows v1.4.1)
- Case study (relabeled as simulation, claims corrected)
- CVE example numbers (replaced with CVE-2025-EXAMPLE)

### Security
- Constant-time webhook secret comparison
- Secret redaction in logs and evidence
- Restricted file permissions on config and state
- CSP headers on Twinthos website
- UFW firewall rules documented

## [1.2.0] - 2026-10-31

### Added
- Sentinel Guardian (v2.0 preview)
- Risk scoring and compliance mapping
- OWASP Agentic Top 10 mapping
- MCP rug-pull detection
- Memory poisoning detection
- Indirect prompt injection detection
- Cloud support (AWS/GCP/Azure/k8s)
- Dashboard (stdlib-only, port 8099)
- Guardian Gate (out-of-process, port 8098)

### Fixed
- Word-boundary keyword matching
- Atomic state/feedback writes
- Webhook authentication
- HTML escaping in alerts
- OSV lockfile matching
