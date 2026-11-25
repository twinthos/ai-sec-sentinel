# Changelog

All notable changes to Twinthos Sentinel are documented here.

## Unreleased — 2026-11-25

### Added
- **ATT&CK / Sigma coverage index** (`detection/attack-coverage.json`,
  `detection_coverage.py`, `tools/build_detection_coverage.py`,
  `docs/DETECTION-COVERAGE.md`): maps 15 ATT&CK techniques to the Sentinel check
  or policy artefact that reasons about each behaviour, with the 709 upstream
  Sigma rules that carry the same technique tags.
- Index is generated offline from MITRE ATT&CK 20.1 and SigmaHQ `876eb7b8cfbc`;
  technique names, tactics, rule ids and rule paths are copied from source, and
  the build aborts on a missing technique or an unresolvable code path.
- `--validate` enforces the index contract (id shape and uniqueness, resolvable
  checks, existing control artefacts, real rule UUIDs with upstream paths, and
  counts that match the entries); exit 1 on error, 2 on an unmapped technique.
- 24 offline tests, including six that corrupt a copy of the index on purpose to
  prove the validator can fail.

### Limits
- The index is a reference map, not detection coverage: `direct` means a check
  inspects the behaviour, `partial` means it sees an adjacent signal.
- Sentinel does not execute Sigma rules and does not redistribute rule bodies.
- MITRE ATLAS (AI/agent-specific techniques) is not mapped.
- CI verifies the committed index against its contract only; it does not
  re-download Sigma or ATT&CK, so a refresh is a manual maintainer step.

## Unreleased — 2026-11-03

### Verified repository improvements
- Added synthetic MCP quickstart and no-argument safety, plus a reproducible CI proof.
- Corrected destination-policy allowlist fallback and URL precheck behaviour; added negative tests.
- Added privacy checks for outbound messages and explicit consent for raw lockfile uploads.
- Moved default local state outside the source checkout, with required operator migration guidance.
- Added responsible issue/PR templates, scoped capability documentation and a development roadmap.
- Added scheduled dependency and static security checks (their outcome must be inspected separately).

### Limits and corrections
- The prior changelog describes security capabilities at a high level; individual modules are not necessarily wired into a protected production agent.
- HTTPS security headers for the live GitHub Pages website cannot be established from a static repository alone; see the website SECURITY.md.
- 'Local-first' does not mean a networked CVE/OSV scan is offline: package identifiers, CVE identifiers and HTTP request metadata may be transmitted.
- No current CI badge demonstrates an independently audited, enterprise-grade or production-proven protection service.

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
