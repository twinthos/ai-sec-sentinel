# Roadmap: from a useful reference to a verified integration

This is a proposed development sequence, not shipped functionality or a delivery-date promise. The current release candidate demonstrates one local file-read boundary, synthetic event triage and public-feed monitoring code.

## 1. Official MCP client interoperability

**Outcome:** a developer can connect a supported client and reproduce the same boundary checks.

Acceptance: pin a reviewed SDK version for integration tests; test initialize, tool discovery, allowed reads, denied calls, malformed requests and clean shutdown through the official client. Publish the exact client/protocol/OS matrix. Keep the standard-library demo available. Do not claim compatibility with untested clients.

## 2. An unavoidable boundary for one real host

**Outcome:** one documented agent runtime can read only its approved workspace through Sentinel.

Acceptance: publish a synthetic container/OS isolation recipe; remove alternate file, shell and network tools; attempt bypasses outside MCP; deny on policy/evidence failure; test restart and cleanup. Include an explicit threat model and external review before production claims.

## 3. Trustworthy monitoring operations

**Outcome:** users can distinguish healthy delivery, source failure and incomplete coverage.

Acceptance: controlled endpoint integration tests cover acknowledgement, retry, deduplication, timeouts and restarts; verify runtime-state migration and permissions; demonstrate recovery without posting to real customer channels. User-authorized live delivery tests must be reported separately from mocks.

## 4. Privacy beyond pattern matching

**Outcome:** documented data minimization and predictable retention across each supported workflow.

Acceptance: map every outbound field and persisted field; add tests for credential-bearing errors and unknown sensitive content; define retention/deletion behavior and tests; review symlink/race handling for private storage. Do not promise arbitrary PII detection or rely on regex alone for confidential workspaces.

## Useful contributions now

- A synthetic failing case for an existing boundary, with expected and observed results.
- A reproducible official-client integration proposal and compatibility matrix.
- Setup improvements tested on a specified Python and POSIX platform.
- A privacy data-flow review that names the exact source, sink and regression test.

Discuss new privileged tools before implementing them. Adding shell, write or network access changes the security model and requires a new design and tests. Report exploitable vulnerabilities through the [private security channel](../SECURITY.md).
