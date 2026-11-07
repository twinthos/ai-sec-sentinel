# Runtime state and outbound privacy

This repository has a local security demonstration and a **separate networked threat-intelligence scanner**. The synthetic file-read proof does not need production credentials. A live vulnerability scan contacts external providers even with `--dry-run` (dry-run disables notifications and deduplication mutations, not network fetches).

## Where runtime data is stored

The default directory for scanner, news and dashboard state is `~/.local/share/twinthos-sentinel/` unless `SENTINEL_DATA_DIR` is set. Writes use a private temporary file, and newly created state directories request owner-only permissions. Existing directories may need permissions audited separately.

**Migration for existing installs:** the previous default placed state next to the source checkout. This update deliberately does not copy old data automatically. Before upgrading a deployed scanner, stop the service, securely back up reviewed `sentinel_state.json` and `sentinel_feedback.json`, and either:

- Set `SENTINEL_DATA_DIR` to your existing, secured runtime volume; or
- Move only the reviewed state files into the new private directory, protect directory permissions, and restart the service.

Failure to migrate seen-state can cause duplicate alert notifications. It must never be interpreted as a clean new environment. Docker Compose already sets its own data volume via `SENTINEL_DATA_DIR`; verify volume ownership before upgrading.

## External transmissions

- The CVE source and CISA / EPSS receive HTTP feed requests and relevant identifiers.
- OSV receives supported package names, exact versions and ecosystems when dependency checks are used. It does **not** receive the entire lockfile from the OSV-only path.
- cve.now may receive the **entire raw lockfile** only with an explicit boolean opt-in (`allow_lockfile_upload=true`) and direct-call consent. Files classified as sensitive, symlinks and files larger than 1 MiB are denied.
- Telegram, Slack or Discord receive configured alerts, which undergo best-effort redaction. Redaction is not complete DLP.
- Any configured RSS domains receive feed requests. Network providers may see standard connection metadata.

Redirects are disabled for the lockfile and OSV POST paths. This reduces unintended disclosure but is not equivalent to a network egress sandbox or protection against all DNS routing attacks.

## Validation

```sh
python3 -m unittest tests.test_outbound_privacy -v
python3 -m unittest discover -s tests -v
```

No production integration, destination webhook delivery, credential rotation or network policy was exercised by these synthetic tests.
