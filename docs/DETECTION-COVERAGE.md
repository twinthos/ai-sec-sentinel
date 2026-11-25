# ATT&CK / Sigma coverage index

## What this is

`detection/attack-coverage.json` maps a small, curated set of MITRE ATT&CK
techniques to two things:

1. the Sentinel code path or policy artefact that actually reasons about that
   behaviour, and
2. the real Sigma rules that exist upstream for the same technique, by rule id,
   title, upstream file path and logsource.

`detection_coverage.py` reads and checks that file. It makes no network calls,
imports only the standard library, and never executes a Sigma rule.

## What this is not

The index is **not** a detection claim. `confidence` is deliberately narrow:

- `direct` — a Sentinel check inspects this behaviour (for example,
  `check_agentic_attack_patterns` classifies rotating-proxy probing for T1090).
- `partial` — a check sees an adjacent signal, not the technique itself (for
  example, `check_attack_surface` flags unauthenticated internet-facing
  services, which is the precondition for T1190, not exploit traffic).

Sentinel does not replace a SIEM, does not run Sigma, and does not attribute
activity to an actor. A mapped technique with 337 upstream rules means the
upstream rules exist; it does not mean Sentinel detects any of them.

## Where the numbers come from

Everything upstream-supplied is copied from source at build time, never typed by
hand:

| Field | Source |
| --- | --- |
| Technique id, name, tactics | MITRE ATT&CK enterprise STIX bundle (`attack-stix-data`) |
| Rule id, title, level, path, logsource | SigmaHQ `sigma` repository, parsed from each rule |
| Rule count per technique | Distinct rules tagged with that technique **or any of its sub-techniques** |

The build aborts if a curated technique is absent from the ATT&CK bundle, if the
named Sentinel check is not a callable in this checkout, or if a named control
artefact does not exist. A plausible-but-unverifiable entry cannot be written.

Current build: ATT&CK **20.1**, SigmaHQ **876eb7b8cfbc**, 2,812 of 3,164 rule
files carry ATT&CK tags, 15 techniques mapped, 709 upstream rules referenced.

## Read it

```sh
python3 detection_coverage.py --report        # the table
python3 detection_coverage.py --validate      # contract check, exit 1 on error
python3 detection_coverage.py --technique T1190
```

`--validate` exits 0 only when every technique id is shaped and unique, every
Sentinel reference resolves in this checkout, every Sigma sample is a real rule
UUID with an upstream path, and the headline counts match the entries. Warnings
(for example, a parent technique and its sub-technique sharing one rule) do not
fail the run.

Exit codes: `0` clean, `1` index invalid, `2` technique not mapped.

## Refresh it

The index is a snapshot, not a live feed. To refresh after a Sigma or ATT&CK
release:

```sh
git clone --depth 1 https://github.com/SigmaHQ/sigma /tmp/sigma
curl -sL -o /tmp/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
python3 tools/build_detection_coverage.py \
  --sigma /tmp/sigma \
  --attack /tmp/enterprise-attack.json \
  --sigma-commit "$(git -C /tmp/sigma rev-parse HEAD)" \
  --sigma-commit-date "$(git -C /tmp/sigma log -1 --format=%cI)"
python3 detection_coverage.py --validate
python3 -B -m unittest discover -s tests -p 'test_detection_coverage.py' -v
```

CI never downloads these sources; it verifies the committed index against its
own contract, so a stale index fails loudly rather than silently drifting.

## Scope limits worth stating to a client

- ATT&CK covers adversary behaviour, not AI/agent-specific techniques. Agentic
  and LLM-specific technique ids belong to MITRE ATLAS, which is not mapped
  here.
- Sigma rules are upstream content. Sentinel stores identifiers and paths, not
  rule bodies; it does not redistribute them.
- A technique with no matching Sigma rule appears with `sigma_rule_count: 0`
  and a warning, because a local-only mapping is still useful and still not a
  detection.

## Attribution and licence

- Sigma rules: Detection Rule License (DRL) 1.1 —
  <https://github.com/SigmaHQ/Detection-Rule-License>. Upstream content remains
  the property of its authors; this repository references it by identifier.
- MITRE ATT&CK: <https://attack.mitre.org/resources/legal-documentation/>.
