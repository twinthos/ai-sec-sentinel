# Sentinel Guardian Platform — implementation and operating boundaries

This additive service introduces a global incident timeline and client-specific vulnerability matching. It is separate from the existing AI-agent execution Guardian in `guardian_gate.py`; the two systems must not be conflated.

## Start

For a container deployment, copy `guardian-deployment-config.example` to `.env`, replace the API key with a random secret, then run:

```sh
docker compose --env-file .env -f docker-compose.guardian.yml up --build -d
```

Open `http://127.0.0.1:8099/console` on the host and enter the deployment API key. The console is an operator interface, not a customer login portal.

For a local Python deployment, install the additional API/report dependencies:

```sh
python -m pip install -r requirements-guardian.txt
export SENTINEL_PLATFORM_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export SENTINEL_GUARDIAN_DB=/data/guardian_platform.sqlite3
uvicorn guardian_platform:app --host 127.0.0.1 --port 8099
```

Run source ingestion separately:

```sh
python guardian_sources.py --once
python guardian_sources.py --interval 60
# Optional one-time history backfill (can take time; observe source rate limits)
python guardian_backfill.py --start 2026-01-01 --end 2026-11-05
```

Do not expose the API directly to the public internet without TLS termination, rate limiting, secret management, backups and a hardened deployment boundary. The default API binds to loopback in the example. Set a unique API key per deployment; rotate it if exposed.

## API

- `GET /console` responsive browser dashboard (deployment API key required for API calls)
- `POST /v1/clients` create client and optional security contact email
- `POST /v1/clients/{id}/scan-github` inspect an authorised GitHub repository's root manifests and supported lockfiles
- `POST /v1/clients/{id}/scan-website` passively inspect an explicitly authorised public website (HTTP/HTML/TLS/robots/sitemap) with public-IP pinning and redirect revalidation
- `GET /v1/clients/{id}/website-scans` list website inspection history
- `POST /v1/incidents/{id}/summary` create a locally generated Ollama summary
- `POST /v1/clients/{id}/components` add a component and exact version
- `PATCH /v1/clients/{id}/components/{component_id}` update inventory version/criticality; the next scan reconciles findings
- `POST /v1/incidents` ingest a normalized incident
- `GET /v1/incidents` global/filterable chronological feed
- `GET /v1/sources` source freshness and error status
- `GET /v1/incidents/timeline-density` density buckets for charting
- `POST /v1/clients/{id}/scan` match known incidents against client inventory
- `GET /v1/clients/{id}/findings` matched incidents and urgency
- `PATCH /v1/findings/{id}` remediation status, owner and due date
- `GET /v1/clients/{id}/dashboard` client overview
- `GET /v1/clients/{id}/monthly-report?month=YYYY-MM` matched incident trends and recommendations
- `GET /v1/clients/{id}/export.json|csv|pdf` reporting
- `POST /v1/clients/{id}/alerts/retry` retry failed client alert deliveries

All endpoints except `/health` require `X-API-Key`.

## Data quality and matching

A match is confirmed only when the advisory provides a valid affected-version specifier and the inventory has a parseable version within it. Missing version data is shown as potential exposure. A missing affected-version range cannot be promoted to a confirmed match. Package and ecosystem identifiers must be normalised by source adapters; name-only framework detection is not proof of exposure.

The current source adapters ingest NVD CVEs, CISA KEV, GitHub Security Advisories, and curated RSS/Atom items from CISA, the UK NCSC, The Hacker News, BleepingComputer, SecurityWeek, Krebs on Security and the Django weblog. RSS matches are news/advisory records; they only become client findings when a conservative package mapping exists, and unverified version ranges remain potential exposure. CISA KEV is exploitation evidence and elevates urgency; it does not provide a complete package/version range. The optional backfill script pages NVD in bounded date windows and GitHub advisories from 2026-01-01 (currently capped at 30 GitHub pages / 3,000 advisory records): `python guardian_backfill.py --start 2026-01-01 --end 2026-11-05`. It has not been run against live sources in this change, so the 30+ incident target is not yet verified. The GitHub inventory scanner reads public repository manifests and supported lockfiles (package.json/package-lock, requirements.txt/pyproject.toml/poetry.lock, composer.json/composer.lock, go.mod and Cargo files). Private repositories require a server-side GITHUB_TOKEN with least-privilege access. It does not clone or execute repository code, and it does not prove deployed runtime versions. The website scanner is opt-in and requires an explicit authorisation flag. It pins outbound connections to resolved public IPs, rejects private/reserved destinations and revalidates redirects. It passively inspects HTTP headers, HTML fingerprints, robots.txt, sitemap.xml and TLS certificate validity. Fingerprints are heuristic, can be hidden or spoofed, and never establish exact dependency versions unless the site exposes a trustworthy version string. WHOIS and full DNS record enrichment are not included.

## Scheduled guardians

The source runner supports an hourly loop and triggers client matching after each ingestion cycle. Failed source pulls are recorded separately; however, the current scan is not a publication-time guarantee and the runner does not yet provide per-tenant schedules, missed-run alerting, quota isolation or robust retry/backoff. Validate the one-hour target with publication-to-ingestion telemetry before making an SLA claim. The stated one-hour detection target is an SLO to validate with publication-to-ingestion telemetry, not a guarantee at this stage.

## Security and privacy boundaries

- Client API key is a single deployment-level shared credential in this first slice, not full multi-tenant identity. Use behind a trusted gateway until per-client principals, key rotation and role-based access are implemented.
- The browser console keeps the deployment API key in memory only (not localStorage). Do not use the console on an untrusted or shared device.
- Email alerts require SENTINEL_SMTP_HOST, SENTINEL_SMTP_FROM, SENTINEL_SMTP_PORT and optional SENTINEL_SMTP_USER / SENTINEL_SMTP_PASSWORD. The client's contact_email is stored in SQLite; protect database files and backups.
- Slack operations alerts require SENTINEL_SLACK_WEBHOOK_URL to be a Slack incoming webhook. This is one configured operations destination, not per-customer Slack routing. Failed deliveries can be retried via the client API.
- Ollama summaries require a local Ollama service and OLLAMA_MODEL (default qwen2.5:3b). For Compose, OLLAMA_HOST defaults to host.docker.internal:11434 via the host-gateway mapping; the API only permits loopback or that explicit local gateway host. Generated text is labelled and original advisory fields remain authoritative.
- No automated remediation or package changes are performed.
- No active port scanning, exploit testing, credential collection or intrusive website probing is included.
- Website fingerprinting is heuristic and can be hidden or spoofed. WHOIS, full DNS/CT enrichment and active service discovery are not included; keep the explicit authorisation gate and public-IP/redirect checks enabled.
- PDF is a basic findings report, not a compliance certificate.
- Per-customer Slack destinations, role-based client login and fully isolated tenant credentials are not implemented. The monthly report API provides matched-incident counts, severity breakdown, month-on-month change and recommendations; it is not an independently assured compliance report. The console is an operator console authenticated with the deployment key, not a customer self-service portal.
- Keep original advisories as source of truth; AI summaries must be labelled generated and never alter severity, affected ranges or fix versions.
