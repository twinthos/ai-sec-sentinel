# Live monitoring

Start with the offline [quickstart](../README.md#reproducible-demonstration--run-it-in-one-command). Live monitoring is a separate workflow that contacts public services and, when configured, sends notifications.

## Preview

Activate the virtual environment from the README, then run:

```sh
python ai_sec_sentinel.py --dry-run --since-hours 24
```

This fetches public feeds but does not send alerts or update deduplication state. It needs access to `cve.now`, `www.cisa.gov` and `api.first.org`. Optional OSV checks need `api.osv.dev`; optional RSS sources need their configured domains. A source failure is not a clean scan. News scanning is disabled in the sample configuration.

## Configure delivery

Use environment variables supplied through your secret manager or environment settings:

| Channel | Required variables |
| --- | --- |
| Telegram | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` |
| Slack or Discord webhook | `SENTINEL_WEBHOOK_URL`, `SENTINEL_WEBHOOK_PLATFORM` (`slack` or `discord`) |

Do not commit credentials. Destination providers receive message content. A webhook is restricted to the supported provider hosts, and outbound POST redirects are disabled.

When you intend to send a real test message to the configured destination:

```sh
python ai_sec_sentinel.py --test-alert
```

Require an acknowledged result before relying on delivery. Then run one scan or continuous monitoring:

```sh
python ai_sec_sentinel.py --since-hours 24
python ai_sec_sentinel.py --daemon --interval 60
```

Monitor nonzero exits and `python ai_sec_sentinel.py --health`. An empty state directory is expected to return unhealthy (exit 2). A running process alone does not prove successful scans or delivery.

## Storage and deployment

`SENTINEL_DATA_DIR` selects the runtime directory; the default is `~/.local/share/twinthos-sentinel`. Scanner, news and dashboard use that location. Keep it outside the source tree with access restricted to the service user. If upgrading from a checkout-local state directory, transfer only the state you intend to retain; existing data is not automatically moved or deleted.

The supplied Docker Compose service runs the scanner with persistent storage under `/data`. Configure a destination before `docker compose up --build -d`. Guardian Gate and Dashboard are separate, authenticated, loopback-bound services; they are not started by the quickstart.

## Coverage and privacy limits

AI relevance filtering is heuristic. Supported pinned dependency checks do not provide comprehensive SCA or SBOM assurance. OSV queries send names and versions even when raw upload is disabled. Raw upload to cve.now requires `allow_lockfile_upload=true` and sends file contents; do not enable it for confidential lockfiles. Notifications and remote API metadata have their own privacy implications. See the [README data-flow summary](STATE-AND-PRIVACY.md).
