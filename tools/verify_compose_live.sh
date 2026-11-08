#!/usr/bin/env bash
# Interactive operator acceptance gate for the *actual* Compose deployment.
# Never run as part of CI: a real test alert is sent to configured destinations.
set -euo pipefail

if [[ "${SENTINEL_ACCEPT_TEST_ALERT:-}" != "yes" ]]; then
  echo "REFUSED: set SENTINEL_ACCEPT_TEST_ALERT=yes to authorise a real test message." >&2
  exit 2
fi

command -v docker >/dev/null 2>&1 || { echo "ERROR: Docker CLI is required." >&2; exit 2; }
docker compose config -q
container_id="$(docker compose ps -q sentinel)"
if [[ -z "$container_id" ]]; then
  echo "FAIL: Compose sentinel container was not found." >&2
  exit 2
fi

state="$(docker inspect -f '{{.State.Status}}' "$container_id")"
health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$container_id")"
printf 'Compose sentinel: container=%s health=%s\n' "$state" "$health"
if [[ "$state" != "running" || "$health" != "healthy" ]]; then
  echo "FAIL: running container and healthy scanner state are required." >&2
  exit 2
fi

echo "Sending a synthetic test alert to every configured channel (not a vulnerability)."
docker compose exec -T sentinel python3 /app/ai_sec_sentinel.py --test-alert
docker compose exec -T sentinel python3 /app/ai_sec_sentinel.py --health

if [[ ! -t 0 ]]; then
  echo "UNVERIFIED: recipient receipt requires interactive human confirmation." >&2
  exit 2
fi
read -r -p "Verify that the test alert arrived in EACH destination. Type RECEIVED to confirm: " confirmed
if [[ "$confirmed" != "RECEIVED" ]]; then
  echo "UNVERIFIED: delivery receipt was not confirmed." >&2
  exit 2
fi
echo "PASS: Compose container health, recent successful scan, provider acknowledgement, and operator-confirmed receipt."
echo "This validates this deployment at this moment, not continuous future delivery or complete threat coverage."
