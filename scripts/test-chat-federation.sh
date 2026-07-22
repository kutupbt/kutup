#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Historical filename retained for developer muscle memory; the suite now
# exercises the shared v2 stack through both Drive and Chat.
compose_file="$root_dir/docker-compose.chat-federation.yml"
project="${KUTUP_FEDERATION_PROJECT:-kutup-chat-federation-test}"
port_a="${KUTUP_FED_A_PORT:-39081}"
port_b="${KUTUP_FED_B_PORT:-39082}"

compose() {
  docker compose --project-name "$project" --file "$compose_file" "$@"
}

run_phase() {
  KUTUP_FEDERATION_PHASE="$1" \
  KUTUP_FEDERATION_SERVER_A="http://127.0.0.1:$port_a" \
  KUTUP_FEDERATION_SERVER_B="http://127.0.0.1:$port_b" \
    cargo test -p kutup-server --test chat_federation_live \
      chat_federation_live -- --exact --nocapture
}

wait_url() {
  local url="$1"
  local deadline=$((SECONDS + 60))
  until curl --fail --silent --show-error "$url" >/dev/null; do
    if (( SECONDS >= deadline )); then
      echo "timed out waiting for $url" >&2
      return 1
    fi
    sleep 1
  done
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if (( status != 0 )); then
    compose ps >&2
    compose logs --no-color frontend edge-a edge-b >&2
  fi
  compose down --volumes --remove-orphans
  exit "$status"
}
trap cleanup EXIT

compose down --volumes --remove-orphans
if [[ "${KUTUP_FEDERATION_SKIP_BUILD:-0}" != "1" ]]; then
  compose build backend-a
fi
compose up --detach --wait

run_phase setup

# Queue while the destination edge is unavailable. Restarting the origin before
# restoring the destination proves the outbox survives process restarts.
compose stop edge-b
run_phase queue
compose restart backend-a
# The nginx test edge resolves its upstream when nginx starts. Refresh it after
# the origin process restart so this test exercises the restarted backend rather
# than a stale disposable proxy connection.
compose restart edge-a
compose start edge-b
compose up --detach --wait
wait_url "http://127.0.0.1:$port_a/api/health"
wait_url "http://127.0.0.1:$port_b/api/health"

run_phase verify-retry

if [[ "${KUTUP_FEDERATION_SKIP_BROWSER:-0}" != "1" ]]; then
  # The API may be healthy while nginx is still reconnecting its separate
  # frontend upstream after the deliberate edge/backend restart above.
  wait_url "http://127.0.0.1:$port_a/register"
  wait_url "http://127.0.0.1:$port_b/register"
  (
    cd "$root_dir/tests/e2e"
    E2E_BASE_URL="http://127.0.0.1:$port_a" \
    E2E_SECONDARY_BASE_URL="http://127.0.0.1:$port_b" \
      npm exec -- playwright test \
        specs/32-chat-two-server-security.spec.ts --project=chromium
  )
fi
