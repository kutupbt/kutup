#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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

wait_server() {
  local url="$1"
  local deadline=$((SECONDS + 60))
  until curl --fail --silent --show-error "$url/api/health" >/dev/null; do
    if (( SECONDS >= deadline )); then
      echo "timed out waiting for $url/api/health" >&2
      return 1
    fi
    sleep 1
  done
}

cleanup() {
  compose down --volumes --remove-orphans
}
trap cleanup EXIT

cleanup
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
wait_server "http://127.0.0.1:$port_a"
wait_server "http://127.0.0.1:$port_b"

run_phase verify-retry
