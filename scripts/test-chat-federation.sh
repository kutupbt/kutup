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

ensure_node_toolchain() {
  if command -v npm >/dev/null 2>&1; then
    return
  fi

  # Managed test runners can preserve the invoking user's HOME while omitting
  # NVM's interactive-shell PATH setup (for example when Docker needs an
  # elevated execution boundary). Load the existing NVM installation without
  # pinning a developer-specific Node version or path.
  local nvm_dir="${NVM_DIR:-$HOME/.nvm}"
  if [[ -s "$nvm_dir/nvm.sh" ]]; then
    # shellcheck source=/dev/null
    source "$nvm_dir/nvm.sh"
    nvm use --silent default >/dev/null
  fi

  if ! command -v npm >/dev/null 2>&1; then
    echo "npm is required for the federation browser gate (Node.js 20+)" >&2
    return 1
  fi
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if (( status != 0 )); then
    KUTUP_E2E_DIAGNOSTICS_DIR="${KUTUP_E2E_DIAGNOSTICS_DIR:-$root_dir/tests/e2e/sanitized-results}" \
      "$root_dir/scripts/collect-chat-e2e-diagnostics.sh" federation "$project" || true
  fi
  compose down --volumes --remove-orphans
  exit "$status"
}
trap cleanup EXIT

compose down --volumes --remove-orphans
if [[ "${KUTUP_FEDERATION_SKIP_BUILD:-0}" != "1" ]]; then
  # The browser exercises the generated Chat WASM as well as the TypeScript
  # coordinator. Reusing an older frontend image can otherwise produce a false
  # green API gate while omitting a newly advertised browser capability.
  compose build backend-a frontend
fi
compose up --detach --wait

run_phase setup

# Queue while the destination edge is unavailable. Restarting the origin before
# restoring the destination proves the outbox survives process restarts.
compose stop edge-b
run_phase queue
compose restart backend-a
compose start edge-b
compose up --detach --wait
# Compose can recreate an anonymous-volume dependency (notably Postgres on a
# cold machine) without restarting an already-running dependent backend. Reset
# both connection pools after every convergence before probing through nginx.
compose restart backend-a backend-b
# The nginx test edges resolve their upstreams when nginx starts. Compose may
# recreate a build-backed dependency such as the frontend above, so restart both
# edges only after every dependency has settled on its final container address.
compose restart edge-a edge-b
wait_url "http://127.0.0.1:$port_a/api/health"
wait_url "http://127.0.0.1:$port_b/api/health"

run_phase verify-retry

# Destination Chat-media state may contain the authenticated origin domain and
# its own local recipient, but never the remote sender account/device. Pending
# reservations must also be empty after the durable retry finishes.
media_sender_rows="$(compose exec -T postgres-b psql -U kutup -d kutup -Atc \
  "SELECT COUNT(*) FROM chat_media_objects WHERE origin_domain='a.test' AND origin_user_id IS NOT NULL")"
media_pending_rows="$(compose exec -T postgres-b psql -U kutup -d kutup -Atc \
  "SELECT COUNT(*) FROM chat_media_federation_inbound_pending")"
media_sender_columns="$(compose exec -T postgres-b psql -U kutup -d kutup -Atc \
  "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='public' AND table_name LIKE 'chat_media_federation_inbound%' AND column_name LIKE 'sender%'")"
media_plaintext_columns="$(compose exec -T postgres-b psql -U kutup -d kutup -Atc \
  "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='public' AND table_name LIKE 'chat_media%' AND (column_name LIKE '%filename%' OR column_name LIKE '%mime%' OR column_name LIKE '%conversation%' OR column_name LIKE '%certificate%' OR column_name LIKE 'sender%')")"
if [[ "$media_sender_rows" != "0" || "$media_pending_rows" != "0" || "$media_sender_columns" != "0" || "$media_plaintext_columns" != "0" ]]; then
  echo "destination Chat-media state retained sender metadata or a completed reservation" >&2
  exit 1
fi
if compose logs --no-color backend-b \
    | grep -Eq 'federation-alice@example\.test|alicefed|sender-free-federated-chat-media|chat-media-queued-across-origin-restart|senderCertificate|ciphertextSha256|retrievalToken|deliveryCapability|ampqampqampqampqampqag==|UlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlI='; then
  echo "destination Chat-media logs contain sender identity, plaintext, certificate, capability, token, or digest fields" >&2
  exit 1
fi
echo "CHAT MEDIA DESTINATION METADATA PRIVACY VERIFIED"

if [[ "${KUTUP_FEDERATION_SKIP_BROWSER:-0}" != "1" ]]; then
  ensure_node_toolchain
  # The API may be healthy while nginx is still reconnecting its separate
  # frontend upstream after the deliberate edge/backend restart above.
  wait_url "http://127.0.0.1:$port_a/register"
  wait_url "http://127.0.0.1:$port_b/register"
  (
    cd "$root_dir/tests/e2e"
    E2E_BASE_URL="http://127.0.0.1:$port_a" \
    E2E_SECONDARY_BASE_URL="http://127.0.0.1:$port_b" \
    E2E_ADMIN_EMAIL="federation-admin-a@example.test" \
    E2E_ADMIN_PASSWORD="federation-live-password" \
    E2E_BOOTSTRAP_PASSWORD="federation-admin-temp" \
    KUTUP_E2E_SAFE_ARTIFACTS="${KUTUP_E2E_SAFE_ARTIFACTS:-0}" \
    KUTUP_E2E_DIAGNOSTICS_DIR="${KUTUP_E2E_DIAGNOSTICS_DIR:-}" \
      npm exec -- playwright test \
        specs/25-tus-upload.spec.ts \
        specs/32-chat-two-server-security.spec.ts \
        specs/34-chat-backup-two-server-recovery.spec.ts --project=chromium
  )

  # The destination necessarily sees its local recipient, but anonymous MLS
  # handling must never log the remote sender or application plaintext.
  if compose logs --no-color backend-b \
      | grep -Eq 'mlsalice[0-9]+|mls-from-alice'; then
    echo "destination MLS logs contain sender identity or plaintext" >&2
    exit 1
  fi
  echo "MLS DESTINATION LOG METADATA PRIVACY VERIFIED"
fi
