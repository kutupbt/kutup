#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="$root_dir/docker-compose.chat-federation.yml"
project="${KUTUP_FEDERATION_PROJECT:-kutup-chat-federation-dev}"
port_a="${KUTUP_FED_A_PORT:-39081}"
port_b="${KUTUP_FED_B_PORT:-39082}"

export KUTUP_FED_A_PORT="$port_a"
export KUTUP_FED_B_PORT="$port_b"

compose() {
  docker compose --project-name "$project" --file "$compose_file" "$@"
}

# The full transport contract publishes intentionally opaque profile fixtures
# that pass server validation but cannot be decrypted by the browser account.
# Persistent manual-dev volumes may retain those rows from an earlier contract
# run, so remove only the known synthetic profiles before handing the stack to
# a browser. The browser will publish its real encrypted profile on first open.
clear_synthetic_chat_profiles() {
  compose exec -T postgres-a psql -U kutup -d kutup -v ON_ERROR_STOP=1 -c \
    "DELETE FROM chat_profiles p USING users u WHERE p.user_id = u.id AND u.email = 'federation-alice@example.test' AND p.version = repeat('71', 32)"
  compose exec -T postgres-b psql -U kutup -d kutup -v ON_ERROR_STOP=1 -c \
    "DELETE FROM chat_profiles p USING users u WHERE p.user_id = u.id AND u.email = 'federation-bob@example.test' AND p.version = repeat('71', 32)"
}

if [[ "${KUTUP_FEDERATION_SKIP_BUILD:-0}" != "1" ]]; then
  compose build backend-a frontend
fi
compose up --detach --wait
# Nginx resolves Compose service names when its workers start. Recreating a
# backend can therefore leave an otherwise healthy, already-running edge
# proxy pinned to the retired container IP. The edges are stateless, so refresh
# only them after the dependency graph has reached health.
compose up --detach --wait --no-deps --force-recreate edge-a edge-b

KUTUP_FEDERATION_PHASE=browser-setup \
KUTUP_FEDERATION_SERVER_A="http://127.0.0.1:$port_a" \
KUTUP_FEDERATION_SERVER_B="http://127.0.0.1:$port_b" \
  cargo test -p kutup-server --test chat_federation_live \
    chat_federation_live -- --exact --nocapture

clear_synthetic_chat_profiles

printf '%s\n' \
  "Kutup MLS development federation is ready." \
  "Server A: http://127.0.0.1:$port_a" \
  "  email: federation-admin-a@example.test" \
  "  password: federation-live-password" \
  "  chat address: admina@a.test" \
  "Server B: http://127.0.0.1:$port_b" \
  "  email: federation-admin-b@example.test" \
  "  password: federation-live-password" \
  "  chat address: adminb@b.test" \
  "Stop with:" \
  "  docker compose --project-name $project --file $compose_file down --volumes"
