#!/usr/bin/env bash
# What the restore drill can't check (docs/plans/wipe-final-test.md §6.2): a
# server restored from a dump holds its deliveries while OUTBOUND_DELIVERY is
# off, and sends them, under the same federation identity, once it is on.
# The drill restores production's backup with delivery off for good; this
# runs the same restore on the two-server harness (docker-compose.chat-
# federation.yml), where nothing is production:
#
#   1. both servers up; accounts on both (the federation gate's setup phase);
#   2. B's edge down; A queues sends to B (the queue phase);
#   3. A's database dumped (pg_dump -Fc), A stopped, its database dropped
#      and restored from the dump;
#   4. A started with OUTBOUND_DELIVERY=false, B's edge back: for a while,
#      A's queued rows stay queued and their attempts don't move, and B sees
#      no request from A;
#   5. A restarted with delivery on: the queued sends arrive and B accepts A
#      (the verify-retry phase), and A's federation discovery document names
#      the same signing key as before the restore.
#
# It takes the lane's federation project and ports (KUTUP_FEDERATION_PROJECT,
# KUTUP_FED_A_PORT, KUTUP_FED_B_PORT), so it can't run beside
# `scripts/gate.sh live federation` in the same lane. Needs docker (with
# Compose), cargo, curl and jq.
#
#   scripts/restore-federation-check.sh            run it
#   KUTUP_FEDERATION_SKIP_BUILD=1 …                 reuse the lane's images
#   KUTUP_RESTORE_HOLD_SECONDS=60 …                 how long step 4 watches (default 45)
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="$root_dir/docker-compose.chat-federation.yml"
project="${KUTUP_FEDERATION_PROJECT:-kutup-chat-federation-test}"
port_a="${KUTUP_FED_A_PORT:-39081}"
port_b="${KUTUP_FED_B_PORT:-39082}"
hold_seconds="${KUTUP_RESTORE_HOLD_SECONDS:-45}"

work="$(mktemp -d)"
state_file="$work/state"
dump="$work/a.dump"
# Delivery off for backend-a only: an override on top of the harness.
override="$work/outbound-off.yml"
cat >"$override" <<'YAML'
services:
  backend-a:
    environment:
      OUTBOUND_DELIVERY: "false"
YAML

compose() {
  docker compose --project-name "$project" --file "$compose_file" "$@"
}

psql_a() {
  compose exec -T postgres-a psql -U kutup -d "${2:-kutup}" -v ON_ERROR_STOP=1 -Atc "$1"
}

psql_b() {
  compose exec -T postgres-b psql -U kutup -d kutup -v ON_ERROR_STOP=1 -Atc "$1"
}

fed_db() {
  local ip
  ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$(compose ps -q "postgres-$1")")"
  printf 'postgres://kutup:federation_test_%s@%s:5432/kutup' "$1" "$ip"
}

run_phase() {
  KUTUP_FEDERATION_DB_A="$(fed_db a)" \
  KUTUP_FEDERATION_DB_B="$(fed_db b)" \
  KUTUP_FEDERATION_STATE="$state_file" \
  KUTUP_FEDERATION_PHASE="$1" \
  KUTUP_FEDERATION_SERVER_A="http://127.0.0.1:$port_a" \
  KUTUP_FEDERATION_SERVER_B="http://127.0.0.1:$port_b" \
    cargo test -p kutup-server --test chat_federation_live \
      chat_federation_live -- --exact --nocapture
}

wait_url() {
  local url="$1" deadline=$((SECONDS + 90))
  until curl --fail --silent --show-error "$url" >/dev/null; do
    if (( SECONDS >= deadline )); then
      echo "timed out waiting for $url" >&2
      return 1
    fi
    sleep 1
  done
}

# A's federation identity as its discovery document names it.
discovery_key() {
  curl --fail --silent --show-error \
    "http://127.0.0.1:$port_a/.well-known/kutup/federation.json" | jq -cS '.identity.key'
}

# The rows A still has to deliver, with their attempts: what must not move
# while delivery is off.
pending_a() {
  psql_a "SELECT id, attempts FROM federation_outbox WHERE state <> 'delivered' ORDER BY id"
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if (( status != 0 )); then
    echo "--- backend logs (last 200 lines each) ---"
    compose logs --no-color --timestamps --tail 200 backend-a backend-b
  fi
  compose --file "$override" down --volumes --remove-orphans >/dev/null 2>&1
  compose down --volumes --remove-orphans
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }

step "1. Both servers, accounts on both"
compose down --volumes --remove-orphans
if [[ "${KUTUP_FEDERATION_SKIP_BUILD:-0}" != "1" ]]; then
  compose build backend-a frontend-a
fi
compose up --detach --wait
wait_url "http://127.0.0.1:$port_a/api/health"
wait_url "http://127.0.0.1:$port_b/api/health"
run_phase setup
key_before="$(discovery_key)"
[[ -n "$key_before" && "$key_before" != "null" ]] || { echo "A's discovery names no identity key" >&2; exit 1; }

step "2. B unreachable; A queues sends to B"
compose stop edge-b
run_phase queue
queued="$(pending_a)"
[[ -n "$queued" ]] || { echo "A queued nothing for B" >&2; exit 1; }
echo "A holds $(wc -l <<<"$queued") undelivered row(s)"

step "3. A's database: dump, drop, restore"
compose exec -T postgres-a pg_dump -U kutup -d kutup -Fc >"$dump"
[[ -s "$dump" ]] || { echo "the dump is empty" >&2; exit 1; }
compose stop backend-a
psql_a "DROP DATABASE kutup WITH (FORCE)" postgres
psql_a "CREATE DATABASE kutup OWNER kutup" postgres
compose exec -T postgres-a pg_restore -U kutup -d kutup --no-owner --exit-on-error <"$dump"
[[ "$(pending_a)" == "$queued" ]] || { echo "the restored outbox differs from the dumped one" >&2; exit 1; }

step "4. A restored with delivery off: nothing leaves"
compose start edge-b
compose --file "$override" up --detach --wait backend-a
# The edges resolve their upstreams when nginx starts.
compose restart edge-a edge-b
wait_url "http://127.0.0.1:$port_a/api/health"
wait_url "http://127.0.0.1:$port_b/api/health"
[[ "$(discovery_key)" == "$key_before" ]] || { echo "A's federation identity changed in the restore" >&2; exit 1; }
# Every signed request B takes is recorded against replays.
b_inbound_before="$(psql_b "SELECT COUNT(*) FROM federation_request_replays")"
sleep "$hold_seconds"
held="$(pending_a)"
if [[ "$held" != "$queued" ]]; then
  echo "with OUTBOUND_DELIVERY=false, A's outbox moved:" >&2
  diff <(echo "$queued") <(echo "$held") >&2 || true
  exit 1
fi
b_inbound_after="$(psql_b "SELECT COUNT(*) FROM federation_request_replays")"
[[ "$b_inbound_after" == "$b_inbound_before" ]] || { echo "B received $((b_inbound_after - b_inbound_before)) request(s) from a server with delivery off" >&2; exit 1; }
echo "held for ${hold_seconds}s: $(wc -l <<<"$held") row(s), attempts unchanged; B received nothing"

step "5. Delivery on: the queued sends arrive, B accepts A"
compose up --detach --wait --force-recreate backend-a
compose restart edge-a edge-b
wait_url "http://127.0.0.1:$port_a/api/health"
run_phase verify-retry
[[ "$(discovery_key)" == "$key_before" ]] || { echo "A's federation identity changed after delivery came back" >&2; exit 1; }

step "A restored server held its deliveries, then sent them under the same identity"
