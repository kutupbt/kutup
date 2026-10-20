#!/usr/bin/env bash
# One load-test run (docs/research/21-load-test.md): the stack pinned to
# KUTUP_LOAD_STACK_CPUS, the generator on KUTUP_LOAD_GEN_CPUS, and every
# container's CPU and memory plus Postgres's connections sampled while it
# runs. Results go to $KUTUP_LOAD_RESULTS/<label>/.
#
#   tests/load/run.sh <label> [kutup-loadtest arguments…]
#
# Needs the stack's secrets in the environment (POSTGRES_PASSWORD,
# JWT_SECRET, OPAQUE_SETUP_KEYS, KUTUP_E2E_DATA_DIR) and nginx/certs. Never
# runs against anything but this local stack.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
label="${1:?usage: tests/load/run.sh <label> [generator arguments]}"
shift
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-kutup-load}"
export COMPOSE_FILE="$root_dir/docker-compose.yml:$root_dir/tests/e2e/docker-compose.isolated.yml:$root_dir/tests/load/docker-compose.load.yml"
gen_cpus="${KUTUP_LOAD_GEN_CPUS:-2-5}"
results="${KUTUP_LOAD_RESULTS:?set KUTUP_LOAD_RESULTS to a directory for results}/$label"
mkdir -p "$results"

compose() { docker compose "$@"; }

echo "stack cpus ${KUTUP_LOAD_STACK_CPUS:-0,1}, store cpus ${KUTUP_LOAD_STORE_CPUS:-6,7}, generator cpus $gen_cpus" | tee "$results/setup.txt"
compose up -d --wait backend postgres
backend_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(compose ps -q backend)")"
server="http://$backend_ip:3000"
until curl -fsS "$server/api/auth/settings" >/dev/null; do sleep 1; done

# Samplers: docker stats every 5 s, Postgres every 5 s.
(
  while true; do
    docker stats --no-stream --format '{{.Name}},{{.CPUPerc}},{{.MemUsage}}' \
      | sed "s/^/$(date +%s),/"
    sleep 5
  done
) > "$results/containers.csv" 2>/dev/null &
stats_pid=$!
(
  while true; do
    compose exec -T postgres psql -U "${POSTGRES_USER:-kutup}" -d "${POSTGRES_DB:-kutup}" -Atc \
      "SELECT extract(epoch FROM now())::bigint, count(*), count(*) FILTER (WHERE state = 'active'),
              (SELECT xact_commit FROM pg_stat_database WHERE datname = current_database()),
              (SELECT coalesce(max(extract(epoch FROM now() - query_start)), 0) FROM pg_stat_activity WHERE state = 'active')
         FROM pg_stat_activity WHERE datname = current_database()" 2>/dev/null || true
    sleep 5
  done
) > "$results/postgres.csv" &
pg_pid=$!
# The generator itself, so a run can show it was never the bottleneck:
# its CPU (percent of one core) and memory.
(
  while true; do
    ps -C kutup-loadtest -o %cpu=,rss= | awk -v t="$(date +%s)" '{print t","$1","$2}'
    sleep 5
  done
) > "$results/generator.csv" &
gen_pid=$!
trap 'kill "$stats_pid" "$pg_pid" "$gen_pid" 2>/dev/null || true' EXIT

status=0
taskset -c "$gen_cpus" "$root_dir/crates/kutup-loadtest/target/release/kutup-loadtest" \
  --server "$server" --out "$results/report.json" "$@" 2> "$results/progress.log" \
  | tee "$results/report.txt" || status=$?
compose logs --no-color backend 2>&1 | grep -ciE 'error|panic' > "$results/backend-errors.count" || true
du -sh "${KUTUP_E2E_DATA_DIR:?}" > "$results/store-size.txt" 2>/dev/null || true
exit "$status"
