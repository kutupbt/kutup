#!/usr/bin/env bash
# Checks that the migrations in this tree build exactly the schema (and seed
# rows) of an older chain of migrations: the squash's proof (docs/contributing.md,
# "Migrations"). Both run on an empty Postgres 16, then are compared by
# pg_dump (schema and data), normalized.
#
#   scripts/check-migration-baseline.sh <old-ref>             compare
#   scripts/check-migration-baseline.sh <old-ref> --generate  write the baseline
#
# <old-ref> is a git ref whose crates/kutup-server/migrations is the old chain.
# --generate writes crates/kutup-server/migrations/20261013000000_baseline.up.sql
# (and its down) from that chain, then compares.
set -euo pipefail

old_ref="${1:?usage: $0 <old-ref> [--generate]}"
generate="${2:-}"
root="$(cd "$(dirname "$0")/.." && pwd)"
migrations="$root/crates/kutup-server/migrations"
baseline="$migrations/20261013000000_baseline"
work="$(mktemp -d)"
container="kutup-baseline-$$"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

docker run -d --name "$container" -e POSTGRES_PASSWORD=x postgres:16-alpine >/dev/null
for _ in $(seq 60); do
  docker exec "$container" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done
psql() { docker exec -i "$container" psql -v ON_ERROR_STOP=1 -q -U postgres "$@"; }
dump() {
  docker exec "$container" pg_dump -U postgres --no-owner --no-privileges \
    --exclude-table=_sqlx_migrations "$@"
}

# Applies the .up.sql files in $1 to database $2, in version order, as sqlx does.
apply() {
  local dir="$1" db="$2" file
  psql -c "CREATE DATABASE $db" >/dev/null
  while IFS= read -r file; do
    psql -d "$db" < "$file" >/dev/null || { echo "failed applying $(basename "$file")" >&2; exit 1; }
  done < <(find "$dir" -maxdepth 1 -name '*.up.sql' | sort -t_ -k1,1n)
}

mkdir -p "$work/old"
git -C "$root" archive "$old_ref" crates/kutup-server/migrations | tar -x -C "$work/old"
apply "$work/old/crates/kutup-server/migrations" chain

if [[ "$generate" == "--generate" ]]; then
  mkdir -p "$migrations"
  {
    echo "-- The schema every migration up to the clean-slate release built, squashed"
    echo "-- (scripts/check-migration-baseline.sh proves it equal). Never edit:"
    echo "-- a change is a new timestamped migration (docs/contributing.md)."
    echo "--"
    echo "-- Refuses a database that already holds the old chain's tables."
    echo "DO \$\$ BEGIN"
    echo "  IF to_regclass('public.users') IS NOT NULL THEN"
    echo "    RAISE EXCEPTION 'this database predates the baseline: start from an empty one';"
    echo "  END IF;"
    echo "END \$\$;"
    echo
    dump --schema-only -d chain | grep -vE '^(SET |SELECT pg_catalog.set_config|\\(un)?restrict )'
    dump --data-only --inserts -d chain | grep -vE '^(SET |SELECT pg_catalog.set_config|\\(un)?restrict )'
  } > "$baseline.up.sql"
  cat > "$baseline.down.sql" <<'DOWN'
-- The baseline cannot be undone into the old chain: drop everything.
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
DOWN
  echo "wrote $(basename "$baseline").up.sql"
fi

apply "$migrations" squashed

# Postgres prints an expression it has parsed again in its own canonical form
# (an AND chain loses its inner parentheses), so the old chain is compared as
# its dump re-applied: the same database, canonicalized the same way.
psql -c "CREATE DATABASE chain_canonical" >/dev/null
dump -d chain | grep -vE '^\\(un)?restrict ' | psql -d chain_canonical >/dev/null

normalize() { grep -vE '^(--|SET |SELECT pg_catalog\.set_config|\\(un)?restrict |$)' | sed -E 's/[[:space:]]+$//'; }
dump --schema-only -d chain_canonical | normalize > "$work/chain.schema"
dump --schema-only -d squashed | normalize > "$work/squashed.schema"
# Seed rows stamped with now() differ only in the time.
mask_times() { sed -E "s/'[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:.]+\+00'/'<time>'/g"; }
dump --data-only --inserts -d chain_canonical | normalize | mask_times | sort > "$work/chain.data"
dump --data-only --inserts -d squashed | normalize | mask_times | sort > "$work/squashed.data"

status=0
diff -u "$work/chain.schema" "$work/squashed.schema" || status=1
diff -u "$work/chain.data" "$work/squashed.data" || status=1
if (( status == 0 )); then
  echo "the migrations in this tree build the same schema and rows as $old_ref"
fi
exit $status
