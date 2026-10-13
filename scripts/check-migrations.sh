#!/usr/bin/env bash
# Checks the server's migrations against a base revision (default: origin/master;
# on master itself, the commit before):
#
#   - a migration present on the base is unchanged here: never edited, renamed
#     or deleted (sqlx refuses a database whose applied migrations changed);
#   - a new migration is named <UTC YYYYMMDDHHMMSS>_<name>.{up,down}.sql, has
#     both halves, and is newer than the base's newest, so it applies after
#     everything already deployed.
#
# The one exception is a squash: every base migration replaced by one
# <timestamp>_baseline pair newer than all of them, optionally followed by
# ordinary new migrations newer than the baseline (docs/contributing.md,
# "Database migrations").
#
#   scripts/check-migrations.sh [base-ref]

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
dir=crates/kutup-server/migrations

base="${1:-${KUTUP_MIGRATION_BASE:-origin/master}}"
base_commit="$(git rev-parse --verify -q "$base^{commit}")" || {
  echo "check-migrations: no base '$base' (fetch it, or pass a ref)" >&2
  exit 2
}
# On the base itself (a push to master), compare with the commit before.
if [ "$base_commit" = "$(git rev-parse HEAD)" ]; then
  base_commit="$(git rev-parse HEAD^1)"
fi

version() { basename "$1" | sed -E 's/^([0-9]+)_.*/\1/'; }

mapfile -t base_files < <(git ls-tree --name-only "$base_commit" "$dir/" | sort)
mapfile -t head_files < <(git ls-tree --name-only HEAD "$dir/" | sort)

max_base=0
for f in "${base_files[@]}"; do
  v="$(version "$f")"
  [ "$((10#$v))" -gt "$max_base" ] && max_base="$((10#$v))"
done

new=()
for f in "${head_files[@]}"; do
  printf '%s\n' "${base_files[@]}" | grep -qxF "$f" || new+=("$f")
done

# A squash: nothing of the base is left, and exactly one baseline pair is new.
# Other new files are ordinary migrations and must come after the baseline.
squash=false
baseline_up=""
mapfile -t new_baselines < <(printf '%s\n' "${new[@]}" | grep -E '_baseline\.(up|down)\.sql$' || true)
if [ "${#base_files[@]}" -gt 0 ] && [ "${#new_baselines[@]}" -eq 2 ] \
  && ! printf '%s\n' "${base_files[@]}" | grep -qxFf <(printf '%s\n' "${head_files[@]}"); then
  baseline_up="$(printf '%s\n' "${new_baselines[@]}" | grep '\.up\.sql$' || true)"
  [ -n "$baseline_up" ] && squash=true
fi

failed=0
fail() { echo "check-migrations: $*" >&2; failed=1; }

if ! $squash; then
  for f in "${base_files[@]}"; do
    if ! printf '%s\n' "${head_files[@]}" | grep -qxF "$f"; then
      fail "$f was removed or renamed; an applied migration never changes"
    elif [ "$(git rev-parse "$base_commit:$f")" != "$(git rev-parse "HEAD:$f")" ]; then
      fail "$f was edited; an applied migration never changes (add a new one)"
    fi
  done
fi

for f in "${new[@]}"; do
  name="$(basename "$f")"
  if ! [[ "$name" =~ ^[0-9]{14}_[a-z0-9_]+\.(up|down)\.sql$ ]]; then
    fail "$name: name it <UTC YYYYMMDDHHMMSS>_<name>.up.sql / .down.sql"
    continue
  fi
  v="$(version "$f")"
  [ "$((10#$v))" -gt "$max_base" ] || fail "$name is not newer than the base's newest migration ($max_base)"
  if $squash && [ "$f" != "$baseline_up" ] && [ "$f" != "${baseline_up%.up.sql}.down.sql" ]; then
    [ "$((10#$v))" -gt "$((10#$(version "$baseline_up")))" ] \
      || fail "$name is not newer than the baseline $(basename "$baseline_up")"
  fi
  case "$f" in
    *.up.sql) other="${f%.up.sql}.down.sql" ;;
    *) other="${f%.down.sql}.up.sql" ;;
  esac
  printf '%s\n' "${head_files[@]}" | grep -qxF "$other" || fail "$name has no $(basename "$other")"
done

if [ "$failed" = 0 ]; then
  if $squash; then
    echo "check-migrations: a squash of ${#base_files[@]} files into $(basename "$baseline_up"), plus $(( ${#new[@]} - 2 )) new file(s) after it"
  else
    echo "check-migrations: ${#new[@]} new file(s), base unchanged (base newest $max_base)"
  fi
fi
exit "$failed"
