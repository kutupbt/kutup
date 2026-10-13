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
# <timestamp>_baseline pair newer than all of them (docs/contributing.md,
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

# A squash: nothing of the base is left and only one baseline pair is new.
squash=false
if [ "${#base_files[@]}" -gt 0 ] && [ "${#new[@]}" -eq 2 ] \
  && printf '%s\n' "${new[@]}" | grep -qE '_baseline\.up\.sql$' \
  && ! printf '%s\n' "${base_files[@]}" | grep -qxFf <(printf '%s\n' "${head_files[@]}"); then
  squash=true
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
  case "$f" in
    *.up.sql) other="${f%.up.sql}.down.sql" ;;
    *) other="${f%.down.sql}.up.sql" ;;
  esac
  printf '%s\n' "${head_files[@]}" | grep -qxF "$other" || fail "$name has no $(basename "$other")"
done

if [ "$failed" = 0 ]; then
  if $squash; then
    echo "check-migrations: a squash of ${#base_files[@]} files into $(printf '%s\n' "${new[@]}" | grep '\.up\.sql$' | xargs basename)"
  else
    echo "check-migrations: ${#new[@]} new file(s), base unchanged (base newest $max_base)"
  fi
fi
exit "$failed"
