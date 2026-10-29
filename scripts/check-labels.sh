#!/usr/bin/env bash
# Every label Kutup derives keys, hashes, signatures or associated data with
# lives in crates/kutup-crypto/src/labels.rs (docs/plans/w6-key-hierarchy.md
# §3). This refuses any string or byte-string literal starting `kutup/` or
# `kutup-` (`"…`, `b"…`, `br"…`, `br#"…`) outside a comment in a crate's
# source, unless scripts/check-labels.allow names that file and literal as
# a non-label (a header, path, name or test fixture). An allow-list entry
# that no longer matches anything fails too, so the list stays exact.
set -euo pipefail
cd "$(dirname "$0")/.."

allow=scripts/check-labels.allow
hits="$(
  git ls-files -- 'crates/*/src/*.rs' 'crates/*/src/**/*.rs' \
    | grep -v '^crates/kutup-crypto/src/labels\.rs$' \
    | xargs -r awk '
        /^[[:space:]]*\/\// { next }
        {
          rest = $0
          while (match(rest, /(br?#?)?"kutup[\/-][a-z0-9\/:.=_-]*/)) {
            print FILENAME "\t" substr(rest, RSTART, RLENGTH) "\t" FNR
            rest = substr(rest, RSTART + RLENGTH)
          }
        }
      '
)"

failed=0
# A literal the allow-list doesn't name.
while IFS=$'\t' read -r path literal line; do
  [ -n "$path" ] || continue
  if ! awk -F'\t' -v p="$path" -v l="$literal" \
      '!/^#/ && $1 == p && $2 == l { found = 1 } END { exit !found }' "$allow"; then
    echo "$path:$line: $literal" >&2
    failed=1
  fi
done <<<"$hits"
if [ "$failed" -ne 0 ]; then
  echo "check-labels: put these labels in crates/kutup-crypto/src/labels.rs" \
    "(or, if one is not a label, in $allow)" >&2
fi

# An allow-list entry nothing matches any more.
while IFS=$'\t' read -r path literal _; do
  case "$path" in '' | '#'*) continue ;; esac
  if ! awk -F'\t' -v p="$path" -v l="$literal" \
      '$1 == p && $2 == l { found = 1 } END { exit !found }' <<<"$hits"; then
    echo "check-labels: $allow names $path $literal, which is no longer there" >&2
    failed=1
  fi
done <"$allow"

# Labels the browser computes in TypeScript: every `kutup/` literal in a
# frontend source must be a registry label, NUL included.
registry="$(grep -o 'b"kutup/[^"]*' crates/kutup-crypto/src/labels.rs | sed 's/^b"//')"
while IFS=: read -r path line literal; do
  [ -n "$path" ] || continue
  label="${literal:1}"
  if ! grep -qxF -- "$label" <<<"$registry"; then
    echo "$path:$line: $literal (not a registry label, or no \\0)" >&2
    failed=1
  fi
done < <(
  git ls-files -- 'frontend/packages/*/src/**' 'frontend/apps/*/src/**' \
    | grep -E '\.(ts|tsx)$' \
    | grep -vE '\.test\.tsx?$' \
    | xargs -r grep -noE "['\"\`]kutup/[a-z0-9/-]*(\\\\0)?" || true
)

[ "$failed" -eq 0 ] || exit 1
echo "check-labels: every label is in the registry"
