#!/usr/bin/env bash
# Every label Kutup derives keys, hashes, signatures or associated data with
# lives in crates/kutup-crypto/src/labels.rs (docs/plans/w6-key-hierarchy.md
# §3). This refuses one written anywhere else in a crate's source: a byte
# string starting with `kutup/` or `kutup-`, or a versioned `"kutup/…/vN`
# string outside a comment. Tests may spell labels out (they pin bytes).
set -euo pipefail
cd "$(dirname "$0")/.."

found=0
while IFS= read -r line; do
  echo "$line" >&2
  found=1
done < <(
  git ls-files -- 'crates/*/src/*.rs' 'crates/*/src/**/*.rs' \
    | grep -v '^crates/kutup-crypto/src/labels\.rs$' \
    | grep -v '/tests\.rs$' \
    | xargs -r awk '
        /^[[:space:]]*\/\// { next }
        /b"kutup[\/-]/ { print FILENAME ":" FNR ": " $0; next }
        /"kutup\/[a-z0-9\/-]*v[0-9]/ { print FILENAME ":" FNR ": " $0 }
      '
)
if [ "$found" -ne 0 ]; then
  echo "check-labels: put these labels in crates/kutup-crypto/src/labels.rs" >&2
  exit 1
fi
echo "check-labels: every label is in the registry"
