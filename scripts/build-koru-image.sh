#!/usr/bin/env bash
# Builds Koru's edge image (docker-compose.koru.yml) from a checkout of
# Koru's sources, on this machine: nothing is pulled from or pushed to a
# registry. scripts/deploy.sh copies the image to the server itself
# (docs/self-hosting.md, "Koru edge (optional)").
#
#   scripts/build-koru-image.sh            build, or reuse, kutup-koru:<commit>
#   scripts/build-koru-image.sh --dry-run  only say which: builds nothing
#
# Settings (environment):
#   KORU_SRC            the Koru checkout (default ../../koru-ref from here);
#                       refused when it has uncommitted changes
#   KUTUP_KORU_COMMIT   the Koru commit to build (default: the checkout's HEAD)
#
# The image is built from that commit's files (git archive), not from the
# working tree, and labelled with it; an image already carrying the label
# is reused. The last line printed is `<image> <image id> <commit>`, with
# `-` for the id when --dry-run finds no such image.

set -euo pipefail

dry=false
case "${1:-}" in
  --dry-run) dry=true ;;
  '') ;;
  *) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="${KORU_SRC:-$root/../../koru-ref}"
[ -d "$src" ] || { echo "build-koru-image: no Koru checkout at $src (KORU_SRC)" >&2; exit 2; }
git -C "$src" rev-parse --git-dir >/dev/null 2>&1 || { echo "build-koru-image: $src is not a git checkout" >&2; exit 2; }
if [ -n "$(git -C "$src" status --porcelain)" ]; then
  echo "build-koru-image: $src has uncommitted changes; commit or discard them first" >&2
  exit 1
fi
commit="$(git -C "$src" rev-parse --verify -q "${KUTUP_KORU_COMMIT:-HEAD}^{commit}")" \
  || { echo "build-koru-image: ${KUTUP_KORU_COMMIT:-HEAD} is not a commit in $src" >&2; exit 1; }
image="kutup-koru:${commit:0:12}"

label() {
  docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image" 2>/dev/null || true
}
if [ "$(label)" != "$commit" ] && $dry; then
  echo "$image - $commit"
  exit 0
fi
if [ "$(label)" != "$commit" ]; then
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  git -C "$src" archive "$commit" | tar -x -C "$work"
  docker build -q --build-context koru="$work" \
    --label "org.opencontainers.image.revision=$commit" \
    -t "$image" "$root/koru" >/dev/null
  [ "$(label)" = "$commit" ] || { echo "build-koru-image: the build did not produce $image" >&2; exit 1; }
fi
echo "$image $(docker image inspect -f '{{.Id}}' "$image") $commit"
