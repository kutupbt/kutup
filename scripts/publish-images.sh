#!/usr/bin/env bash
# Builds the two images Kutup is made of and pushes them to a registry, so a
# server can run Kutup without building it (docker-compose.images.yml). The
# Rust build needs several GiB of memory; a small VPS cannot do it.
#
#   scripts/publish-images.sh            # build and push
#   scripts/publish-images.sh --no-push  # build only
#
# The images are tagged with the commit they were built from, and the script
# refuses a working tree with uncommitted changes, so a tag always names
# exactly one source state. Log in first: docker login ghcr.io
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
registry="${KUTUP_IMAGE_REGISTRY:-ghcr.io/kutupbt}"
push=1
for arg in "$@"; do
  case "$arg" in
    --no-push) push=0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

cd "$root_dir"
if [ -n "$(git status --porcelain)" ]; then
  echo "the working tree has uncommitted changes; commit or stash them first" >&2
  exit 1
fi
revision="$(git rev-parse HEAD)"
tag="$(git rev-parse --short=12 HEAD)"
source_url="https://github.com/kutupbt/kutup"

build() {
  local name="$1" dockerfile="$2" title="$3"
  docker build \
    --file "$dockerfile" \
    --tag "$registry/$name:$tag" \
    --label "org.opencontainers.image.source=$source_url" \
    --label "org.opencontainers.image.revision=$revision" \
    --label "org.opencontainers.image.title=$title" \
    --label "org.opencontainers.image.licenses=AGPL-3.0-only" \
    .
}

build kutup-server Dockerfile.server "Kutup server"
build kutup-web frontend/Dockerfile "Kutup web apps"

if [ "$push" = 1 ]; then
  docker push "$registry/kutup-server:$tag"
  docker push "$registry/kutup-web:$tag"
fi

echo
echo "KUTUP_SERVER_IMAGE=$registry/kutup-server:$tag"
echo "KUTUP_WEB_IMAGE=$registry/kutup-web:$tag"
