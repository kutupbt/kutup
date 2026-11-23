#!/usr/bin/env bash
# Builds the images Kutup is made of and pushes them to a registry, so a
# server can run Kutup without building it (docker-compose.images.yml, and
# docker-compose.mail-images.yml for Mail's Stalwart setup). The Rust build
# needs several GiB of memory; a small VPS cannot do it.
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
# The release version (docs/plans/api-surface.md §1.2): CalVer in semver
# shape, YYYY.MDD.N from the commit's UTC date (the month without a leading
# zero, which semver forbids), N counting the earlier commits of that day on
# the first-parent line. The server and the web apps report it, and clients
# send theirs in X-Kutup-Client.
day="$(TZ=UTC git show -s --format=%cd --date=format-local:%Y-%m-%d HEAD)"
year="${day%%-*}"; rest="${day#*-}"; month="${rest%%-*}"; dom="${rest#*-}"
same_day="$(git rev-list --count --first-parent --since="${day}T00:00:00Z" HEAD)"
release="${year}.$((10#$month))${dom}.$((same_day > 0 ? same_day - 1 : 0))"
source_url="https://github.com/kutupbt/kutup"

build() {
  local name="$1" dockerfile="$2" title="$3" context="${4:-.}"
  docker build \
    --file "$dockerfile" \
    --build-arg "KUTUP_RELEASE=$release" \
    --tag "$registry/$name:$tag" \
    --label "org.opencontainers.image.source=$source_url" \
    --label "org.opencontainers.image.revision=$revision" \
    --label "org.opencontainers.image.title=$title" \
    --label "org.opencontainers.image.licenses=AGPL-3.0-only" \
    "$context"
}

build kutup-server Dockerfile.server "Kutup server"
build kutup-web frontend/Dockerfile "Kutup web apps"
build kutup-stalwart-setup stalwart/Dockerfile "Kutup Stalwart setup" stalwart

if [ "$push" = 1 ]; then
  docker push "$registry/kutup-server:$tag"
  docker push "$registry/kutup-web:$tag"
  docker push "$registry/kutup-stalwart-setup:$tag"
fi

echo
echo "release $release"
echo "KUTUP_SERVER_IMAGE=$registry/kutup-server:$tag"
echo "KUTUP_WEB_IMAGE=$registry/kutup-web:$tag"
echo "KUTUP_STALWART_SETUP_IMAGE=$registry/kutup-stalwart-setup:$tag"
