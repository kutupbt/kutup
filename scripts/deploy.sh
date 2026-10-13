#!/usr/bin/env bash
# Deploy a published release to a Kutup server that runs from images
# (docker-compose.images.yml; docs/self-hosting.md), the same steps every time.
#
#   scripts/deploy.sh <tag>            update to images <tag> (a 12-character commit)
#   scripts/deploy.sh <tag> --wipe     the same, after deleting every account and its
#                                      data (a clean-slate release; asks to confirm)
#   scripts/deploy.sh <tag> --dry-run  steps 1 to 3: checks CI, pulls the images, lists a
#                                      wipe's deletions with --wipe --dry-run; changes nothing
#
# A rollback is a deploy of the previous tag: its images stay on the server,
# and .env pins every image by digest, recorded per deploy in deploy-history/.
#
# Settings (environment):
#   KUTUP_DEPLOY_HOST   ssh destination, e.g. root@kutup.example   (required)
#   KUTUP_DEPLOY_KEY    ssh identity file                          (optional)
#   KUTUP_DEPLOY_DIR    the server's checkout                      (default /opt/kutup)
#   KUTUP_DEPLOY_HOSTS  app hostnames to check, space-separated    (default: the ten apps
#                       under the server's KUTUP_BASE_DOMAIN)
#
# What it does, in order, and it stops at the first failure:
#   1. refuses unless GitHub CI passed for the tag's commit on master;
#   2. pulls the three images on the server and records their digests and the
#      running ones (deploy-history/), so a rollback is exact;
#   3. with --wipe: lists what the bucket wipe would delete (aws-cli --dryrun)
#      and refuses if a backup is among it;
#   4. checks out the commit and validates its nginx config, and runs the new
#      server's check-config against .env (also in --dry-run);
#   5. backs up the database and Mail's Stalwart data (the systemd backup units);
#   6. with --wipe only: stops the stack, drops the database volume and empties
#      the bucket except the backup prefixes; Stalwart's volume (DKIM keys) stays;
#   7. sets the images in .env, pinned by digest (kept as .env.bak-<old tag>),
#      starts the stack and restarts nginx;
#   8. checks: migrations, backend errors, Stalwart's setup, storage, every host;
#   9. removes Kutup images other than the new and the previous release.

set -euo pipefail

tag="${1:-}"
wipe=false dry=false
shift || true
for arg in "$@"; do
  case "$arg" in
    --wipe) wipe=true ;;
    --dry-run) dry=true ;;
    *) tag="" ;;
  esac
done
if ! [[ "$tag" =~ ^[0-9a-f]{12}$ ]]; then
  sed -n '2,/^# Settings/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'
  exit 2
fi
host="${KUTUP_DEPLOY_HOST:?set KUTUP_DEPLOY_HOST (ssh destination)}"
dir="${KUTUP_DEPLOY_DIR:-/opt/kutup}"
ssh_opts=(-o BatchMode=yes)
[ -n "${KUTUP_DEPLOY_KEY:-}" ] && ssh_opts+=(-i "$KUTUP_DEPLOY_KEY")

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
git fetch -q origin master
sha="$(git rev-parse --verify -q "$tag^{commit}")" || { echo "deploy: $tag is not a commit here" >&2; exit 1; }
git merge-base --is-ancestor "$sha" origin/master || { echo "deploy: $tag is not on master" >&2; exit 1; }
# Only a server that knows the subcommand may be asked: an older one ignores
# the word and starts a full second backend on the live database.
has_check_config=false
git grep -q '"check-config"' "$sha" -- crates/kutup-server/src && has_check_config=true

echo "== CI for $sha"
ci="$(gh run list --commit "$sha" --workflow CI --branch master --json status,conclusion \
  -q 'map(select(.status=="completed")) | first | .conclusion // "none"')"
if [ "$ci" != "success" ]; then
  echo "deploy: CI on master for $tag is '$ci', not success" >&2
  exit 1
fi

if $wipe && ! $dry; then
  git ls-tree -r --name-only "$sha" crates/kutup-server/migrations | grep -q '_baseline\.up\.sql$' \
    || { echo "deploy: --wipe needs a release with the squashed baseline migration" >&2; exit 1; }
  echo
  echo "--wipe deletes EVERY account, file, chat and mail on $host, keeping only the backups"
  echo "and Stalwart's keys. Type the host name to go on:"
  read -r answer
  [ "$answer" = "${host#*@}" ] || { echo "deploy: not confirmed" >&2; exit 1; }
fi

ssh "${ssh_opts[@]}" "$host" bash -s -- "$dir" "$tag" "$sha" "$wipe" "$dry" "$has_check_config" "${KUTUP_DEPLOY_HOSTS:-}" <<'REMOTE'
set -euo pipefail
dir="$1" tag="$2" sha="$3" wipe="$4" dry="$5" has_check_config="$6" hosts="${7:-}"
cd "$dir"
# One value from .env, read literally (.env is a Compose file, not shell).
env_get() {
  { grep -E "^$1=" .env || true; } | tail -1 | cut -d= -f2- \
    | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}
images="kutup-server kutup-web kutup-stalwart-setup"
registry="$(env_get KUTUP_SERVER_IMAGE | sed -E 's#/kutup-server[:@].*##')"
# The running tag; .env names images as <repo>:<tag>@sha256:<digest>.
old="$(env_get KUTUP_SERVER_IMAGE | sed -nE 's/.*:([0-9a-f]{12})(@sha256:[0-9a-f]+)?$/\1/p')"
echo "== $old -> $tag on $(hostname)"

echo "== images and digests"
mkdir -p deploy-history
record="deploy-history/$(date -u +%Y%m%dT%H%M%SZ)-$tag.txt"
for i in $images; do
  docker pull -q "$registry/$i:$tag" >/dev/null
  echo "new $i $(docker image inspect -f '{{index .RepoDigests 0}}' "$registry/$i:$tag")" >> "$record"
  [ -n "$old" ] && echo "old $i $(docker image inspect -f '{{index .RepoDigests 0}}' "$registry/$i:$old" 2>/dev/null || echo unknown)" >> "$record"
done
cat "$record"

echo "== commit $sha"
git fetch -q origin
git cat-file -e "$sha^{commit}"

# The two backup prefixes, as the backup scripts read them (raw). A value the
# wipe's exclude could misread is refused rather than risked.
prefix_setting() {
  local value
  value="$({ grep -E "^$1=" .env || true; } | tail -1 | cut -d= -f2-)"
  value="${value:-$2}"
  case "$value" in
    *\"*|*\'*|/*|*/|*' '*|'')
      echo "deploy: $1='$value' is not a plain prefix; refusing the wipe" >&2; return 1 ;;
  esac
  printf '%s' "$value"
}

# The bucket wipe, run as aws-cli 'rm --dryrun' first: it lists what would go,
# and nothing under a backup prefix may be among it.
s3_rm() {
  docker run --rm -e AWS_ACCESS_KEY_ID="$(env_get S3_ACCESS_KEY)" \
    -e AWS_SECRET_ACCESS_KEY="$(env_get S3_SECRET_KEY)" \
    -e AWS_DEFAULT_REGION="$(env_get S3_REGION)" amazon/aws-cli:2.37.9 \
    --endpoint-url "$(env_get S3_ENDPOINT)" s3 rm "s3://$bucket/" --recursive \
    --exclude "$db_prefix/*" --exclude "$mail_prefix/*" "$@"
}
if [ "$wipe" = true ]; then
  db_prefix="$(prefix_setting KUTUP_BACKUP_PREFIX database-backups)"
  mail_prefix="$(prefix_setting KUTUP_MAIL_BACKUP_PREFIX mail-backups)"
  bucket="$(env_get S3_BUCKET)"
  [ -n "$bucket" ] || { echo "deploy: S3_BUCKET is empty" >&2; exit 1; }
  echo "== wipe plan: bucket $bucket, keeping $db_prefix/ and $mail_prefix/"
  listing="$(s3_rm --dryrun)"
  would="$(printf '%s\n' "$listing" | grep -c '^(dryrun) delete:' || true)"
  if printf '%s\n' "$listing" | grep -qE "^\(dryrun\) delete: s3://$bucket/($db_prefix|$mail_prefix)/"; then
    echo "deploy: the wipe would delete a backup; refusing" >&2
    exit 1
  fi
  echo "   objects to delete: $would; database volume to drop; Stalwart's volume kept"
fi

# The new server's settings check against this .env (kutup-server
# check-config: environment only, no database), with the new image and the
# current compose files; repeated after the checkout below.
check_config() {
  local out
  if [ "$has_check_config" != true ]; then
    echo "   (this release has no check-config; skipped)"
    return 0
  fi
  # A named, time-limited container, removed whatever happens: no second
  # server stays up (a timeout alone stops the client, not the container).
  local name="kutup-check-config-$$" status=0
  out="$(KUTUP_SERVER_IMAGE="$registry/kutup-server:$tag" \
    timeout 120 docker compose run --rm --no-deps -T --name "$name" backend check-config 2>&1)" || status=$?
  docker rm -f "$name" >/dev/null 2>&1 || true
  if [ "$status" = 0 ]; then
    echo "   $out"
  else
    printf '%s\n' "$out" >&2
    echo "deploy: the new release refuses this server's settings (above)" >&2
    return 1
  fi
}
echo "== settings check"
check_config

if [ "$dry" = true ]; then
  rm -f "$record"
  echo "== dry run: would back up${wipe:+, wipe: $wipe}, check out $sha, set .env to $tag"
  echo "   (pinned by digest), start the stack and check it. Current image lines:"
  grep -E '^KUTUP_(SERVER|WEB|STALWART_SETUP)_IMAGE=' .env
  git log --oneline -1
  exit 0
fi

echo "== update: the commit's compose files and nginx config"
# Before anything destructive: a failed checkout or nginx check leaves the
# database, the bucket, .env and the running stack as they were.
git checkout -q --detach "$sha"
docker compose run --rm --no-deps --entrypoint nginx nginx -t
check_config

echo "== backups"
since="$(date '+%Y-%m-%d %H:%M:%S')"
systemctl start kutup-backup.service
systemctl start kutup-mail-backup.service
journalctl -u kutup-backup.service --since "$since" --no-pager | grep "backup: stored" | tail -1

if [ "$wipe" = true ]; then
  echo "== wipe: stack down, database volume dropped, bucket emptied (backups kept)"
  docker compose down
  project="$(docker compose config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')"
  docker volume rm "${project}_postgres_data"
  s3_rm --only-show-errors
  # Mail queued to outside hosts by the old accounts stays in Stalwart's queue;
  # it was signed and is retried or bounced there, which is harmless.
fi

# Then the images, pinned by digest (the tag kept for reading), so a re-pushed
# tag can never change what runs.
echo "== update: images"
[ -n "$old" ] && cp .env ".env.bak-$old"
for i in $images; do
  var="$(echo "$i" | sed -e 's/^kutup-//' -e 's/-/_/g' | tr '[:lower:]' '[:upper:]')"
  digest="$(docker image inspect -f '{{index .RepoDigests 0}}' "$registry/$i:$tag" | sed 's/.*@//')"
  sed -i "s#^KUTUP_${var}_IMAGE=.*#KUTUP_${var}_IMAGE=$registry/$i:$tag@$digest#" .env
done
grep -E '^KUTUP_(SERVER|WEB|STALWART_SETUP)_IMAGE=' .env
docker compose up -d --wait
docker compose restart nginx >/dev/null

echo "== checks"
sleep 5
docker compose exec -T postgres sh -c 'psql -U "${POSTGRES_USER:-kutup}" -d "${POSTGRES_DB:-kutup}" -tAc "select max(version) from _sqlx_migrations"' \
  | sed 's/^/latest migration: /'
# Log lines at ERROR level and panics, not every line containing "error".
errors="$(docker compose logs --no-color backend --since 3m 2>&1 | sed 's/\x1b\[[0-9;]*m//g' \
  | grep -cE ' ERROR |level=error|panicked' || true)"
echo "backend error lines: $errors"
docker compose logs stalwart-setup --since 5m 2>&1 | grep -q 'Authentication-Results' \
  || { echo "deploy: stalwart-setup did not report Authentication-Results" >&2; exit 1; }
docker compose run --rm --no-deps backend storage-check | tail -1
[ -n "$hosts" ] || hosts="$(for a in account drive chat office editor maps photos contacts mail pass; do printf '%s.%s ' "$a" "$(env_get KUTUP_BASE_DOMAIN)"; done)"
failed=0
for h in $hosts; do
  code="$(curl -s -o /dev/null -w '%{http_code}' "https://$h/")"
  echo "  $h $code"
  [ "$code" = 200 ] || failed=1
done
[ "$failed" = 0 ] || { echo "deploy: a host did not answer 200" >&2; exit 1; }
[ "$errors" = 0 ] || { echo "deploy: backend logged errors; read: docker compose logs backend" >&2; exit 1; }

echo "== images kept: $tag ${old:-}"
docker images --format '{{.Repository}}:{{.Tag}}' | grep -E "^$registry/" \
  | grep -vE ":($tag${old:+|$old})$" | xargs -r docker rmi >/dev/null 2>&1 || true
docker image prune -f >/dev/null
df -h / | tail -1
REMOTE
$dry && echo "== dry run done, nothing changed" || echo "== deployed $tag"
