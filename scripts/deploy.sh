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
#   KUTUP_DEPLOY_KORU_SRC  a checkout of Koru's sources, for a server whose edge is Koru
#                       (docker-compose.koru.yml in its COMPOSE_FILE); required there
#   KUTUP_KORU_COMMIT   the Koru commit to ship                    (default: that checkout's HEAD)
#
# What it does, in order, and it stops at the first failure:
#   1. refuses unless GitHub CI passed for the tag's commit on master;
#   2. pulls the three images on the server and records their digests and the
#      running ones (deploy-history/), so a rollback is exact;
#   3. with --wipe: lists what the bucket wipe would delete (aws-cli --dryrun)
#      and refuses if a backup is among it;
#   4. runs the new server's check-config against .env with the commit's compose
#      files read from git (also in --dry-run), then checks out the commit,
#      validates its nginx config and runs check-config again;
#   5. backs up the database and Mail's Stalwart data (the systemd backup units);
#   6. with --wipe only: stops the stack, drops the database volume and empties
#      the bucket except the backup prefixes; Stalwart's volume (DKIM keys) stays;
#   7. sets the images in .env, pinned by digest (kept as .env.bak-<old tag>),
#      starts the stack and restarts nginx;
#   8. checks: migrations, backend errors, Stalwart's setup, storage, every host;
#   9. removes Kutup images other than the new and the previous release.
# With Koru as the edge (docs/self-hosting.md, "Koru edge (optional)"), first,
# here: builds or reuses the image for the Koru commit (scripts/build-koru-image.sh),
# copies it to the server (docker save | docker load; no registry) unless it is
# there already, and checks that the server's image has the same layers.
# On the server, step 2 records it (commit and the server's image id) beside
# the others, step 4 runs `koru check` instead of `nginx -t`, step 7 sets
# KUTUP_KORU_IMAGE and KUTUP_KORU_IMAGE_ID in .env (the id checked again first) and
# reloads Koru instead of restarting nginx, and step 9 keeps the new and the
# previous Koru image. --dry-run builds nothing and copies nothing.
# It reports success only when the server's part ran to its last line.

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

# Koru's image, when the server's edge is Koru: built on this machine and
# copied over, never fetched from a registry.
koru_image="" koru_id="" koru_commit=""
if [ -n "${KUTUP_DEPLOY_KORU_SRC:-}" ]; then
  echo "== Koru image"
  server_files="$(ssh "${ssh_opts[@]}" "$host" "grep -E '^COMPOSE_FILE=' '$dir/.env' | tail -1 | cut -d= -f2-" </dev/null)"
  case ":${server_files//[\"\']/}:" in
    *:docker-compose.koru.yml:*) ;;
    *) echo "deploy: KUTUP_DEPLOY_KORU_SRC is set, but the server's COMPOSE_FILE has no docker-compose.koru.yml" >&2; exit 1 ;;
  esac
  build_koru=(env KORU_SRC="$KUTUP_DEPLOY_KORU_SRC" scripts/build-koru-image.sh)
  if $dry; then
    read -r koru_image koru_id koru_commit < <("${build_koru[@]}" --dry-run | tail -1)
  else
    read -r koru_image koru_id koru_commit < <("${build_koru[@]}" | tail -1)
  fi
  [ -n "$koru_commit" ] || { echo "deploy: no Koru image" >&2; exit 1; }
  # The same image on both machines: the same layers (their content
  # digests). Its id is not compared, since Docker's two image stores
  # (classic and containerd) give one image different ids.
  layers() { printf '%s' "$1" | sha256sum | cut -c1-16; }
  layers_of="docker image inspect -f '{{range .RootFS.Layers}}{{.}} {{end}}' '$koru_image' 2>/dev/null || true"
  remote_layers() { layers "$(ssh "${ssh_opts[@]}" "$host" "$layers_of" </dev/null)"; }
  if [ "$koru_id" = "-" ]; then
    echo "   would build $koru_image (Koru $koru_commit) and copy it to $host"
  else
    local_layers="$(layers "$(bash -c "$layers_of")")"
    if [ "$(remote_layers)" = "$local_layers" ]; then
      echo "   $koru_image (Koru $koru_commit, layers $local_layers) is on $host already"
    elif $dry; then
      echo "   would copy $koru_image (Koru $koru_commit, layers $local_layers, $koru_id here) to $host"
    else
      echo "   copying $koru_image (Koru $koru_commit, layers $local_layers) to $host"
      docker save "$koru_image" | ssh "${ssh_opts[@]}" "$host" docker load >/dev/null
      [ "$(remote_layers)" = "$local_layers" ] || { echo "deploy: $host's $koru_image does not have the layers built here" >&2; exit 1; }
    fi
    # From here on the image is named by the server's own id for it.
    koru_id="$(ssh "${ssh_opts[@]}" "$host" "docker image inspect -f '{{.Id}}' '$koru_image' 2>/dev/null || echo -" </dev/null)"
  fi
fi

# The server's output, kept to see that its script ran to the end.
log="$(mktemp)"
trap 'rm -f "$log"' EXIT
ssh "${ssh_opts[@]}" "$host" bash -s -- "$dir" "$tag" "$sha" "$wipe" "$dry" "$has_check_config" "${KUTUP_DEPLOY_HOSTS:-}" \
  "$koru_image" "$koru_id" "$koru_commit" <<'REMOTE' | tee "$log"
set -euo pipefail
# bash -s reads this script from stdin as it runs, and a command that reads
# stdin (docker compose run or exec) would swallow the rest of it, ending the
# deploy early but successfully. One block is read whole before it runs, and
# nothing in it gets the script as its stdin.
{
dir="$1" tag="$2" sha="$3" wipe="$4" dry="$5" has_check_config="$6" hosts="${7:-}"
koru_image="${8:-}" koru_id="${9:-}" koru_commit="${10:-}"
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

# The target commit's compose files, read from git without checking it out:
# a release may add a setting that only its own compose files pass to the
# server, so the first settings check must use them. Paths in them resolve
# from the checkout, and a server-local file outside git is used as it is.
target="$(mktemp -d)"
trap 'rm -rf "$target"' EXIT
compose_files="${COMPOSE_FILE:-$(env_get COMPOSE_FILE)}"
if [ -z "$compose_files" ]; then
  compose_files=docker-compose.yml
  if git cat-file -e "$sha:docker-compose.override.yml" 2>/dev/null || [ -f docker-compose.override.yml ]; then
    compose_files="$compose_files:docker-compose.override.yml"
  fi
fi
target_compose=(--project-directory "$dir" --env-file "$dir/.env")
IFS="${COMPOSE_PATH_SEPARATOR:-:}" read -ra files <<< "$compose_files"
for f in "${files[@]}"; do
  if [[ "$f" != /* ]] && git cat-file -e "$sha:$f" 2>/dev/null; then
    mkdir -p "$target/$(dirname "$f")"
    git show "$sha:$f" > "$target/$f"
    target_compose+=(-f "$target/$f")
  elif [ -f "$f" ]; then
    target_compose+=(-f "$f")
  else
    echo "deploy: compose file $f is neither in $sha nor on the server" >&2
    exit 1
  fi
done

# The edge: nginx, or Koru when its overlay is among the compose files. Its
# image came from the deploying machine; every compose command below uses it.
edge=nginx
case ":$compose_files:" in *:docker-compose.koru.yml:*) edge=koru ;; esac
if [ "$edge" = koru ]; then
  [ -n "$koru_image" ] || { echo "deploy: this server's edge is Koru: set KUTUP_DEPLOY_KORU_SRC" >&2; exit 1; }
  old_koru="$(env_get KUTUP_KORU_IMAGE)"
  echo "new kutup-koru $koru_image $koru_id (Koru $koru_commit)" >> "$record"
  [ -n "$old_koru" ] && echo "old kutup-koru $old_koru $(env_get KUTUP_KORU_IMAGE_ID)" >> "$record"
  if [ "$dry" != true ]; then
    [ "$(docker image inspect -f '{{.Id}}' "$koru_image" 2>/dev/null)" = "$koru_id" ] \
      || { echo "deploy: $koru_image here is not $koru_id" >&2; exit 1; }
    export KUTUP_KORU_IMAGE="$koru_image"
  elif [ "$(docker image inspect -f '{{.Id}}' "$koru_image" 2>/dev/null || true)" = "$koru_id" ]; then
    export KUTUP_KORU_IMAGE="$koru_image"
  else
    # Not here yet: the settings check runs with the current Koru image.
    export KUTUP_KORU_IMAGE="${old_koru:-$koru_image}"
  fi
fi

# The new server's settings check against this .env (kutup-server
# check-config: environment only, no database), with the new image; the
# arguments choose the compose files. Repeated after the checkout below.
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
    timeout 120 docker compose "$@" run --rm --no-deps -T --name "$name" backend check-config 2>&1)" || status=$?
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
check_config "${target_compose[@]}"

if [ "$dry" = true ]; then
  rm -f "$record"
  echo "== dry run: would back up${wipe:+, wipe: $wipe}, check out $sha, set .env to $tag"
  echo "   (pinned by digest), start the stack and check it. Current image lines:"
  grep -E '^KUTUP_(SERVER|WEB|STALWART_SETUP)_IMAGE=' .env
  if [ "$edge" = koru ]; then
    echo "   Koru: would set KUTUP_KORU_IMAGE=$koru_image (id $koru_id, Koru $koru_commit), now:"
    grep -E '^KUTUP_KORU_IMAGE(_ID)?=' .env || echo "   (none)"
  fi
  git log --oneline -1
  echo "== server done: dry run"
  exit 0
fi

if [ "$edge" = koru ]; then
  echo "== update: the commit's compose files and Koru's config ($koru_image)"
  # As for nginx below; Koru's check writes its configuration from .env as
  # a start would, and validates it.
  git checkout -q --detach "$sha"
  docker compose run --rm --no-deps -T koru check
else
  echo "== update: the commit's compose files and nginx config"
  # Before anything destructive: a failed checkout or nginx check leaves the
  # database, the bucket, .env and the running stack as they were.
  git checkout -q --detach "$sha"
  docker compose run --rm --no-deps --entrypoint nginx nginx -t
fi
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
if [ "$edge" = koru ]; then
  # Koru's image is local to this server: pinned by its id, which was
  # checked above to be the one built for $koru_commit.
  for kv in "KUTUP_KORU_IMAGE=$koru_image" "KUTUP_KORU_IMAGE_ID=$koru_id"; do
    if grep -qE "^${kv%%=*}=" .env; then sed -i "s#^${kv%%=*}=.*#$kv#" .env; else echo "$kv" >> .env; fi
  done
  grep -E '^KUTUP_KORU_IMAGE(_ID)?=' .env
fi
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ "$edge" = koru ]; then
  # Switching a running nginx edge: its container (its profile now off)
  # keeps the edge ports, and acme (no longer in the compose files) is an
  # orphan. Both go just before the start; nothing listens for those
  # seconds. On later deploys there is nothing to remove.
  docker compose rm -sf nginx >/dev/null
  docker compose up -d --wait --remove-orphans || {
    echo "deploy: the stack did not come up behind Koru, and the nginx edge is removed;" >&2
    echo "deploy: read docker compose logs koru, or go back: docs/self-hosting.md, \"Back to nginx\"" >&2
    exit 1
  }
else
  docker compose up -d --wait
fi
if [ "$edge" = koru ]; then
  # Recreated by `up` for a new image or settings; a reload re-reads the
  # certificates and reopens the logs without dropping a connection.
  docker compose kill -s HUP koru >/dev/null
else
  docker compose restart nginx >/dev/null
fi

echo "== checks"
sleep 5
docker compose exec -T postgres sh -c 'psql -U "${POSTGRES_USER:-kutup}" -d "${POSTGRES_DB:-kutup}" -tAc "select max(version) from _sqlx_migrations"' \
  | sed 's/^/latest migration: /'
# Log lines at ERROR level and panics, not every line containing "error".
errors="$(docker compose logs --no-color backend --since 3m 2>&1 | sed 's/\x1b\[[0-9;]*m//g' \
  | grep -cE ' ERROR |level=error|panicked' || true)"
echo "backend error lines: $errors"
# stalwart-setup reports its mail check a little after the stack is up: wait
# for the line (read whole, then searched, so no pipe ends early).
deadline=$((SECONDS + 120))
until docker compose logs --no-color stalwart-setup --since "$started" 2>&1 \
    | grep -c 'Authentication-Results' | grep -qv '^0$'; do
  if (( SECONDS >= deadline )); then
    echo "deploy: stalwart-setup did not report Authentication-Results within 120 s" >&2
    exit 1
  fi
  sleep 3
done
docker compose run --rm --no-deps backend storage-check | tail -1
[ -n "$hosts" ] || hosts="$(for a in account drive chat office editor maps photos contacts mail pass calendar; do printf '%s.%s ' "$a" "$(env_get KUTUP_BASE_DOMAIN)"; done)"
# A new app (a host the certificate doesn't name yet) is certified only when
# acme asks Let's Encrypt again, and its loop sleeps 12 hours after a
# success: restart it, and wait for the certificate that names every host.
cert_names() {
  openssl x509 -in nginx/certs/fullchain.pem -noout -ext subjectAltName 2>/dev/null \
    | tr ',' '\n' | sed -n 's/.*DNS://p' || true
}
uncovered() {
  local names
  names="$(cert_names)"
  for h in $hosts; do grep -qxF "$h" <<<"$names" || printf '%s ' "$h"; done
}
if docker compose ps --services 2>/dev/null | grep -qx acme && command -v openssl >/dev/null; then
  missing="$(uncovered)"
  if [ -n "$missing" ]; then
    echo "certificate lacks: $missing- asking acme for a new one"
    docker compose restart acme >/dev/null
    deadline=$((SECONDS + 300))
    until [ -z "$(uncovered)" ]; do
      if (( SECONDS >= deadline )); then
        echo "deploy: after 5 minutes the certificate still lacks: $(uncovered)" >&2
        echo "deploy: check that each name points at this machine; read: docker compose logs acme" >&2
        exit 1
      fi
      sleep 5
    done
    echo "certificate now names every host"
    # nginx notices a new certificate only on its own 30-second check: reload
    # it now, and wait until what it serves names the new hosts.
    docker compose exec -T nginx nginx -s reload >/dev/null
    served() {
      local names
      names="$(openssl s_client -connect 127.0.0.1:443 -servername "$1" </dev/null 2>/dev/null \
        | openssl x509 -noout -ext subjectAltName 2>/dev/null \
        | tr ',' '\n' | sed -n 's/.*DNS://p' || true)"
      grep -qxF "$1" <<<"$names"
    }
    deadline=$((SECONDS + 60))
    for h in $missing; do
      until served "$h"; do
        if (( SECONDS >= deadline )); then
          echo "deploy: nginx still serves a certificate without $h after its reload" >&2
          exit 1
        fi
        sleep 2
      done
    done
    echo "nginx serves it"
  fi
fi
failed=0
for h in $hosts; do
  # curl's own exit says why a host gave no answer at all (60: the
  # certificate doesn't name it).
  code="$(curl -s -o /dev/null -w '%{http_code}' "https://$h/")" || code="000 (curl exit $?)"
  echo "  $h $code"
  [ "$code" = 200 ] || failed=1
done
[ "$failed" = 0 ] || { echo "deploy: a host did not answer 200" >&2; exit 1; }
[ "$errors" = 0 ] || { echo "deploy: backend logged errors; read: docker compose logs backend" >&2; exit 1; }

echo "== images kept: $tag ${old:-}"
docker images --format '{{.Repository}}:{{.Tag}}' | grep -E "^$registry/" \
  | grep -vE ":($tag${old:+|$old})$" | xargs -r docker rmi >/dev/null 2>&1 || true
if [ "$edge" = koru ]; then
  echo "== Koru images kept: $koru_image ${old_koru:-}"
  docker images --format '{{.Repository}}:{{.Tag}}' kutup-koru \
    | grep -vxF -e "$koru_image" ${old_koru:+-e "$old_koru"} | xargs -r docker rmi >/dev/null 2>&1 || true
fi
docker image prune -f >/dev/null
df -h / | tail -1
echo "== server done: deployed"
} </dev/null
REMOTE
# Success only when the server's script reached its own end.
if $dry; then end="== server done: dry run"; else end="== server done: deployed"; fi
if [ "$(tail -n 1 "$log")" != "$end" ]; then
  echo "deploy: the server's script stopped before its end; nothing after its last line ran" >&2
  exit 1
fi
$dry && echo "== dry run done, nothing changed" || echo "== deployed $tag"
