#!/usr/bin/env bash
# The restore drill's steps 1 to 4, scripted (docs/self-hosting.md, "Restore
# drill"; docs/plans/restore-drill-and-alerting.md, Part 1), for a test
# machine with lane stacks (move-to-vm/lanes/). It restores from nothing but
# what a lost server leaves: the backup bucket, the blob bucket (or its
# replica) and the offline secrets. It never touches the running server.
#
# Run scripts/restore-drill.sh --help for the options.
#
# What it does:
#   1. Starts an empty stack, Compose project kutup-drill-l<lane>, from the
#      release images, with settings of its own (the offline .env plus the
#      drill's changes) in its work directory.
#   2. Fetches the newest (or a named) database dump from the backup bucket,
#      checks and decrypts it with the age identity, and pg_restores it into
#      the empty database, timed (scripts/backup-postgres.sh --restore).
#   3. Copies the blob bucket into the drill's scratch bucket and points the
#      stack there (never at the source), starts the server with
#      BACKGROUND_JOBS=false, then
#   4. restores Stalwart's volume (scripts/backup-stalwart.sh --restore), and
#      restarts the server with its background jobs on.
# Then it asks /api/health/ready, runs kutup-server check-config, compares
# the migrations table with the release's migrations, and prints the
# timings and the newest dump's age (the data-loss window).
#
# Every destructive step is held to the drill's own stack (a project named
# kutup-drill-l<lane>, on this machine's Docker) and its own scratch bucket
# (a name with "drill" in it, never the source, the data or the backup
# bucket). The source bucket is only read.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<EOF
Usage: scripts/restore-drill.sh --env FILE --identity FILE --images TAG \\
         --source-bucket NAME --scratch-bucket NAME [options]
       scripts/restore-drill.sh --down [--lane N] [--work-dir DIR] [--dry-run]

Restores a Kutup backup into an empty lane stack on this machine: the
restore drill's steps 1-4 (docs/self-hosting.md, "Restore drill").

Required:
  --env FILE             the offline copy of the production .env (JWT_SECRET,
                         OPAQUE_SETUP_KEYS, POSTGRES_*, S3_*, BACKUP_S3_*,
                         mail secrets, ...). Only read; the drill writes its
                         own copy with its changes into the work directory.
  --identity FILE        the age identity (private key) the backups are
                         encrypted to (kutup-backup.key, kept offline).
  --images TAG           the release's image tag (the commit
                         scripts/publish-images.sh tagged), e.g. 2d26c64eb60d.
  --source-bucket NAME   the blob bucket, or its replica, at S3_ENDPOINT.
                         Only read: copied into the scratch bucket.
  --scratch-bucket NAME  the drill's copy of it, which the stack uses. Its
                         name must contain "drill"; it must not be the
                         source, S3_BUCKET of --env, or BACKUP_S3_BUCKET.
                         Created when missing, and made an exact copy of the
                         source (objects not in the source are deleted).

Options:
  --lane N               the test lane (1-3; default \$KUTUP_LANE). Sources
                         \$KUTUP_LANES_DIR/laneN.sh (default
                         ../move-to-vm/lanes); the drill's ports are the
                         lane's HTTP/HTTPS ports + 100, so it runs beside the
                         lane's own stack.
  --dump NAME            restore this dump (from backup-postgres.sh --list)
                         instead of the newest.
  --mail-backup NAME     restore this Stalwart backup instead of the newest.
  --no-mail              no Stalwart (a server without Mail).
  --registry PREFIX      where the images are (default
                         \${KUTUP_IMAGE_REGISTRY:-ghcr.io/kutupbt}).
  --set KEY=VALUE        change one setting in the drill's copy of the .env
                         (repeatable), e.g. --set S3_ACCESS_KEY=... for a key
                         scoped to the scratch bucket. S3_BUCKET and
                         BACKGROUND_JOBS are the drill's own.
  --work-dir DIR         where the drill's settings and certificate go
                         (default \${XDG_STATE_HOME:-~/.local/state}/kutup-restore-drill/l<lane>).
  --jobs-stay-off        leave BACKGROUND_JOBS off at the end. With them on,
                         the restored federation and mail outboxes deliver
                         what the dump had queued, and Stalwart its queue.
  --dry-run              print every step and run nothing.
  --down                 remove the drill's stack (its containers, volumes
                         and network) and its work directory. The scratch
                         bucket stays; empty or delete it at the provider.
  -h, --help             this text.

Needs on this machine: docker (with Compose), age, jq, openssl, git.
EOF
}

die() {
  echo "restore drill: $*" >&2
  exit 1
}

usage_error() {
  echo "restore drill: $*" >&2
  echo "Run scripts/restore-drill.sh --help for the options." >&2
  exit 2
}

# ---- Arguments --------------------------------------------------------------

env_source="" identity="" images="" source_bucket="" scratch_bucket=""
lane="${KUTUP_LANE:-}" dump="" mail_backup="" mail=1 dry_run=0 down=0
jobs_on=1 work_dir=""
registry="${KUTUP_IMAGE_REGISTRY:-ghcr.io/kutupbt}"
overrides=()

need_value() {
  { [ "$#" -ge 2 ] && [ -n "$2" ]; } || usage_error "$1 needs a value"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --env) need_value "$@"; env_source="$2"; shift 2 ;;
    --identity) need_value "$@"; identity="$2"; shift 2 ;;
    --images) need_value "$@"; images="$2"; shift 2 ;;
    --source-bucket) need_value "$@"; source_bucket="$2"; shift 2 ;;
    --scratch-bucket) need_value "$@"; scratch_bucket="$2"; shift 2 ;;
    --lane) need_value "$@"; lane="$2"; shift 2 ;;
    --dump) need_value "$@"; dump="$2"; shift 2 ;;
    --mail-backup) need_value "$@"; mail_backup="$2"; shift 2 ;;
    --no-mail) mail=0; shift ;;
    --registry) need_value "$@"; registry="$2"; shift 2 ;;
    --set) need_value "$@"; overrides+=("$2"); shift 2 ;;
    --work-dir) need_value "$@"; work_dir="$2"; shift 2 ;;
    --jobs-stay-off) jobs_on=0; shift ;;
    --dry-run) dry_run=1; shift ;;
    --down) down=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage_error "unknown argument: $1" ;;
  esac
done

case "$lane" in
  1|2|3) ;;
  "") usage_error "give --lane 1, 2 or 3 (or source your lane file first)" ;;
  *) usage_error "--lane must be 1, 2 or 3, not $lane" ;;
esac

# The drill's own Compose project: every destructive step checks it.
project="kutup-drill-l$lane"
work_dir="${work_dir:-${XDG_STATE_HOME:-$HOME/.local/state}/kutup-restore-drill/l$lane}"
drill_env="$work_dir/drill.env"

# ---- Printing and running ---------------------------------------------------

step() {
  printf '\n== %s\n' "$*"
}

note() {
  echo "restore drill: $*"
}

# Prints a command; runs it unless this is a dry run.
run() {
  printf '+ %s\n' "$(printf '%q ' "$@")"
  if [ "$dry_run" -eq 0 ]; then
    "$@"
  fi
}

# Every step that removes or overwrites something calls this first.
guard_project() {
  [[ "${COMPOSE_PROJECT_NAME:-}" =~ ^kutup-drill-l[123]$ ]] \
    || die "refusing: the Compose project is '${COMPOSE_PROJECT_NAME:-}', not the drill's own (kutup-drill-l<lane>)"
  [ "$COMPOSE_PROJECT_NAME" = "$project" ] || die "refusing: the Compose project is $COMPOSE_PROJECT_NAME, not $project"
  [ "${KUTUP_ENV_FILE:-}" = "$drill_env" ] || die "refusing: the settings file is '${KUTUP_ENV_FILE:-}', not the drill's own ($drill_env)"
}

# Docker must be this machine's: a DOCKER_HOST or context reaching another
# machine (the production server, say) is refused.
guard_local_docker() {
  case "${DOCKER_HOST:-unix://}" in
    unix://*) ;;
    *) die "refusing: DOCKER_HOST is ${DOCKER_HOST}; the drill runs on this machine's Docker only" ;;
  esac
  if [ "$dry_run" -eq 1 ]; then
    printf '+ %s\n' "docker context inspect --format '{{.Endpoints.docker.Host}}'   # must be unix://..."
    return
  fi
  local endpoint
  endpoint="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)"
  case "$endpoint" in
    unix://*) ;;
    *) die "refusing: the Docker context's endpoint is '$endpoint'; the drill runs on this machine's Docker only" ;;
  esac
}

# The project's containers and volumes, by Compose's label.
project_resources() {
  docker ps --all --quiet --filter "label=com.docker.compose.project=$project"
  docker volume ls --quiet --filter "label=com.docker.compose.project=$project"
}

# ---- The lane ---------------------------------------------------------------

lanes_dir="${KUTUP_LANES_DIR:-$root_dir/../move-to-vm/lanes}"
lane_file="$lanes_dir/lane$lane.sh"
[ -f "$lane_file" ] || die "no lane file $lane_file (set KUTUP_LANES_DIR to move-to-vm/lanes)"
# shellcheck source=/dev/null
. "$lane_file"
[ "${KUTUP_LANE:-}" = "$lane" ] || die "$lane_file did not set KUTUP_LANE=$lane"
{ [ -n "${KUTUP_HTTP_PORT:-}" ] && [ -n "${KUTUP_HTTPS_PORT:-}" ]; } \
  || die "$lane_file did not set KUTUP_HTTP_PORT and KUTUP_HTTPS_PORT"
# Beside the lane's own stack, never in it.
export COMPOSE_PROJECT_NAME="$project"
export KUTUP_HTTP_PORT=$((KUTUP_HTTP_PORT + 100))
export KUTUP_HTTPS_PORT=$((KUTUP_HTTPS_PORT + 100))
mail_smtp_port="$(( KUTUP_HTTP_PORT / 1000 ))025"
export KUTUP_ENV_FILE="$drill_env"
export COMPOSE_ENV_FILES="$drill_env"

# ---- --down -----------------------------------------------------------------

if [ "$down" -eq 1 ]; then
  step "Removing the drill's stack $project and $work_dir"
  guard_project
  guard_local_docker
  if [ "$dry_run" -eq 1 ]; then
    printf '+ %s\n' "docker rm --force --volumes <containers labelled com.docker.compose.project=$project>"
    printf '+ %s\n' "docker volume rm <volumes labelled com.docker.compose.project=$project>"
    printf '+ %s\n' "docker network rm ${project}_default"
  else
    mapfile -t containers < <(docker ps --all --quiet --filter "label=com.docker.compose.project=$project")
    [ "${#containers[@]}" -eq 0 ] || docker rm --force --volumes "${containers[@]}" >/dev/null
    mapfile -t volumes < <(docker volume ls --quiet --filter "label=com.docker.compose.project=$project")
    [ "${#volumes[@]}" -eq 0 ] || docker volume rm "${volumes[@]}" >/dev/null
    docker network rm "${project}_default" >/dev/null 2>&1 || true
  fi
  case "$work_dir" in
    */kutup-restore-drill/l[123]|*restore-drill*) run rm -rf -- "$work_dir" ;;
    *) note "left $work_dir (not a drill work directory by its name); remove it yourself" ;;
  esac
  note "the scratch bucket is left as it is; empty or delete it at the provider"
  exit 0
fi

# ---- Checking the inputs ----------------------------------------------------

[ -n "$env_source" ] || usage_error "give --env (the offline copy of the production .env)"
[ -n "$identity" ] || usage_error "give --identity (the age identity file that opens the backups)"
[ -n "$images" ] || usage_error "give --images (the release's image tag)"
[ -n "$source_bucket" ] || usage_error "give --source-bucket (the blob bucket or its replica)"
[ -n "$scratch_bucket" ] || usage_error "give --scratch-bucket (the drill's copy of the blobs)"
[[ "$images" =~ ^[A-Za-z0-9_.-]+$ ]] || usage_error "--images is a tag (letters, digits, . _ -), not $images"
{ [ -f "$env_source" ] && [ -r "$env_source" ]; } || die "cannot read --env $env_source"
{ [ -f "$identity" ] && [ -r "$identity" ]; } || die "cannot read --identity $identity"
identity="$(cd "$(dirname "$identity")" && pwd)/$(basename "$identity")"
env_source="$(cd "$(dirname "$env_source")" && pwd)/$(basename "$env_source")"
[ "$env_source" != "$drill_env" ] || die "--env must be the offline copy, not the drill's own $drill_env"
if [ -n "$(find "$identity" -perm /077 2>/dev/null)" ]; then
  note "warning: $identity can be read by others; chmod 600 it"
fi
if [ "$dry_run" -eq 0 ]; then
  for tool in docker age jq openssl git; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed on this machine"
  done
fi

# The last assignment of a key in a settings file, taken literally.
setting_in() {
  sed -n "s/^$2=//p" "$1" | tail -n 1
}

for entry in "${overrides[@]}"; do
  key="${entry%%=*}"
  [[ "$entry" == *=* && "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || usage_error "--set takes KEY=VALUE, not $entry"
  case "$key" in
    S3_BUCKET) usage_error "--set S3_BUCKET: the stack's bucket is --scratch-bucket" ;;
    BACKGROUND_JOBS) usage_error "--set BACKGROUND_JOBS: the drill turns the jobs off and on itself" ;;
    COMPOSE_*|KUTUP_SERVER_IMAGE|KUTUP_WEB_IMAGE|KUTUP_STALWART_SETUP_IMAGE)
      usage_error "--set $key: set by the drill (--images, --registry, --lane)" ;;
  esac
done

# A setting as the drill's stack will see it: the offline .env, then --set.
drill_setting() {
  local value entry
  value="$(setting_in "$env_source" "$1")"
  for entry in "${overrides[@]}"; do
    [ "${entry%%=*}" != "$1" ] || value="${entry#*=}"
  done
  printf '%s' "$value"
}

s3_endpoint="$(drill_setting S3_ENDPOINT)"
s3_region="$(drill_setting S3_REGION)"
data_bucket="$(setting_in "$env_source" S3_BUCKET)"
backup_bucket="$(drill_setting BACKUP_S3_BUCKET)"
backup_endpoint="$(drill_setting BACKUP_S3_ENDPOINT)"

# ---- The bucket guards ------------------------------------------------------

[ -n "$s3_endpoint" ] || die "S3_ENDPOINT is not set in --env (or --set); the drill copies blobs at that store"
case "$s3_endpoint" in
  *seaweedfs-s3*) die "S3_ENDPOINT is the bundled SeaweedFS ($s3_endpoint), which a lost server takes with it; restore from the replica's store" ;;
  http://*|https://*) ;;
  *) die "S3_ENDPOINT is not an http(s) address: $s3_endpoint" ;;
esac
{ [ -n "$(drill_setting S3_ACCESS_KEY)" ] && [ -n "$(drill_setting S3_SECRET_KEY)" ]; } \
  || die "S3_ACCESS_KEY and S3_SECRET_KEY must be set in --env (or --set) for the blob copy"
valid_bucket='^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'
[[ "$source_bucket" =~ $valid_bucket ]] || die "--source-bucket is not a bucket name: $source_bucket"
[[ "$scratch_bucket" =~ $valid_bucket ]] || die "--scratch-bucket is not a bucket name: $scratch_bucket"
[ "$scratch_bucket" != "$source_bucket" ] \
  || die "refusing: the scratch bucket is the source bucket ($source_bucket); the drill must never write to it"
[[ "$scratch_bucket" == *drill* ]] \
  || die "refusing: the scratch bucket's name ($scratch_bucket) does not contain \"drill\"; name the drill's copy so it cannot be taken for a live bucket"
[ -z "$data_bucket" ] || [ "$scratch_bucket" != "$data_bucket" ] \
  || die "refusing: the scratch bucket is S3_BUCKET of --env ($data_bucket), the production data bucket"
if [ "$scratch_bucket" = "$backup_bucket" ] && { [ -z "$backup_endpoint" ] || [ "$backup_endpoint" = "$s3_endpoint" ]; }; then
  die "refusing: the scratch bucket is BACKUP_S3_BUCKET ($backup_bucket)"
fi
[ -n "$backup_bucket" ] || die "BACKUP_S3_BUCKET is not set in --env; the dumps come from there"

# ---- The images and compose files -------------------------------------------

server_image="$registry/kutup-server:$images"
web_image="$registry/kutup-web:$images"
stalwart_setup_image="$registry/kutup-stalwart-setup:$images"
override_file="$work_dir/drill.override.yml"
compose_files=(
  "$root_dir/docker-compose.yml"
  "$root_dir/docker-compose.images.yml"
  "$root_dir/docker-compose.external-s3.yml"
)
if [ "$mail" -eq 1 ]; then
  compose_files+=("$root_dir/docker-compose.mail.yml" "$root_dir/docker-compose.mail-images.yml")
fi
compose_files+=("$override_file")
COMPOSE_FILE="$(IFS=:; printf '%s' "${compose_files[*]}")"
export COMPOSE_FILE

# The blob copy, with the stack's own S3 key (the drill's .env).
blob_s3() {
  run docker run --rm \
    -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
    -e AWS_DEFAULT_REGION="${s3_region:-us-east-1}" \
    -e AWS_REQUEST_CHECKSUM_CALCULATION=when_required \
    -e AWS_RESPONSE_CHECKSUM_VALIDATION=when_required \
    amazon/aws-cli:2.37.9 --endpoint-url "$s3_endpoint" "$@"
}

# Sets KEY=VALUE in the drill's settings (the last assignment wins, for
# Compose and for the backup scripts alike).
drill_set() {
  if [ "$dry_run" -eq 1 ]; then
    printf '+ %s\n' "echo $1=... >> $drill_env"
    return
  fi
  printf '%s=%s\n' "$1" "$2" >> "$drill_env"
}

# Seconds, as "1h 02m 03s".
duration() {
  local s="$1"
  if [ "$s" -ge 3600 ]; then
    printf '%dh %02dm %02ds' $((s / 3600)) $((s % 3600 / 60)) $((s % 60))
  elif [ "$s" -ge 60 ]; then
    printf '%dm %02ds' $((s / 60)) $((s % 60))
  else
    printf '%ds' "$s"
  fi
}

timings=()
timed() {
  local what="$1" started
  shift
  started="$(date +%s)"
  "$@"
  timings+=("$what|$(( $(date +%s) - started ))")
}

cd "$root_dir"
[ "$dry_run" -eq 0 ] || note "dry run: nothing is run, created or changed"
note "lane $lane, project $project, https://<app>.localhost:$KUTUP_HTTPS_PORT, images $registry/*:$images"
note "blobs: s3://$source_bucket (read only) -> s3://$scratch_bucket at $s3_endpoint"
guard_project
guard_local_docker

# ---- Step 1: an empty stack -------------------------------------------------

step "1. An empty stack: $project from $images"
if [ "$dry_run" -eq 1 ]; then
  printf '+ %s\n' "docker ps/volume ls --filter label=com.docker.compose.project=$project   # must be empty"
else
  [ -z "$(project_resources)" ] \
    || die "refusing: $project already has containers or volumes; remove them first with scripts/restore-drill.sh --down --lane $lane"
fi
run mkdir -p "$work_dir"
run chmod 700 "$work_dir"
if [ "$dry_run" -eq 1 ]; then
  printf '+ %s\n' "cp $env_source $drill_env   # then the drill's changes:"
else
  (umask 077 && cp "$env_source" "$drill_env")
  # A file without a final newline would join the next line to its last.
  [ -z "$(tail -c 1 "$drill_env")" ] || echo >> "$drill_env"
  echo "# restore drill ($(date -u +%Y-%m-%dT%H:%M:%SZ)): the changes below win" >> "$drill_env"
fi
drill_set S3_BUCKET "$scratch_bucket"
drill_set KUTUP_SERVER_IMAGE "$server_image"
drill_set KUTUP_WEB_IMAGE "$web_image"
drill_set KUTUP_STALWART_SETUP_IMAGE "$stalwart_setup_image"
drill_set MAIL_SMTP_PORT "$mail_smtp_port"
drill_set BACKGROUND_JOBS false
for entry in "${overrides[@]}"; do
  drill_set "${entry%%=*}" "${entry#*=}"
done
# The drill's own certificate, never this checkout's nginx/certs.
run mkdir -p "$work_dir/certs"
run openssl req -x509 -nodes -newkey rsa:2048 -days 7 \
  -keyout "$work_dir/certs/privkey.pem" -out "$work_dir/certs/fullchain.pem" \
  -subj /CN=localhost -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"
if [ "$dry_run" -eq 1 ]; then
  printf '+ %s\n' "write $override_file (nginx certs from $work_dir/certs)"
else
  cat > "$override_file" <<EOF
# Written by scripts/restore-drill.sh: the drill's certificate.
services:
  nginx:
    volumes:
      - $work_dir/certs:/etc/nginx/certs:ro
EOF
fi
run docker compose config --quiet
timed "pull the images" run docker compose pull --quiet
timed "start PostgreSQL" run docker compose up --detach --wait postgres

# ---- Step 2: the database ---------------------------------------------------

step "2. The database dump"
if [ -z "$dump" ]; then
  if [ "$dry_run" -eq 1 ]; then
    run scripts/backup-postgres.sh --list
    dump="kutup-<newest>.dump.age"
  else
    dump="$(scripts/backup-postgres.sh --list | tail -n 1)"
    [ -n "$dump" ] || die "no dump in the backup bucket $backup_bucket"
  fi
fi
note "restoring $dump"
guard_project
# Checked whole with the identity before the database is touched.
timed "restore the dump (fetch, check, pg_restore)" run scripts/backup-postgres.sh --restore "$dump" "$identity"

# ---- Step 3: the blobs, and the server with its jobs off --------------------

step "3. The blobs: a copy in s3://$scratch_bucket, and the server with its jobs off"
AWS_ACCESS_KEY_ID="$(drill_setting S3_ACCESS_KEY)"
AWS_SECRET_ACCESS_KEY="$(drill_setting S3_SECRET_KEY)"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
if [ "$dry_run" -eq 1 ]; then
  blob_s3 s3api head-bucket --bucket "$scratch_bucket"
  printf '+ %s\n' "(if missing) aws s3 mb s3://$scratch_bucket"
elif ! blob_s3 s3api head-bucket --bucket "$scratch_bucket" >/dev/null 2>&1; then
  blob_s3 s3 mb "s3://$scratch_bucket" \
    || die "could not create s3://$scratch_bucket; create it at the provider and run again"
fi
[ "$scratch_bucket" != "$source_bucket" ] || die "refusing: the scratch bucket is the source"
# Reads the source, writes only the scratch copy (--delete removes there
# what the source does not have, so the copy is exact).
timed "copy the blobs" blob_s3 s3 sync --only-show-errors --delete \
  "s3://$source_bucket" "s3://$scratch_bucket"
if [ "$dry_run" -eq 0 ]; then
  [ "$(setting_in "$drill_env" S3_BUCKET)" = "$scratch_bucket" ] \
    || die "refusing: the drill's S3_BUCKET is not $scratch_bucket"
  [ "$(setting_in "$drill_env" BACKGROUND_JOBS)" = false ] \
    || die "refusing: BACKGROUND_JOBS is not off in $drill_env"
fi
guard_project
timed "start the stack, jobs off" run docker compose up --detach --wait

# ---- Step 4: Stalwart -------------------------------------------------------

if [ "$mail" -eq 1 ]; then
  step "4. Stalwart's volume"
  if [ -z "$mail_backup" ]; then
    if [ "$dry_run" -eq 1 ]; then
      run scripts/backup-stalwart.sh --list
      mail_backup="stalwart-<newest>.tar.gz.age"
    else
      mail_backup="$(scripts/backup-stalwart.sh --list | tail -n 1)"
      [ -n "$mail_backup" ] || die "no Stalwart backup in the backup bucket $backup_bucket"
    fi
  fi
  note "restoring $mail_backup"
  guard_project
  timed "restore Stalwart (fetch, check, untar)" run scripts/backup-stalwart.sh --restore "$mail_backup" "$identity"
else
  step "4. Stalwart's volume: skipped (--no-mail)"
fi

# ---- The jobs on ------------------------------------------------------------

if [ "$jobs_on" -eq 1 ]; then
  step "Background jobs on"
  guard_project
  drill_set BACKGROUND_JOBS true
  timed "restart the server, jobs on" run docker compose up --detach --wait --no-deps --force-recreate backend
else
  step "Background jobs stay off (--jobs-stay-off)"
fi

# ---- Checks -----------------------------------------------------------------

step "Checks"
failed=0

# /api/health/ready, from the stack's own network (the internal network may ask).
ready_status="not run"
if [ "$dry_run" -eq 1 ]; then
  run docker run --rm --network "${project}_default" curlimages/curl:8.11.1 \
    --silent --show-error --max-time 30 --write-out '\n%{http_code}' http://backend:3000/api/health/ready
  ready_status="(dry run)"
else
  ready="$(docker run --rm --network "${project}_default" curlimages/curl:8.11.1 \
    --silent --show-error --max-time 30 --write-out '\n%{http_code}' http://backend:3000/api/health/ready)" || ready=$'\n000'
  ready_code="$(printf '%s' "$ready" | tail -n 1)"
  ready_body="$(printf '%s' "$ready" | sed '$d')"
  echo "GET /api/health/ready: $ready_code"
  printf '%s' "$ready_body" | jq . 2>/dev/null || printf '%s\n' "$ready_body"
  failing="$(printf '%s' "$ready_body" | jq -r '.checks // {} | to_entries[] | select(.value.status == "fail") | .key' 2>/dev/null | paste -sd, - || true)"
  case "$ready_code:$failing" in
    200:) ready_status="ok" ;;
    503:backups) ready_status="ok but backups (expected: no backup has run from this stack)" ;;
    *) ready_status="FAIL ($ready_code${failing:+: $failing})"; failed=1 ;;
  esac
fi

config_status="not run"
if [ "$dry_run" -eq 1 ]; then
  run docker compose run --rm --no-deps backend check-config
  config_status="(dry run)"
elif docker compose run --rm --no-deps backend check-config; then
  config_status="ok"
else
  config_status="FAIL"
  failed=1
fi

# The migrations the release has, against the restored (and migrated) table.
migrations_status="not run"
release_ref=""
if git -C "$root_dir" rev-parse --quiet --verify "$images^{commit}" >/dev/null 2>&1; then
  release_ref="$images"
fi
release_versions() {
  if [ -n "$release_ref" ]; then
    git -C "$root_dir" ls-tree --name-only "$release_ref" crates/kutup-server/migrations/
  else
    ls "$root_dir/crates/kutup-server/migrations/"
  fi | sed -n 's#^.*/\{0,1\}\([0-9]\{14\}\)_.*\.up\.sql$#\1#p; s#^.*/\{0,1\}\([0-9]\{14\}\)_[^.]*\.sql$#\1#p' | sort -u
}
db_user="$(drill_setting POSTGRES_USER)"
db_name="$(drill_setting POSTGRES_DB)"
migrations_query="SELECT version FROM _sqlx_migrations WHERE success ORDER BY version"
if [ "$dry_run" -eq 1 ]; then
  run docker compose exec -T postgres psql -U "${db_user:-kutup}" -d "${db_name:-kutup}" -At -c "$migrations_query"
  printf '+ %s\n' "compare with crates/kutup-server/migrations at ${release_ref:-this checkout (no commit $images here)}"
  migrations_status="(dry run)"
else
  [ -n "$release_ref" ] || note "warning: no commit $images in this checkout; comparing with its own migrations"
  expected="$(release_versions)"
  applied="$(docker compose exec -T postgres psql -U "${db_user:-kutup}" -d "${db_name:-kutup}" -At -c "$migrations_query")"
  unfinished="$(docker compose exec -T postgres psql -U "${db_user:-kutup}" -d "${db_name:-kutup}" -At \
    -c "SELECT count(*) FROM _sqlx_migrations WHERE NOT success")"
  if [ "$expected" = "$applied" ] && [ "$unfinished" = 0 ]; then
    migrations_status="ok ($(printf '%s\n' "$applied" | wc -l | tr -d ' ') applied, newest $(printf '%s\n' "$applied" | tail -n 1))"
  else
    migrations_status="FAIL"
    failed=1
    echo "migrations: the release has $(printf '%s\n' "$expected" | wc -l | tr -d ' '), the table $(printf '%s\n' "$applied" | wc -l | tr -d ' '); $unfinished unfinished"
    diff <(printf '%s\n' "$expected") <(printf '%s\n' "$applied") | sed 's/^</  release only:/; s/^>/  table only:/' | grep only || true
  fi
fi

# ---- Summary ----------------------------------------------------------------

stamp="$(printf '%s' "$dump" | sed -n 's/^.*kutup-\([0-9]\{8\}\)T\([0-9]\{2\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)Z\.dump\.age$/\1 \2:\3:\4/p')"
if [ -n "$stamp" ] && dumped_at="$(date -u -d "$stamp" +%s 2>/dev/null)"; then
  window="$(duration $(( $(date -u +%s) - dumped_at ))) (dumped $(date -u -d "@$dumped_at" +%Y-%m-%dT%H:%M:%SZ))"
else
  window="unknown (the dump's name has no timestamp)"
fi

step "Summary"
echo "Release images:      $registry/*:$images"
echo "Stack:               $project, https://<app>.localhost:$KUTUP_HTTPS_PORT (settings: $drill_env)"
echo "Dump restored:       $dump"
[ "$mail" -eq 0 ] || echo "Stalwart restored:   $mail_backup"
echo "Blobs:               s3://$scratch_bucket (a copy of s3://$source_bucket)"
echo "Timings:"
total=0
for entry in "${timings[@]}"; do
  seconds="${entry##*|}"
  total=$((total + seconds))
  printf '  %-48s %s\n' "${entry%|*}" "$(duration "$seconds")"
done
printf '  %-48s %s\n' "total" "$(duration "$total")"
echo "Data-loss window:    $window"
echo "Readiness:           $ready_status"
echo "check-config:        $config_status"
echo "Migrations:          $migrations_status"
echo "Background jobs:     $([ "$jobs_on" -eq 1 ] && echo on || echo off)"
echo
echo "Next: the checks as a user and as the operator (docs/self-hosting.md, \"Restore drill\", steps 5-7)."
echo "Remove it after: scripts/restore-drill.sh --down --lane $lane"
exit "$failed"
