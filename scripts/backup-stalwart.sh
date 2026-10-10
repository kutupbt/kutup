#!/usr/bin/env bash
# Backs up Stalwart's data volume (docker-compose.mail.yml): its DKIM private
# keys, its settings and the queue of mail not yet handed over. Encrypted on
# this machine and stored beside the database backups, in the object store
# Kutup already uses (S3_* in .env). Run it from the deployment's directory,
# by hand or on a timer (docs/self-hosting.md, "Mail backups"):
#
#   scripts/backup-stalwart.sh             # back up, then prune old backups
#   scripts/backup-stalwart.sh --list      # what is stored
#   scripts/backup-stalwart.sh --fetch <name> <file>   # download and decrypt one
#   scripts/backup-stalwart.sh --restore <file>        # put a decrypted one back
#
# Stalwart keeps its data in RocksDB, which cannot be copied safely while it
# writes, so Stalwart is stopped for the seconds the copy takes. Senders retry
# mail they could not hand over, so nothing is lost. Mail already delivered
# lives in Kutup (and its database backup), not here.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

setting() {
  # The last assignment of a key in .env, taken literally (never evaluated).
  sed -n "s/^$1=//p" .env | tail -n 1
}
required() {
  local value
  value="$(setting "$1")"
  [ -n "$value" ] || { echo "mail backup: set $1 in .env" >&2; exit 1; }
  printf '%s' "$value"
}

[ -f .env ] || { echo "mail backup: no .env in $root_dir" >&2; exit 1; }
endpoint="$(required S3_ENDPOINT)"
bucket="$(required S3_BUCKET)"
region="$(setting S3_REGION)"
prefix="$(setting KUTUP_MAIL_BACKUP_PREFIX)"
prefix="${prefix:-mail-backups}"
keep_days="$(setting KUTUP_BACKUP_KEEP_DAYS)"
keep_days="${keep_days:-30}"
export KUTUP_BACKUP_PASSPHRASE
KUTUP_BACKUP_PASSPHRASE="$(required KUTUP_BACKUP_PASSPHRASE)"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
AWS_ACCESS_KEY_ID="$(required S3_ACCESS_KEY)"
AWS_SECRET_ACCESS_KEY="$(required S3_SECRET_KEY)"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

s3() {
  docker run --rm \
    -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
    -e AWS_DEFAULT_REGION="${region:-us-east-1}" \
    -e AWS_REQUEST_CHECKSUM_CALCULATION=when_required \
    -e AWS_RESPONSE_CHECKSUM_VALIDATION=when_required \
    -v "$work_dir:/work" \
    amazon/aws-cli:2.37.9 --endpoint-url "$endpoint" "$@"
}
cipher() {
  openssl enc "$1" -aes-256-cbc -pbkdf2 -iter 600000 -pass env:KUTUP_BACKUP_PASSPHRASE
}
stored() {
  s3 s3api list-objects-v2 --bucket "$bucket" --prefix "$prefix/" \
    --query 'Contents[].Key' --output text | tr '\t' '\n' | grep -E '\.tar\.gz\.enc$' | sort || true
}
# The volume mounted as Stalwart's data directory in this deployment.
volume() {
  local container name
  container="$(docker compose ps --all --quiet stalwart)"
  [ -n "$container" ] || { echo "mail backup: no stalwart container (is docker-compose.mail.yml in use?)" >&2; exit 1; }
  name="$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/stalwart"}}{{.Name}}{{end}}{{end}}' "$container")"
  [ -n "$name" ] || { echo "mail backup: stalwart has no data volume" >&2; exit 1; }
  printf '%s' "$name"
}
# Stopped while its files are read or written; started again however that ends.
with_stalwart_stopped() {
  docker compose stop stalwart >/dev/null
  local status=0
  "$@" || status=$?
  docker compose start stalwart >/dev/null
  return "$status"
}

case "${1:-}" in
  --list)
    stored | sed "s#^$prefix/##"
    exit 0
    ;;
  --fetch)
    name="${2:?name of the backup, from --list}"
    target="${3:?file to write the decrypted archive to}"
    s3 s3 cp --only-show-errors "s3://$bucket/$prefix/$name" /work/fetched.enc
    cipher -d < "$work_dir/fetched.enc" > "$target"
    echo "mail backup: wrote $target (put it back with --restore)"
    exit 0
    ;;
  --restore)
    archive="$(cd "$(dirname "${2:?decrypted archive from --fetch}")" && pwd)/$(basename "$2")"
    [ -s "$archive" ] || { echo "mail backup: $archive is empty or missing" >&2; exit 1; }
    data="$(volume)"
    restore() {
      docker run --rm -v "$data:/data" -v "$archive:/backup.tar.gz:ro" alpine:3.22 \
        sh -c 'find /data -mindepth 1 -delete && tar -xzf /backup.tar.gz -C /data'
    }
    with_stalwart_stopped restore
    echo "mail backup: restored $data from $archive"
    exit 0
    ;;
  "") ;;
  *) echo "mail backup: unknown argument $1" >&2; exit 2 ;;
esac

data="$(volume)"
name="stalwart-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.enc"
copy() {
  docker run --rm -v "$data:/data:ro" alpine:3.22 tar -czf - -C /data . > "$work_dir/plain.tar.gz"
}
with_stalwart_stopped copy
[ -s "$work_dir/plain.tar.gz" ] || { echo "mail backup: the archive is empty" >&2; exit 1; }
cipher -e < "$work_dir/plain.tar.gz" > "$work_dir/$name"
rm -f "$work_dir/plain.tar.gz"
size="$(wc -c < "$work_dir/$name")"
chmod a+rX "$work_dir" "$work_dir/$name"
s3 s3 cp --only-show-errors "/work/$name" "s3://$bucket/$prefix/$name"
echo "mail backup: stored $prefix/$name ($size bytes)"

# Prune by the date in each name. The newest backup is never removed.
cutoff="$(date -u -d "$keep_days days ago" +%Y%m%dT%H%M%SZ)"
stored | sed '$d' | while read -r key; do
  stamp="$(basename "$key" | sed -n 's/^stalwart-\([0-9]\{8\}T[0-9]\{6\}Z\)\.tar\.gz\.enc$/\1/p')"
  if [ -n "$stamp" ] && [ "$stamp" \< "$cutoff" ]; then
    s3 s3 rm --only-show-errors "s3://$bucket/$key"
    echo "mail backup: removed $key (older than $keep_days days)"
  fi
done
