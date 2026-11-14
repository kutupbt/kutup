#!/usr/bin/env bash
# Backs up Stalwart's data volume (docker-compose.mail.yml): its DKIM private
# keys, its settings and the queue of mail not yet handed over. Encrypted with
# age on this machine and stored beside the database backups, in the backup
# bucket (BACKUP_S3_* in .env). Run it from the deployment's directory, by
# hand or on a timer (docs/self-hosting.md, "Mail backups"):
#
#   scripts/backup-stalwart.sh                              # back up, then prune
#   scripts/backup-stalwart.sh --list                       # what is stored
#   scripts/backup-stalwart.sh --fetch <name> <file> <identity>
#                                     # download, check and decrypt one
#   scripts/backup-stalwart.sh --restore <name|file> <identity>
#                                     # check, decrypt and put one back
#
# Stalwart keeps its data in RocksDB, which cannot be copied safely while it
# writes, so Stalwart is stopped for the seconds the copy takes. Senders retry
# mail they could not hand over, so nothing is lost. Mail already delivered
# lives in Kutup (and its database backup), not here.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
label="mail backup"
# shellcheck source=scripts/backup-lib.sh
. "$root_dir/scripts/backup-lib.sh"

backup_store
need_age
prefix="$(setting KUTUP_MAIL_BACKUP_PREFIX)"
prefix="${prefix:-mail-backups}"
keep_days="$(setting KUTUP_BACKUP_KEEP_DAYS)"
keep_days="${keep_days:-30}"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
chmod a+rX "$work_dir"

# The volume mounted as Stalwart's data directory in this deployment.
volume() {
  local container name
  container="$(docker compose ps --all --quiet stalwart)"
  [ -n "$container" ] || fail "no stalwart container (is docker-compose.mail.yml in use?)"
  name="$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/stalwart"}}{{.Name}}{{end}}{{end}}' "$container")"
  [ -n "$name" ] || fail "stalwart has no data volume"
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
    stored_with '\.tar\.gz\.age$' | sed "s#^$prefix/##"
    exit 0
    ;;
  --fetch)
    name="${2:?name of the backup, from --list}"
    target="${3:?file to write the decrypted archive to}"
    identity="${4:?the age identity file (kept offline) that opens the backups}"
    encrypted="$(encrypted_backup "$name")"
    decrypt_checked "$encrypted" "$target" "$identity"
    echo "mail backup: wrote $target, checked"
    exit 0
    ;;
  --restore)
    name="${2:?name of the backup from --list, or a downloaded .tar.gz.age file}"
    identity="${3:?the age identity file (kept offline) that opens the backups}"
    # Checked whole before Stalwart's volume is touched.
    archive="$work_dir/restore.tar.gz"
    encrypted="$(encrypted_backup "$name")"
    decrypt_checked "$encrypted" "$archive" "$identity"
    chmod a+r "$archive"
    data="$(volume)"
    # shellcheck disable=SC2317  # run by with_stalwart_stopped
    restore() {
      docker run --rm -v "$data:/data" -v "$archive:/backup.tar.gz:ro" alpine:3.22 \
        sh -c 'find /data -mindepth 1 -delete && tar -xzf /backup.tar.gz -C /data'
    }
    with_stalwart_stopped restore
    echo "mail backup: restored $data from $name"
    exit 0
    ;;
  "") ;;
  *) echo "mail backup: unknown argument $1" >&2; exit 2 ;;
esac

backup_recipients
data="$(volume)"
name="stalwart-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.age"
copy() {
  docker run --rm -v "$data:/data:ro" alpine:3.22 tar -czf - -C /data . > "$work_dir/plain.tar.gz"
}
with_stalwart_stopped copy
[ -s "$work_dir/plain.tar.gz" ] || fail "the archive is empty"
encrypt "$work_dir/plain.tar.gz" "$work_dir/$name"
rm -f "$work_dir/plain.tar.gz"
size="$(wc -c < "$work_dir/$name")"
chmod a+r "$work_dir/$name"
s3 s3 cp --only-show-errors "/work/$name" "s3://$bucket/$prefix/$name"
echo "mail backup: stored $prefix/$name ($size bytes)"
record_run mail "$name" "$size"

prune 'stalwart-' '.tar.gz.age'
