#!/usr/bin/env bash
# Dumps the PostgreSQL database, encrypts the dump with age, and stores it
# in the backup bucket (BACKUP_S3_* in .env: a bucket and key of its own,
# never the data bucket). Run it from the deployment's directory, by hand or
# on a timer (docs/self-hosting.md, "Database backups"):
#
#   scripts/backup-postgres.sh                              # back up, then prune
#   scripts/backup-postgres.sh --list                       # what is stored
#   scripts/backup-postgres.sh --fetch <name> <file> <identity>
#                                     # download, check and decrypt one
#   scripts/backup-postgres.sh --restore <name|file> <identity>
#                                     # check, decrypt and pg_restore one
#
# The database holds every account, key envelope and object reference; the
# object store holds only ciphertext. A dump is encrypted on this machine to
# the public key KUTUP_BACKUP_AGE_RECIPIENT; its identity (the private key)
# is kept offline, so this server cannot read its own backups. A backup that
# was changed or cut fails age's check before anything is restored.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
label=backup
# shellcheck source=scripts/backup-lib.sh
. "$root_dir/scripts/backup-lib.sh"

backup_store
need_age
prefix="$(setting KUTUP_BACKUP_PREFIX)"
prefix="${prefix:-database-backups}"
keep_days="$(setting KUTUP_BACKUP_KEEP_DAYS)"
keep_days="${keep_days:-30}"
database="$(setting POSTGRES_DB)"
database_user="$(setting POSTGRES_USER)"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
chmod a+rX "$work_dir"

case "${1:-}" in
  --list)
    stored_with '\.dump\.age$' | sed "s#^$prefix/##"
    exit 0
    ;;
  --fetch)
    name="${2:?name of the backup, from --list}"
    target="${3:?file to write the decrypted dump to}"
    identity="${4:?the age identity file (kept offline) that opens the backups}"
    encrypted="$(encrypted_backup "$name")"
    decrypt_checked "$encrypted" "$target" "$identity"
    echo "backup: wrote $target, checked (restore with --restore or pg_restore; see docs/self-hosting.md)"
    exit 0
    ;;
  --restore)
    name="${2:?name of the backup from --list, or a downloaded .dump.age file}"
    identity="${3:?the age identity file (kept offline) that opens the backups}"
    if [ -n "$(docker compose ps --status running --quiet backend 2>/dev/null)" ]; then
      fail "the backend is running; stop it first (docker compose stop backend), so nothing writes during the restore"
    fi
    # Checked whole before the database is touched.
    encrypted="$(encrypted_backup "$name")"
    decrypt_checked "$encrypted" "$work_dir/restore.dump" "$identity"
    started="$(date +%s)"
    docker compose exec -T postgres pg_restore -U "${database_user:-kutup}" -d "${database:-kutup}" \
      --clean --if-exists --no-owner < "$work_dir/restore.dump"
    echo "backup: restored $name into ${database:-kutup} in $(( $(date +%s) - started )) s"
    exit 0
    ;;
  "") ;;
  *) echo "backup: unknown argument $1" >&2; exit 2 ;;
esac

backup_recipients
name="kutup-$(date -u +%Y%m%dT%H%M%SZ).dump.age"
# The custom format is compressed and restores selectively with pg_restore.
docker compose exec -T postgres pg_dump -U "${database_user:-kutup}" -d "${database:-kutup}" -Fc \
  > "$work_dir/plain.dump"
[ -s "$work_dir/plain.dump" ] || fail "the dump is empty"
encrypt "$work_dir/plain.dump" "$work_dir/$name"
rm -f "$work_dir/plain.dump"
size="$(wc -c < "$work_dir/$name")"
chmod a+r "$work_dir/$name"
s3 s3 cp --only-show-errors "/work/$name" "s3://$bucket/$prefix/$name"
echo "backup: stored $prefix/$name ($size bytes)"
record_run database "$name" "$size"

prune 'kutup-' '.dump.age'
