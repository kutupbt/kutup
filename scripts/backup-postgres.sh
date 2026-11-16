#!/usr/bin/env bash
# Dumps the PostgreSQL database, encrypts the dump with age, and stores it
# in the backup bucket (BACKUP_S3_* in .env: a bucket and key of its own,
# never the data bucket). Run it from the deployment's directory, by hand or
# on a timer (docs/self-hosting.md, "Database backups"):
#
#   scripts/backup-postgres.sh                              # back up, then prune
#   scripts/backup-postgres.sh --list                       # the database dumps
#   scripts/backup-postgres.sh --list-keys                  # the key dumps
#   scripts/backup-postgres.sh --fetch <name|keys:name> <file> <identity>
#                                     # download, check and decrypt one
#   scripts/backup-postgres.sh --restore <name|file> <identity> [<keys name|file>]
#                                     # check, decrypt and pg_restore one, with
#                                     # the newest key dump (or the one named)
#
# The database holds every account, key envelope and object reference; the
# object store holds only ciphertext. The account data keys (the schema
# account_keys, docs/plans/server-personal-data.md, A2) are dumped apart, under
# "<prefix>-keys", and kept only `key_backup_keep_days` (a site setting,
# default 7): a deleted account's key is then in no copy, so what was sealed
# under it can't be read from any backup. The schema also holds the
# destruction log (A7). A restore takes the keys and the log from the newest
# key dump, whichever database dump it restores, and the server, at start,
# deletes again the accounts the log says were deleted since
# (docs/self-hosting.md).
#
# A dump is encrypted on this machine to the public key
# KUTUP_BACKUP_AGE_RECIPIENT; its identity (the private key) is kept
# offline, so this server cannot read its own backups. A backup that was
# changed or cut fails age's check before anything is restored.
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
key_prefix="$prefix-keys"
keep_days="$(setting KUTUP_BACKUP_KEEP_DAYS)"
keep_days="${keep_days:-30}"
database="$(setting POSTGRES_DB)"
database_user="$(setting POSTGRES_USER)"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
chmod a+rX "$work_dir"

psql_in() {
  docker compose exec -T postgres psql -U "${database_user:-kutup}" -d "${database:-kutup}" "$@"
}

# The key dumps, oldest first (backup-lib reads $prefix).
stored_keys() {
  prefix="$key_prefix" stored_with '\.dump\.age$'
}

case "${1:-}" in
  --list)
    stored_with '\.dump\.age$' | sed "s#^$prefix/##"
    exit 0
    ;;
  --list-keys)
    stored_keys | sed "s#^$key_prefix/##"
    exit 0
    ;;
  --fetch)
    name="${2:?name of the backup, from --list (or keys:<name> from --list-keys)}"
    target="${3:?file to write the decrypted dump to}"
    identity="${4:?the age identity file (kept offline) that opens the backups}"
    case "$name" in
      keys:*) encrypted="$(prefix="$key_prefix" encrypted_backup "${name#keys:}")" ;;
      *) encrypted="$(encrypted_backup "$name")" ;;
    esac
    decrypt_checked "$encrypted" "$target" "$identity"
    echo "backup: wrote $target, checked (restore with --restore or pg_restore; see docs/self-hosting.md)"
    exit 0
    ;;
  --restore)
    name="${2:?name of the backup from --list, or a downloaded .dump.age file}"
    identity="${3:?the age identity file (kept offline) that opens the backups}"
    # The account data keys and the destruction log: always the NEWEST key
    # dump, whichever database dump is restored (or the one named).
    keys_name="${4:-}"
    if [ -z "$keys_name" ]; then
      keys_name="$(stored_keys | tail -n 1 | sed "s#^$key_prefix/##")"
      [ -n "$keys_name" ] || fail "no key dump under $key_prefix: a restore needs the account data keys"
    fi
    if [ -n "$(docker compose ps --status running --quiet backend 2>/dev/null)" ]; then
      fail "the backend is running; stop it first (docker compose stop backend), so nothing writes during the restore"
    fi
    # Both checked whole before the database is touched.
    encrypted="$(encrypted_backup "$name")"
    decrypt_checked "$encrypted" "$work_dir/restore.dump" "$identity"
    rm -f "$work_dir/fetched.age"
    encrypted="$(prefix="$key_prefix" encrypted_backup "$keys_name")"
    decrypt_checked "$encrypted" "$work_dir/keys.dump" "$identity"
    started="$(date +%s)"
    docker compose exec -T postgres pg_restore -U "${database_user:-kutup}" -d "${database:-kutup}" \
      --clean --if-exists --no-owner < "$work_dir/restore.dump"
    # Keys of accounts deleted since are in the key dump no more, so their
    # sealed fields stay unreadable; at start the server deletes those
    # accounts again. Keys of accounts made after the database dump go before
    # the foreign keys are added back, which would fail on them.
    docker compose exec -T postgres pg_restore -U "${database_user:-kutup}" -d "${database:-kutup}" \
      --clean --if-exists --no-owner --section=pre-data --section=data < "$work_dir/keys.dump"
    psql_in -v ON_ERROR_STOP=1 \
      -c "DELETE FROM account_keys.account_data_keys k WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.id = k.user_id)" \
      -c "DELETE FROM account_keys.mail_group_data_keys k WHERE NOT EXISTS (SELECT 1 FROM mail_groups g WHERE g.id = k.group_id)" \
      >/dev/null
    docker compose exec -T postgres pg_restore -U "${database_user:-kutup}" -d "${database:-kutup}" \
      --no-owner --exit-on-error --section=post-data < "$work_dir/keys.dump"
    echo "backup: restored $name with keys $keys_name into ${database:-kutup} in $(( $(date +%s) - started )) s"
    exit 0
    ;;
  "") ;;
  *) echo "backup: unknown argument $1" >&2; exit 2 ;;
esac

backup_recipients
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
name="kutup-$stamp.dump.age"
# The custom format is compressed and restores selectively with pg_restore.
docker compose exec -T postgres pg_dump -U "${database_user:-kutup}" -d "${database:-kutup}" -Fc \
  --exclude-schema=account_keys > "$work_dir/plain.dump"
[ -s "$work_dir/plain.dump" ] || fail "the dump is empty"
encrypt "$work_dir/plain.dump" "$work_dir/$name"
rm -f "$work_dir/plain.dump"
size="$(wc -c < "$work_dir/$name")"
chmod a+r "$work_dir/$name"
s3 s3 cp --only-show-errors "/work/$name" "s3://$bucket/$prefix/$name"
echo "backup: stored $prefix/$name ($size bytes)"

# The account data keys and the destruction log, apart (an empty schema
# still dumps).
key_name="kutup-keys-$stamp.dump.age"
docker compose exec -T postgres pg_dump -U "${database_user:-kutup}" -d "${database:-kutup}" -Fc \
  --schema=account_keys > "$work_dir/keys.dump"
[ -s "$work_dir/keys.dump" ] || fail "the key dump is empty"
encrypt "$work_dir/keys.dump" "$work_dir/$key_name"
rm -f "$work_dir/keys.dump"
chmod a+r "$work_dir/$key_name"
s3 s3 cp --only-show-errors "/work/$key_name" "s3://$bucket/$key_prefix/$key_name"
echo "backup: stored $key_prefix/$key_name"
# Recorded once both are stored: a database dump without its keys can't be
# restored.
record_run database "$name" "$size"

prune 'kutup-' '.dump.age'
key_keep_days="$(psql_in -tAc "SELECT value FROM site_settings WHERE key = 'key_backup_keep_days'" | tr -d '[:space:]')"
case "$key_keep_days" in
  ''|*[!0-9]*) key_keep_days=7 ;;
esac
prefix="$key_prefix" keep_days="$key_keep_days" prune 'kutup-keys-' '.dump.age'
