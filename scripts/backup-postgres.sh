#!/usr/bin/env bash
# Dumps the PostgreSQL database, encrypts the dump, and stores it in the
# object store Kutup already uses (S3_* in .env), under its own prefix.
# Run it from the deployment's directory, by hand or on a timer
# (docs/self-hosting.md, "Database backups"):
#
#   scripts/backup-postgres.sh            # back up, then prune old backups
#   scripts/backup-postgres.sh --list     # what is stored
#   scripts/backup-postgres.sh --fetch <name> <file>   # download and decrypt one
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
# (docs/self-hosting.md). A dump is encrypted before it leaves
# this machine with KUTUP_BACKUP_PASSPHRASE from .env. Keep a copy of that
# passphrase somewhere else: without it the backups cannot be read, and it
# is lost with this machine otherwise.
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
  [ -n "$value" ] || { echo "backup: set $1 in .env" >&2; exit 1; }
  printf '%s' "$value"
}

[ -f .env ] || { echo "backup: no .env in $root_dir" >&2; exit 1; }
endpoint="$(required S3_ENDPOINT)"
bucket="$(required S3_BUCKET)"
region="$(setting S3_REGION)"
prefix="$(setting KUTUP_BACKUP_PREFIX)"
prefix="${prefix:-database-backups}"
keep_days="$(setting KUTUP_BACKUP_KEEP_DAYS)"
keep_days="${keep_days:-30}"
database="$(setting POSTGRES_DB)"
database_user="$(setting POSTGRES_USER)"
export KUTUP_BACKUP_PASSPHRASE
KUTUP_BACKUP_PASSPHRASE="$(required KUTUP_BACKUP_PASSPHRASE)"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
AWS_ACCESS_KEY_ID="$(required S3_ACCESS_KEY)"
AWS_SECRET_ACCESS_KEY="$(required S3_SECRET_KEY)"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

# Checksums only where S3 requires one, as the server does: several
# S3-compatible stores reject the CLI's default trailers.
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
  # $1: the prefix to list (the database dumps' by default).
  s3 s3api list-objects-v2 --bucket "$bucket" --prefix "${1:-$prefix}/" \
    --query 'Contents[].Key' --output text | tr '\t' '\n' | grep -E '\.dump\.enc$' | sort || true
}
psql_value() {
  docker compose exec -T postgres psql -U "${database_user:-kutup}" -d "${database:-kutup}" -tAc "$1"
}
key_prefix="$prefix-keys"

case "${1:-}" in
  --list)
    stored | sed "s#^$prefix/##"
    stored "$key_prefix" | sed "s#^$key_prefix/#keys: #"
    exit 0
    ;;
  --fetch)
    name="${2:?name of the backup, from --list}"
    target="${3:?file to write the decrypted dump to}"
    # "keys:<name>" fetches a key dump.
    case "$name" in
      keys:*) source_key="$key_prefix/${name#keys:}" ;;
      *) source_key="$prefix/$name" ;;
    esac
    s3 s3 cp --only-show-errors "s3://$bucket/$source_key" /work/fetched.enc
    cipher -d < "$work_dir/fetched.enc" > "$target"
    echo "backup: wrote $target (restore with pg_restore; see docs/self-hosting.md)"
    exit 0
    ;;
  "") ;;
  *) echo "backup: unknown argument $1" >&2; exit 2 ;;
esac

name="kutup-$(date -u +%Y%m%dT%H%M%SZ).dump.enc"
# The custom format is compressed and restores selectively with pg_restore.
docker compose exec -T postgres pg_dump -U "${database_user:-kutup}" -d "${database:-kutup}" -Fc \
  --exclude-schema=account_keys > "$work_dir/plain.dump"
[ -s "$work_dir/plain.dump" ] || { echo "backup: the dump is empty" >&2; exit 1; }
cipher -e < "$work_dir/plain.dump" > "$work_dir/$name"
rm -f "$work_dir/plain.dump"
size="$(wc -c < "$work_dir/$name")"
chmod a+rX "$work_dir" "$work_dir/$name"
s3 s3 cp --only-show-errors "/work/$name" "s3://$bucket/$prefix/$name"
echo "backup: stored $prefix/$name ($size bytes)"

# The account data keys and the destruction log, apart (an empty schema
# still dumps).
key_name="kutup-keys-$(date -u +%Y%m%dT%H%M%SZ).dump.enc"
docker compose exec -T postgres pg_dump -U "${database_user:-kutup}" -d "${database:-kutup}" -Fc \
  --schema=account_keys > "$work_dir/keys.dump"
[ -s "$work_dir/keys.dump" ] || { echo "backup: the key dump is empty" >&2; exit 1; }
cipher -e < "$work_dir/keys.dump" > "$work_dir/$key_name"
rm -f "$work_dir/keys.dump"
chmod a+rX "$work_dir/$key_name"
s3 s3 cp --only-show-errors "/work/$key_name" "s3://$bucket/$key_prefix/$key_name"
echo "backup: stored $key_prefix/$key_name"

# Prune each kind by the date in its names. The newest of each is never removed.
prune() {
  local from="$1" pattern="$2" days="$3" cutoff
  cutoff="$(date -u -d "$days days ago" +%Y%m%dT%H%M%SZ)"
  stored "$from" | sed '$d' | while read -r key; do
    stamp="$(basename "$key" | sed -n "s/^$pattern\([0-9]\{8\}T[0-9]\{6\}Z\)\.dump\.enc$/\1/p")"
    if [ -n "$stamp" ] && [ "$stamp" \< "$cutoff" ]; then
      s3 s3 rm --only-show-errors "s3://$bucket/$key"
      echo "backup: removed $key (older than $days days)"
    fi
  done
}
prune "$prefix" 'kutup-' "$keep_days"
key_keep_days="$(psql_value "SELECT value FROM site_settings WHERE key = 'key_backup_keep_days'" | tr -d '[:space:]')"
case "$key_keep_days" in
  ''|*[!0-9]*) key_keep_days=7 ;;
esac
prune "$key_prefix" 'kutup-keys-' "$key_keep_days"
