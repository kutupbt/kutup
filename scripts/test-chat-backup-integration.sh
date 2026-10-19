#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project="${KUTUP_BACKUP_PROJECT:-kutup-chat-backup-test}"
port="${KUTUP_BACKUP_TEST_PORT:-39083}"
db_port="${KUTUP_BACKUP_DB_PORT:-39084}"
s3_port="${KUTUP_BACKUP_S3_PORT:-39085}"
test_admin_username="backupadmin"
test_admin_password="BackupIntegrationAdmin123!"
# username:password (the password may hold colons).
export ADMIN_ACCOUNT="$test_admin_username:$test_admin_password"
# The live tests sign in many times a minute. This stack runs as production
# (RATE_LIMITS_RELAXED is for APP_ENV=test only), so the limits it meets are raised
# one by one.
export RATE_LIMIT_LOGIN_PER_MIN=1000
export RATE_LIMIT_PREFLIGHT_PER_MIN=1000
export RATE_LIMIT_REGISTER_PER_HOUR=1000
# Recovery grants and preflights, from several tests in an hour.
export RATE_LIMIT_RECOVERY_PER_HOUR=1000
# The live tests register their own accounts.
export REGISTRATION_MODE=on
# The device tests register more than 20 devices on one account in a minute.
export RATE_LIMIT_DEVICE_CHALLENGES_PER_MIN=1000
# Held names freed within seconds of their date, for the renames test.
export NAME_SWEEP_SECONDS=2
export POSTGRES_DB="kutup_backup_test"
export POSTGRES_USER="kutup_backup_test"
export POSTGRES_PASSWORD="BackupIntegrationDatabase123!"
export JWT_SECRET="backup-integration-jwt-secret-at-least-32-bytes"
export OPAQUE_SETUP_KEYS="1:0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dE="
# A production server must know where its web apps live; this test only
# talks to the API, so any domain will do.
export KUTUP_BASE_DOMAIN="${KUTUP_BASE_DOMAIN:-backup.test}"

compose() {
  docker compose \
    --project-name "$project" \
    --file "$root_dir/docker-compose.yml" \
    --file "$root_dir/tests/chat-backup/compose.yml" \
    "$@"
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if (( status != 0 )); then
    compose ps >&2
    compose logs --no-color --tail 80 backend >&2
  fi
  compose down --volumes --remove-orphans
  exit "$status"
}
trap cleanup EXIT

compose down --volumes --remove-orphans
compose up --detach --build --wait \
  postgres seaweedfs-master seaweedfs-volume seaweedfs-filer seaweedfs-s3 seaweedfs-init backend

curl --fail --silent --show-error --retry 30 --retry-delay 1 \
  --retry-connrefused --retry-all-errors \
  "http://127.0.0.1:$port/api/health" >/dev/null

KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  cargo test -p kutup-server --test chat_live chat_v1_contract -- --exact --nocapture
# Groups off by default (CHAT_GROUPS unset on this stack): no groups, no
# group calls (though an SFU is configured), every group and MLS route refused.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  cargo test -p kutup-server --test chat_groups_off_live -- --nocapture

# Meetings by link show a vouched-for account by its current name.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  cargo test -p kutup-server --test call_links_live -- --nocapture

# One identity per account (docs/plans/account-identity.md): sign-in by
# name, the key binding, fake answers, temporary passwords.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server --test account_identity_live -- --nocapture
# The group list (docs/plans/pairwise-groups.md §5): sealed entries by keyed
# id, compare-and-swap revisions, the head's chatGroups index.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  cargo test -p kutup-server --test chat_group_list_live -- --nocapture
# Permanent account ids (docs/plans/account-ids.md): minted at sign-up,
# retired on delete, found by id, kept through a rename.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  cargo test -p kutup-server --test account_ids_live -- --nocapture
# Shared mailboxes' keys (docs/plans/mail-groups.md): lists signed by the
# group's signers only, a rotation racing a removal, re-sealing after a reset.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server --test mail_groups_live -- --nocapture --test-threads 1

# Drive: names unique in a folder, as Proton Drive's hashes (required on
# every write, restore under a new name, which names are free), moves, and
# new versions over tus with the uploads table's check. Each test purges its
# accounts, so the purge checks below cover what they stored.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  cargo test -p kutup-server --test unique_names_live -- --nocapture
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  cargo test -p kutup-server --test drive_move_live -- --nocapture
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server --test version_uploads_live -- --nocapture
# Registration modes and referral codes (docs/plans/registration-codes.md):
# one test that switches the mode, so it runs on its own; it puts the mode
# back to on.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  cargo test -p kutup-server --test registration_codes_live -- --nocapture

# The collaboration log over HTTP (the CLI's way in): kept like a socket's
# frame, and every bad frame refused alike on both paths.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  cargo test -p kutup-server --test collab_frames_live -- --nocapture
# Collaboration devices: only the account's own statement registers one.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  cargo test -p kutup-server --test devices_live -- --nocapture

# Remote collaboration devices: only the share recipient's own announced,
# fresh, unrevoked devices; revocations page past one announce.
KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server --bin kutup-server remote_devices::tests -- --nocapture
# OPAQUE sign-in (docs/plans/opaque.md): a login id once, the per-name cap,
# new passwords and recoveries ending sessions, grants bound to their use.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  cargo test -p kutup-server --test opaque_live -- --nocapture
# Sessions, thumbnails and versions: run nowhere else.
for test in sessions_live thumbnails_live versions_live; do
  KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
    KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
    cargo test -p kutup-server --test "$test" -- --nocapture
done
# The account head chain (docs/plans/rollback-protection.md): every listed
# write carries the next head; two first heads at once; a wipe starts again.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  cargo test -p kutup-server --test account_heads_live -- --nocapture
KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server --bin kutup-server account_heads::tests::live_ -- --nocapture

# Username renames (docs/plans/username-renames.md): folded names, the held
# name's fake answer and shared lockout, 409 renamed, holds and freeing.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server --test renames_live -- --nocapture
KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server --bin kutup-server account_names::tests::live_ -- --nocapture
KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server --bin kutup-server remote_renames::tests::live_ -- --nocapture

# A rotation of the OPAQUE setup: an account made under key 1, the server
# restarted with a newer key 2, the account moved at its next sign-in.
rotation_file="$(mktemp)"
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_ROTATION_PHASE=before KUTUP_ROTATION_FILE="$rotation_file" \
  cargo test -p kutup-server --test opaque_rotation_live -- --nocapture
OPAQUE_SETUP_KEYS="$OPAQUE_SETUP_KEYS,2:0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tI=" \
  compose up --detach --wait --force-recreate backend
curl --fail --silent --show-error --retry 30 --retry-delay 1 \
  --retry-connrefused --retry-all-errors \
  "http://127.0.0.1:$port/api/health" >/dev/null
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  KUTUP_ROTATION_PHASE=after KUTUP_ROTATION_FILE="$rotation_file" \
  KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server --test opaque_rotation_live -- --nocapture
rm -f "$rotation_file"

# A wrong OPAQUE_SETUP_KEYS key for a stored setup stops the server.
KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server --bin kutup-server opaque_setup::tests::live_ -- --nocapture

# Kutup Pass on the server: vault secrets, reauth under the sign-in check,
# the PIN's three tries per sign-in.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  cargo test -p kutup-server --test pass_live -- --nocapture

KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server jobs::tests::live_fixed_cutoff_mailbox_retention \
  -- --exact --nocapture

# Sealed federation: a backlog for one server does not starve another.
KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server chat_federation::tests::live_sealed_backlog_does_not_starve_other_destinations \
  -- --exact --nocapture
# Sealed federation queues: a destination's batches below the signature
# check (a mismatch holds nothing behind it, a repeat replays its answers, a
# malformed batch applies nothing) and stale answers at the origin.
KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server --bin kutup-server chat_federation::sealed_live_tests::live_ -- --nocapture

KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  KUTUP_LIVE_S3_ENDPOINT="http://127.0.0.1:$s3_port" \
  KUTUP_LIVE_S3_ACCESS_KEY="${S3_ACCESS_KEY:-kutup}" \
  KUTUP_LIVE_S3_SECRET_KEY="${S3_SECRET_KEY:-kutup_dev_s3_secret}" \
  KUTUP_LIVE_S3_BUCKET="${S3_BUCKET:-kutup-files}" \
  cargo test -p kutup-server jobs::tests::live_fixed_cutoff_delivery_media_retention \
  -- --exact --nocapture

backup_facts="$(compose exec -T postgres psql \
  --username "${POSTGRES_USER:-kutup}" \
  --dbname "${POSTGRES_DB:-kutup}" \
  --tuples-only --no-align \
  --command "SELECT
    (SELECT COUNT(*) FROM chat_backups) +
    (SELECT COUNT(*) FROM chat_backup_provision_operations) +
    (SELECT COUNT(*) FROM chat_backup_segments) +
    (SELECT COUNT(*) FROM chat_backup_device_heads) +
    (SELECT COUNT(*) FROM chat_backup_bases) +
    (SELECT COUNT(*) FROM chat_backup_media_objects) +
    (SELECT COUNT(*) FROM chat_backup_media_references) +
    (SELECT COUNT(*) FROM chat_backup_media_operations) +
    (SELECT COUNT(*) FROM chat_backup_media_reconciliations) +
    (SELECT COUNT(*) FROM chat_backup_media_reconciliation_entries) +
    (SELECT COUNT(*) FROM chat_backup_media_reconciliation_pages),
    COALESCE((SELECT SUM(storage_used_bytes) FROM users), 0);")"
if [[ "$backup_facts" != "0|0" ]]; then
  echo "account purge left backup rows or charged storage bytes: $backup_facts" >&2
  exit 1
fi

backup_objects="$(compose exec -T seaweedfs-filer wget \
  --header=Accept:application/json --quiet --output-document=- \
  "http://seaweedfs-filer:8888/buckets/${S3_BUCKET:-kutup-files}/chat-backup/?pretty=y" \
  2>/dev/null || true)"
if [[ "$backup_objects" =~ \"FileSize\":[[:space:]]+[1-9][0-9]* ]]; then
  echo "account purge left Chat backup object bytes" >&2
  exit 1
fi

# The kutup CLI end to end, as a person runs it: Drive (scripts/verify-cli.sh),
# then Kutup Pass sync between two machines and its SSH agent. Each makes its
# own account with `kutup register`. After the purge checks above, which
# expect no account's bytes left.
for check in verify-cli verify-pass-sync verify-pass-ssh; do
  KUTUP_SERVER="http://127.0.0.1:$port" "$root_dir/scripts/$check.sh"
done
