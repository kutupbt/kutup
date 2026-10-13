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
export POSTGRES_DB="kutup_backup_test"
export POSTGRES_USER="kutup_backup_test"
export POSTGRES_PASSWORD="BackupIntegrationDatabase123!"
export JWT_SECRET="backup-integration-jwt-secret-at-least-32-bytes"
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

# One identity per account (docs/plans/account-identity.md): sign-in by
# name, the key binding, fake answers, temporary passwords.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server --test account_identity_live -- --nocapture

KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server jobs::tests::live_fixed_cutoff_mailbox_retention \
  -- --exact --nocapture

# Sealed federation: a backlog for one server does not starve another.
KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server chat_federation::tests::live_sealed_backlog_does_not_starve_other_destinations \
  -- --exact --nocapture

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

# Drive: names unique in a folder, as Proton Drive's hashes (required on
# every write, restore under a new name, which names are free), and moves.
# After the purge checks above: these leave their files in place.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  cargo test -p kutup-server --test unique_names_live -- --nocapture
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  cargo test -p kutup-server --test drive_move_live -- --nocapture
# New versions over tus (Replace at any size), and the uploads table's check.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server --test version_uploads_live -- --nocapture

# Kutup Pass on the server: vault secrets, reauth under the sign-in check,
# the PIN's three tries per sign-in. After the purge checks: it keeps its
# vaults.
KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  cargo test -p kutup-server --test pass_live -- --nocapture
