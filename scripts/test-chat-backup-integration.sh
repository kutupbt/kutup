#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project="${KUTUP_BACKUP_PROJECT:-kutup-chat-backup-test}"
port="${KUTUP_BACKUP_TEST_PORT:-39083}"
db_port="${KUTUP_BACKUP_DB_PORT:-39084}"
s3_port="${KUTUP_BACKUP_S3_PORT:-39085}"
test_admin_email="backup-admin@kutup.dev"
test_admin_username="backupadmin"
test_admin_password="BackupIntegrationAdmin123!"
export ADMIN_ACCOUNT="$test_admin_email:$test_admin_username:$test_admin_password"
export POSTGRES_DB="kutup_backup_test"
export POSTGRES_USER="kutup_backup_test"
export POSTGRES_PASSWORD="BackupIntegrationDatabase123!"
export JWT_SECRET="backup-integration-jwt-secret-at-least-32-bytes"

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
  KUTUP_LIVE_ADMIN="$test_admin_email:$test_admin_password" \
  cargo test -p kutup-server --test chat_live chat_v1_contract -- --exact --nocapture

KUTUP_LIVE_DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:$db_port/$POSTGRES_DB" \
  cargo test -p kutup-server jobs::tests::live_fixed_cutoff_mailbox_retention \
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
    COALESCE((SELECT SUM(chat_storage_used_bytes) FROM users), 0);")"
if [[ "$backup_facts" != "0|0" ]]; then
  echo "account purge left backup rows or charged Chat bytes: $backup_facts" >&2
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
