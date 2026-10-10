#!/usr/bin/env bash
# The mail gate (docs/plans/mail.md): a real Stalwart in front of the
# backend, mail sent to it over SMTP, checked to arrive encrypted to the
# address key and charged to the pool; then the account is deleted and its
# mail rows and objects must be gone.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project="${KUTUP_MAIL_PROJECT:-kutup-mail-test}"
port="${KUTUP_MAIL_TEST_PORT:-39086}"
smtp_port="${KUTUP_MAIL_SMTP_PORT:-39087}"
test_admin_email="mail-admin@kutup.dev"
test_admin_username="mailadmin"
test_admin_password="MailIntegrationAdmin123!"
export KUTUP_MAIL_TEST_PORT="$port"
export ADMIN_ACCOUNT="$test_admin_email:$test_admin_username:$test_admin_password"
export POSTGRES_DB="kutup_mail_test"
export POSTGRES_USER="kutup_mail_test"
export POSTGRES_PASSWORD="MailIntegrationDatabase123!"
export JWT_SECRET="mail-integration-jwt-secret-at-least-32-bytes"
export KUTUP_BASE_DOMAIN="${KUTUP_BASE_DOMAIN:-mail.test}"
export CHAT_SERVER_NAME="kutup.test"
export MAIL_HOSTNAME="mail.kutup.test"
export MAIL_SMTP_PORT="127.0.0.1:$smtp_port"
export MAIL_INBOUND_TOKEN="mail-integration-inbound-token-at-least-32"
export STALWART_ADMIN_SECRET="mail-integration-stalwart-admin-secret"
export RATE_LIMIT_REGISTER_PER_HOUR=100

compose() {
  docker compose \
    --project-name "$project" \
    --file "$root_dir/docker-compose.yml" \
    --file "$root_dir/docker-compose.mail.yml" \
    --file "$root_dir/tests/mail/compose.yml" \
    "$@"
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if (( status != 0 )); then
    compose ps >&2
    compose logs --tail 80 backend stalwart stalwart-setup >&2
  fi
  compose down --volumes --remove-orphans
  exit "$status"
}
trap cleanup EXIT

compose down --volumes --remove-orphans
compose build backend stalwart-setup
compose up --detach --wait \
  postgres seaweedfs-master seaweedfs-volume seaweedfs-filer seaweedfs-s3 seaweedfs-init \
  backend stalwart
compose run --rm stalwart-setup

curl --fail --silent --show-error --retry 30 --retry-delay 1 \
  --retry-connrefused --retry-all-errors \
  "http://127.0.0.1:$port/api/health" >/dev/null

KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_SMTP="127.0.0.1:$smtp_port" \
  KUTUP_LIVE_ADMIN="$test_admin_email:$test_admin_username:$test_admin_password" \
  cargo test -p kutup-server --test mail_inbound_live -- --exact --nocapture \
  mail_from_outside_arrives_encrypted

# The test deleted its account: no mail rows of it may remain, and no mail
# object bytes for anyone (the other test account received none).
mail_rows="$(compose exec -T postgres psql \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --tuples-only --no-align --command "SELECT COUNT(*) FROM mail_messages;")"
if [[ "$mail_rows" != "0" ]]; then
  echo "account purge left $mail_rows mail rows" >&2
  exit 1
fi
mail_objects="$(compose exec -T seaweedfs-filer wget \
  --header=Accept:application/json --quiet --output-document=- \
  "http://seaweedfs-filer:8888/buckets/${S3_BUCKET:-kutup-files}/mail/?pretty=y&recursive=true" \
  2>/dev/null || true)"
if [[ "$mail_objects" =~ \"FileSize\":[[:space:]]+[1-9][0-9]* ]]; then
  echo "account purge left mail object bytes" >&2
  exit 1
fi
echo "mail gate passed"
