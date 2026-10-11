#!/usr/bin/env bash
# The mail gate (docs/plans/mail.md): a real Stalwart in front of the
# backend. Mail sent to it over SMTP must arrive encrypted to the address key
# and charged to the pool, and leave no rows or objects once the account is
# deleted; mail between Kutup users must arrive end to end, and mail to the
# outside (a sink standing in for it) must leave DKIM-signed, without Bcc.
# A GnuPG user at outside.test (key served by WKD) gets PGP/MIME that GnuPG
# opens and verifies, and writes back end to end (docs/plans/mail.md, C3).
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
MAIL_INBOUND_TOKEN="$(openssl rand -hex 32)"
export MAIL_INBOUND_TOKEN
export STALWART_ADMIN_SECRET="mail-integration-stalwart-admin-secret"
export RATE_LIMIT_REGISTER_PER_HOUR=100
# Every test signs accounts in; the default per-minute limit trips.
export RATE_LIMIT_LOGIN_PER_MIN=1000
# Key lookups go to the gate's WKD stand-in (only on a test stack).
export APP_ENV=test
export MAIL_OUTSIDE_SENDING=on

command -v gpg >/dev/null || { echo "the mail gate needs GnuPG (gpg)" >&2; exit 1; }
output="$(mktemp)"
# Short, so gpg-agent's socket path fits.
gpg_home="$(mktemp -d /tmp/kutup-gpg.XXXXXX)"
KUTUP_MAIL_KEYS_DIR="$(mktemp -d)"
export KUTUP_MAIL_KEYS_DIR

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
  gpgconf --homedir "$gpg_home" --kill gpg-agent 2>/dev/null
  rm -rf "$output" "$gpg_home" "$KUTUP_MAIL_KEYS_DIR"
  exit "$status"
}
trap cleanup EXIT

# Dave at outside.test: a GnuPG key, published at his domain's Web Key
# Directory (the advanced method's path, under the stand-in's root).
dave="dave@outside.test"
gpg_batch() { gpg --homedir "$gpg_home" --batch --yes --quiet --passphrase '' --pinentry-mode loopback "$@"; }
gpg_batch --quick-gen-key "Dave Outside <$dave>" ed25519 cert,sign 1y
dave_fpr="$(gpg_batch --with-colons --list-keys "$dave" | awk -F: '/^fpr:/ {print $10; exit}')"
gpg_batch --quick-add-key "$dave_fpr" cv25519 encr 1y
wkd_hash="$(gpg_batch --with-wkd-hash --list-keys "$dave" | grep -o '[a-z0-9]\{32\}@outside.test' | head -1 | cut -d@ -f1)"
[[ "$wkd_hash" =~ ^[a-z0-9]{32}$ ]] || { echo "no WKD hash for $dave" >&2; exit 1; }
wkd_dir="$KUTUP_MAIL_KEYS_DIR/openpgpkey.outside.test/.well-known/openpgpkey/outside.test/hu"
mkdir -p "$wkd_dir"
gpg_batch --export "$dave" >"$wkd_dir/$wkd_hash"
chmod -R a+rX "$KUTUP_MAIL_KEYS_DIR"

compose down --volumes --remove-orphans
compose build backend stalwart-setup
compose up --detach --wait \
  postgres seaweedfs-master seaweedfs-volume seaweedfs-filer seaweedfs-s3 seaweedfs-init \
  backend stalwart mail-sink mail-keys
compose run --rm stalwart-setup

curl --fail --silent --show-error --retry 30 --retry-delay 1 \
  --retry-connrefused --retry-all-errors \
  "http://127.0.0.1:$port/api/health" >/dev/null

KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_SMTP="127.0.0.1:$smtp_port" \
  KUTUP_LIVE_ADMIN="$test_admin_email:$test_admin_username:$test_admin_password" \
  KUTUP_LIVE_GPG_HOME="$gpg_home" \
  cargo test -p kutup-server --test mail_inbound_live -- --nocapture --test-threads 1 \
  | tee "$output"

# The first test deleted its account: no mail row or object of it may remain.
purged="$(grep -o 'PURGED-USER [0-9a-f-]*' "$output" | cut -d' ' -f2)"
[[ "$purged" =~ ^[0-9a-f-]{36}$ ]] || { echo "the test did not report its deleted account" >&2; exit 1; }
mail_rows="$(compose exec -T postgres psql \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --tuples-only --no-align \
  --command "SELECT COUNT(*) FROM mail_messages WHERE user_id = '$purged';")"
if [[ "$mail_rows" != "0" ]]; then
  echo "account purge left $mail_rows mail rows" >&2
  exit 1
fi
mail_objects="$(compose exec -T seaweedfs-filer wget \
  --header=Accept:application/json --quiet --output-document=- \
  "http://seaweedfs-filer:8888/buckets/${S3_BUCKET:-kutup-files}/mail/$purged/?pretty=y" \
  2>/dev/null || true)"
if [[ "$mail_objects" =~ \"FileSize\":[[:space:]]+[1-9][0-9]* ]]; then
  echo "account purge left mail object bytes" >&2
  exit 1
fi

# The outside copy reached the sink DKIM-signed by Stalwart, with no Bcc.
outside_id="$(grep -o 'OUTSIDE-MESSAGE-ID [^ ]*' "$output" | cut -d' ' -f2)"
deadline=$((SECONDS + 60))
until compose logs --no-log-prefix mail-sink | grep -q "Message-ID: <$outside_id>"; do
  if (( SECONDS >= deadline )); then
    echo "the outside copy never reached the sink" >&2
    exit 1
  fi
  sleep 1
done
outside="$(compose logs --no-log-prefix mail-sink \
  | awk -v id="<$outside_id>" '/^SINK-MESSAGE-BEGIN/ {m=""; next} /^SINK-MESSAGE-END/ {if (index(m, id)) print m; next} {m = m $0 "\n"}')"
grep -q "^DKIM-Signature: v=1; a=ed25519-sha256" <<<"$outside" || { echo "outside copy is not DKIM-signed" >&2; exit 1; }
if grep -qi "^bcc:\|carol@outside.test" <<<"$(sed '/^$/q' <<<"$outside")"; then
  echo "outside copy shows its Bcc recipient" >&2
  exit 1
fi
# Mail to Dave reached the sink as PGP/MIME: no plaintext on the way, and
# GnuPG opens it and checks Alice's signature.
pgp_id="$(grep -o 'PGP-MESSAGE-ID [^ ]*' "$output" | cut -d' ' -f2)"
pgp_marker="$(grep -o 'PGP-MARKER .*' "$output" | cut -d' ' -f2-)"
[[ -n "$pgp_id" && -n "$pgp_marker" ]] || { echo "the PGP test did not report its message" >&2; exit 1; }
deadline=$((SECONDS + 60))
until compose logs --no-log-prefix mail-sink | grep -q "Message-ID: <$pgp_id>"; do
  if (( SECONDS >= deadline )); then
    echo "the PGP message never reached the sink" >&2
    exit 1
  fi
  sleep 1
done
pgp_message="$(compose logs --no-log-prefix mail-sink \
  | awk -v id="<$pgp_id>" '/^SINK-MESSAGE-BEGIN/ {m=""; next} /^SINK-MESSAGE-END/ {if (index(m, id)) print m; next} {m = m $0 "\n"}')"
grep -q 'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"' <<<"$pgp_message" \
  || { echo "the message to Dave is not PGP/MIME" >&2; exit 1; }
grep -q "^DKIM-Signature: v=1; a=ed25519-sha256" <<<"$pgp_message" || { echo "the PGP message is not DKIM-signed" >&2; exit 1; }
if grep -qF "$pgp_marker" <<<"$pgp_message"; then
  echo "the message to Dave carries its text in clear" >&2
  exit 1
fi
armored="$(sed -n '/-----BEGIN PGP MESSAGE-----/,/-----END PGP MESSAGE-----/p' <<<"$pgp_message" | tr -d '\r')"
gpg_status="$(mktemp)"
plaintext="$(gpg_batch --status-file "$gpg_status" --decrypt <<<"$armored")"
grep -qF "$pgp_marker" <<<"$plaintext" || { echo "GnuPG did not open the message to Dave" >&2; exit 1; }
grep -q '^\[GNUPG:\] GOODSIG' "$gpg_status" || { echo "GnuPG did not verify Alice's signature" >&2; cat "$gpg_status" >&2; exit 1; }
rm -f "$gpg_status"
echo "mail gate passed"
