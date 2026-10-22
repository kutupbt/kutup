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
keys_port="${KUTUP_MAIL_KEYS_PORT:-39088}"
export KUTUP_MAIL_KEYS_PORT="$keys_port"
test_admin_username="mailadmin"
test_admin_password="MailIntegrationAdmin123!"
export KUTUP_MAIL_TEST_PORT="$port"
export ADMIN_ACCOUNT="$test_admin_username:$test_admin_password"
export POSTGRES_DB="kutup_mail_test"
export POSTGRES_USER="kutup_mail_test"
export POSTGRES_PASSWORD="MailIntegrationDatabase123!"
export JWT_SECRET="mail-integration-jwt-secret-at-least-32-bytes"
export OPAQUE_SETUP_KEYS="1:wcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcE="
export KUTUP_BASE_DOMAIN="${KUTUP_BASE_DOMAIN:-mail.test}"
export CHAT_SERVER_NAME="kutup.test"
export MAIL_HOSTNAME="mail.kutup.test"
export MAIL_SMTP_PORT="127.0.0.1:$smtp_port"
MAIL_INBOUND_TOKEN="$(openssl rand -hex 32)"
export MAIL_INBOUND_TOKEN
export STALWART_ADMIN_SECRET="mail-integration-stalwart-admin-secret"
export RATE_LIMIT_REGISTER_PER_HOUR=100
# The live tests register their own accounts.
export REGISTRATION_MODE=on
# Every test signs accounts in; the default per-minute limit trips.
export RATE_LIMIT_LOGIN_PER_MIN=1000
# The custom domains test checks its domains many times in a minute.
export RATE_LIMIT_MAIL_DOMAIN_CHECKS_PER_HOUR=1000
# Key lookups go to the gate's WKD stand-in (only on a test stack).
export APP_ENV=test
export MAIL_OUTSIDE_SENDING=on
# Select all in chunks of 2, so the live tests cross chunk boundaries.
export MAIL_BATCH_CHUNK=2

command -v gpg >/dev/null || { echo "the mail gate needs GnuPG (gpg)" >&2; exit 1; }
output="$(mktemp)"
# Short, so gpg-agent's socket path fits.
gpg_home="$(mktemp -d /tmp/kutup-gpg.XXXXXX)"
KUTUP_MAIL_KEYS_DIR="$(mktemp -d)"
export KUTUP_MAIL_KEYS_DIR
# Custom domains' zones, written by the live test, served by mail-dns.
KUTUP_MAIL_DNS_DIR="$(mktemp -d)"
chmod a+rx "$KUTUP_MAIL_DNS_DIR"
export KUTUP_MAIL_DNS_DIR
# The scoped Stalwart key custom domains are managed with (stalwart-setup
# makes its account; the backend holds the same secret).
MAIL_STALWART_DOMAINS_TOKEN="$(openssl rand -hex 32)"
export MAIL_STALWART_DOMAINS_TOKEN

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
  rm -rf "$output" "$gpg_home" "$KUTUP_MAIL_KEYS_DIR" "$KUTUP_MAIL_DNS_DIR"
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
  backend stalwart mail-sink mail-keys mail-dns
compose run --rm stalwart-setup
# The custom domains' account signs in (stalwart/plan-domains.ndjson), from
# inside Stalwart's container: its management port is never published.
compose exec -T stalwart curl -fsS -o /dev/null \
  -u "kutup-domains@$CHAT_SERVER_NAME:$MAIL_STALWART_DOMAINS_TOKEN" \
  http://127.0.0.1:8080/jmap/session \
  || { echo "the custom domains account can't sign in to Stalwart" >&2; exit 1; }
# ... and manages domains and nothing else: through submission (2587) it can't
# send, whatever sender it names. Stalwart must answer with a refusal (5xx to
# AUTH, MAIL or RCPT), so a connection that failed for another reason can't
# pass for one.
if smtp_log="$(compose exec -T stalwart sh -c \
  "printf 'Subject: x\r\n\r\nx\r\n' | curl -sv --max-time 20 smtp://127.0.0.1:2587 \
     --mail-from postmaster@$CHAT_SERVER_NAME --mail-rcpt someone@outside.test \
     -u 'kutup-domains@$CHAT_SERVER_NAME:$MAIL_STALWART_DOMAINS_TOKEN' -T - 2>&1")"; then
  echo "the custom domains account sent mail through submission" >&2
  exit 1
fi
if ! grep -Eq '^< 5[0-9][0-9]' <<<"$smtp_log"; then
  echo "submission didn't refuse the custom domains account itself:" >&2
  echo "$smtp_log" >&2
  exit 1
fi

curl --fail --silent --show-error --retry 30 --retry-delay 1 \
  --retry-connrefused --retry-all-errors \
  "http://127.0.0.1:$port/api/health" >/dev/null

KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
  KUTUP_LIVE_SMTP="127.0.0.1:$smtp_port" \
  KUTUP_LIVE_FORWARDING_KEY="Zm9yd2FyZGluZy10ZXN0LWtleS0wMTIzNDU2Nzg5YWI=" \
  KUTUP_LIVE_KEYS="http://127.0.0.1:$keys_port" \
  KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
  KUTUP_LIVE_GPG_HOME="$gpg_home" \
  KUTUP_LIVE_DNS_DIR="$KUTUP_MAIL_DNS_DIR" \
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
# Mail from a custom domain's address left signed for that domain, with the
# shared key behind its CNAMEs (docs/plans/mail-custom-domains.md §4).
domain_id="$(grep -o 'DOMAIN-OUTSIDE-ID [^ ]*' "$output" | cut -d' ' -f2)"
[[ -n "$domain_id" ]] || { echo "the custom domains test did not report its message" >&2; exit 1; }
deadline=$((SECONDS + 60))
until compose logs --no-log-prefix mail-sink | grep -q "Message-ID: <$domain_id>"; do
  if (( SECONDS >= deadline )); then
    echo "the custom domain's message never reached the sink" >&2
    exit 1
  fi
  sleep 1
done
domain_message="$(compose logs --no-log-prefix mail-sink \
  | awk -v id="<$domain_id>" '/^SINK-MESSAGE-BEGIN/ {m=""; next} /^SINK-MESSAGE-END/ {if (index(m, id)) print m; next} {m = m $0 "\n"}')"
grep -q "^DKIM-Signature: v=1; a=rsa-sha256;.*d=customer.test" <<<"$(tr -d '\r' <<<"$domain_message" | sed ':a;N;$!ba;s/\n[ \t]\+/ /g')" \
  || { echo "the custom domain's message is not signed for customer.test" >&2; exit 1; }
echo "CUSTOM DOMAINS VERIFIED"
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
# Forwarding outside Kutup (docs/plans/mail-forwarding.md), in phases: the
# confirmation link reaches the sink, its token goes back to the test, and
# what the address receives afterwards reaches the sink carrying our marker
# and DKIM; end-to-end Kutup mail doesn't.
sink_message() {
  compose logs --no-log-prefix mail-sink \
    | awk -v needle="$1" '/^SINK-MESSAGE-BEGIN/ {m=""; next} /^SINK-MESSAGE-END/ {if (index(m, needle)) print m; next} {m = m $0 "\n"}'
}
wait_sink() {
  local deadline=$((SECONDS + 60))
  until [[ -n "$(sink_message "$1")" ]]; do
    if (( SECONDS >= deadline )); then
      echo "nothing reached the sink with $1" >&2
      return 1
    fi
    sleep 1
  done
}
forward_state="$(mktemp)"
forward_output="$(mktemp)"
run_forward() {
  KUTUP_LIVE_SERVER="http://127.0.0.1:$port" \
    KUTUP_LIVE_SMTP="127.0.0.1:$smtp_port" \
  KUTUP_LIVE_FORWARDING_KEY="Zm9yd2FyZGluZy10ZXN0LWtleS0wMTIzNDU2Nzg5YWI=" \
    KUTUP_LIVE_ADMIN="$test_admin_username:$test_admin_password" \
    KUTUP_LIVE_FORWARD_PHASE="$1" \
    KUTUP_LIVE_FORWARD_STATE="$forward_state" \
    KUTUP_LIVE_FORWARD_TOKEN="${2:-}" \
    KUTUP_LIVE_FORWARD_CODE="${3:-}" \
    cargo test -p kutup-server --test mail_inbound_live outside_forwarding -- --exact --nocapture \
    | tee -a "$forward_output"
}
run_forward setup
forward_to="$(grep -o 'FORWARD-OUTSIDE-TO [^ ]*' "$forward_output" | cut -d' ' -f2)"
[[ -n "$forward_to" ]] || { echo "the forwarding test did not report its forwardee" >&2; exit 1; }
# Only the code mail has gone to it yet.
wait_sink "$forward_to"
forward_mail="$(sink_message "$forward_to")"
forward_token="$(grep -o '/email-forwarding#[A-Za-z0-9_-]*' <<<"$forward_mail" | head -1 | cut -d'#' -f2)"
[[ "$forward_token" =~ ^[A-Za-z0-9_-]{43}$ ]] || { echo "no stop link reached $forward_to" >&2; exit 1; }
forward_code="$(grep -o 'Verification code: [0-9]\{6\}' <<<"$forward_mail" | head -1 | cut -d' ' -f3)"
[[ "$forward_code" =~ ^[0-9]{6}$ ]] || { echo "no verification code reached $forward_to" >&2; exit 1; }
grep -q "^From: .*<postmaster@" <<<"$forward_mail" \
  || { echo "the code is not from the system sender" >&2; exit 1; }
grep -q "^DKIM-Signature: v=1; a=ed25519-sha256" <<<"$forward_mail" \
  || { echo "the code mail is not DKIM-signed" >&2; exit 1; }
run_forward confirm "$forward_token" "$forward_code"
for expected in $(grep -o 'FORWARD-EXPECT [^ ]*' "$forward_output" | cut -d' ' -f2); do
  wait_sink "Message-ID: <$expected>"
  forwarded="$(sink_message "Message-ID: <$expected>")"
  grep -q "^X-Kutup-Forwarded: [0-9a-f]\{16\}" <<<"$forwarded" \
    || { echo "the forward of $expected carries no marker" >&2; exit 1; }
  grep -q "^DKIM-Signature: v=1; a=ed25519-sha256" <<<"$forwarded" \
    || { echo "the forward of $expected is not DKIM-signed" >&2; exit 1; }
  # From our return path: fwd-<forwarding>-<day>-<hmac>@<server>.
  grep -q "^X-Sink-Envelope-From: <fwd-[0-9a-f]\{32\}-[0-9]\+-[0-9a-f]\{16\}@" <<<"$forwarded" \
    || { echo "the forward of $expected is not from our return path" >&2; exit 1; }
done
# Both: outside mail that arrived for the address, and readable Kutup mail.
(( $(grep -c 'FORWARD-EXPECT ' "$forward_output") == 2 )) \
  || { echo "the forwarding test did not report its two forwards" >&2; exit 1; }
for unexpected in $(grep -o 'FORWARD-NOT [^ ]*' "$forward_output" | cut -d' ' -f2); do
  if [[ -n "$(sink_message "Message-ID: <$unexpected>")" ]]; then
    echo "$unexpected was forwarded outside (end-to-end, or a loop)" >&2
    exit 1
  fi
done
run_forward end
rm -f "$forward_state" "$forward_output"
echo "OUTSIDE FORWARDING VERIFIED"

echo "mail gate passed"
