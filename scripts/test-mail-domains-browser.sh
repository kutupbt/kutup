#!/usr/bin/env bash
# Custom domains in the browser (docs/plans/mail-custom-domains.md §11-12):
# the mail gate's stack (Stalwart, and CoreDNS serving the zones the spec
# writes) with the frontend and nginx in front, then the `mail-domains`
# browser suite. The shared DKIM key is published in the server's own zone
# first, as an operator does, so a domain's DKIM can check good.
#
# Runs on master and on demand (CI's mail-domains-browser job); run it
# locally before merging a change to custom domains. One Docker stack at a
# time: it takes ports 38443 and 39086-39088.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project="${KUTUP_MAIL_DOMAINS_PROJECT:-kutup-mail-domains-browser}"
export KUTUP_MAIL_TEST_PORT="${KUTUP_MAIL_TEST_PORT:-39086}"
smtp_port="${KUTUP_MAIL_SMTP_PORT:-39087}"
export KUTUP_MAIL_KEYS_PORT="${KUTUP_MAIL_KEYS_PORT:-39088}"
# The browser specs' administrator (tests/e2e/fixtures/apps.ts).
export ADMIN_ACCOUNT="admin:Bootstrap*Temporary123"
export POSTGRES_DB="kutup_mail_domains"
export POSTGRES_USER="kutup_mail_domains"
export POSTGRES_PASSWORD="MailDomainsBrowserDatabase123!"
export JWT_SECRET="mail-domains-browser-jwt-secret-at-least-32-bytes"
export OPAQUE_SETUP_KEYS="1:wcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcE="
export CHAT_SERVER_NAME="kutup.test"
export MAIL_HOSTNAME="mail.kutup.test"
export MAIL_SMTP_PORT="127.0.0.1:$smtp_port"
MAIL_INBOUND_TOKEN="$(openssl rand -hex 32)"
export MAIL_INBOUND_TOKEN
MAIL_STALWART_DOMAINS_TOKEN="$(openssl rand -hex 32)"
export MAIL_STALWART_DOMAINS_TOKEN
export STALWART_ADMIN_SECRET="mail-domains-browser-stalwart-admin-secret"
export APP_ENV=test
export RATE_LIMITS_RELAXED=true
export REGISTRATION_MODE=on
export MAIL_DEFAULT_DELAY_SEND_SECONDS=0
# One app per hostname; *.localhost resolves to this machine.
export KUTUP_HTTPS_PORT=38443
for app in account drive chat office editor maps photos contacts mail pass calendar; do
  export "KUTUP_${app^^}_URL=https://$app.localhost:38443"
done

KUTUP_MAIL_KEYS_DIR="$(mktemp -d)"
export KUTUP_MAIL_KEYS_DIR
# The zones the spec writes (`<origin>.zone`), served by mail-dns.
KUTUP_MAIL_DNS_DIR="$(mktemp -d)"
chmod a+rx "$KUTUP_MAIL_DNS_DIR" "$KUTUP_MAIL_KEYS_DIR"
export KUTUP_MAIL_DNS_DIR

compose() {
  docker compose \
    --project-name "$project" \
    --file "$root_dir/docker-compose.yml" \
    --file "$root_dir/docker-compose.mail.yml" \
    --file "$root_dir/tests/mail/compose.yml" \
    "$@"
}
psql_stack() {
  compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -tA "$@"
}

made_certs=""
cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if (( status != 0 )); then
    compose ps >&2
    compose logs --tail 80 backend stalwart frontend nginx >&2
  fi
  compose down --volumes --remove-orphans
  rm -rf "$KUTUP_MAIL_KEYS_DIR" "$KUTUP_MAIL_DNS_DIR"
  [[ -n "$made_certs" ]] && rm -f "$root_dir/nginx/certs/fullchain.pem" "$root_dir/nginx/certs/privkey.pem"
  exit "$status"
}
trap cleanup EXIT

# nginx's certificate: the developer's own when present, else a day's one.
if [[ ! -f "$root_dir/nginx/certs/fullchain.pem" ]]; then
  mkdir -p "$root_dir/nginx/certs"
  names="DNS:localhost"
  for app in account drive chat office editor maps photos contacts mail pass calendar; do names="$names,DNS:$app.localhost"; done
  openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
    -keyout "$root_dir/nginx/certs/privkey.pem" -out "$root_dir/nginx/certs/fullchain.pem" \
    -subj /CN=localhost -addext "subjectAltName=$names,IP:127.0.0.1" 2>/dev/null
  made_certs=1
fi

# A zone file as the mail gate's live test writes them (TTL 1s).
write_zone() {
  local origin="$1"
  shift
  {
    printf '$ORIGIN %s.\n$TTL 1\n' "$origin"
    printf '@ IN SOA ns.%s. admin.%s. %s 1 1 1 1\n@ IN NS ns.%s.\nns IN A 127.0.0.1\n' "$origin" "$origin" "$(date +%s)" "$origin"
    printf '%s\n' "$@"
  } >"$KUTUP_MAIL_DNS_DIR/$origin.zone"
}
# A TXT value as zone-file strings of at most 255 bytes.
txt() {
  local value="$1" out=""
  while [[ -n "$value" ]]; do
    out="$out \"${value:0:255}\""
    value="${value:255}"
  done
  printf '%s' "${out# }"
}

spf="_spf IN TXT $(txt 'v=spf1 ip4:0.0.0.0/0 -all')"
write_zone "$CHAT_SERVER_NAME" "$spf"

compose down --volumes --remove-orphans
compose build backend stalwart-setup frontend
compose up --detach --wait \
  postgres seaweedfs-master seaweedfs-volume seaweedfs-filer seaweedfs-s3 seaweedfs-init \
  backend stalwart mail-sink mail-keys mail-dns frontend nginx
compose run --rm stalwart-setup

# The shared DKIM key: made pending by the server, published by "the
# operator", then active (minutes on the test clock).
deadline=$((SECONDS + 120))
selector=""
until [[ -n "$selector" ]]; do
  (( SECONDS < deadline )) || { echo "no DKIM key was made" >&2; exit 1; }
  sleep 2
  selector="$(psql_stack -c "SELECT selector FROM mail_dkim_keys WHERE state = 'pending' LIMIT 1" | tr -d '[:space:]')"
done
spki="$(psql_stack -c "SELECT encode(public_spki, 'base64') FROM mail_dkim_keys WHERE state = 'pending' LIMIT 1" | tr -d '[:space:]')"
write_zone "$CHAT_SERVER_NAME" "$spf" "*.$selector._dk IN TXT $(txt "v=DKIM1; k=rsa; p=$spki")"
deadline=$((SECONDS + 180))
until [[ "$(psql_stack -c "SELECT count(*) FROM mail_dkim_keys WHERE state = 'active'" | tr -d '[:space:]')" == 1 ]]; do
  (( SECONDS < deadline )) || { echo "the DKIM key never became active" >&2; exit 1; }
  sleep 2
done

curl --fail --silent --show-error --insecure --retry 60 --retry-delay 1 \
  --retry-connrefused --retry-all-errors \
  --resolve "account.localhost:38443:127.0.0.1" \
  https://account.localhost:38443/register >/dev/null

E2E_PSQL="docker compose --project-name $project --file $root_dir/docker-compose.yml --file $root_dir/docker-compose.mail.yml --file $root_dir/tests/mail/compose.yml exec -T postgres psql -U $POSTGRES_USER -d $POSTGRES_DB -v ON_ERROR_STOP=1"
export E2E_PSQL
cd "$root_dir"
scripts/gate.sh browser mail-domains
echo "mail domains browser specs passed"
