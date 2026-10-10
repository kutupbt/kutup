#!/bin/sh
# Brings Stalwart's settings to Kutup's plan (docs/plans/mail.md), then keeps
# its TLS certificate current. Stalwart 0.16 keeps every setting in its own
# database; `stalwart-cli apply` reconciles them with plan.ndjson, which this
# script fills in with the mail domain and host name.
set -eu

: "${STALWART_URL:?}" "${STALWART_USER:?}" "${STALWART_PASSWORD:?}"
: "${MAIL_DOMAIN:?set MAIL_DOMAIN (CHAT_SERVER_NAME), the domain after the @}"
: "${MAIL_HOSTNAME:?set MAIL_HOSTNAME, the mail server name (mail.<domain>)}"
: "${MAIL_INBOUND_TOKEN:?set MAIL_INBOUND_TOKEN}"
# Kutup's sending account signs in with the same secret its LMTP and hook
# use; it is spliced into the plan, so it must be plain.
if ! printf '%s' "$MAIL_INBOUND_TOKEN" | grep -Eq '^[A-Za-z0-9_-]{32,}$'; then
  echo "MAIL_INBOUND_TOKEN must be 32 or more letters, digits, _ or - (openssl rand -hex 32)" >&2
  exit 1
fi
export STALWART_URL STALWART_USER STALWART_PASSWORD

for name in "$MAIL_DOMAIN" "$MAIL_HOSTNAME"; do
  if ! printf '%s' "$name" | grep -Eq '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'; then
    echo "not a lowercase DNS name: $name" >&2
    exit 1
  fi
done

dir=/etc/kutup-stalwart
apply() {
  stalwart-cli apply --quiet --no-color --stdin
}

until wget -q -O /dev/null "$STALWART_URL/healthz/live"; do
  echo "waiting for Stalwart at $STALWART_URL"
  sleep 2
done

sed -e "s/@MAIL_DOMAIN@/$MAIL_DOMAIN/g" -e "s/@MAIL_HOSTNAME@/$MAIL_HOSTNAME/g" \
  -e "s/@MAIL_SUBMISSION_SECRET@/$MAIL_INBOUND_TOKEN/g" "$dir/plan.ndjson" | apply
# The TLS certificate for port 25 comes from the ACME files when they are
# mounted (/certs, root-only); Stalwart (uid 2000) reads its own copy in
# /stalwart-certs. Without them it offers a self-signed one.
copy_certificate() {
  [ -s /certs/fullchain.pem ] && [ -s /certs/privkey.pem ] || return 1
  if cmp -s /certs/fullchain.pem /stalwart-certs/fullchain.pem \
    && cmp -s /certs/privkey.pem /stalwart-certs/privkey.pem; then
    return 2
  fi
  for file in fullchain.pem privkey.pem; do
    install -o 2000 -g 2000 -m 600 "/certs/$file" "/stalwart-certs/$file.new"
    mv "/stalwart-certs/$file.new" "/stalwart-certs/$file"
  done
}
# One Certificate object, created once: it names the files, which Stalwart
# rereads on every certificate reload.
status=0
copy_certificate || status=$?
if [ "$status" -ne 1 ] && [ -z "$(stalwart-cli query Certificate --json --no-color)" ]; then
  apply < "$dir/certificate.ndjson"
fi
# Settings a test stack adds (tests/mail/plan.ndjson); never in production.
if [ -n "${STALWART_EXTRA_PLAN:-}" ]; then
  apply < "$STALWART_EXTRA_PLAN"
fi
# A reload of its own: inside one plan it would run before reconcile's
# removals.
apply < "$dir/reload.ndjson"

# Listeners are bound only when Stalwart starts: if port 25 or the
# submission port does not answer, ask run.sh to restart it.
smtp_host="${STALWART_URL#http://}"
smtp_host="${smtp_host%%:*}"
listening() {
  printf 'QUIT\r\n' | nc -w 3 "$smtp_host" "$1" 2>/dev/null | grep -q '^220'
}
if ! listening 25 || ! listening 2587; then
  echo "$(date +%s)-$$" > /stalwart-control/restart
  tries=0
  until listening 25 && listening 2587; do
    tries=$((tries + 1))
    if [ "$tries" -gt 120 ]; then
      echo "Stalwart did not come back with its listeners" >&2
      exit 1
    fi
    sleep 1
  done
fi
echo "Stalwart is configured for $MAIL_DOMAIN as $MAIL_HOSTNAME"

if [ "${STALWART_WATCH_CERTIFICATES:-0}" = 1 ]; then
  # Let's Encrypt renews a month before expiry; a daily look picks the new
  # certificate up well before the old one ends.
  while sleep 86400; do
    status=0
    copy_certificate || status=$?
    if [ "$status" -eq 0 ]; then
      apply < "$dir/reload-certificates.ndjson" || echo "certificate reload failed; retrying tomorrow" >&2
    fi
  done
fi
