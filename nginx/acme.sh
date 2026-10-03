#!/bin/sh
# Gets and renews the Let's Encrypt certificate for Kutup's hostnames
# (docker-compose.acme.yml). Ownership of each name is proved over HTTP:
# Let's Encrypt fetches a file this script puts where nginx serves it on
# port 80, so every name must already point at this machine.
#
# nginx cannot start without a certificate, and the check needs nginx, so
# the first start makes a self-signed one that lasts until the real one
# arrives (browsers warn in between).
set -eu

CERTS=/certs
WEBROOT=/var/www/acme

if [ -n "${KUTUP_ACME_DOMAINS:-}" ]; then
  domains=$(printf '%s' "$KUTUP_ACME_DOMAINS" | tr ',' ' ')
elif [ -n "${KUTUP_BASE_DOMAIN:-}" ]; then
  domains=""
  for app in account drive chat photos maps office; do
    domains="$domains $app.$KUTUP_BASE_DOMAIN"
  done
else
  echo "acme: set KUTUP_BASE_DOMAIN (or KUTUP_ACME_DOMAINS) to the hostnames to certify" >&2
  exit 1
fi
# Names beside the apps: the group-call SFU's, say.
domains="$domains $(printf '%s' "${KUTUP_ACME_EXTRA_DOMAINS:-}" | tr ',' ' ')"
# shellcheck disable=SC2086
set -- $domains
first="$1"

# Test certificates come from Let's Encrypt's staging service, which browsers
# do not trust but which has generous limits. They are kept apart, so turning
# staging off gets a real certificate at once.
if [ "${KUTUP_ACME_STAGING:-0}" = 1 ]; then
  name=kutup-staging
  staging=--staging
else
  name=kutup
  staging=
fi
live="/etc/letsencrypt/live/$name"

install_certificate() {
  # The key first: nginx reloads when the certificate file changes.
  cp -L "$live/privkey.pem" "$CERTS/privkey.pem.new"
  chmod 600 "$CERTS/privkey.pem.new"
  mv "$CERTS/privkey.pem.new" "$CERTS/privkey.pem"
  cp -L "$live/fullchain.pem" "$CERTS/fullchain.pem.new"
  mv "$CERTS/fullchain.pem.new" "$CERTS/fullchain.pem"
  rm -f "$CERTS/.self-signed"
  echo "acme: installed the certificate for$domains"
}

if [ ! -s "$CERTS/fullchain.pem" ] || [ ! -s "$CERTS/privkey.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -days 7 -subj "/CN=$first" \
    -keyout "$CERTS/privkey.pem" -out "$CERTS/fullchain.pem" 2>/dev/null
  chmod 600 "$CERTS/privkey.pem"
  touch "$CERTS/.self-signed"
  echo "acme: made a self-signed certificate so nginx can start"
fi

if [ -n "${KUTUP_ACME_EMAIL:-}" ]; then
  contact="--email $KUTUP_ACME_EMAIL --no-eff-email"
else
  contact="--register-unsafely-without-email"
fi

request=""
for domain in $domains; do
  request="$request -d $domain"
done

while :; do
  # One command for both cases: it issues when there is no certificate or the
  # names changed, renews within 30 days of expiry, and otherwise does nothing.
  # shellcheck disable=SC2086
  if certbot certonly --webroot -w "$WEBROOT" --cert-name "$name" $request \
    $contact --agree-tos --non-interactive --keep-until-expiring \
    --renew-with-new-domains $staging; then
    if [ -e "$CERTS/.self-signed" ] || ! cmp -s "$live/fullchain.pem" "$CERTS/fullchain.pem"; then
      install_certificate
    fi
    sleep 43200
  else
    # Let's Encrypt allows five failed checks an hour for a name.
    echo "acme: no certificate yet; trying again in 15 minutes" >&2
    sleep 900
  fi
done
