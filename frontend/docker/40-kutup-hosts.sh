#!/bin/sh
# Writes the nginx site for the four Kutup web apps, one server block per
# hostname, from the same settings kutup-server reads:
# KUTUP_{ACCOUNT,DRIVE,CHAT,OFFICE}_URL, or KUTUP_BASE_DOMAIN for
# https://<app>.<domain>. The reverse proxy in front terminates TLS and must
# pass the Host header through.
set -eu

origin_of() {
  app=$1
  var=$2
  eval "value=\${$var:-}"
  if [ -z "$value" ]; then
    if [ -z "${KUTUP_BASE_DOMAIN:-}" ]; then
      echo "kutup: set KUTUP_BASE_DOMAIN or $var" >&2
      exit 1
    fi
    value="https://$app.$KUTUP_BASE_DOMAIN"
  fi
  printf '%s' "$value" | sed -E 's#/+$##'
}

host_of() {
  printf '%s' "$1" | sed -E 's#^[a-z]+://##; s#[:/].*$##'
}

account=$(origin_of account KUTUP_ACCOUNT_URL)
drive=$(origin_of drive KUTUP_DRIVE_URL)
chat=$(origin_of chat KUTUP_CHAT_URL)
office=$(origin_of office KUTUP_OFFICE_URL)

conf=/etc/nginx/conf.d/kutup.conf
{
  cat <<'NGINX'
# Generated at start by 40-kutup-hosts.sh.
server {
    listen 80 default_server;
    server_name _;
    return 404;
}
NGINX
  for app in account drive chat; do
    eval "origin=\$$app"
    host=$(host_of "$origin")
    cat <<NGINX
server {
    listen 80;
    server_name $host;
    root /usr/share/nginx/html/$app;
    index index.html;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy same-origin always;

    # wasm-bindgen emits stable filenames: revalidate so a deployment never
    # pairs an old Rust ABI with a new bundle.
    location ~ ^/(crypto|chat)-wasm/ {
        try_files \$uri =404;
        add_header Cache-Control "no-cache" always;
        add_header X-Content-Type-Options nosniff always;
    }

    # Vite's content-hashed bundles.
    location /assets/ {
        try_files \$uri =404;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        add_header X-Content-Type-Options nosniff always;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-cache" always;
        add_header X-Content-Type-Options nosniff always;
        add_header Referrer-Policy same-origin always;
    }
}
NGINX
  done
  host=$(host_of "$office")
  # The same policy as the dev server (frontend/packages/config/vite.ts):
  # OnlyOffice needs eval and inline script, so its origin holds nothing
  # worth stealing and only Drive may embed it.
  csp="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; media-src 'self' blob:; connect-src 'self' data: blob:; worker-src 'self' blob:; frame-src 'self' blob:; frame-ancestors 'self' $drive; base-uri 'none'; form-action 'none'"
  cat <<NGINX
server {
    listen 80;
    server_name $host;
    root /usr/share/nginx/html/office;
    add_header Content-Security-Policy "$csp" always;
    add_header Referrer-Policy no-referrer always;
    add_header X-Content-Type-Options nosniff always;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
NGINX
} > "$conf"
echo "kutup: serving account=$account drive=$drive chat=$chat office=$office"
