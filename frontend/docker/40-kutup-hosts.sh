#!/bin/sh
# Writes the nginx site for the Kutup web apps and the editor sandbox, one
# server block per hostname, from the same settings kutup-server reads:
# KUTUP_{ACCOUNT,DRIVE,CHAT,OFFICE,EDITOR,MAPS,PHOTOS,CONTACTS}_URL, or KUTUP_BASE_DOMAIN for
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
editor=$(origin_of editor KUTUP_EDITOR_URL)
maps=$(origin_of maps KUTUP_MAPS_URL)
photos=$(origin_of photos KUTUP_PHOTOS_URL)
contacts=$(origin_of contacts KUTUP_CONTACTS_URL)
mail=$(origin_of mail KUTUP_MAIL_URL)

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
  editor_origin=$(printf '%s' "$editor" | sed -E 's#^([a-z]+://[^/]+).*#\1#')
  for app in account drive chat maps photos office contacts mail; do
    eval "origin=\$$app"
    host=$(host_of "$origin")
    # The apps' policy. WASM needs 'wasm-unsafe-eval' (and libsodium paths
    # count as eval); in-tab viewers render decrypted PDFs and media from
    # blob: URLs; Chat and collaboration use WebSockets. Office alone, where
    # documents and PDFs open, may frame the editor sandbox; nothing may
    # frame an app.
    frames="'self' blob:"
    if [ "$app" = office ]; then frames="$frames $editor_origin"; fi
    # Mail shows a message's remote images once its reader allows them
    # (its sanitiser blocks them until then).
    images="'self' data: blob:"
    if [ "$app" = mail ]; then images="$images https:"; fi
    app_csp="default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src $images; media-src 'self' blob:; frame-src $frames; frame-ancestors 'self'; connect-src 'self' wss: blob:; worker-src 'self' blob:; font-src 'self' data:"
    cat <<NGINX
server {
    listen 80;
    server_name $host;
    root /usr/share/nginx/html/$app;
    index index.html;
    add_header X-Content-Type-Options nosniff always;
    add_header Content-Security-Policy "$app_csp" always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header Referrer-Policy same-origin always;

    # The Rust runtimes live in directories named for their content hash
    # (frontend/packages/config/vite.ts), which the bundle names: a new
    # build is a new URL, so they are cached for good, like /assets/.
    location ~ "^/(crypto|chat)-wasm/[0-9a-f]{16}/" {
        try_files \$uri =404;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        add_header X-Content-Type-Options nosniff always;
        add_header Content-Security-Policy "$app_csp" always;
        add_header X-Frame-Options SAMEORIGIN always;
    }

    # Anything else there (none is expected) is revalidated.
    location ~ ^/(crypto|chat)-wasm/ {
        try_files \$uri =404;
        add_header Cache-Control "no-cache" always;
        add_header X-Content-Type-Options nosniff always;
        add_header Content-Security-Policy "$app_csp" always;
        add_header X-Frame-Options SAMEORIGIN always;
    }

    # Vite's content-hashed bundles.
    location /assets/ {
        try_files \$uri =404;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        add_header X-Content-Type-Options nosniff always;
        add_header Content-Security-Policy "$app_csp" always;
        add_header X-Frame-Options SAMEORIGIN always;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-cache" always;
        add_header X-Content-Type-Options nosniff always;
        add_header Content-Security-Policy "$app_csp" always;
        add_header X-Frame-Options SAMEORIGIN always;
        add_header Referrer-Policy same-origin always;
    }
}
NGINX
  done
  host=$(host_of "$editor")
  # The same policy as the dev server (frontend/packages/config/vite.ts):
  # OnlyOffice needs eval and inline script, so its origin holds nothing
  # worth stealing and only Office may embed it.
  csp="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; media-src 'self' blob:; connect-src 'self' data: blob:; worker-src 'self' blob:; frame-src 'self' blob:; frame-ancestors 'self' $office; base-uri 'none'; form-action 'none'"
  cat <<NGINX
server {
    listen 80;
    server_name $host;
    root /usr/share/nginx/html/editor;
    add_header Content-Security-Policy "$csp" always;
    add_header Referrer-Policy no-referrer always;
    add_header X-Content-Type-Options nosniff always;

    # The OnlyOffice client and x2t, in directories named for their
    # versions (frontend/Dockerfile): cached for good.
    location ^~ /onlyoffice/dist/ {
        try_files \$uri =404;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        add_header Content-Security-Policy "$csp" always;
        add_header Referrer-Policy no-referrer always;
        add_header X-Content-Type-Options nosniff always;
    }

    # The bridge pages and templates, which name those directories.
    location / {
        try_files \$uri \$uri/ =404;
        add_header Cache-Control "no-cache" always;
        add_header Content-Security-Policy "$csp" always;
        add_header Referrer-Policy no-referrer always;
        add_header X-Content-Type-Options nosniff always;
    }
}
NGINX
} > "$conf"
echo "kutup: serving account=$account drive=$drive chat=$chat maps=$maps photos=$photos office=$office contacts=$contacts mail=$mail editor=$editor"
