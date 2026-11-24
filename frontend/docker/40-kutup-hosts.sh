#!/bin/sh
# Writes the nginx site for the Kutup web apps and the editor sandbox, one
# server block per hostname, from the same settings kutup-server reads:
# KUTUP_{ACCOUNT,DRIVE,CHAT,OFFICE,EDITOR,MAPS,PHOTOS,CONTACTS,MAIL,PASS,CALENDAR}_URL,
# or KUTUP_BASE_DOMAIN for https://<app>.<domain>. The reverse proxy in front
# terminates TLS and must pass the Host header through.
#
# Content-Security-Policy (docs/content-security-policy.md): every app has a
# strict policy, one base plus a few additions per app. Until
# KUTUP_CSP_ENFORCE=1 it is sent as Content-Security-Policy-Report-Only
# beside the older, looser policy, which stays enforced; browsers report
# what the strict one would block to /api/csp-report. KUTUP_CSP_ENFORCE=1
# enforces the strict policy and drops the old one. Also read:
# CHAT_SFU_URL (the group-call SFU Chat connects to) and
# KUTUP_MAP_DIRECT_ORIGINS (map providers browsers may load directly).
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

# scheme://host[:port] of a URL.
bare_origin() {
  printf '%s' "$1" | sed -E 's#^([a-z]+://[^/?#]+).*#\1#'
}

# The WebSocket origin of an http(s) origin: ws:// for http, wss:// for https.
ws_origin() {
  printf '%s' "$1" | sed -E 's#^http(s?)://#ws\1://#'
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
pass=$(origin_of pass KUTUP_PASS_URL)
calendar=$(origin_of calendar KUTUP_CALENDAR_URL)

case "${KUTUP_CSP_ENFORCE:-}" in
  1 | true) enforce=1 ;;
  '' | 0 | false) enforce=0 ;;
  *)
    echo "kutup: KUTUP_CSP_ENFORCE must be 1 or 0, not '$KUTUP_CSP_ENFORCE'" >&2
    exit 1
    ;;
esac

# The group-call SFU (CHAT_SFU_URL, wss://sfu.<domain>): its WebSocket and
# the same host over http(s), which LiveKit's client also asks.
sfu=""
if [ -n "${CHAT_SFU_URL:-}" ]; then
  case "$CHAT_SFU_URL" in
    ws://* | wss://* | http://* | https://*) ;;
    *)
      echo "kutup: CHAT_SFU_URL must be a ws(s):// or http(s):// URL" >&2
      exit 1
      ;;
  esac
  sfu_origin=$(bare_origin "$CHAT_SFU_URL")
  sfu_ws=$(printf '%s' "$sfu_origin" | sed -E 's#^http(s?)://#ws\1://#')
  sfu_http=$(printf '%s' "$sfu_ws" | sed -E 's#^ws(s?)://#http\1://#')
  sfu="$sfu_ws $sfu_http"
fi

# Map providers browsers may load from directly (KUTUP_MAP_DIRECT_ORIGINS;
# the server offers direct loading only for these). Empty: every map comes
# through the server's relay, on the app's own origin.
map_direct=""
for item in $(printf '%s' "${KUTUP_MAP_DIRECT_ORIGINS:-}" | tr ',' ' '); do
  item=$(printf '%s' "$item" | sed -E 's#/+$##')
  if ! printf '%s' "$item" | grep -Eq '^https?://[A-Za-z0-9.-]+(:[0-9]+)?$'; then
    echo "kutup: KUTUP_MAP_DIRECT_ORIGINS takes bare http(s) origins, not '$item'" >&2
    exit 1
  fi
  map_direct="$map_direct $item"
done

editor_origin=$(bare_origin "$editor")

# The strict policy for one app ($1, its origin $2).
strict_policy() {
  app=$1
  origin=$2
  connect="'self' $(ws_origin "$origin")"
  images="'self' data: blob:"
  frames="'none'"
  # <style> elements only with this response's nonce ($request_id, which
  # the page's <meta name="csp-nonce"> also gets; see the index.html
  # location below). Style attributes in markup: none, but where the next
  # case allows them.
  styles="'self' 'nonce-\$request_id'"
  style_attrs=""
  # The apps that draw maps (@kutup/map): direct providers' tiles, styles
  # and glyphs are fetched, raster tiles also drawn as images.
  case "$app" in
    account | chat | maps | photos)
      if [ -n "$map_direct" ]; then
        connect="$connect$map_direct"
        images="$images$map_direct"
      fi
      ;;
  esac
  case "$app" in
    # Quick Look shows PDFs in a frame of their decrypted blob: URL.
    # Whiteboards, diagrams and maths (Excalidraw, mermaid, KaTeX) write
    # style attributes into the SVG and HTML they make.
    drive)
      frames="blob:"
      style_attrs="; style-src-attr 'unsafe-inline'"
      ;;
    # Photos reads a decrypted original back from its blob: URL to convert it.
    photos) connect="$connect blob:" ;;
    # Group calls; PDF attachments in a blob: frame.
    chat)
      connect="$connect$(if [ -n "$sfu" ]; then printf ' %s' "$sfu"; fi)"
      frames="blob:"
      ;;
    # The message body is a sandboxed srcdoc frame (it inherits this policy);
    # PDF attachments open in a blob: frame. Remote images come through the
    # image proxy as blob: URLs: no https: here.
    # Messages keep their senders' style attributes (sanitized; the frame
    # inherits this policy).
    mail)
      frames="blob:"
      style_attrs="; style-src-attr 'unsafe-inline'"
      ;;
    # Documents and PDFs open in the editor sandbox; viewers in blob: frames.
    # Whiteboards, diagrams and maths, as in Drive.
    office)
      frames="$editor_origin blob:"
      style_attrs="; style-src-attr 'unsafe-inline'"
      ;;
    # Site icons come back from the server as blob: URLs that are read again.
    pass) connect="$connect blob:" ;;
  esac
  printf '%s' "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src $styles$style_attrs; img-src $images; font-src 'self' data:; media-src 'self' blob:; connect-src $connect; worker-src 'self'; manifest-src 'self'; frame-src $frames; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; report-uri /api/csp-report; report-to kutup-csp"
}

# The policy enforced before the strict one (until KUTUP_CSP_ENFORCE=1). WASM
# needs 'wasm-unsafe-eval'; in-tab viewers render decrypted PDFs and media
# from blob: URLs; Chat and collaboration use WebSockets. Office alone may
# frame the editor sandbox; nothing may frame an app. Mail shows a message's
# remote images once its reader allows them.
old_policy() {
  app=$1
  frames="'self' blob:"
  if [ "$app" = office ]; then frames="$frames $editor_origin"; fi
  images="'self' data: blob:"
  if [ "$app" = mail ]; then images="$images https:"; fi
  connect="'self' wss: blob:"
  case "$app" in
    account | chat | maps | photos)
      if [ -n "$map_direct" ]; then
        connect="$connect$map_direct"
        images="$images$map_direct"
      fi
      ;;
  esac
  if [ "$app" = pass ]; then
    printf '%s' "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; frame-src 'none'; frame-ancestors 'none'; connect-src $connect; worker-src 'self' blob:; font-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'"
  else
    printf '%s' "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src $images; media-src 'self' blob:; frame-src $frames; frame-ancestors 'self'; connect-src $connect; worker-src 'self' blob:; font-src 'self' data:"
  fi
}

# The editor sandbox: OnlyOffice needs eval and inline script, so its origin
# holds nothing worth stealing (no API: the reverse proxy answers 404 for
# /api/ there) and only Office may embed it. 'self' in frame-ancestors:
# OnlyOffice nests its own editor frame inside the bridge, and the check
# covers every ancestor. The same policy as the dev server
# (frontend/packages/config/vite.ts).
editor_old="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; media-src 'self' blob:; connect-src 'self' data: blob:; worker-src 'self' blob:; frame-src 'self' blob:; frame-ancestors 'self' $office; base-uri 'none'; form-action 'none'"
editor_strict="$editor_old; object-src 'none'"

# The header lines every response of a site carries ($1 the indent), from
# $csp_lines, $frame_options and $referrer.
headers() {
  indent=$1
  printf '%s\n' "$csp_lines" | while IFS= read -r line; do
    [ -n "$line" ] && printf '%s%s\n' "$indent" "$line"
  done
  printf '%sadd_header X-Content-Type-Options nosniff always;\n' "$indent"
  if [ -n "$frame_options" ]; then printf '%sadd_header X-Frame-Options %s always;\n' "$indent" "$frame_options"; fi
  printf '%sadd_header Referrer-Policy %s always;\n' "$indent" "$referrer"
}

conf=${KUTUP_NGINX_CONF:-/etc/nginx/conf.d/kutup.conf}
{
  cat <<'NGINX'
# Generated at start by 40-kutup-hosts.sh.
server {
    listen 80 default_server;
    server_name _;
    return 404;
}
NGINX
  for app in account drive chat maps photos office contacts mail pass calendar; do
    eval "origin=\$$app"
    host=$(host_of "$origin")
    strict=$(strict_policy "$app" "$origin")
    reporting="add_header Reporting-Endpoints 'kutup-csp=\"$origin/api/csp-report\"' always;"
    if [ "$enforce" = 1 ]; then
      csp_lines="add_header Content-Security-Policy \"$strict\" always;
$reporting"
      frame_options=DENY
    else
      csp_lines="add_header Content-Security-Policy \"$(old_policy "$app")\" always;
add_header Content-Security-Policy-Report-Only \"$strict\" always;
$reporting"
      frame_options=SAMEORIGIN
      if [ "$app" = pass ]; then frame_options=DENY; fi
    fi
    referrer=same-origin
    cat <<NGINX
server {
    listen 80;
    server_name $host;
    root /usr/share/nginx/html/$app;
    index index.html;
$(headers '    ')

    # The Rust runtimes live in directories named for their content hash
    # (frontend/packages/config/vite.ts), which the bundle names: a new
    # build is a new URL, so they are cached for good, like /assets/.
    location ~ "^/(crypto|crypto-calendar|calendar-ics|chat|pass|mail-search)-wasm/[0-9a-f]{16}/" {
        try_files \$uri =404;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
$(headers '        ')
    }

    # Anything else there (none is expected) is revalidated.
    location ~ ^/(crypto|crypto-calendar|calendar-ics|chat|pass|mail-search)-wasm/ {
        try_files \$uri =404;
        add_header Cache-Control "no-cache" always;
$(headers '        ')
    }

    # The page itself, with the style nonce: nginx writes this response's
    # \$request_id (128 random bits) over the placeholder in its
    # <meta name="csp-nonce"> (frontend/packages/config/src/styleNonce.ts),
    # as the policy above names it. So it is never served as stored: not
    # the precompressed copies, and without ETag or Last-Modified (sub_filter
    # drops them) a cache cannot revalidate an old page and nonce.
    location = /index.html {
        gzip_static off;
        brotli_static off;
        gzip on;
        sub_filter_once on;
        sub_filter '__KUTUP_CSP_NONCE__' '\$request_id';
        add_header Cache-Control "no-cache" always;
$(headers '        ')
    }

    # Vite's content-hashed bundles.
    location /assets/ {
        try_files \$uri =404;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
$(headers '        ')
    }

    # The service worker (Drive, Photos, Chat, Calendar; the others have no
    # such file and answer 404): always revalidated, so a new one is found
    # at the next check (docs/plans/drive-block-format.md §4).
    location = /kutup-sw.js {
        try_files \$uri =404;
        add_header Cache-Control "no-cache" always;
$(headers '        ')
    }

    # Streams live only in the service worker: a request it doesn't take
    # (no worker, or a Shift-reload) must not fall through to the app.
    location ^~ /sw/ {
        add_header Cache-Control "no-store" always;
        add_header X-Content-Type-Options nosniff always;
        add_header Content-Security-Policy "default-src 'none'; sandbox" always;
        return 404;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-cache" always;
$(headers '        ')
    }
}
NGINX
  done
  host=$(host_of "$editor")
  if [ "$enforce" = 1 ]; then
    csp_lines="add_header Content-Security-Policy \"$editor_strict\" always;"
  else
    csp_lines="add_header Content-Security-Policy \"$editor_old\" always;
add_header Content-Security-Policy-Report-Only \"$editor_strict\" always;"
  fi
  frame_options=""
  referrer=no-referrer
  cat <<NGINX
server {
    listen 80;
    server_name $host;
    root /usr/share/nginx/html/editor;
$(headers '    ')

    # No API on the sandbox's host (the reverse proxy in front answers
    # this already; kept here for a proxy that sends everything on).
    location /api/ {
        return 404;
    }

    # The OnlyOffice client and x2t, in directories named for their
    # versions (frontend/Dockerfile): cached for good.
    location ^~ /onlyoffice/dist/ {
        try_files \$uri =404;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
$(headers '        ')
    }

    # The bridge pages and templates, which name those directories.
    location / {
        try_files \$uri \$uri/ =404;
        add_header Cache-Control "no-cache" always;
$(headers '        ')
    }
}
NGINX
} > "$conf"
if [ "$enforce" = 1 ]; then mode=enforced; else mode=report-only; fi
echo "kutup: serving account=$account drive=$drive chat=$chat maps=$maps photos=$photos office=$office contacts=$contacts mail=$mail pass=$pass calendar=$calendar editor=$editor; strict CSP $mode"
