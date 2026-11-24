#!/bin/sh
# Writes koru.toml for Kutup's edge from the same settings the nginx edge
# and the apps read, then runs Koru (docker-compose.koru.yml; docs/self-hosting.md,
# "Koru edge (optional)"). The nginx edge's rules, as Koru sites and routes:
#
#   every app host (KUTUP_BASE_DOMAIN or KUTUP_<APP>_URL), MAIL_HOSTNAME and
#   the other names in KUTUP_ACME_EXTRA_DOMAINS: one site, the frontend by
#   default and the API, federation and /.well-known/ routes to the backend;
#   the editor sandbox: a site of its own with no API at all (404);
#   sfu.<domain> (CHAT_SFU_URL): the group-call SFU;
#   turn.<domain> and sfu-turn.<domain>: passed through by name on the HTTPS
#   port, undecrypted, to the relays, which end TLS themselves.
#
#   render.sh run      write the file, then run Koru (the container's default)
#   render.sh check    write the file, then `koru check` it
#   render.sh print    print the file only
#
# Settings beside Kutup's own:
#   KORU_MODE            off | detect | block (default detect: log, refuse nothing)
#   KORU_TLS             files (default): KORU_CERT and KORU_KEY, PEM, for every name;
#                        acme: Koru gets and renews them from Let's Encrypt itself
#                        (KUTUP_ACME_EMAIL, KUTUP_ACME_STAGING=1 for test certificates)
#   KORU_CERT, KORU_KEY  default /certs/fullchain.pem and /certs/privkey.pem
#   KORU_TRUSTED_PROXIES       addresses whose X-Forwarded-For is believed (comma-separated)
#   KORU_PROXY_PROTOCOL_FROM   load balancers that send the PROXY protocol (comma-separated)
#   KORU_RELAY_PROXY_PROTOCOL  v1 | v2: a PROXY header before passed-through TURN
#                        connections; only for relays that read one (default none)
#   KORU_BLOCK_CONTACT   who a blocked visitor should write to (shown on Koru's page)
#   KORU_BACKEND, KORU_FRONTEND, KORU_SFU, KORU_TURN_RELAY, KORU_SFU_TURN_RELAY
#                        the upstreams (defaults: the compose services and host ports)
set -eu

out_dir=${KORU_CONFIG_DIR:-/etc/koru}
koru=${KORU_BIN:-/usr/local/bin/koru}
action=${1:-run}

fail() {
  echo "kutup-koru: $*" >&2
  exit 1
}

origin_of() {
  eval "value=\${$2:-}"
  if [ -z "$value" ]; then
    [ -n "${KUTUP_BASE_DOMAIN:-}" ] || fail "set KUTUP_BASE_DOMAIN or $2"
    value="https://$1.$KUTUP_BASE_DOMAIN"
  fi
  printf '%s' "$value"
}

# The host name of a URL or bare name, lower-case, without port or path.
host_of() {
  printf '%s' "$1" | sed -E 's#^[a-zA-Z0-9+.-]+://##; s#^([^@/]*@)?##; s#[:/?].*$##' | tr 'A-Z' 'a-z'
}

# Names go into the file as TOML strings: only host-name characters.
check_host() {
  case "$1" in
    '' | *[!a-z0-9.-]* | .* | *. | *..*) fail "'$1' is not a host name" ;;
  esac
}

# A space-separated list without repeats, in first-seen order.
add() {
  list=$1
  shift
  for item in "$@"; do
    [ -n "$item" ] || continue
    case " $list " in *" $item "*) ;; *) list="${list:+$list }$item" ;; esac
  done
  printf '%s' "$list"
}

remove() {
  list=""
  for item in $1; do
    [ "$item" = "$2" ] || list="${list:+$list }$item"
  done
  printf '%s' "$list"
}

# ["a", "b"] from a space-separated list.
toml_list() {
  printf '['
  sep=""
  for item in $1; do
    printf '%s"%s"' "$sep" "$item"
    sep=", "
  done
  printf ']'
}

# A comma-separated list of addresses (IPs or CIDR blocks) as a TOML list.
address_list() {
  items=""
  for item in $(printf '%s' "$1" | tr ',' ' '); do
    case "$item" in
      *[!0-9a-fA-F.:/]*) fail "'$item' is not an address or CIDR block" ;;
    esac
    items="$items $item"
  done
  toml_list "$items"
}

case "${KORU_MODE:=detect}" in
  off | detect | block) ;;
  *) fail "KORU_MODE must be off, detect or block, not '$KORU_MODE'" ;;
esac
case "${KORU_TLS:=files}" in
  files | acme) ;;
  *) fail "KORU_TLS must be files or acme, not '$KORU_TLS'" ;;
esac
case "${KORU_RELAY_PROXY_PROTOCOL:=}" in
  '' | v1 | v2) ;;
  *) fail "KORU_RELAY_PROXY_PROTOCOL must be v1, v2 or empty" ;;
esac

# Checked here: a failure inside the file's own $(...) below would be lost.
address_list "${KORU_TRUSTED_PROXIES:-}" >/dev/null
address_list "${KORU_PROXY_PROTOCOL_FROM:-}" >/dev/null

backend=${KORU_BACKEND:-http://backend:3000}
frontend=${KORU_FRONTEND:-http://frontend:80}
sfu_upstream=${KORU_SFU:-http://host.docker.internal:7880}
turn_relay=${KORU_TURN_RELAY:-host.docker.internal:5350}
sfu_turn_relay=${KORU_SFU_TURN_RELAY:-host.docker.internal:5349}

# The apps' hosts, as the frontend container serves them (40-kutup-hosts.sh).
sites=""
for app in account drive chat office maps photos contacts mail pass calendar; do
  var="KUTUP_$(printf '%s' "$app" | tr 'a-z' 'A-Z')_URL"
  # One assignment each: a failure inside a nested $(...) would be lost.
  origin=$(origin_of "$app" "$var")
  sites=$(add "$sites" "$(host_of "$origin")")
done
origin=$(origin_of editor KUTUP_EDITOR_URL)
editor=$(host_of "$origin")
sites=$(add "$sites" "$(host_of "${MAIL_HOSTNAME:-}")")

# The call relays and the SFU: by the names their settings give, and by the
# turn. / sfu-turn. / sfu. names on the certificate (as nginx's stream map).
sfu=""
[ -z "${CHAT_SFU_URL:-}" ] || sfu=$(host_of "$CHAT_SFU_URL")
turn=""
for url in $(printf '%s' "${CHAT_TURN_URLS:-}" | tr ',' ' '); do
  case "$url" in
    turns:*) turn=$(add "$turn" "$(host_of "${url#turns:}")") ;;
  esac
done
sfu_turn=$(host_of "${CHAT_SFU_TURN_DOMAIN:-}")
for name in $(printf '%s' "${KUTUP_ACME_EXTRA_DOMAINS:-}" | tr ',' ' '); do
  name=$(host_of "$name")
  case "$name" in
    turn.*) turn=$(add "$turn" "$name") ;;
    sfu-turn.*) sfu_turn=$(add "$sfu_turn" "$name") ;;
    sfu.*) [ -n "$sfu" ] || sfu=$name ;;
    *) sites=$(add "$sites" "$name") ;;
  esac
done
# One name, one place: the SFU and the relays are not app hosts, and an
# editor that shares an app's host name (a development layout on another
# port) is told apart by the backend alone, as behind nginx.
for name in $sfu $turn $sfu_turn; do sites=$(remove "$sites" "$name"); done
for name in $turn $sfu_turn; do [ "$name" != "$sfu" ] || fail "$name is both the SFU and a relay"; done
case " $sites " in *" $editor "*) editor="" ;; esac
case " $sfu $turn $sfu_turn " in *" $editor "*) fail "the editor host $editor is also a call host" ;; esac
for name in $sites $editor $sfu $turn $sfu_turn; do check_host "$name"; done
[ -n "$sites" ] || fail "no app hosts"

if [ "$KORU_TLS" = files ]; then
  cert=${KORU_CERT:-/certs/fullchain.pem}
  key=${KORU_KEY:-/certs/privkey.pem}
  case "$cert$key" in *'"'* | *'\'*) fail "KORU_CERT and KORU_KEY must be plain paths" ;; esac
  site_tls="tls = { cert = \"$cert\", key = \"$key\" }"
else
  # The certificate named in [server.acme] below covers every site.
  site_tls=""
fi

# What every /api route shares with nginx's `location /api/`: bodies
# streamed to the backend up to 10 GB, five minutes for an answer, and the
# per-address flood wall (nginx: 50 a second, bursts of 500).
api_route() {
  printf '\n[[site.route]]\npath = "%s"\nupstreams = ["%s"]\nmax_body_size = "10GB"\n' "$1" "$backend"
  printf 'read_timeout_secs = %s\nwrite_timeout_secs = %s\n' "${3:-300}" "${3:-300}"
  [ -z "$2" ] || printf '%b\n' "$2"
  if [ "${4:-api}" = auth ]; then
    # nginx's `auth` zone: 10 a minute with a burst of 5.
    printf '[site.route.rate_limit]\nrequests = 15\nwindow_secs = 60\n'
  else
    printf '[site.route.rate_limit]\nrequests = 1000\nwindow_secs = 10\n'
  fi
}

backend_route() {
  printf '\n[[site.route]]\npath = "%s"\nupstreams = ["%s"]\n' "$1" "$backend"
}

edge_headers() {
  printf '\n[site.response_headers]\n'
  printf 'Strict-Transport-Security = "max-age=31536000; includeSubDomains"\n'
  printf 'X-Content-Type-Options = "nosniff"\n'
  [ "${1:-}" = sfu ] || printf 'Referrer-Policy = "strict-origin-when-cross-origin"\n'
  printf 'Server = ""\n'
}

site_common() {
  printf 'mode = "%s"\nhttps_redirect = true\n' "$KORU_MODE"
  [ -z "$site_tls" ] || printf '%s\n' "$site_tls"
  [ -z "${KORU_BLOCK_CONTACT:-}" ] || printf 'block_contact = "%s"\n' "$(printf '%s' "$KORU_BLOCK_CONTACT" | tr -d '"\\')"
}

body_off='inspect_body = false'
private='log_query = false\nlog_path = "prefix"'

render() {
  printf '# Written by koru/render.sh at every start: edit Kutup'"'"'s settings, not this file.\n'
  printf '[server]\nlisten_http = ["0.0.0.0:8080"]\nlisten_https = ["0.0.0.0:8443"]\n'
  printf 'health_path = "/healthz"\n'
  printf 'event_log = "%s"\naccess_log = "%s"\n' "${KORU_EVENT_LOG:-/dev/stderr}" "${KORU_ACCESS_LOG:-/dev/stdout}"
  [ -z "${KORU_TRUSTED_PROXIES:-}" ] || printf 'trusted_proxies = %s\n' "$(address_list "$KORU_TRUSTED_PROXIES")"
  [ -z "${KORU_PROXY_PROTOCOL_FROM:-}" ] || printf 'proxy_protocol_from = %s\n' "$(address_list "$KORU_PROXY_PROTOCOL_FROM")"

  if [ "$KORU_TLS" = acme ]; then
    printf '\n[server.acme]\ndir = "/var/lib/koru/acme"\n'
    if [ -n "${KUTUP_ACME_EMAIL:-}" ]; then
      case "$KUTUP_ACME_EMAIL" in *[!A-Za-z0-9@._+-]*) fail "KUTUP_ACME_EMAIL is not an address" ;; esac
      printf 'email = "%s"\n' "$KUTUP_ACME_EMAIL"
    fi
    [ "${KUTUP_ACME_STAGING:-0}" != 1 ] || printf 'directory = "https://acme-staging-v02.api.letsencrypt.org/directory"\n'
    # One certificate for the web names, as nginx's single one; the relays
    # get theirs apart, named after their first host, so that they can
    # read it from Koru's directory (certs/<name>.crt and .key).
    printf '\n[[server.acme.certificate]]\nhosts = %s\n' "$(toml_list "$sites $editor $sfu")"
    [ -z "$turn$sfu_turn" ] || printf '\n[[server.acme.certificate]]\nhosts = %s\n' "$(toml_list "$turn $sfu_turn")"
  fi

  # The apps, the API and federation.
  printf '\n[[site]]\nhosts = %s\nupstreams = ["%s"]\n' "$(toml_list "$sites")" "$frontend"
  site_common
  # nginx's client_max_body_size 1m: only /api/ takes more.
  printf 'max_body_size = "1MB"\n'

  # Public calendar links: the query may be the link's key, the path its id.
  api_route "/api/v1/calendar/links/*" "$private"
  # Public Drive links: their id in the path.
  api_route "/api/v1/drive/public-links/*" "$private"
  # The credential-facing requests (nginx's `auth` zone): an OPAQUE
  # sign-in start, a second factor, a sign-up, a recovery grant.
  for p in login/start login/2fa register recover/grant; do
    api_route "/api/v1/auth/$p" "" 300 auth
  done
  # WebSockets: Chat's mailbox stream, the device-link wait.
  api_route "/api/v1/chat/ws" "$body_off" 3600
  api_route "/api/v1/chat/provisioning" "$body_off" 900
  # Meeting links: reached without an account; their bodies are inspected.
  api_route "/api/v1/chat/call-links/*" ""
  # Ciphertext: Chat, Drive (tus uploads, blocks, live editing and its
  # WebSockets, which a prefix cannot single out, hence the hour), Mail,
  # Photos, Calendar, Contacts, Pass and the account's sealed records.
  api_route "/api/v1/chat/*" "$body_off"
  api_route "/api/v1/drive/*" "$body_off" 3600
  for p in mail photos calendar contacts pass account/records; do
    api_route "/api/v1/$p/*" "$body_off"
  done
  # Federation: sealed Chat messages, media and live-editing frames are
  # ciphertext; the rest of /api/fed/ is inspected whole.
  for p in chat/sealed/* chat/messages chat/media/* drive/collab/*; do
    api_route "/api/fed/v2/$p" "$body_off"
  done
  api_route "/api/*" ""
  # Federation discovery and identity history, security.txt, the Web Key Directory.
  backend_route "/.well-known/kutup/*"
  backend_route "/.well-known/security.txt"
  backend_route "/.well-known/openpgpkey/*"
  edge_headers
  # The apps tell people to wait on this code (nginx's @rate_limited).
  printf '\n[site.error_pages]\n429 = "%s/429.json"\n' "$out_dir"

  # The OnlyOffice sandbox runs eval'd code: no API on its host.
  if [ -n "$editor" ]; then
    printf '\n[[site]]\nhosts = ["%s"]\nupstreams = ["%s"]\n' "$editor" "$frontend"
    site_common
    printf 'max_body_size = "1MB"\n'
    printf '\n[[site.rule]]\nname = "no API on the editor sandbox"\naction = "block"\nstatus = 404\npath = "/api/*"\n'
    edge_headers
  fi

  # The group-call SFU (LiveKit on the host network): its signalling
  # socket stays open for the whole call.
  if [ -n "$sfu" ]; then
    printf '\n[[site]]\nhosts = ["%s"]\nupstreams = ["%s"]\n' "$sfu" "$sfu_upstream"
    site_common
    printf '%s\nread_timeout_secs = 3600\nwrite_timeout_secs = 3600\n' "$body_off"
    edge_headers sfu
  fi

  # TURN over TLS on port 443, for networks that let nothing else out.
  relay_stream() {
    printf '\n[[stream]]\nhosts = %s\nupstream = "%s"\n' "$(toml_list "$1")" "$2"
    [ -z "$KORU_RELAY_PROXY_PROTOCOL" ] || printf 'proxy_protocol = "%s"\n' "$KORU_RELAY_PROXY_PROTOCOL"
  }
  [ -z "$turn" ] || relay_stream "$turn" "$turn_relay"
  [ -z "$sfu_turn" ] || relay_stream "$sfu_turn" "$sfu_turn_relay"
}

config=$(render)
if [ "$action" = print ]; then
  printf '%s\n' "$config"
  exit 0
fi
mkdir -p "$out_dir"
printf '{"error":"too many requests","code":"rateLimited","event_id":"{event_id}"}\n' > "$out_dir/429.json.new"
mv "$out_dir/429.json.new" "$out_dir/429.json"
printf '%s\n' "$config" > "$out_dir/koru.toml.new"
mv "$out_dir/koru.toml.new" "$out_dir/koru.toml"
case "$action" in
  run) exec "$koru" run -c "$out_dir/koru.toml" ;;
  check) exec "$koru" check -c "$out_dir/koru.toml" ;;
  *) fail "unknown action '$action' (run, check or print)" ;;
esac
