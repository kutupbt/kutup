#!/usr/bin/env bash
# Runs the Koru edge (docker-compose.koru.yml) on its Kutup configuration in
# block mode, in front of a stub upstream, and checks what nginx's edge
# promises: a public calendar link's key and id and a public Drive link's id
# never reach a log (the access log, events, error lines: on an answer, on a
# blocked request, on a referer, and when the upstream is down), the sign-in
# rate limit answers 429 with code rateLimited, the editor sandbox has no
# API, the edge headers are set, and `koru check` accepts the file.
#
#   scripts/test-koru-edge.sh       needs Docker and KUTUP_KORU_IMAGE, the image
#                                   scripts/build-koru-image.sh builds
#                                   (it prints the name)
#
# Koru is not in CI (it is built from the operator's own checkout of its
# sources); scripts/test-koru-config.py checks the file in the static gate.

set -euo pipefail

image="${KUTUP_KORU_IMAGE:?set KUTUP_KORU_IMAGE (scripts/build-koru-image.sh prints it)}"
docker image inspect "$image" >/dev/null 2>&1 || { echo "test-koru-edge: build $image first" >&2; exit 2; }
run="kutup-koru-edge-test-$$"
work="$(mktemp -d)"
cleanup() {
  docker rm -f "$run-koru" "$run-stub" >/dev/null 2>&1 || true
  docker network rm "$run" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

# Secrets that must not be logged: a calendar link's id and key, a Drive link's id.
cal_id="0d5a1d3e-3b7f-4c1e-9d2a-$(openssl rand -hex 6)"
cal_key="$(openssl rand -hex 16)"
share_id="$(openssl rand -hex 12)"
domain=example.test

mkdir -p "$work/certs"
openssl req -x509 -nodes -newkey rsa:2048 -days 1 -subj "/CN=$domain" \
  -addext "subjectAltName=DNS:account.$domain,DNS:calendar.$domain,DNS:drive.$domain,DNS:editor.$domain" \
  -keyout "$work/certs/privkey.pem" -out "$work/certs/fullchain.pem" 2>/dev/null
chmod 0644 "$work/certs/privkey.pem"

docker network create "$run" >/dev/null
# The stub upstream: busybox's httpd from the same image, 404 for everything.
docker run -d --name "$run-stub" --network "$run" --entrypoint /bin/busybox "$image" \
  httpd -f -p 3000 -h /etc/koru >/dev/null
koru_env=(-e KUTUP_BASE_DOMAIN="$domain" -e KORU_MODE=block -e KORU_BACKEND="http://$run-stub:3000"
  -e KORU_FRONTEND="http://$run-stub:3000")

echo "== koru check"
docker run --rm --network "$run" -v "$work/certs:/certs:ro" --tmpfs /etc/koru:uid=65532,gid=65532 \
  "${koru_env[@]}" "$image" check

docker run -d --name "$run-koru" --network "$run" -v "$work/certs:/certs:ro" \
  --tmpfs /etc/koru:uid=65532,gid=65532 --read-only -p 127.0.0.1::8443 -p 127.0.0.1::8080 \
  "${koru_env[@]}" "$image" >/dev/null
https_port="$(docker port "$run-koru" 8443/tcp | head -1 | sed 's/.*://')"
http_port="$(docker port "$run-koru" 8080/tcp | head -1 | sed 's/.*://')"
for _ in $(seq 50); do
  curl -fsS "http://127.0.0.1:$http_port/healthz" >/dev/null 2>&1 && break
  sleep 0.2
done

failures=0
expect() {
  local want="$1" host="$2" path="$3"
  shift 3
  local got
  got="$(curl -sk --path-as-is -o "$work/body" -D "$work/headers" -w '%{http_code}' \
    --resolve "$host.$domain:$https_port:127.0.0.1" "$@" "https://$host.$domain:$https_port$path")" || true
  if [ "$got" = "$want" ]; then
    echo "  ok   $want $host ${path%%\?*}"
  else
    echo "  FAIL $host ${path%%\?*}: $got, expected $want" >&2
    failures=$((failures + 1))
  fi
}

echo "== requests"
expect 404 calendar "/api/v1/calendar/links/$cal_id/calendar.ics?key=$cal_key"
expect 403 calendar "/api/v1/calendar/links/$cal_id/events?key=$cal_key&q=1%27%20OR%201%3D1--"
expect 403 calendar "/api/v1/calendar/links/$cal_id/../../../../etc/passwd?key=$cal_key"
expect 404 drive "/api/v1/drive/public-links/$share_id?k=$cal_key"
# A referer is cut down as its request's own address is. (A referer naming a
# link on a request to another route is kept whole, as nginx keeps it.)
expect 404 calendar "/api/v1/calendar/links/$cal_id/busy?key=$cal_key" -H "Referer: https://calendar.$domain/api/v1/calendar/links/$cal_id/calendar.ics?key=$cal_key"
# The editor sandbox runs eval'd code: no API there.
expect 404 editor "/api/v1/auth/settings"
grep -qi '^strict-transport-security: max-age=31536000; includeSubDomains' "$work/headers" \
  || { echo "  FAIL no HSTS on Koru's own answer" >&2; failures=$((failures + 1)); }
expect 404 account "/"
grep -qi '^x-content-type-options: nosniff' "$work/headers" || { echo "  FAIL no nosniff" >&2; failures=$((failures + 1)); }
grep -qi '^content-security-policy' "$work/headers" && { echo "  FAIL CSP at the edge" >&2; failures=$((failures + 1)); }
# Plain HTTP is sent to HTTPS.
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: account.$domain" "http://127.0.0.1:$http_port/x")"
[ "$code" = 308 ] && echo "  ok   308 http -> https" || { echo "  FAIL http: $code" >&2; failures=$((failures + 1)); }

# nginx's `auth` zone: 10 a minute and a burst of 5; then 429 that says so.
for _ in $(seq 15); do
  curl -sk -o /dev/null --resolve "account.$domain:$https_port:127.0.0.1" -X POST \
    "https://account.$domain:$https_port/api/v1/auth/login/start"
done
expect 429 account /api/v1/auth/login/start -X POST
grep -q '"code":"rateLimited"' "$work/body" && echo "  ok   429 says rateLimited" \
  || { echo "  FAIL 429 body: $(cat "$work/body")" >&2; failures=$((failures + 1)); }

# Upstream errors: the request is written to the error log.
docker stop -t 1 "$run-stub" >/dev/null
expect 502 calendar "/api/v1/calendar/links/$cal_id/calendar.ics?key=$cal_key"
expect 502 drive "/api/v1/drive/public-links/$share_id?k=$cal_key"
sleep 1

echo "== logs"
docker logs "$run-koru" > "$work/log" 2>&1
[ -z "${KORU_TEST_LOG:-}" ] || cp "$work/log" "$KORU_TEST_LOG"
grep -q '"action":"block"' "$work/log" || { echo "  FAIL no block event logged" >&2; failures=$((failures + 1)); }
grep -q '/api/v1/calendar/links/\*' "$work/log" || { echo "  FAIL calendar links not logged by their route" >&2; failures=$((failures + 1)); }
# The error log's case: the upstream is down, and the line names the request.
grep -q 'Fail to proxy.*GET /api/v1/calendar/links/\*?\[redacted\]' "$work/log" \
  || { echo "  FAIL no redacted upstream error line" >&2; failures=$((failures + 1)); }
for secret in "$cal_id" "$cal_key" "$share_id"; do
  if grep -qF "$secret" "$work/log"; then
    echo "  FAIL a secret reached Koru's log:" >&2
    grep -nF "$secret" "$work/log" | sed "s/$secret/<secret>/g" | head -5 >&2
    failures=$((failures + 1))
  fi
done
[ "$failures" = 0 ] && echo "  ok   no link id or key in $(wc -l < "$work/log") log lines"

if [ "$failures" != 0 ]; then
  echo "test-koru-edge: $failures failure(s)" >&2
  exit 1
fi
echo "test-koru-edge: ok"
