#!/usr/bin/env bash
# After certbot renewed nginx/certs/ on a server whose edge is Koru
# (docker-compose.koru.yml + docker-compose.koru-certbot.yml): Koru re-reads
# its certificates on SIGHUP; coturn and LiveKit read theirs only at start, so
# they restart (a call relayed through them reconnects). Stalwart's setup
# copies the files for Stalwart and has it reread them; it looks once a day by
# itself, and restarting it here makes that immediate. With the nginx edge,
# nginx reloads itself and this does nothing.
#
# Run from the deployment's directory, by the kutup-certificates.path unit
# (docs/self-hosting.md, "Koru edge (optional)") or by hand.
set -euo pipefail
cd "${KUTUP_DIR:-/opt/kutup}"

services="$(docker compose config --services)"
if ! grep -qx koru <<<"$services"; then
  echo "reload-certificate-users: the edge is not Koru; nothing to do"
  exit 0
fi
# A key Koru cannot read would stop it at the next reload: refuse first.
owner="$(stat -c %u nginx/certs/privkey.pem)"
if [ "$owner" != 65532 ]; then
  echo "reload-certificate-users: nginx/certs/privkey.pem is owned by $owner, not Koru's 65532" >&2
  exit 1
fi

docker compose kill -s HUP koru >/dev/null
echo "reload-certificate-users: Koru reloaded"
for relay in coturn livekit stalwart-setup; do
  if grep -qx "$relay" <<<"$services" && [ -n "$(docker compose ps -q "$relay")" ]; then
    docker compose restart "$relay" >/dev/null
    echo "reload-certificate-users: $relay restarted"
  fi
done
