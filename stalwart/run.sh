#!/bin/sh
# Runs Stalwart, restarting it when stalwart-setup asks (setup.sh): Stalwart
# binds its listeners only at start, so a new listener in the plan (the
# submission port on first boot) needs a restart. A request is a new token
# in /stalwart-control/restart; docker stop still stops Stalwart cleanly.
set -u
child=0
handled="$(cat /stalwart-control/restart 2>/dev/null || true)"
trap 'kill -TERM "$child" 2>/dev/null; wait "$child"; exit 0' TERM INT
while :; do
  /usr/local/bin/stalwart --config /etc/stalwart/config.json &
  child=$!
  restart=0
  while kill -0 "$child" 2>/dev/null; do
    token="$(cat /stalwart-control/restart 2>/dev/null || true)"
    if [ -n "$token" ] && [ "$token" != "$handled" ]; then
      handled="$token"
      restart=1
      echo "restarting Stalwart for new listeners"
      kill -TERM "$child"
      break
    fi
    sleep 1 &
    wait $!
  done
  wait "$child"
  status=$?
  [ "$restart" = 1 ] || exit "$status"
done
