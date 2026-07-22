#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPOSE=(docker compose -f "$ROOT/docker-compose.chat-transparency-witness.yml")

cleanup() {
  "${COMPOSE[@]}" down --volumes --remove-orphans
}
trap cleanup EXIT

"${COMPOSE[@]}" up -d --build

for _ in $(seq 1 60); do
  if curl --fail --silent http://127.0.0.1:39001/api/health >/dev/null; then
    break
  fi
  sleep 1
done
curl --fail --silent http://127.0.0.1:39001/api/health >/dev/null

KUTUP_LIVE_SERVER=http://127.0.0.1:39001 \
  cargo test --manifest-path "$ROOT/Cargo.toml" -p kutup-server \
  --test chat_live chat_v1_contract -- --exact --nocapture

for _ in $(seq 1 30); do
  if python3 - <<'PY'
import json
import urllib.request

with urllib.request.urlopen("http://127.0.0.1:39001/api/chat/transparency/checkpoint") as response:
    value = json.load(response)
witnesses = value["authentication"].get("witnesses", [])
raise SystemExit(0 if any(item.get("witnessId") == "audit.test" for item in witnesses) else 1)
PY
  then
    curl --fail --silent http://127.0.0.1:39002/v1/view | python3 -c '
import json, sys
view = json.load(sys.stdin)
assert view["version"] == 1
assert view["witnessId"] == "audit.test"
assert 1 <= len(view["statements"]) <= 64
assert view["statements"][-1]["authentication"]["witnesses"]
'
    echo "SIGNED CHECKPOINT + INDEPENDENT WITNESS VERIFIED"
    exit 0
  fi
  sleep 1
done

"${COMPOSE[@]}" logs backend witness
echo "witness did not attest the current checkpoint" >&2
exit 1
