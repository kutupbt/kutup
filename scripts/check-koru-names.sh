#!/usr/bin/env bash
# Before switching a server's edge from nginx to Koru (docs/self-hosting.md,
# "Koru edge (optional)"): nginx answers every name, Koru only the names its
# configuration lists. This prints what Koru would be configured with from
# this .env and compares it with the names on nginx/certs/fullchain.pem.
#
#   KUTUP_KORU_IMAGE=kutup-koru:<tag> scripts/check-koru-names.sh
#
# Run it from the deployment's directory. It changes nothing; it starts one
# short-lived Koru container (render.sh print) on the project's network.
# Exit status 1 when a name on the certificate is neither a Koru site nor
# a passed-through TURN name.

set -euo pipefail

: "${KUTUP_KORU_IMAGE:?set KUTUP_KORU_IMAGE to the Koru image (scripts/build-koru-image.sh)}"
cert="${KUTUP_CERT:-nginx/certs/fullchain.pem}"
rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT
# The overlay is added here, so this works before COMPOSE_FILE names it.
files="${COMPOSE_FILE:-$({ grep -E '^COMPOSE_FILE=' .env || true; } | tail -1 | cut -d= -f2- | tr -d "\"'")}"
files="${files:-docker-compose.yml}"
case ":$files:" in *:docker-compose.koru.yml:*) ;; *) files="$files:docker-compose.koru.yml" ;; esac
files="$(printf '%s' "$files" | sed 's/:docker-compose\.acme\.yml//')"
COMPOSE_FILE="$files" docker compose run --rm --no-deps -T koru print > "$rendered"

python3 - "$rendered" "$cert" <<'EOF'
import subprocess, sys, tomllib
cfg = tomllib.load(open(sys.argv[1], "rb"))
san = subprocess.run(["openssl", "x509", "-in", sys.argv[2], "-noout", "-ext", "subjectAltName"],
                     capture_output=True, text=True, check=True).stdout
names = sorted({p.strip()[4:] for p in san.replace("\n", ",").split(",") if p.strip().startswith("DNS:")})
sites = {h: s for s in cfg["site"] for h in s["hosts"]}
streams = {h: s for s in cfg.get("stream", []) for h in s["hosts"]}
print("mode:", ", ".join(sorted({s["mode"] for s in cfg["site"]})))
for s in cfg["site"]:
    tls = s.get("tls", "acme ([server.acme])")
    print(f"site {s['hosts'][0]} (+{len(s['hosts']) - 1}) -> {s['upstreams'][0]}, tls {tls}")
for s in cfg.get("stream", []):
    print(f"stream {', '.join(s['hosts'])} -> {s['upstream']} (PROXY {s.get('proxy_protocol', 'none')})")
missing = [n for n in names if n not in sites and n not in streams]
extra = [n for n in list(sites) + list(streams) if n not in names]
print("on the certificate, not served by Koru:", ", ".join(missing) or "none")
print("served by Koru, not on the certificate:", ", ".join(extra) or "none")
sys.exit(1 if missing else 0)
EOF
