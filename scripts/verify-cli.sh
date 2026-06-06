#!/usr/bin/env bash
#
# verify-cli.sh — end-to-end differential check for the Rust kutup CLI against a
# live kutup backend. Exercises the full encrypted round-trip:
#
#   login → whoami → mkdir → upload → ls → download → checksum-compare → rm → logout
#
# This is the Phase-2 verification gate (see docs/roadmap.md / the Go→Rust
# rewrite). Run it on a VM/host that can reach a running stack.
#
# Required env:
#   KUTUP_SERVER     e.g. https://localhost:38443
#   KUTUP_EMAIL      an existing account (created via the web UI)
#   KUTUP_PASSWORD   that account's password (used for non-interactive login)
#
# Optional env:
#   KUTUP_INSECURE_TLS=1   accept a self-signed dev cert
#   VERIFY_SIZE=6291456    test-file size in bytes (default 6 MiB → multi-chunk)
#
# Requires: cargo, jq, sha256sum (coreutils).
set -euo pipefail

: "${KUTUP_SERVER:?set KUTUP_SERVER (e.g. https://localhost:38443)}"
: "${KUTUP_EMAIL:?set KUTUP_EMAIL}"
: "${KUTUP_PASSWORD:?set KUTUP_PASSWORD (used for non-interactive login)}"
export KUTUP_PASSWORD
[ -n "${KUTUP_INSECURE_TLS:-}" ] && export KUTUP_INSECURE_TLS

SIZE="${VERIFY_SIZE:-6291456}" # 6 MiB → spans the 5 MiB secretstream chunk
PROFILE="verify-$$"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cd "$(dirname "$0")/.."
echo "==> building kutup-cli (release)…"
cargo build -q --release -p kutup-cli
BIN="target/release/kutup"
run() { "$BIN" --profile "$PROFILE" "$@"; }

pass() { printf '  \033[32mok\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

echo "==> login as $KUTUP_EMAIL @ $KUTUP_SERVER"
run login --server "$KUTUP_SERVER" --email "$KUTUP_EMAIL" >/dev/null
pass "login"

run whoami >/dev/null && pass "whoami"

FOLDER="$(run --json mkdir "verify-folder-$$" | jq -r .id)"
[ -n "$FOLDER" ] && [ "$FOLDER" != null ] || fail "mkdir returned no id"
pass "mkdir ($FOLDER)"

head -c "$SIZE" /dev/urandom > "$TMP/in.bin"
WANT="$(sha256sum "$TMP/in.bin" | cut -d' ' -f1)"
run upload "$TMP/in.bin" "$FOLDER" >/dev/null && pass "upload ($SIZE bytes)"

FILE="$(run --json ls "$FOLDER" | jq -r '.[] | select(.type=="file") | .id' | head -1)"
[ -n "$FILE" ] && [ "$FILE" != null ] || fail "uploaded file not found in ls"
pass "ls (file $FILE)"

run download "$FILE" "$TMP/out.bin" >/dev/null
GOT="$(sha256sum "$TMP/out.bin" | cut -d' ' -f1)"
[ "$WANT" = "$GOT" ] || fail "checksum mismatch: $WANT != $GOT"
pass "download + checksum match"

run rm "$FILE" >/dev/null && pass "rm file"
run rm --folder "$FOLDER" >/dev/null && pass "rm folder"
run logout >/dev/null && pass "logout"

echo "==> all checks passed"
