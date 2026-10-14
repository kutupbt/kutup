#!/usr/bin/env bash
#
# verify-cli-account-head.sh — the account head on the command line against a
# live stack (docs/plans/rollback-protection.md):
#
#   register → meeting someone pins them, which starts the account's head →
#   the server rolled back (SQL) → the next listed read stops with exit 6 →
#   `kutup account reanchor --yes` goes on with the server's data.
#
# Required env:
#   KUTUP_SERVER   e.g. https://account.localhost:38643
#   KUTUP_PEER     an address on that server with published keys (the e2e admin)
#   E2E_PSQL       a command that runs SQL from its stdin against the stack's
#                  database (tests/e2e/README.md, "Server rollbacks")
# Optional: KUTUP_INSECURE_TLS=1 for a self-signed dev certificate.
#
# Requires: cargo, jq.
set -euo pipefail

: "${KUTUP_SERVER:?set KUTUP_SERVER}"
: "${KUTUP_PEER:?set KUTUP_PEER (user@server with published keys)}"
: "${E2E_PSQL:?set E2E_PSQL (see tests/e2e/README.md)}"
[ -n "${KUTUP_INSECURE_TLS:-}" ] && export KUTUP_INSECURE_TLS

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
# This run's own profile data (anchor, guard), not the person's.
export XDG_DATA_HOME="$TMP/data" XDG_CONFIG_HOME="$TMP/config"
export KUTUP_PASSWORD="Deneme123*CliAccountHead$$"
USERNAME="clihead$(date +%s | tail -c 7)$$"

cd "$(dirname "$0")/.."
cargo build -q -p kutup-cli
BIN="target/debug/kutup"
kutup() { "$BIN" --profile headcheck "$@"; }
state() { kutup --json account state; }
fail() { echo "FAIL: $*" >&2; exit 1; }

echo "==> register and sign in $USERNAME"
kutup register --server "$KUTUP_SERVER" --username "$USERNAME" >/dev/null
kutup login --server "$KUTUP_SERVER" --username "$USERNAME" >/dev/null

[ "$(state | jq -r .status)" = trusted ] || fail "a new account should be trusted"
[ "$(state | jq -r .current)" = null ] || fail "a new account has no head yet"

echo "==> meeting $KUTUP_PEER pins them: the head starts"
kutup identity show "$KUTUP_PEER" >/dev/null
[ "$(state | jq -r .current)" = 2 ] || fail "expected head #2 (the start and the pin), got $(state)"
[ "$(state | jq -r .anchor)" = 2 ] || fail "this device should remember #2"

echo "==> the server goes back to #1"
echo "DELETE FROM account_heads WHERE sequence > 1 AND user_id = (SELECT id FROM users WHERE username = '$USERNAME');" | $E2E_PSQL >/dev/null

set +e
kutup identity show "$KUTUP_PEER" >/dev/null 2>"$TMP/err"
code=$?
set -e
[ "$code" = 6 ] || fail "a rolled-back history should stop with exit 6, got $code: $(cat "$TMP/err")"
[ "$(state | jq -r .status)" = rollback ] || fail "state should say rollback"

echo "==> reanchor"
[ "$(kutup --json account reanchor --yes | jq -r .reanchored)" = true ] || fail "reanchor should move the device"
[ "$(state | jq -r .status)" = trusted ] || fail "trusted again after reanchoring"
[ "$(state | jq -r .anchor)" = 1 ] || fail "this device should now remember #1"

echo "OK: the CLI follows, blocks on a rollback (exit 6), and re-anchors"
