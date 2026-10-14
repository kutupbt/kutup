#!/usr/bin/env bash
#
# verify-cli-account-head.sh — the account head on the command line against a
# live stack (docs/plans/rollback-protection.md §9):
#
#   the old plaintext pin revision taken over · meeting someone pins them,
#   which starts the account's head · a vault key kept and forgotten under the
#   head · a corrupt state file kept aside and said so ·
#   the server rolled back (exit 6, --json needs --yes, reanchor) · another
#   device shown another history (a fork: exit 6, reanchor).
#
# Required env:
#   KUTUP_SERVER   e.g. https://account.localhost:38643
#   E2E_PSQL       a command that runs SQL from its stdin against the stack's
#                  database (tests/e2e/README.md, "Server rollbacks")
# Optional: KUTUP_INSECURE_TLS=1 for a self-signed dev certificate.
#
# Requires: cargo, jq.
set -euo pipefail

: "${KUTUP_SERVER:?set KUTUP_SERVER}"
: "${E2E_PSQL:?set E2E_PSQL (see tests/e2e/README.md)}"
[ -n "${KUTUP_INSECURE_TLS:-}" ] && export KUTUP_INSECURE_TLS

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
# This run's own profile data (anchor, guard), not the person's.
export XDG_DATA_HOME="$TMP/data" XDG_CONFIG_HOME="$TMP/config"
export KUTUP_PASSWORD="Deneme123*CliAccountHead$$"
export KUTUP_VAULT_PASSWORD="kasa-$$-parolası"
USERNAME="clihead$(date +%s | tail -c 7)$$"

cd "$(dirname "$0")/.."
cargo build -q -p kutup-cli
cargo build -q -p kutup-pass --example vault
BIN="target/debug/kutup"
VAULT_TOOL="target/debug/examples/vault"
a() { "$BIN" --profile a "$@"; }
p() { "$BIN" --profile p "$@"; }
b() { "$BIN" --profile b "$@"; }
state() { "$BIN" --profile "$1" --json account state; }
fail() { echo "FAIL: $*" >&2; exit 1; }
dir_of() { echo "$XDG_DATA_HOME/kutup/$1"; }
exit_of() { set +e; "$@" >/dev/null 2>"$TMP/err"; local code=$?; set -e; echo "$code"; }
# A restore from an older backup, as the server would show it: the heads after
# #$1 gone, and the kept vault keys as they were then (none at the points
# this script goes back to), so the server's data matches its newest head.
rollback_to() {
  {
    echo "DELETE FROM account_heads WHERE sequence > $1 AND user_id = (SELECT id FROM users WHERE username = '$USERNAME');"
    echo "DELETE FROM pass_vault_secrets WHERE user_id = (SELECT id FROM users WHERE username = '$USERNAME');"
  } | $E2E_PSQL >/dev/null
}

echo "==> someone to meet: a peer account of its own"
p register --server "$KUTUP_SERVER" --username "${USERNAME}p" >/dev/null
p login --server "$KUTUP_SERVER" --username "${USERNAME}p" >/dev/null
KUTUP_PEER="$(p --json whoami | jq -r .address)"

echo "==> register and sign in $USERNAME"
a register --server "$KUTUP_SERVER" --username "$USERNAME" >/dev/null
a login --server "$KUTUP_SERVER" --username "$USERNAME" >/dev/null
[ "$(state a | jq -r .status)" = trusted ] || fail "a new account should be trusted"
[ "$(state a | jq -r .current)" = null ] || fail "a new account has no head yet"

echo "==> meeting $KUTUP_PEER pins them: the head starts"
a identity show "$KUTUP_PEER" >/dev/null
[ "$(state a | jq -r .current)" = 2 ] || fail "expected head #2 (the start and the pin), got $(state a)"

echo "==> the old plaintext pin revision is taken over once"
# As an older CLI left it: no sealed guard yet, the revision in plain text.
rm "$(dir_of a)/revisions.json"
echo 1 >"$(dir_of a)/identity-pins-revision"
a identity show "$KUTUP_PEER" >/dev/null
[ ! -e "$(dir_of a)/identity-pins-revision" ] || fail "the old revision file should be gone"
jq -e 'length > 0' "$(dir_of a)/revisions.json" >/dev/null || fail "the guard should hold the pin list"

echo "==> a vault key kept and forgotten under the head"
FOLDER="$(a --json mkdir "Kasa-$$" | jq -r .id)"
VAULT_PASSWORD="$KUTUP_VAULT_PASSWORD" "$VAULT_TOOL" new "$TMP/vault.kdbx" >/dev/null
VAULT="$(a --json upload "$TMP/vault.kdbx" "$FOLDER" | jq -r .id)"
a pass keep "$VAULT" >/dev/null
[ "$(state a | jq -r .current)" = 3 ] || fail "keeping the key should write head #3"
[ "$(a --json pass ls | jq length)" = 1 ] || fail "the kept key should be listed"
a pass keep "$VAULT" >/dev/null
[ "$(state a | jq -r .current)" = 3 ] || fail "keeping the same key again sends nothing"
a pass forget "$VAULT" >/dev/null
[ "$(state a | jq -r .current)" = 4 ] || fail "forgetting should write head #4"
a pass keep "$VAULT" >/dev/null
[ "$(state a | jq -r .current)" = 5 ] || fail "keeping again should write head #5"

echo "==> a corrupt state file is kept aside and said so"
for file in "$(dir_of a)"/account-head-*; do
  case "$file" in *.corrupt-*|*.lock) ;; *) echo "not a sealed state" >"$file" ;; esac
done
report="$(state a 2>"$TMP/warn")"
grep -q "could not be read" "$TMP/warn" || fail "a corrupt state must be warned about"
[ "$(echo "$report" | jq -r .startedOver)" = unreadable ] || fail "the report should say it started over: $report"
ls "$(dir_of a)"/account-head-*.corrupt-* >/dev/null || fail "the corrupt file should be kept aside"
[ "$(echo "$report" | jq -r .status)" = trusted ] || fail "a fresh start trusts the current history"

# Processes at once on one profile: the CLI's session database already lets
# only one open it at a time ("Database already open"), so they cannot meet
# here; the head state's own lock (and its atomic writes) is tested with
# threads in crates/kutup-cli/src/account_head.rs.
[ "$(state a | jq -r .anchor)" = 5 ] || fail "the anchor should be #5"

echo "==> the server goes back to #4 (no key kept then): exit 6, then reanchor"
rollback_to 4
# Reads go on (held to this device's guard, with a note); writes stop.
[ "$(exit_of a pass ls)" = 0 ] || fail "reads go on while blocked: $(cat "$TMP/err")"
grep -q "rollback" "$TMP/err" || fail "a read while blocked should say why"
[ "$(exit_of a pass keep "$VAULT")" = 6 ] || fail "a rolled-back history should stop writes with exit 6: $(cat "$TMP/err")"
[ "$(state a | jq -r .status)" = rollback ] || fail "state should say rollback"
[ "$(exit_of a --json account reanchor)" = 2 ] || fail "--json without --yes must be refused (exit 2)"
[ "$(a --json account reanchor --yes | jq -r .reanchored)" = true ] || fail "reanchor should move the device"
[ "$(state a | jq -r .anchor)" = 4 ] || fail "this device should now remember #4"

echo "==> another device is shown another history: a fork"
a pass keep "$VAULT" >/dev/null                        # a writes #5 and remembers it
rollback_to 4                                          # the server drops a's #5
b login --server "$KUTUP_SERVER" --username "$USERNAME" >/dev/null
b pass keep "$VAULT" >/dev/null                        # b writes another #5
[ "$(exit_of a pass keep "$VAULT")" = 6 ] || fail "a forked history should stop writes with exit 6: $(cat "$TMP/err")"
[ "$(state a | jq -r .status)" = fork ] || fail "state should say fork"
[ "$(a --json account reanchor --yes | jq -r .reanchored)" = true ] || fail "reanchor after a fork"
[ "$(state a | jq -r .status)" = trusted ] || fail "trusted after reanchoring the fork"

echo "OK: the CLI's account head (takeover, pins, vault keys, corrupt state, rollback, fork)"
