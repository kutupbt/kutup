#!/usr/bin/env bash
#
# verify-mk-rotation.sh — the master-key rotation exercise's live check from
# the CLI (docs/plans/mk-rotation-exercise.md, §6):
#
#   one account on two CLI profiles (A and B, two devices); A rotates its
#   master key (`kutup account rotate-master-key`).
#
# Checked: the rotation answers generation 2 and a new phrase; B's sign-in
# ended with it, and B signs in again and follows the account's history across
# the rotation (its anchor was sealed under the old key); A's does too; the
# old recovery phrase no longer recovers and the new one does; after the
# recovery both profiles sign in with the new password.
#
# Required env:
#   KUTUP_SERVER     e.g. https://drive.localhost:38643 or http://<backend>:3000
#
# Optional env:
#   KUTUP_INSECURE_TLS=1   accept a self-signed dev cert
#
# Requires: cargo, jq.
set -euo pipefail

: "${KUTUP_SERVER:?set KUTUP_SERVER}"
[ -n "${KUTUP_INSECURE_TLS:-}" ] && export KUTUP_INSECURE_TLS

A="mk-a-$$"
B="mk-b-$$"
trap '[ -n "${BIN:-}" ] && { "$BIN" --profile "$A" logout >/dev/null 2>&1; "$BIN" --profile "$B" logout >/dev/null 2>&1; }; true' EXIT

cd "$(dirname "$0")/.."
echo "==> building kutup-cli…"
cargo build -q -p kutup-cli
BIN="target/debug/kutup"

pass() { printf '  \033[32mok\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }
same() { [ "$1" = "$2" ] || fail "$3: got '$1', want '$2'"; }

export KUTUP_PASSWORD="mk-rotation-pw-$$-123456"
NAME="mk$(date +%s | tail -c 7)$((RANDOM % 100))"
echo "==> account $NAME @ $KUTUP_SERVER"
OLD_PHRASE="$("$BIN" --profile "$A" --json register --server "$KUTUP_SERVER" --username "$NAME" | jq -r .recoveryPhrase)"
[ "$(wc -w <<<"$OLD_PHRASE")" -eq 24 ] || fail "register printed no recovery phrase"
"$BIN" --profile "$A" login --server "$KUTUP_SERVER" --username "$NAME" >/dev/null
"$BIN" --profile "$B" login --server "$KUTUP_SERVER" --username "$NAME" >/dev/null
same "$("$BIN" --profile "$B" --json account state | jq -r .status)" trusted "B before the rotation"
pass "two devices signed in, both trusting the account's history"

# --json needs --yes: nobody confirms a phrase they did not see.
if "$BIN" --profile "$A" --json account rotate-master-key >/dev/null 2>&1; then
  fail "--json without --yes was taken"
fi
ROTATED="$("$BIN" --profile "$A" --json account rotate-master-key --yes)"
same "$(jq -r .masterKeyGeneration <<<"$ROTATED")" 2 "the rotated generation"
NEW_PHRASE="$(jq -r .recoveryPhrase <<<"$ROTATED")"
[ "$(wc -w <<<"$NEW_PHRASE")" -eq 24 ] || fail "the rotation gave no new phrase"
[ "$NEW_PHRASE" != "$OLD_PHRASE" ] || fail "the rotation kept the old phrase"
pass "A rotated the master key: generation 2, a new phrase"

same "$("$BIN" --profile "$A" --json account state | jq -r .status)" trusted "A after the rotation"
pass "A follows its own history across the rotation"

# B's sign-in ended with the rotation (exit 3: signed out).
set +e
"$BIN" --profile "$B" whoami >/dev/null 2>&1
code=$?
set -e
same "$code" 3 "B's old sign-in after the rotation"
"$BIN" --profile "$B" login --server "$KUTUP_SERVER" --username "$NAME" >/dev/null
same "$("$BIN" --profile "$B" --json account state | jq -r .status)" trusted "B after signing in again"
pass "B signed out by the rotation, signed in again, history followed across it"

# The old phrase recovers nothing; the new one does, with a new password.
export KUTUP_RECOVERY_PHRASE="$OLD_PHRASE"
export KUTUP_PASSWORD="mk-recovered-pw-$$-654321"
if "$BIN" --profile "$A" recover --server "$KUTUP_SERVER" --username "$NAME" >/dev/null 2>&1; then
  fail "the old recovery phrase still recovered the account"
fi
pass "the old recovery phrase is refused"
export KUTUP_RECOVERY_PHRASE="$NEW_PHRASE"
"$BIN" --profile "$A" recover --server "$KUTUP_SERVER" --username "$NAME" >/dev/null
same "$("$BIN" --profile "$A" --json account state | jq -r .status)" trusted "A after the recovery"
"$BIN" --profile "$B" login --server "$KUTUP_SERVER" --username "$NAME" >/dev/null
same "$("$BIN" --profile "$B" --json account state | jq -r .status)" trusted "B after the recovery"
pass "the new phrase recovers; both devices sign in with the new password"
unset KUTUP_RECOVERY_PHRASE

echo "==> master-key rotation: all checks passed"
