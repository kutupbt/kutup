#!/usr/bin/env bash
#
# verify-pass-sync.sh — the K1 live check of Kutup Pass (docs/plans/pass.md):
# two machines edit one KeePass vault offline, then sync, and nothing is lost.
#
#   machine A and machine B (two CLI profiles of one account, two folders)
#   share vault.kdbx through `kutup sync`; each edits it while the other does
#   not sync; the second to sync merges (base, local, remote) and saves a
#   version of the same file made from what it merged.
#
# Checked: disjoint edits from both sides survive; the same field edited on
# both sides keeps the later sync's value, the other in the entry's history,
# and the entry marked for review; the vault stays one Drive file with a
# stable id; without the vault key, sync falls back to a conflict copy.
#
# Required env:
#   KUTUP_SERVER     e.g. https://drive.localhost:38643 or http://<backend>:3000
#
# Optional env:
#   KUTUP_INSECURE_TLS=1   accept a self-signed dev cert
#
# Requires: cargo, jq, sha256sum (coreutils).
set -euo pipefail

: "${KUTUP_SERVER:?set KUTUP_SERVER}"
[ -n "${KUTUP_INSECURE_TLS:-}" ] && export KUTUP_INSECURE_TLS

TMP="$(mktemp -d)"
A="pass-a-$$"
B="pass-b-$$"
trap 'rm -rf "$TMP"; [ -n "${BIN:-}" ] && { "$BIN" --profile "$A" logout >/dev/null 2>&1; "$BIN" --profile "$B" logout >/dev/null 2>&1; }; true' EXIT

cd "$(dirname "$0")/.."
echo "==> building kutup-cli and the vault tool…"
cargo build -q -p kutup-cli
cargo build -q -p kutup-pass --example vault
BIN="target/debug/kutup"
VAULT_TOOL="target/debug/examples/vault"

pass() { printf '  \033[32mok\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

export KUTUP_PASSWORD="pass-sync-pw-$$-123456"
export VAULT_PASSWORD="vault-pw-çğ-$$"
export KUTUP_VAULT_PASSWORD="$VAULT_PASSWORD"
vault() { "$VAULT_TOOL" "$@"; }
sync_on() { # machine dir
  "$BIN" --profile "$1" sync "$TMP/$1" "$FOLDER" 2>"$TMP/$1.log" >/dev/null ||
    { cat "$TMP/$1.log"; fail "sync on $1"; }
}
same() { [ "$1" = "$2" ] || fail "$3: got '$1', want '$2'"; }
# A new mtime for the next local write.
tick() { sleep 1.1; }

EMAIL="pass$$-$(date +%s)@example.com"
echo "==> account $EMAIL @ $KUTUP_SERVER"
"$BIN" --profile "$A" register --server "$KUTUP_SERVER" --email "$EMAIL" \
  --username "pass$(date +%s | tail -c 7)$((RANDOM % 100))" >/dev/null
"$BIN" --profile "$A" login --server "$KUTUP_SERVER" --email "$EMAIL" >/dev/null
"$BIN" --profile "$B" login --server "$KUTUP_SERVER" --email "$EMAIL" >/dev/null
pass "machine A registered, machine B signed in"

FOLDER="$("$BIN" --profile "$A" --json mkdir "Passwords-$$" | jq -r .id)"
mkdir -p "$TMP/$A" "$TMP/$B"

# --- the vault reaches both machines ---
vault new "$TMP/$A/vault.kdbx"
vault set "$TMP/$A/vault.kdbx" Bank UserName ayse
vault set "$TMP/$A/vault.kdbx" Bank Password start
sync_on "$A"
sync_on "$B"
same "$(vault get "$TMP/$B/vault.kdbx" Bank Password)" start "B has the vault"
FILE_ID="$("$BIN" --profile "$A" --json ls "$FOLDER" | jq -r '.[] | select(.type=="file") | .id')"
pass "vault synced to both machines (file $FILE_ID)"

# --- disjoint offline edits ---
tick
vault set "$TMP/$A/vault.kdbx" Bank Password from-a
vault set "$TMP/$A/vault.kdbx" Mail Password mail-a
vault set "$TMP/$B/vault.kdbx" Bank UserName ayse-b
vault set "$TMP/$B/vault.kdbx" Git Password git-b
sync_on "$A"
grep -q "↑ vault.kdbx" "$TMP/$A.log" || { cat "$TMP/$A.log"; fail "A saved a version"; }
sync_on "$B"
grep -q "⇄ vault.kdbx" "$TMP/$B.log" || { cat "$TMP/$B.log"; fail "B merged"; }
sync_on "$A"
for m in "$A" "$B"; do
  v="$TMP/$m/vault.kdbx"
  same "$(vault get "$v" Bank Password)" from-a "$m: A's password"
  same "$(vault get "$v" Bank UserName)" ayse-b "$m: B's user name"
  same "$(vault get "$v" Mail Password)" mail-a "$m: A's new entry"
  same "$(vault get "$v" Git Password)" git-b "$m: B's new entry"
  same "$(vault review "$v" Bank)" "" "$m: nothing to review"
done
same "$(sha256sum <"$TMP/$A/vault.kdbx")" "$(sha256sum <"$TMP/$B/vault.kdbx")" "both machines hold the same file"
pass "disjoint edits from both machines kept on both"

# --- the same field on both sides ---
tick
vault set "$TMP/$A/vault.kdbx" Bank Notes "note from a"
vault set "$TMP/$B/vault.kdbx" Bank Notes "note from b"
sync_on "$A"
sync_on "$B"
sync_on "$A"
for m in "$A" "$B"; do
  v="$TMP/$m/vault.kdbx"
  same "$(vault get "$v" Bank Notes)" "note from b" "$m: the later sync's value"
  vault history "$v" Bank Notes | grep -qx "note from a" || fail "$m: A's note is in the history"
  vault review "$v" Bank | grep -q Notes || fail "$m: Bank marked for review"
done
pass "a field edited on both sides: one value current, the other in history, marked for review"

# --- still one file, the same one ---
FILES="$("$BIN" --profile "$A" --json ls "$FOLDER" | jq -r '[.[] | select(.type=="file")] | length')"
same "$FILES" 1 "files in the folder"
same "$("$BIN" --profile "$A" --json ls "$FOLDER" | jq -r '.[] | select(.type=="file") | .id')" "$FILE_ID" "the vault's file id"
ls "$TMP/$A" "$TMP/$B" | grep -q sync-conflict && fail "no conflict copies"
pass "the vault is one Drive file with a stable id; no conflict copies"

# --- without the key: a conflict copy, as for any file ---
tick
vault set "$TMP/$A/vault.kdbx" Bank Password keyless-a
vault set "$TMP/$B/vault.kdbx" Bank Password keyless-b
sync_on "$A"
( unset KUTUP_VAULT_PASSWORD; sync_on "$B" ) </dev/null
ls "$TMP/$B" | grep -q "vault.*sync-conflict" || { ls "$TMP/$B"; fail "B kept a conflict copy"; }
pass "without the vault key, sync keeps a conflict copy"

echo "==> all Kutup Pass sync checks passed"
