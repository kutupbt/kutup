#!/usr/bin/env bash
#
# verify-pass-ssh.sh — the K3b live check of the kutup SSH agent
# (docs/plans/pass.md): SSH keys kept in a KeePass vault (KeeAgent entries)
# that `kutup sync` keeps, served to OpenSSH's own tools.
#
# Checked: the agent lists the vault's keys (`ssh-add -l`) after opening the
# vault with the key kept in the account (no password given); a git-style
# signature made through it verifies (`ssh-keygen -Y sign/verify`); without
# a terminal to ask on, a request is denied unless --no-confirm; a key added
# to the vault later is listed without restarting; `kutup ssh-add` pushes a
# key into a system ssh-agent with a lifetime.
#
# Required env:
#   KUTUP_SERVER     e.g. http://<backend>:3000
# Requires: cargo, jq, OpenSSH (ssh-keygen, ssh-add, ssh-agent), setsid.
set -euo pipefail

: "${KUTUP_SERVER:?set KUTUP_SERVER}"
[ -n "${KUTUP_INSECURE_TLS:-}" ] && export KUTUP_INSECURE_TLS

TMP="$(mktemp -d)"
P="pass-ssh-$$"
AGENT_PID=""
SYS_AGENT_PID=""
cleanup() {
  [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null
  [ -n "$SYS_AGENT_PID" ] && kill "$SYS_AGENT_PID" 2>/dev/null
  [ -n "${BIN:-}" ] && "$BIN" --profile "$P" logout >/dev/null 2>&1
  rm -rf "$TMP"
  true
}
trap cleanup EXIT

cd "$(dirname "$0")/.."
echo "==> building kutup-cli and the vault tool…"
cargo build -q -p kutup-cli
cargo build -q -p kutup-pass --example vault
BIN="target/debug/kutup"
VAULT_TOOL="target/debug/examples/vault"

pass() { printf '  \033[32mok\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

export KUTUP_PASSWORD="pass-ssh-pw-$$-123456"
export VAULT_PASSWORD="vault-pw-$$"
EMAIL="passssh$$-$(date +%s)@example.com"
"$BIN" --profile "$P" register --server "$KUTUP_SERVER" --email "$EMAIL" --username "pssh$(date +%s | tail -c 7)$((RANDOM % 100))" >/dev/null 2>&1
"$BIN" --profile "$P" login --server "$KUTUP_SERVER" --email "$EMAIL" >/dev/null 2>&1
FOLDER="$("$BIN" --profile "$P" --json mkdir "Keys-$$" | jq -r .id)"
mkdir -p "$TMP/sync"

# A vault with an SSH key whose passphrase is the entry's password.
ssh-keygen -q -t ed25519 -C "ayse@laptop" -N "key-passphrase" -f "$TMP/id_ed25519"
"$VAULT_TOOL" new "$TMP/sync/keys.kdbx"
"$VAULT_TOOL" ssh-key "$TMP/sync/keys.kdbx" "Sunucu" "$TMP/id_ed25519" "key-passphrase"
KUTUP_VAULT_PASSWORD="$VAULT_PASSWORD" "$BIN" --profile "$P" sync "$TMP/sync" "$FOLDER" >/dev/null 2>&1
FILE_ID="$("$BIN" --profile "$P" --json ls "$FOLDER" | jq -r '.[] | select(.type=="file") | .id')"
KUTUP_VAULT_PASSWORD="$VAULT_PASSWORD" "$BIN" --profile "$P" pass keep "$FILE_ID" >/dev/null
WANT="$(ssh-keygen -lf "$TMP/id_ed25519.pub" | awk '{print $2}')"
pass "a vault with a KeeAgent key, synced, its key kept in the account"

start_agent() { # extra args…
  rm -f "$TMP/agent.sock"
  # No terminal (setsid): the agent cannot ask. No password in the environment:
  # the vault opens with the key kept in the account.
  env -u KUTUP_VAULT_PASSWORD setsid "$BIN" --profile "$P" ssh-agent "$TMP/sync" "$FOLDER" \
    --socket "$TMP/agent.sock" "$@" >"$TMP/agent.out" 2>"$TMP/agent.log" </dev/null &
  AGENT_PID=$!
  for _ in $(seq 1 50); do [ -S "$TMP/agent.sock" ] && return; sleep 0.2; done
  cat "$TMP/agent.log"; fail "the agent did not start"
}
stop_agent() { kill "$AGENT_PID" 2>/dev/null; wait "$AGENT_PID" 2>/dev/null || true; AGENT_PID=""; }

# --- listing, and a git signature through the agent ---
start_agent --no-confirm
LISTED="$(SSH_AUTH_SOCK="$TMP/agent.sock" ssh-add -l)"
echo "$LISTED" | grep -q "$WANT" || { echo "$LISTED"; cat "$TMP/agent.log"; fail "ssh-add -l lists the key"; }
grep -q "SSH_AUTH_SOCK=$TMP/agent.sock; export SSH_AUTH_SOCK;" "$TMP/agent.out" || fail "the agent prints the shell line"
pass "the agent lists the vault's key (opened with the kept key)"

echo "commit tree 1234" > "$TMP/message"
SSH_AUTH_SOCK="$TMP/agent.sock" ssh-keygen -q -Y sign -f "$TMP/id_ed25519.pub" -n git "$TMP/message" 2>"$TMP/sign.err" ||
  { cat "$TMP/sign.err" "$TMP/agent.log"; fail "sign through the agent"; }
echo "ayse $(cat "$TMP/id_ed25519.pub")" > "$TMP/allowed"
ssh-keygen -q -Y verify -f "$TMP/allowed" -I ayse -n git -s "$TMP/message.sig" < "$TMP/message" >/dev/null ||
  fail "the signature verifies"
grep -q "signed with Sunucu (git signature)" "$TMP/agent.log" || { cat "$TMP/agent.log"; fail "the agent logs the git signature"; }
pass "a git signature made through the agent verifies"

# --- a key added to the vault is listed without restarting ---
ssh-keygen -q -t ed25519 -C "deploy" -N "" -f "$TMP/id_deploy"
"$VAULT_TOOL" ssh-key "$TMP/sync/keys.kdbx" "Deploy" "$TMP/id_deploy" ""
WANT2="$(ssh-keygen -lf "$TMP/id_deploy.pub" | awk '{print $2}')"
SSH_AUTH_SOCK="$TMP/agent.sock" ssh-add -l | grep -q "$WANT2" || { cat "$TMP/agent.log"; fail "the new key is listed"; }
pass "a key added to the vault is listed without restarting"
stop_agent

# --- asking: without a terminal, denied ---
start_agent
rm -f "$TMP/message.sig"
if SSH_AUTH_SOCK="$TMP/agent.sock" ssh-keygen -q -Y sign -f "$TMP/id_ed25519.pub" -n git "$TMP/message" 2>/dev/null; then
  fail "a request nobody allowed was signed"
fi
grep -q "denied" "$TMP/agent.log" || { cat "$TMP/agent.log"; fail "the agent says it denied"; }
pass "without a terminal to ask on, the agent denies"
stop_agent

# --- push mode: into a system ssh-agent, with a lifetime ---
eval "$(ssh-agent -s -a "$TMP/sys.sock")" >/dev/null
SYS_AGENT_PID="$SSH_AGENT_PID"
env -u KUTUP_VAULT_PASSWORD "$BIN" --profile "$P" ssh-add "$TMP/sync" "$FOLDER" "Sunucu" --lifetime 120 </dev/null >"$TMP/add.out" 2>&1 ||
  { cat "$TMP/add.out"; fail "kutup ssh-add"; }
ssh-add -l | grep -q "$WANT" || { ssh-add -l; fail "the system agent holds the key"; }
pass "kutup ssh-add pushes the key into the system agent with a lifetime"

echo "==> all kutup SSH agent checks passed"
