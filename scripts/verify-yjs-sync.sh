#!/usr/bin/env bash
#
# verify-yjs-sync.sh — the live check of notes, code files and place lists in
# `kutup sync` (docs/plans/cli-yjs-sync.md): the CLI edits them as a
# collaboration peer, like a browser tab, so edits made on two machines merge
# and the file stays one Drive file.
#
#   machine A and machine B (two CLI profiles of one account, two folders,
#   two collaboration devices) share notes/todo.md and trip.kutupmap through
#   `kutup sync`.
#
# Checked: a new note goes up as a file and reaches the other machine (from
# its upload: nobody has opened it); disjoint edits on both machines merge,
# Turkish letters and emoji included; edits to the same words converge to
# one text on both; place lists merge by place; the file id never changes
# and no conflict copy appears; the CLI saves `yjs` versions; each machine
# registered a signed device, and a revoked one is replaced on the next run;
# a note deleted on one machine while edited on the other comes back, and
# goes once nobody edits it.
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
A="yjs-a-$$"
B="yjs-b-$$"
trap 'rm -rf "$TMP"; [ -n "${BIN:-}" ] && { "$BIN" --profile "$A" logout >/dev/null 2>&1; "$BIN" --profile "$B" logout >/dev/null 2>&1; }; true' EXIT

cd "$(dirname "$0")/.."
echo "==> building kutup-cli…"
cargo build -q -p kutup-cli
BIN="target/debug/kutup"

pass() { printf '  \033[32mok\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

export KUTUP_PASSWORD="yjs-sync-pw-$$-123456"
sync_on() { # machine [flags]
  local m="$1"
  shift
  "$BIN" --profile "$m" sync "$@" "$TMP/$m" "$FOLDER" 2>"$TMP/$m.log" >/dev/null ||
    { cat "$TMP/$m.log"; fail "sync on $m"; }
}
same() { [ "$1" = "$2" ] || fail "$3: got '$1', want '$2'"; }
# A new mtime for the next local write.
tick() { sleep 1.1; }
note() { cat "$TMP/$1/notes/todo.md"; }
place_names() { jq -r '[.places[].name] | join(",")' "$TMP/$1/trip.kutupmap"; }
file_id() { # name
  local sub="$FOLDER"
  [ "$1" = todo.md ] && sub="$NOTES"
  "$BIN" --profile "$A" --json ls "$sub" | jq -r --arg n "$1" '.[] | select(.type=="file" and .name==$n) | .id'
}

NAME="yjs$(date +%s | tail -c 7)$((RANDOM % 100))"
echo "==> account $NAME @ $KUTUP_SERVER"
"$BIN" --profile "$A" register --server "$KUTUP_SERVER" --username "$NAME" >/dev/null
"$BIN" --profile "$A" login --server "$KUTUP_SERVER" --username "$NAME" >/dev/null
"$BIN" --profile "$B" login --server "$KUTUP_SERVER" --username "$NAME" >/dev/null
pass "machine A registered, machine B signed in"

FOLDER="$("$BIN" --profile "$A" --json mkdir "Notes-$$" | jq -r .id)"
mkdir -p "$TMP/$A/notes" "$TMP/$B"

# --- a new note and list reach both machines ---
printf 'İstanbul listesi 😀\nekmek al\nsüt al\nçay al\n' >"$TMP/$A/notes/todo.md"
cat >"$TMP/$A/trip.kutupmap" <<'EOF'
{"format":"kutupmap","version":1,"places":[
 {"id":"galata","name":"Galata","note":"","lat":41.0256,"lon":28.9742,"addedBy":"","addedAt":"2026-10-13T10:00:00.000Z"},
 {"id":"moda","name":"Moda","note":"","lat":40.98,"lon":29.03,"addedBy":"","addedAt":"2026-10-13T11:00:00.000Z"}]}
EOF
sync_on "$A"
sync_on "$B"
NOTES="$("$BIN" --profile "$A" --json ls "$FOLDER" | jq -r '.[] | select(.type=="folder" and .name=="notes") | .id')"
same "$(note "$B")" "$(note "$A")" "B has the note"
same "$(place_names "$B")" "Galata,Moda" "B has the list"
NOTE_ID="$(file_id todo.md)"
LIST_ID="$(file_id trip.kutupmap)"
pass "note and list synced to both machines (files $NOTE_ID, $LIST_ID)"

# --- disjoint edits on both machines merge ---
tick
printf 'İstanbul listesi 😀🎉\nekmek al\nsüt al\nçay al\n' >"$TMP/$A/notes/todo.md"
printf 'İstanbul listesi 😀\nekmek al\nsüt al\nçay al\nıhlamur al\n' >"$TMP/$B/notes/todo.md"
sync_on "$A"
grep -q "↑ notes/todo.md" "$TMP/$A.log" || { cat "$TMP/$A.log"; fail "A sent its edit"; }
sync_on "$B"
grep -q "⇅ notes/todo.md" "$TMP/$B.log" || { cat "$TMP/$B.log"; fail "B merged"; }
sync_on "$A"
want="$(printf 'İstanbul listesi 😀🎉\nekmek al\nsüt al\nçay al\nıhlamur al\n')"
for m in "$A" "$B"; do same "$(note "$m")" "$want" "$m: both edits"; done
pass "disjoint edits from both machines merged on both (Turkish, emoji)"

# --- the same words edited on both: one text on both ---
tick
sed -i 's/süt al/süt al (2 litre)/' "$TMP/$A/notes/todo.md"
sed -i 's/süt al/ayran al/' "$TMP/$B/notes/todo.md"
sync_on "$A"
sync_on "$B"
sync_on "$A"
same "$(note "$A")" "$(note "$B")" "the same text on both"
grep -q "ekmek al" "$TMP/$A/notes/todo.md" || fail "untouched lines kept"
grep -q "litre" "$TMP/$A/notes/todo.md" || fail "A's edit kept"
grep -q "ayran" "$TMP/$A/notes/todo.md" || fail "B's edit kept"
pass "edits to the same words converge, neither lost"

# --- place lists merge by place ---
tick
jq '.places |= map(if .id == "galata" then .name = "Galata Kulesi" else . end)' "$TMP/$A/trip.kutupmap" >"$TMP/l" && mv "$TMP/l" "$TMP/$A/trip.kutupmap"
jq '.places += [{"id":"kadikoy","name":"Kadıköy","note":"","lat":40.99,"lon":29.02,"addedBy":"","addedAt":"2026-10-13T12:00:00.000Z"}] | .places |= map(select(.id != "moda"))' "$TMP/$B/trip.kutupmap" >"$TMP/l" && mv "$TMP/l" "$TMP/$B/trip.kutupmap"
sync_on "$A"
sync_on "$B"
sync_on "$A"
for m in "$A" "$B"; do same "$(place_names "$m")" "Galata Kulesi,Kadıköy" "$m: the list"; done
pass "a rename on one machine, an add and a removal on the other: all kept"

# --- one file each, the same ones; versions saved ---
same "$(file_id todo.md)" "$NOTE_ID" "the note's file id"
same "$(file_id trip.kutupmap)" "$LIST_ID" "the list's file id"
same "$("$BIN" --profile "$A" --json ls "$NOTES" | jq -r '[.[] | select(.type=="file") | .name] | join(",")')" todo.md "files in notes/"
find "$TMP/$A" "$TMP/$B" -name '*conflict*' | grep -q . && fail "no conflict copies"
YJS="$("$BIN" --profile "$A" --json versions list "$NOTE_ID" | jq '[.[] | select(.kind=="yjs")] | length')"
[ "$YJS" -ge 1 ] || fail "the CLI saved yjs versions"
pass "one Drive file each with a stable id; no conflict copies; $YJS yjs versions"

# --- devices: one signed device per machine; a revoked one is replaced ---
DEVICES="$("$BIN" --profile "$A" --json devices list)"
same "$(jq '[.[] | select(.trusted)] | length' <<<"$DEVICES")" 2 "trusted devices"
B_DEVICE="$("$BIN" --profile "$B" --json devices list | jq -r '[.[] | select(.trusted)] | sort_by(.createdAt) | last | .deviceId')"
"$BIN" --profile "$A" devices revoke "$B_DEVICE" --yes >/dev/null
tick
printf 'yeni satır\n' >>"$TMP/$B/notes/todo.md"
sync_on "$B"
sync_on "$A"
grep -q "yeni satır" "$TMP/$A/notes/todo.md" || fail "B's edit after the revocation reached A"
same "$("$BIN" --profile "$A" --json devices list | jq '[.[] | select(.trusted)] | length')" 2 "trusted devices after"
"$BIN" --profile "$A" --json devices list | jq -e --argjson d "$B_DEVICE" '.[] | select(.deviceId == $d) | .isActive == false' >/dev/null ||
  fail "the revoked device stays revoked"
pass "a revoked device is replaced by a newly signed one on the next run"

# --- delete on one machine, edit on the other: the edit wins ---
tick
rm "$TMP/$A/notes/todo.md"
printf 'son not\n' >>"$TMP/$B/notes/todo.md"
sync_on "$B"
sync_on "$A" --delete
[ -f "$TMP/$A/notes/todo.md" ] || { cat "$TMP/$A.log"; fail "the edited note came back"; }
grep -q "son not" "$TMP/$A/notes/todo.md" || fail "with B's edit"
tick
rm "$TMP/$A/notes/todo.md"
sync_on "$A" --delete
[ -z "$(file_id todo.md)" ] || { cat "$TMP/$A.log"; fail "an unedited note is deleted"; }
pass "a deletion loses to an edit made elsewhere, and goes through once nobody edits"
