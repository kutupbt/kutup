#!/usr/bin/env bash
set -euo pipefail

# The `.ics` runtime (crates/kutup-calendar-ics-wasm): the Calendar app loads
# it on the first import or export (docs/plans/calendar.md, E2c).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="$ROOT/crates/kutup-calendar-ics-wasm"
OUT="$ROOT/frontend/wasm/calendar-ics-wasm"

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "wasm-bindgen CLI is required (install version 0.2.126)" >&2
  exit 1
fi

mkdir -p "$OUT"
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo build \
  --manifest-path "$WRAPPER/Cargo.toml" \
  --profile wasm-release \
  --target wasm32-unknown-unknown
wasm-bindgen \
  "$ROOT/target/wasm32-unknown-unknown/wasm-release/kutup_calendar_ics_wasm.wasm" \
  --target web \
  --typescript \
  --remove-name-section \
  --remove-producers-section \
  --out-dir "$OUT" \
  --out-name kutup_calendar_ics_wasm
