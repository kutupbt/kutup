#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="$ROOT/crates/kutup-mail-search-wasm"
OUT="$ROOT/frontend/wasm/mail-search-wasm"

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
  "$ROOT/target/wasm32-unknown-unknown/wasm-release/kutup_mail_search_wasm.wasm" \
  --target web \
  --typescript \
  --remove-name-section \
  --remove-producers-section \
  --out-dir "$OUT" \
  --out-name kutup_mail_search_wasm
