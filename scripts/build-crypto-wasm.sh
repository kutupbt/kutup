#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="$ROOT/crates/kutup-crypto-wasm"
OUT="$ROOT/frontend/public/crypto-wasm"

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "wasm-bindgen CLI is required (install version 0.2.126)" >&2
  exit 1
fi

mkdir -p "$OUT"
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo build \
  --manifest-path "$WRAPPER/Cargo.toml" \
  --release \
  --target wasm32-unknown-unknown
wasm-bindgen \
  "$ROOT/target/wasm32-unknown-unknown/release/kutup_crypto_wasm.wasm" \
  --target web \
  --typescript \
  --out-dir "$OUT" \
  --out-name kutup_crypto_wasm
