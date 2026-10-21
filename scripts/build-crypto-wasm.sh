#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="$ROOT/crates/kutup-crypto-wasm"
OUT="$ROOT/frontend/wasm/crypto-wasm"

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "wasm-bindgen CLI is required (install version 0.2.126)" >&2
  exit 1
fi

# Two runtimes from the one crate: `crypto` for every app, and
# `crypto-calendar` (the `calendar` feature: calendars and the time zone
# database) for the apps that need it, which load it instead of `crypto`.
build() {
  local out="$1"
  shift
  mkdir -p "$out"
  RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo build \
    --manifest-path "$WRAPPER/Cargo.toml" \
    --profile wasm-release \
    --target wasm32-unknown-unknown \
    "$@"
  wasm-bindgen \
    "$ROOT/target/wasm32-unknown-unknown/wasm-release/kutup_crypto_wasm.wasm" \
    --target web \
    --typescript \
    --remove-name-section \
    --remove-producers-section \
    --out-dir "$out" \
    --out-name kutup_crypto_wasm
}

build "$OUT"
build "$ROOT/frontend/wasm/crypto-calendar-wasm" --features calendar
