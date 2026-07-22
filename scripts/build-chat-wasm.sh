#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE="$ROOT/crates/kutup-chat-core"
OUT="$ROOT/frontend/public/chat-wasm"

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "wasm-bindgen CLI is required (install version 0.2.126)" >&2
  exit 1
fi

mkdir -p "$OUT"
cargo build \
  --manifest-path "$CORE/Cargo.toml" \
  --release \
  --target wasm32-unknown-unknown \
  --no-default-features \
  --features wasm
wasm-bindgen \
  "$CORE/target/wasm32-unknown-unknown/release/kutup_chat_core.wasm" \
  --target web \
  --typescript \
  --out-dir "$OUT" \
  --out-name kutup_chat_core
