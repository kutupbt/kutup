#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE="$ROOT/crates/kutup-client-ffi"
OUT="${1:-$ROOT/build/native-bindings}"

case "$(uname -s)" in
  Darwin) LIB="$CRATE/target/release/libkutup_client_ffi.dylib" ;;
  Linux) LIB="$CRATE/target/release/libkutup_client_ffi.so" ;;
  *)
    echo "Generate bindings on macOS or Linux; unsupported host: $(uname -s)" >&2
    exit 1
    ;;
esac

if ! command -v protoc >/dev/null 2>&1; then
  echo "protoc is required to compile the pinned libsignal dependency" >&2
  exit 1
fi

mkdir -p "$OUT/swift" "$OUT/kotlin"
cargo build --manifest-path "$CRATE/Cargo.toml" --release
cargo run \
  --manifest-path "$CRATE/Cargo.toml" \
  --release \
  --features bindgen \
  --bin uniffi-bindgen \
  -- generate --library "$LIB" --language swift --out-dir "$OUT/swift"
cargo run \
  --manifest-path "$CRATE/Cargo.toml" \
  --release \
  --features bindgen \
  --bin uniffi-bindgen \
  -- generate --library "$LIB" --language kotlin --out-dir "$OUT/kotlin"

echo "Generated Swift and Kotlin bindings in $OUT"
