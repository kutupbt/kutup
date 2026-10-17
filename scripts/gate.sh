#!/usr/bin/env bash
# The one gate. CI's jobs call these stages, and so does a local pre-merge
# run, so what passes here passes there (docs/contributing.md).
#
#   scripts/gate.sh static              formatting, lints, docs and config checks
#   scripts/gate.sh rust                Rust tests and lockfile checks, every Cargo root
#                                       (rust-workspace + rust-standalone)
#   scripts/gate.sh web                 frontend install, WASM builds and tests, build
#   scripts/gate.sh browser <suite>...  browser specs from tests/e2e/suites/<suite>.txt,
#                                       against an already running stack
#   scripts/gate.sh live <name>...      live gates: mail, backup, federation, and pass
#                                       (pass: against a running stack, KUTUP_LIVE_SERVER
#                                       and KUTUP_LIVE_DATABASE_URL set)
#   scripts/gate.sh all                 static, rust and web
#
# The Cargo roots: the workspace, plus three that stay outside it with their
# own Cargo.lock (Chat core, the native client FFI and the fuzz targets). A
# root-level `cargo fmt --all` or `cargo test --workspace` never sees those,
# which once let a formatting error and a stale FFI lock reach master.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# The Cargo roots outside the workspace, each with its own lockfile.
standalone_crates=(crates/kutup-chat-core crates/kutup-client-ffi)

step() {
  printf '\n== %s\n' "$*"
}

static() {
  step "Compose S3 credential wiring"
  python3 scripts/test-compose-s3-credentials.py
  step "Migrations (applied ones unchanged, new ones newer than the base)"
  scripts/check-migrations.sh "${KUTUP_MIGRATION_BASE:-origin/master}"
  step "Documentation checks"
  python3 scripts/test-check-docs.py
  python3 scripts/check-docs.py
  step "Formatting (workspace, standalone crates, fuzz)"
  cargo fmt --all -- --check
  for crate in "${standalone_crates[@]}"; do
    cargo fmt --manifest-path "$crate/Cargo.toml" -- --check
  done
  cargo fmt --manifest-path fuzz/Cargo.toml -- --check
  step "Clippy (workspace)"
  cargo clippy --locked --workspace --all-targets -- -D warnings
  # TODO(after the clean-slate release): clippy -D warnings for the
  # standalone crates too. Chat core has 76 findings and the FFI one, never
  # checked before; they are fixed once the Chat wire changes have landed,
  # to keep that churn out of the same release.
}

rust_workspace() {
  step "Workspace tests"
  # --workspace on purpose: feature unification turns on kutup-crypto's
  # `mail` feature, and its vector tests need it (a per-crate run skips them).
  cargo test --locked --workspace --all-targets
}

rust_standalone() {
  step "Chat core tests"
  cargo test --locked --manifest-path crates/kutup-chat-core/Cargo.toml --all-targets
  step "Native client FFI (lockfile current, compiles)"
  cargo check --locked --manifest-path crates/kutup-client-ffi/Cargo.toml --all-targets
  step "Fuzz targets (lockfile current, compile)"
  cargo check --locked --manifest-path fuzz/Cargo.toml --bins
}

rust() {
  rust_workspace
  rust_standalone
}

web() {
  # The apps' Vite configs import TypeScript from packages/config, which Node
  # loads natively from 22.18 (type stripping on by default). CI and the
  # images use the newest Node 22; an older local Node fails the build.
  node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>22||(a===22&&b>=18)?0:1)' \
    || { echo "gate: web needs Node 22.18 or newer (this is $(node -v))" >&2; return 2; }
  step "Frontend dependencies"
  pnpm -C frontend install --frozen-lockfile
  step "WASM modules"
  pnpm -C frontend run build:wasm
  step "Type check and lint"
  pnpm -C frontend exec tsc --noEmit
  pnpm -C frontend lint
  step "Frontend tests"
  pnpm -C frontend exec vitest run --reporter=dot
  step "WASM vectors and modules"
  pnpm -C frontend run test:crypto-wasm
  pnpm -C frontend run test:pass-wasm
  pnpm -C frontend run test:mail-search-wasm
  step "Production build"
  pnpm -C frontend run build
}

# The specs of one or more suites. Each list lives in
# tests/e2e/suites/<suite>.txt, one spec path per line ('#' starts a
# comment); CI reads the same files.
suite_specs() {
  local suite file
  for suite in "$@"; do
    file="tests/e2e/suites/$suite.txt"
    if [ ! -f "$file" ]; then
      echo "gate: no suite '$suite' (tests/e2e/suites/*.txt)" >&2
      return 2
    fi
    sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$file"
  done
}

browser() {
  if [ "$#" -eq 0 ]; then
    echo "gate: browser needs a suite: $(ls tests/e2e/suites | sed 's/\.txt$//' | tr '\n' ' ')" >&2
    return 2
  fi
  local specs
  specs="$(suite_specs "$@")"
  if [ -z "$specs" ]; then
    echo "gate: suite '$*' lists no specs" >&2
    return 2
  fi
  step "Browser specs: $*"
  # One spec path per word: spec paths never contain spaces.
  # shellcheck disable=SC2086
  (cd tests/e2e && npm exec -- playwright test $specs --project=chromium)
}

live() {
  if [ "$#" -eq 0 ]; then
    echo "gate: live needs a gate: mail backup federation pass" >&2
    return 2
  fi
  local name
  for name in "$@"; do
    case "$name" in
      mail) step "Mail gate"; scripts/test-mail-inbound.sh ;;
      backup) step "Chat backup lifecycle"; scripts/test-chat-backup-integration.sh ;;
      federation) step "Two-server federation"; scripts/test-chat-federation.sh ;;
      pass)
        : "${KUTUP_LIVE_SERVER:?live pass needs KUTUP_LIVE_SERVER (the backend of a running stack)}"
        : "${KUTUP_LIVE_DATABASE_URL:?live pass needs KUTUP_LIVE_DATABASE_URL}"
        step "Kutup Pass: live server tests"
        cargo test --locked -p kutup-server --test pass_live -- --test-threads=1
        step "Kutup Pass: two machines sync one vault"
        KUTUP_SERVER="$KUTUP_LIVE_SERVER" scripts/verify-pass-sync.sh
        step "Kutup Pass: the SSH agent against OpenSSH"
        KUTUP_SERVER="$KUTUP_LIVE_SERVER" scripts/verify-pass-ssh.sh
        ;;
      *) echo "gate: unknown live gate '$name' (mail backup federation pass)" >&2; return 2 ;;
    esac
  done
}

stage="${1:-}"
shift || true
case "$stage" in
  static) static ;;
  rust) rust ;;
  rust-workspace) rust_workspace ;;
  rust-standalone) rust_standalone ;;
  web) web ;;
  browser) browser "$@" ;;
  live) live "$@" ;;
  suite-specs) suite_specs "$@" ;;
  all) static; rust; web ;;
  *)
    sed -n '2,/gate\.sh all /p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
