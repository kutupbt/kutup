#!/usr/bin/env bash
# Runs the vendored keepass crate's own unit tests (crates/kutup-pass/vendor/
# keepass, KUTUP.md) with the features Kutup Pass builds it with.
#
# The crate is outside the workspace, and its manifest names dependencies
# Kutup never builds (upstream's command-line tools, YubiKey support, and
# dev-dependencies for files the published crate doesn't ship), so it can't
# be tested in place without a lockfile of its own. Instead a copy is tested
# in the target directory: its manifest without the [[bin]] targets, those
# optional dependencies and the dev-dependencies, and the workspace's
# Cargo.lock, offline, so it builds with exactly the versions Kutup ships.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${CARGO_TARGET_DIR:-$ROOT/target}"
WORK="$TARGET/vendored-keepass-test"
rm -rf "$WORK/keepass"
mkdir -p "$WORK"
cp -r "$ROOT/crates/kutup-pass/vendor/keepass" "$WORK/keepass"
cp "$ROOT/Cargo.lock" "$WORK/keepass/Cargo.lock"
python3 -I - "$WORK/keepass/Cargo.toml" <<'PY'
import re, sys
path = sys.argv[1]
sections, current = [], []
for line in open(path).read().split("\n"):
    if line.startswith("[") and current:
        sections.append(current)
        current = []
    current.append(line)
sections.append(current)
unused = {"anyhow", "challenge_response", "clap", "rpassword"}
out = []
for section in sections:
    head = section[0].strip()
    if head == "[[bin]]" or "dev-dependencies" in head:
        continue
    name = re.match(r"\[dependencies\.([^\]]+)\]", head)
    if name and name.group(1) in unused:
        continue
    if head == "[features]":
        text = "\n".join(section)
        for feature in ("challenge_response", "utilities"):
            text, count = re.subn(feature + r" = \[[^\]]*\]\n", "", text)
            if count != 1:
                sys.exit(f"test-vendored-keepass: feature {feature} not found once")
        section = text.split("\n")
    out.extend(section)
open(path, "w").write("\n".join(out) + "\n[workspace]\n")
PY
CARGO_TARGET_DIR="$WORK/target" cargo test --offline \
  --manifest-path "$WORK/keepass/Cargo.toml" --lib --features save_kdbx4,totp
