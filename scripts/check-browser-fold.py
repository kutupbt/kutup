#!/usr/bin/env python3
"""Keeps kutup-search's `browser` fold to indexes that stay in one browser.

The `browser` feature folds through the browser's own Unicode normalization
(String.prototype.normalize), whose Unicode version is the browser's. That is
fine for an index built and queried in the same browser (Pass's search, Mail's
body search), and wrong for anything another machine must reproduce: the
server's keyed search tokens (server-personal-data.md, L7), any hash, index
or record the server or another device folds again. Those keep the Rust
tables everywhere.

So only the crates below may turn the feature on, directly or through
kutup-pass's own `browser` feature. Adding one means checking that what it
folds never leaves the browser that folded it, then adding it here.
"""
import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
ALLOWED = {
    # Forwards the feature to kutup-search; on only in the Pass WASM.
    "crates/kutup-pass/Cargo.toml",
    # Pass: the vault's search, in the page's worker.
    "crates/kutup-pass-wasm/Cargo.toml",
    # Mail's body search: an index sealed in that browser's IndexedDB.
    "crates/kutup-mail-search-wasm/Cargo.toml",
}
CARRIERS = {"kutup-search", "kutup-pass"}


def dependency_tables(manifest):
    for name in ("dependencies", "dev-dependencies", "build-dependencies"):
        yield manifest.get(name, {})
    for target in manifest.get("target", {}).values():
        for name in ("dependencies", "dev-dependencies", "build-dependencies"):
            yield target.get(name, {})


def uses(manifest):
    """Where a manifest turns the browser fold on."""
    found = []
    for table in dependency_tables(manifest):
        for name, spec in table.items():
            package = spec.get("package", name) if isinstance(spec, dict) else name
            if package in CARRIERS and isinstance(spec, dict) and "browser" in spec.get("features", []):
                found.append(f"{package} with features = [\"browser\"]")
    for feature, items in manifest.get("features", {}).items():
        for item in items:
            if item in {"kutup-search/browser", "kutup-pass/browser", "kutup-search?/browser", "kutup-pass?/browser"}:
                found.append(f"feature {feature} = [\"{item}\"]")
    return found


def main():
    failures = []
    for path in sorted(ROOT.rglob("Cargo.toml")):
        relative = path.relative_to(ROOT).as_posix()
        if any(part in {"target", "node_modules", "vendor", ".git"} for part in path.parts):
            continue
        found = uses(tomllib.loads(path.read_text()))
        if found and relative not in ALLOWED:
            failures.append(f"{relative}: {', '.join(found)}")
    if failures:
        print("check-browser-fold: the browser fold is only for indexes that stay in one browser:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print("  (see scripts/check-browser-fold.py before allowing one)", file=sys.stderr)
        return 1
    print("check-browser-fold: the browser fold is used only where allowed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
