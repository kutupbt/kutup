# Vendored: keepass 0.15.2

Upstream: https://github.com/sseemayer/keepass-rs (crates.io `keepass` 0.15.2,
MIT licence, see `LICENSE`). Crate archive SHA-256: `83630a8882d1f2a8c03ee00911b67904c1b878daf1d51efe3fed133d20fc9b87`.

Kutup carries one patch, applied by `scripts/patch-vendored-keepass.py`: it
makes the database model's internal fields and two id constructors public, so
`crates/kutup-pass` can read and write a vault completely (custom icons keep
their UUIDs, history items keep their attachments), points the README's relative examples link at upstream (the README is the
crate's rustdoc), then formats the crate
with the workspace's rustfmt settings so `cargo fmt --all -- --check` passes
(upstream's own formatting is not consistent). Neither changes behaviour.

To update: replace this directory with the new release from crates.io, delete
`Cargo.lock`, `.cargo_vcs_info.json` and `.cargo-ok`, keep this file, run the patch script,
and run `cargo test -p kutup-pass` (the KeePassXC corpus and the merge tests
must pass). Review the upstream diff first: this code decrypts vaults.
