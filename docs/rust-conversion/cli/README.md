# `kutup` CLI

**Status:** Go-to-Rust conversion complete. This page now summarizes the
current Rust CLI while preserving links to the conversion test record.

The `kutup` binary is implemented in `crates/kutup-cli`, uses the canonical
`kutup-crypto` formats, and communicates with the current Rust server. Run
`kutup --help` and each subcommand's `--help` for the exact live interface.

## Command groups

- Account/session: `register`, `login`, `recover`, `logout`, `whoami`.
- Drive: `ls`, `mkdir`, `mv`, `rm`, `upload`, `download`, `sync`, `color`.
- Recovery/lifecycle: `trash`, `versions`, `devices`, `2fa`.
- Sharing: `share folder`, `share federated`, `share public`, federated-share
  browse/upload/download/incoming operations, and unauthenticated `pub`
  consumption.
- Diagnostics: `version`.

Global flags are `--profile <name>` (default `default`) and `--json`.
Interrupted uploads resume by default; recursive upload, sync watch/poll,
deletion propagation, and dry-run behavior are documented in the top-level
[`README.md`](../../../README.md#common-workflows).

## Intentional platform behavior

- Sessions use `redb`; the CLI device-key service is `kutup-cli` and is
  separate from the Tauri application's `dev.kutup.client` service.
- macOS and Windows protect the device key in the OS credential store. Linux
  uses a mode-0600 file under the profile data directory.
- Public-share URLs use `/s/<token>#key=...`; the Go-era `/p/` form remains
  accepted for compatibility.
- `.excalidraw` upload extracts assets and download re-inlines them. The older
  conversion-era deferral is complete.

## Build and live verification

```sh
cargo build --release -p kutup-cli

KUTUP_SERVER=https://localhost:38443 \
KUTUP_EMAIL=you@example.com \
KUTUP_PASSWORD='your-password' \
KUTUP_INSECURE_TLS=1 \
scripts/verify-cli.sh
```

See [`testing.md`](testing.md) for the current live-stack walkthrough. The old
Go differential comparisons are retained only in Git history; the Go binary is
no longer part of this repository.
