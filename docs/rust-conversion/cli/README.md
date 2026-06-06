# kutup-cli (Phase 2 ✅)

The `kutup` CLI — Rust rewrite of `cmd/kutup/`. All 16 commands match the Go CLI's
surface. Built on `reqwest::blocking` (sync), reusing the verified `kutup-crypto` crate.

## Commands

`login`, `logout`, `whoami`, `ls` (`--tree`), `mkdir` (`--parent`), `mv`, `rm`
(`--folder`), `upload` (`-r`), `download`, `sync` (`--watch`), `color`, `devices`
(`list` | `revoke --yes`), `versions` (`list` | `download` | `restore` |
`label --keep-forever`), `share` (`folder` | `federated` | `public` | `files` |
`download` | `upload` | `incoming {list|accept|remove}`), `pub` (`get` | `ls` |
`download`), `version`.

Global flags: `--profile <name>` (default `default`), `--json`.

## Module map (Go → Rust)

| Go | Rust |
|---|---|
| `internal/crypto/*` | `kutup-crypto` crate |
| `internal/session/store.go` | `src/session.rs` |
| `internal/api/*` | `src/api/*` (`mod, types, tus, versions, files, devices, sharing, federation, public`) |
| `internal/upload/stream.go` + `download/stream.go` | `src/transfer.rs` |
| `internal/sync/engine.go` | `src/syncengine.rs` |
| `cmd/*.go` | `src/commands/*.rs` |
| `cmd/helpers.go` | `src/cryptohelpers.rs` |
| `cmd/session.go` | `src/context.rs` |

## Intentional deviations from Go (all defensible)

- `reqwest::blocking` instead of `net/http` (synchronous-flow parity).
- Store is `redb` (`kutup.redb`), not BoltDB → switching binaries requires `kutup login`
  again (the redb file deliberately doesn't collide with a Go-era `kutup.db`).
- Linux device key lives in a chmod-600 file (no libdbus); macOS/Windows use the OS
  keychain (service `kutup-cli/<profile>`, account `device-key`).
- `envelope::verify` is strict (see `../decisions.md`).
- `.excalidraw` asset extraction (upload) + hydration (download) are **deferred** — they
  need the asset/snapshot API; regular files transfer correctly. Tracked in
  `docs/roadmap.md`.

## Automation / testing env vars

- `KUTUP_INSECURE_TLS=1` — accept the self-signed dev cert.
- `KUTUP_PASSWORD` + `kutup login --server X --email Y` — non-interactive login.
- `KUTUP_DEVICE_KEY` (base64, 32 bytes) — device key for Docker / CI.
- **Live check** (run on a VM with a reachable stack):

  ```sh
  KUTUP_SERVER=https://localhost:38443 \
  KUTUP_EMAIL=you@example.com \
  KUTUP_PASSWORD=… \
  KUTUP_INSECURE_TLS=1 \
  scripts/verify-cli.sh
  ```

  It runs login → whoami → mkdir → upload (6 MiB, multi-chunk) → ls → download →
  sha256 compare → rm → logout.

See **[`testing.md`](testing.md)** for the full VM testing guide — build, getting a test
account, manual walkthrough, differential testing against the Go CLI, known quirks, and
troubleshooting.
