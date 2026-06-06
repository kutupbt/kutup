# Testing the Rust CLI on a VM

Practical guide for verifying `kutup-cli` against a live stack. The crypto is already
byte-verified offline; this exercises the HTTP wiring + session + transfer end-to-end.

## Prerequisites

- A running kutup stack reachable from the VM (e.g. the dev stack at
  `https://localhost:38443`, or a deployed server). The Rust **server** isn't required —
  test the Rust CLI against the existing **Go** backend (that's the differential oracle).
- Rust toolchain (the repo built with rustc 1.94; any recent stable works).
- `jq` and `sha256sum` (coreutils) for `verify-cli.sh`.
- **A test account.** Registration generates a 24-word mnemonic client-side, so it must
  be created via the **web UI** first — there's no `register` CLI command. Note the
  email + password.

## Build

```sh
cargo build --release -p kutup-cli      # → target/release/kutup
# or run ad-hoc:  cargo run -q -p kutup-cli -- <args>
```

## Fastest path: the automated round-trip

```sh
KUTUP_SERVER=https://localhost:38443 \
KUTUP_EMAIL=you@example.com \
KUTUP_PASSWORD='your-password' \
KUTUP_INSECURE_TLS=1 \
scripts/verify-cli.sh
```

Runs: login → whoami → mkdir → upload (6 MiB, multi-chunk) → ls → download →
sha256 compare → rm file → rm folder → logout. Each step prints `ok`/`FAIL`. A green run
proves crypto + session + tus streaming + version-preferred download all work against the
real server.

Tune the test-file size with `VERIFY_SIZE=<bytes>` (default 6 MiB, which spans the 5 MiB
secretstream chunk boundary).

## Manual walkthrough

```sh
BIN=target/release/kutup
export KUTUP_INSECURE_TLS=1                       # self-signed dev cert
export KUTUP_PASSWORD='your-password'             # non-interactive login

$BIN login --server https://localhost:38443 --email you@example.com
$BIN whoami
$BIN --json mkdir "test folder"                   # note the returned id
$BIN upload ./somefile.pdf <folder-id>
$BIN ls <folder-id>                               # find the file id
$BIN download <file-id> /tmp/out
$BIN versions list <file-id>
$BIN share public <folder-id>                     # prints a /s/ link
$BIN rm <file-id>
$BIN rm --folder <folder-id>
$BIN logout
```

Add `--json` to most commands for machine-readable output. Use `--profile <name>` to keep
multiple accounts isolated.

## Differential test against the Go CLI (recommended)

Run the same operation with both binaries against the same account and compare `--json`:

```sh
go -C cmd/kutup build -o /tmp/kutup-go .          # Go binary
diff <(/tmp/kutup-go --json ls <folder-id>) <($BIN --json ls <folder-id>)
```

The strongest cross-check: upload a file with one binary and download it with the other —
the plaintext sha256 must match (proves wire-format parity end-to-end).

## Known quirks (mirrored from the Go CLI — expected, not bugs)

- **`pub` expects `/p/<token>`, `share public` prints `/s/<token>`.** This inconsistency
  exists in the Go CLI too (`/s/` is the web page route; `pub get|ls|download` parse
  `/p/`). To test `pub`, use a `/p/` form URL. Don't "fix" this without fixing Go.
- **Switching between the Go and Rust CLI requires `kutup login` again.** The Rust CLI
  uses a `redb` store (`kutup.redb`); the Go CLI uses BoltDB (`kutup.db`). They don't
  share session state by design.
- **Linux has no OS keychain integration** (avoids a libdbus C dep) — the device key is a
  chmod-600 file under `$XDG_DATA_HOME/kutup/<profile>/device.key`. macOS/Windows use the
  native keychain.
- **`.excalidraw` whiteboards**: upload/download work, but the asset extraction/hydration
  optimization is deferred (see `docs/roadmap.md`). Regular files are unaffected.

## Troubleshooting

| Symptom | Fix |
|---|---|
| TLS/cert error against the dev stack | `export KUTUP_INSECURE_TLS=1` |
| `not logged in` | run `kutup login` (a different `--profile` has its own session) |
| `login` hangs at a prompt | set `KUTUP_PASSWORD` and pass `--email`/`--server` |
| `session decryption failed — wrong device key` | the device key changed/was lost — `kutup login` again |
| `HTTP 401` mid-session | token refresh failed; re-login (refresh token expired) |
| `account requires first-login setup` | finish setup in the web UI first |

## What to report back

If something fails, capture: the command, the full stderr (anyhow prints the error
chain), and whether the **Go** CLI succeeds on the same input. That isolates a Rust port
bug from a server/account issue.
