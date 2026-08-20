# Testing the Rust CLI on a live stack

The `kutup` CLI and Rust backend are the current implementations. This guide
tests their encrypted file/session path against a real Kutup deployment; the
former Go differential oracle has been removed.

## Prerequisites

- Rust 1.91.1 or newer.
- A healthy Kutup server, such as the Compose edge at
  `https://localhost:38443`.
- `jq` and `sha256sum` for `scripts/verify-cli.sh`.
- A disposable account. Create one with `kutup register` or the web UI and
  store its recovery phrase safely.

## Build

```sh
cargo build --release -p kutup-cli
target/release/kutup --help
```

## Automated encrypted round trip

```sh
KUTUP_SERVER=https://localhost:38443 \
KUTUP_EMAIL=you@example.com \
KUTUP_PASSWORD='your-password' \
KUTUP_INSECURE_TLS=1 \
scripts/verify-cli.sh
```

The script uses an isolated CLI profile and verifies login, identity, folder
creation, a 6 MiB multi-chunk encrypted upload, listing, streaming download,
plaintext SHA-256 equality, trash moves, and logout. `KUTUP_INSECURE_TLS=1` is
for the local self-signed certificate only; never use it with a production
server. Set `VERIFY_SIZE=<bytes>` to change the input size.

## Manual walkthrough

```sh
BIN=target/release/kutup
export KUTUP_INSECURE_TLS=1
export KUTUP_PASSWORD='your-password'

$BIN login --server https://localhost:38443 --email you@example.com
$BIN whoami
$BIN --json mkdir "test folder"
$BIN upload ./somefile.pdf <folder-id>
$BIN ls <folder-id>
$BIN download <file-id> /tmp/out.pdf
$BIN versions list <file-id>
$BIN share public <folder-id>
$BIN trash ls
$BIN rm <file-id> --yes
$BIN rm <folder-id> --folder --yes
$BIN logout
```

Use `--profile <name>` to isolate accounts and `--json` for one-document stdout
suited to scripts. Prompts and progress are written to stderr.

## Troubleshooting

| Symptom | Action |
|---|---|
| TLS error against local Compose | Set `KUTUP_INSECURE_TLS=1`; confirm you are targeting only the local self-signed edge. |
| `not logged in` | Run `kutup login` for the same `--profile`. |
| Login waits for input | Set `KUTUP_PASSWORD` and pass `--email` and `--server`. |
| Session decryption fails | The profile's device key is missing or changed; log in again. |
| First-login setup is required | Complete setup in the web UI, or use a normally registered account. |
| Download checksum differs | Preserve stderr, the file id, command, and server version; do not include keys, passwords, recovery phrases, or ciphertext in an issue. |

For full server, frontend, Chat, federation, and backup gates, use
[`../../contributing.md`](../../contributing.md) and
[`../../../tests/e2e/README.md`](../../../tests/e2e/README.md).
