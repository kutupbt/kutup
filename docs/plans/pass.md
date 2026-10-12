# Kutup Pass (password manager)

**Status:** plan, 2026-10-11. K0 (`crates/kutup-pass`), K1 (conditional
saves, `kutup sync` merging vaults) and K2a (vault secrets) built. The research and every product
decision are in
[`../research/19-password-manager.md`](../research/19-password-manager.md)
("Priorities", "Direction", "SSH agent in the `kutup` CLI", "Unlocking, key
files and several vaults").

## Goal

A password manager whose vaults are standard KeePass (KDBX 4.1) files kept in
Kutup Drive, editable **offline** everywhere, with KeePassXC and the other
KeePass apps still working, and with merges that never lose an edit.

## Decisions this plan builds on

| Decision | Where |
|---|---|
| Offline editing is the first requirement; the website is the product built now; sharing comes last | research 19, Priorities |
| A vault is one KDBX 4.1 file in Drive, encrypted by KDBX and again by Drive | research 19, Direction |
| Merges are three-way (base, ours, theirs), field by field, always on a client; device clocks never decide | research 19, "Kutup's three-way merge" |
| Saves are conditional on the version they started from; nothing overwrites an unseen version | research 19, "Saving without overwriting" |
| Phones use the website until Kutup's native apps; no WebDAV, CalDAV or CardDAV | research 19; `docs/research/06-webdav-support.md` |
| Unlock with the Kutup sign-in (vault password sealed under the account key), as Proton Pass; key files and YubiKey supported; several vaults per account | research 19, "Unlocking…" |
| An opt-in SSH agent in the `kutup` CLI, compatible with KeeAgent entries | research 19, "SSH agent…" |

## What exists to build on

- **Drive versions.** A file's current content is its latest whole-file
  version, else its original upload (`handlers/files.rs` download).
  `POST /api/files/{id}/versions` (multipart, `kind = file`) stores a new
  version in one request; Office already saves documents this way
  ([`drive-versions-v2.md`](drive-versions-v2.md)).
- **`kutup sync`** (`crates/kutup-cli/src/syncengine.rs`): a three-way sync
  of a folder against the recorded base state; it notices remote changes by
  the newest `file_versions` id. Today a changed local file is pushed as a new
  upload (new file id, old one to the trash), and a conflict produces a
  `name.sync-conflict-<ts>` copy.
- **The account master key**, `account_envelope` sealing, and WASM/UniFFI
  builds of `kutup-crypto`.
- **The `keepass` crate** (0.15.2, MIT): probed on 2026-10-11 against
  KeePassXC's test vaults (`kutup-references/keepassxc/tests/data/`). Every
  vault in a format in use today (KDBX 3.1, 4.0, 4.1; passwords, all key-file
  kinds, protected strings, recycle bins, non-ASCII passwords) opened, was
  saved as 4.1 and reopened with identical content (24 vaults). Only KDBX 2.x
  files from before 2009 and the YubiKey vault (needs the hardware) did not
  open. It writes only 4.1, so older vaults are upgraded on save, as KeePassXC
  does. Its model keeps fields with their protected flag, auto-type, tags,
  times, custom data, icons, colours, URL override, attachments, previous
  parent group and history; challenge-response is behind a feature.

## Architecture

```
crates/kutup-pass          (pure Rust; no server or UI dependencies)
  kdbx.rs     open / save through `keepass`, upgrade to 4.1 on save,
              composite key (password, key file)
  merge.rs    three-way merge of `keepass::Database` values, with a report
  refs.rs     moving entries between vaults (attachments, custom icons,
              history) and rebuilding the crate's back-references
  vendor/keepass  the `keepass` crate 0.15.2 (MIT), patched only to make its
              model fields public (`scripts/patch-vendored-keepass.py`,
              `vendor/keepass/KUTUP.md`); its public API cannot move
              attachments and custom icons between vaults with their ids,
              which a lossless merge needs
crates/kutup-pass-wasm     (K2) the same for the website
crates/kutup-cli           (K1) `kutup sync` merges .kdbx; (K3b) ssh agent
crates/kutup-server        (K1) conditional version writes; (K2) vault-secret
                           records; the pass origin
frontend/apps/pass         (K2) the website at pass.<domain>
```

`kutup-pass` stays separate from `kutup-crypto`: KDBX is KeePass's format,
not a Kutup cryptographic format, and keeping its dependencies (the
`keepass` crate, XML, KDBX ciphers) out of `kutup-crypto` keeps the canonical
crypto crate small. Kutup-owned formats (the sealed vault secret) go in
`kutup-crypto` as usual.

## The three-way merge (K0)

Inputs: **base** (the version the client last synced and started from),
**ours** (the local edit), **theirs** (the current version on Drive). Output:
one database, plus a report of what happened.

| Object | Rule |
|---|---|
| Entries and groups | matched by UUID |
| Present only in ours or theirs, not in base | added |
| An entry field (standard and custom strings with their protected flag, tags as a set, attachments by name and content, icon, colours, URL override, expiry, auto-type, custom data per key, quality check) | changed on one side → that side; same change on both → no conflict; different changes → **ours**, theirs' whole entry goes into the entry's history, and the entry is marked for review |
| Entry history | union by modification time, then trimmed to the database's history limits |
| Parent group (moves) | three-way: moved on one side → that side; moved on both → ours |
| Deleted on one side, unchanged on the other since base | deleted |
| Deleted on one side, edited on the other since base | **the edit wins**; the entry is restored and reported |
| Deleted objects list | union, minus restored objects |
| Groups' own fields | as entry fields |
| Database metadata (name, description, recycle bin, history limits, colours, default user name…) | three-way per field; custom icons unioned; custom data per key |
| No base available | KeePassXC's rule: the newer whole entry wins, the other goes to history |

- **The review mark** is a custom-data key `KutupMergeReview` on the entry
  (other KeePass apps keep unknown custom data and ignore it), listing the
  fields that conflicted. Kutup Pass shows it and removes it once reviewed.
- **Timestamps are data.** The merged entry's modification time is the later
  of the two, but no rule uses time to pick a winner while a base exists.
- **Determinism.** The same three inputs always give the same output, so two
  clients that merge the same versions agree.
- **Report.** `MergeReport { added, updated, conflicts[], restored, deleted,
  moved }`, for the UI and the CLI.

### Tests (K0)

- **Round-trip corpus** (`tests/corpus.rs`): every vault in
  `keepassxc/tests/data/` that opens is saved as 4.1 and compared after
  reopening, and merged with itself without change. KeePassXC's vaults are
  GPL, so they are not copied into this repository: the test reads
  `KUTUP_KDBX_CORPUS` or the `kutup-references/keepassxc` checkout beside the
  repository, and is skipped when neither is there (CI runs the generated
  fixtures and properties below).
- **Merge cases** (`tests/merge.rs`) as named fixtures: disjoint edits; same field different
  values; same field same value; edit vs delete (both orders); move vs edit;
  moves on both sides; added on both sides with the same UUID; history
  overflow; metadata changes; no base.
- **Properties** (`tests/properties.rs`, proptest): merging base with itself returns it; the result
  contains every field change made on either side, either current or in
  history; merging is deterministic; `merge(base, ours, base) == ours`;
  `merge(base, base, theirs) == theirs`.
- **Interop**: a merged vault opens in KeePassXC (a CI step with
  `keepassxc-cli` exporting the merged vault to XML and comparing it with the
  expected XML), added once `keepassxc-cli` is available in the CI image.

## Saving without overwriting (K1)

- `POST /api/files/{id}/versions` gains an optional `basedOn` (a version id,
  or `original` for the upload). If the file's current content is not that
  version, the server answers `409` `{ code: "version_conflict", current }`
  and stores nothing. Without `basedOn` the endpoint behaves as today.
- Each version records the version it replaced (`parent_version_id`, a
  migration numbered one above the highest on master and in open PRs at the
  time). Two versions with the same parent are a divergence; clients fetch
  the parent as the merge base.
- Downloads name what they serve (`X-Kutup-Version`: a version id or
  `original`), so a client records the exact version its copy came from.
- Whole-file saves of one file are serialized (a row lock on the file) and
  stamped when stored, so "current" is well defined and two saves from one
  base cannot both land (the live test races four).
- Federated saves carry `basedOn` to the file's server and its `409` back.
- Kept versions follow Drive's retention, unchanged (decided in K1). A merge
  fetches its base from Drive; if retention pruned it, the merge runs
  without a base by KeePassXC's rules (the newer whole entry wins, the other
  goes to history), which loses no field either. Clients keep no copy of
  their own.

## Clients

### `kutup sync` (K1, the first offline client)

- `.kdbx` files are saved as **new versions of the same file** with `basedOn`,
  not as new uploads, so the file id stays stable for the website and for
  KeePassXC users on other machines.
- On a conflict (`409`, or a local and a remote change since the base), sync
  merges the three versions with `kutup-pass` instead of writing a
  `.sync-conflict` copy, saves the result with `basedOn = current` (merging
  again on top if another save lands first, up to five times), and writes it
  locally. KeePassXC notices the file changed and reloads. If Drive already
  holds everything the local copy changed, nothing is uploaded.
- The base is the version the local copy was synced from. After a fallback
  conflict copy the local copy did not start from the recorded version, so
  the next merge runs without a base. A vault on both sides with no base (a
  second machine joining with its own copy) is merged by KeePassXC's rules.
- A vault edited again during the merge is left alone and merged again on
  the next pass (the base is not moved, so the new edit is not lost).
- It needs the vault's composite key: `KUTUP_VAULT_PASSWORD` and/or
  `KUTUP_VAULT_KEY_FILE`, otherwise a prompt in the terminal (remembered in
  memory for the run and every `--watch` pass), otherwise it falls back to
  today's conflict copy and says so. A key changed on one side since the base
  wins like any other change. The vault secret stored in the account comes in
  K2.
- Checked live by `scripts/verify-pass-sync.sh`: two machines (two CLI
  profiles) edit one vault offline; disjoint edits, the same field on both
  sides, the stable file id and the keyless fallback. The vaults it edits
  are made with `cargo run -p kutup-pass --example vault`.

### The website (K2, `pass.<domain>`)

- A new app on its own origin, like the others: `apps.pass` in the server's
  app origins, client type `web-pass`, a frontend host, the app switcher, the
  nginx and compose wiring, DNS and a certificate for `pass.kutup.dev`
  (deploy).
- Lists every `.kdbx` file the account can reach in Drive, own and shared.
- Opens a vault with `kutup-pass-wasm`; edits entries and groups; saves with
  `basedOn`; on `409` merges and retries; shows the merge report and the
  review marks.
- **Offline**: the open vault's encrypted file, its base version and an
  outbox of pending saves are kept in IndexedDB (encrypted records, research
  16); a reload without network can open the vault again once offline unlock
  exists (research 19 §5.6).
- **Vault secrets** (built in K2a): a per-user, per-vault record sealed
  under the account master key: `kutup_crypto::pass_vault`, an
  `account_envelope` with the new purpose `PassVaultSecret = 6` (bound to the
  login email) whose payload binds the vault's file id, holding the vault
  password and/or the key file. Key files over 2048 bytes are kept as their
  SHA-256, which KeePass treats as the same key; what is kept is checked to
  open the vault first. Stored by the server (`pass_vault_secrets`,
  `/api/pass/vault-secrets`), unreadable to it. Creating or opening a vault
  offers to remember it; a removed member's record is deleted when it is
  next listed, and purging the vault deletes them all. `kutup sync` tries the
  kept secret before the environment and the prompt, offers to keep a typed
  password, and `kutup pass keep|ls|forget` manages them headless.
- Entry editing covers the KeePassXC fields (research 19 §4): standard fields,
  custom fields (protected or not), tags, attachments, TOTP (`otp`), URLs
  (`URL`, `KP2A_URL*`), expiry, history, groups, recycle bin; passkeys and SSH
  key entries shown and editable as data.
- Generator, search, and a simple security report (weak, reused) on the
  client.

### Phones

The website in the phone browser (K2–K3). Native apps later
([`../mobile-build.md`](../mobile-build.md)).

### SSH agent (K3b)

As decided in research 19, "SSH agent in the `kutup` CLI": opt-in
`kutup ssh-agent`, KeeAgent-compatible entries from the vault `kutup sync`
keeps, approval per use, keys listed while locked, memory only,
`kutup ssh-add` push mode.

## Slices

| Slice | Contents | Done when |
|---|---|---|
| **K0a** ✅ | `crates/kutup-pass`: KDBX open/save through `keepass`, upgrade to 4.1, composite keys; the corpus round-trip test | every corpus vault in a supported format round-trips equal |
| **K0b** ✅ | Three-way merge with the report and review marks; fixtures and property tests | all merge cases and properties pass |
| **K1** ✅ | `basedOn` and parent versions on the server (+ migration); `kutup sync` saves `.kdbx` as versions and merges on conflict | two machines editing one vault offline, then syncing, lose nothing (live test) |
| **K2a** ✅ | Vault secrets: `kutup_crypto::pass_vault` (+ vectors, WASM), the server records (+ migration), `kutup sync` and `kutup pass` using them | sync merges a vault with no password given once its key is kept |
| **K2b** | Vault editing in `kutup-pass` (a view and edit operations as KeePass apps make them) and `kutup-pass-wasm` | the website's operations round-trip through KDBX and merge |
| **K2c** | The `pass.<domain>` app: vault list, unlock, entry editor, offline outbox, conflict review | a vault can be created, edited offline in the browser and merged with a KeePassXC edit |
| **K3** | Divergence handling and re-merge; the website on phone browsers | diverged versions are merged by the next client that opens the vault |
| **K3b** | The `kutup` SSH agent | `ssh` and `git commit -S` work through it with approvals |
| **K4** | Native apps (separate repositories, later) | — |

Each slice ships production-grade with its tests and docs, English and
Turkish strings for every UI text, and e2e specs from this session's block
(70–79) for K2 onwards.

## Risks

- **The `keepass` crate is a dependency in a security-critical path.** Pin it,
  review its changes on every update, and keep the corpus and merge tests as
  the guard. If it falls short (an unreadable variant, lost data), the
  fallback is our own reader and writer behind the same `kdbx.rs` interface.
- **YubiKey vaults** cannot merge in the background and need WebHID on the
  web (Chromium only).
- **Merge correctness** decides whether offline editing is trusted; the
  property tests are part of K0, not later.
