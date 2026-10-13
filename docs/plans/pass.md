# Kutup Pass (password manager)

**Status:** plan, 2026-10-11. K0 (`crates/kutup-pass`), K1 (conditional
saves, `kutup sync` merging vaults), K2a (vault secrets), K2b (vault
editing, `kutup-pass-wasm`) and K2c (the website) built. The research and every product
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
  time): the version current when it was stored. Because whole-file saves of
  a file are serialized and every Pass client (the website, `kutup sync`)
  saves conditionally, two versions never replace the same one: divergence is
  prevented, not repaired afterwards (K3, as built). A save without `basedOn`
  (a Drive restore or upload of a `.kdbx`) is a deliberate replacement; Pass
  clients merge it like any other remote change, against their base.
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

**Built in K2c** (`frontend/apps/pass`):

- **The app.** Vaults are listed from Drive (own folders, shared folders and
  vaults shared by themselves; vaults on other servers stay in Drive for
  now). Drive and Office open a `.kdbx` file in Pass (`appFor` in
  `@kutup/editors/paths`). New vaults are made in a chosen folder with a
  password and/or key file, optionally kept with the sign-in; Drive's New
  menu and right-click menu offer "Password vault", which opens Pass's
  create dialog with that folder chosen (`/new?folder=`), since Drive holds
  no vault keys. A folder holds any number of vaults; a taken name gets a
  free one ("Passwords (2)"). A vault's name is its file's name: renaming in
  Drive shows in Pass, and renaming in Pass renames the file (and the name
  inside the KeePass file with it).
- **The worker.** Vaults live in a long-lived worker
  (`src/vault/worker.ts`) holding `kutup-pass-wasm`; the page gets views and
  values only. Saving derives the key, so edits close together are saved
  once.
- **Saving** (`src/sync/vaultSession.ts`). Each edit is applied at once and
  kept in the outbox; the vault is saved as a version made from the version
  it started from. On `409` the other device's version is merged here (base,
  ours, theirs) and saved on top of it; a merge with conflicts or restored
  entries shows a notice, and the entries carry the review mark until marked
  reviewed. A vault saved elsewhere under a new key asks for it, merges, and
  keeps it. Every minute while the tab is visible, and when it comes back,
  the open vault takes in another device's save.
- **Offline** (`src/sync/outbox.ts`). Per vault, IndexedDB keeps the base
  version (id and contents) and the edited vault waiting to be saved: both
  KeePass files under the vault's own key, so no readable secret is stored.
  Without a connection the edits wait and go when it is back, also after the
  tab was closed (spec 78). Opening a vault while Drive cannot be reached
  uses the kept copy; a reload without network still needs the sign-in to
  work offline first (research 19 §5.6).
- **Locking.** Open vaults lock after a while without use on the device
  (15 minutes unless changed on the vault list; "only when I sign out" is a
  choice), when the account's session ends (signed out in Pass or another
  Pass tab, or refused by the server because it was revoked elsewhere, which
  the minute's refresh notices), and by hand. A vault locked in a tab waits
  for a click before its kept key opens it again, also after a reload of the
  tab. **What opens it again** is a setting on the device, as Proton Pass's
  lock modes: the account password (the default; checked by the server as
  at sign-in, `POST /api/user/reauth` with the login key, under the sign-in
  lockout, so a stolen access token gives no way to guess the password
  offline), the account's PIN, or one click. A vault without a
  kept key always asks for its own key. Signing out also deletes the vaults
  this device kept for offline use; a refused session keeps them, unsaved
  edits included, for the next sign-in.
- **The PIN** (as Proton Pass's PIN lock): six digits per account, used on
  every device whose mode is the PIN; the sixth digit sends it. Like the
  password mode it is a lock on the app, not on a key: the tab already holds
  the vault's kept key and opens it after the server's yes, so it guards
  against someone at an unattended device, not against code running in the
  tab. The server keeps only its bcrypt hash (`pass_pins`, migration 156)
  and checks it, `POST /api/pass/pin/verify`, so the PIN cannot be worked
  through: three wrong PINs in a row end the sign-in that tried them (every
  session of it) and the app signs out. The count is per sign-in
  (`pass_pin_failures`, keyed by the root session): each try is reserved
  before the check, so parallel tries get no more; only that sign-in's right
  PIN clears it; it is never reset by a lockout (a new sign-in, with the
  password, starts its own); another sign-in's misses or right PIN do not
  change it. Setting, changing (`PUT /api/pass/pin`, which starts every
  count again) or removing it (`DELETE /api/pass/pin`) takes the account
  password, under the sign-in lockout. Choosing the PIN mode without a PIN
  asks for one first; a PIN removed on another device sends this one back to
  the password. A wrong password at these re-checks (`invalid credentials`)
  is not retried with a refreshed token, which would count it twice toward
  the lockout; an expired token there is refreshed as anywhere. Later, as
  Proton does, a right PIN could release a server-held wrapping secret for
  the kept keys, so the lock would guard key material too.
  Specs 151 and `pass_live`.
- **Site icons** (as Proton Pass's website favicons): an entry shows its
  website's icon in the list and its header, else the title's first letter.
  Only the host name of the entry's URL is used (none for IP addresses,
  `localhost` or single labels). As in Proton, the account chooses between
  icons through Kutup (the default) and none, on every device
  (`pass_settings`, migration 160; `GET/PUT /api/pass/settings`; the vault
  list's "Website icons"). The browser never asks a website itself: that
  would need the pass host to load outside images, the only way a script
  injected into the vault app could send data out, and would show sites the
  reader's address and cookies.
  - **Through Kutup:** `POST /api/pass/icon` with the host name; the server
    reads the site's home page for `<link rel="icon">` and Apple touch
    icons, picks the smallest of at least 64 px, else the largest, and falls
    back to `/favicon.ico`. It fetches through `public_fetch` (the narrow
    fetcher Chat link previews use: https on 443, public addresses only,
    pinned connections, redirects checked again, size and time limits) and
    returns only PNG, JPEG, GIF, WebP or ICO recognised by their bytes,
    never SVG, with `nosniff` and a sandboxing CSP. The website never sees
    the browser; the server sees the host name, in the body (so not in
    access logs), and keeps icons in memory only (a day, an hour for none;
    bounded), never on disk, and per account, so how fast an answer comes
    tells no account what another asked for. Fetches the cache cannot
    answer are limited to 120 sites a minute per account and 16 at once on
    the server, and a second ask for a site being fetched waits for that
    fetch. It refuses (`403`) when the account chose otherwise, so a tab
    still in that mode on another device stops. Being the default, every
    account sends its entries' host names to its server from the release
    that brings this, as Proton Pass's default does; the release note says
    so.
  - **Off:** first letters only; nothing is asked.

  The tab asks only for rows on screen, six at a time, once per host per
  visit (after a `429`, again 15 seconds later), keeps icons in memory and
  drops them when the choice leaves Kutup. Sites whose TLS needs legacy
  ciphers, or that refuse non-browser clients, give no icon. Spec 152 and
  `pass_live`.
- **Page policy.** The pass host allows no inline or eval'd script
  (`script-src 'self' 'wasm-unsafe-eval'`), nothing may frame it
  (`frame-ancestors 'none'`, `X-Frame-Options: DENY`), and its theme and
  reload guard load as files (`strictCsp` in the shared Vite config). Spec 79
  checks the headers and that the page breaks none of it.
- **Entries.** Standard fields, the TOTP secret (`otp`, an otpauth:// URI or
  a base32 key) with a live code, custom fields (hidden or not), tags,
  expiry, attachments up to 50 MB, history with restore, groups, the recycle
  bin; copied secrets leave the clipboard after 30 seconds if still there. A
  password generator from `crypto.getRandomValues` without modulo bias, and
  a strength hint. Auto-type settings and other KeePass data are kept as they
  are.
- **Specs** 76 (vault, entries, history, attachments, groups, recycle bin,
  Drive), 77 (two devices: disjoint edits merge, one field on both is marked
  for review), 78 (offline outbox, also across a closed tab), 79 (unlock,
  wrong key, kept and forgotten keys, lock), 150 (CSV import), 151 (PIN),
  152 (site icons), 153 (custom icons), 154 (vault keys).
- **Security report** (the vault's Security button): weak passwords,
  passwords shared by several entries, and expired entries, worked out on
  the device from the open vault; nothing is sent anywhere, so there is no
  breach lookup (a k-anonymity check against an outside service would send
  hash prefixes away).
- **Import** (Vault actions → Import from another app…): a CSV export from
  KeePassXC, Bitwarden, 1Password, LastPass, Proton Pass, NordPass,
  Dashlane, Chrome (also Edge and Brave), Firefox, Safari / Apple Passwords,
  or any CSV with named columns (`kutup-pass::import`). The format is worked
  out from the header (or picked); the file is read on the device in the
  vault worker and shown first: how many entries, the folders that become
  groups, a sample, what will be skipped (cards, identities and other
  non-login items) and notes on values kept as they were (an OTP that could
  not be read stays as a hidden field). Decoding takes UTF-8 with or without
  a BOM and UTF-16, separators `,` `;` or tab; limits 20 MB and 50,000
  entries. The import is one edit (`importCsv`): a new group at the top of
  the vault holds it all, folders as groups below, extra URLs as
  `KP2A_URL_n`, custom fields kept (secret-looking ones hidden), times kept;
  it applies all or nothing. The dialog asks to delete the plaintext export
  afterwards. Spec 150.
- **Custom icons** (KeePass's own pictures, kept in the vault, so KeePassXC
  and other KeePass apps show them too): an entry's or group's picture
  shows before its website's icon (entries) or the folder (groups). "Change
  icon" (the entry's icon, the group's menu) offers the vault's pictures,
  an uploaded image, or, for an entry when icons come through Kutup, its
  website's icon saved into the vault; or the default icon again. The tab
  redraws a new picture as a PNG of at most 64 px a side (KeePassXC keeps
  128), which drops everything but the pixels; inputs up to 5 MB, raster
  types only. The edits are `setEntryIcon` (the previous state into the
  entry's history) and `setGroupIcon`, which take a PNG of at most 256 KiB
  and reuse a picture with the same bytes. The view lists the vault's
  pictures browsers can show (PNG, JPEG, GIF, WebP, ICO, BMP; never SVG) as
  base64, shown as `data:` addresses, so the pass host still loads no
  outside images. As KeePass apps, a picture nothing uses any more stays in
  the vault (merges union them). Spec 153 and `tests/edit.rs`.
- **Not yet:** sharing single entries; on the roadmap.

**The plan as written:**

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
  `account_envelope` with the purpose `PassVaultSecret = 6` whose payload
  (`kutup/pass-vault-secret/v2`) binds the vault's file id. What it holds
  opens the vault without telling a password the person chose: such a
  password is kept only as its SHA-256, which is KeePass's password part of
  the composite key (the vendored library opens and saves with it,
  `DatabaseKey::with_password_hash`; checked against KeePassXC's test
  vaults), so a vault password used elsewhere too is not given away with the
  master key. A password Kutup Pass generated (below) is kept as it is, so it
  can be shown. Key files are kept as they are, those over 2048 bytes as
  their SHA-256, which KeePass treats as the same key; what is kept is
  checked to open the vault first. Stored by the server
  (`pass_vault_secrets`, `/api/pass/vault-secrets`), unreadable to it.
  Creating or opening a vault offers to remember it; a removed member's
  record is deleted when it is next listed, and purging the vault deletes
  them all. `kutup sync` tries the kept secret before the environment and the
  prompt, offers to keep a typed password, and `kutup pass keep|ls|forget`
  manages them headless.
- **Vault secrets and the account's binding** (docs/plans/account-identity.md):
  a vault secret is an account envelope (suite 2) whose header names the
  account's permanent random key binding and, as its object, the vault's file
  id; its AEAD key is derived for that binding and vault alone. The server
  refuses one bound to another binding or vault.
- **Vault keys** (as Proton Pass, whose vaults have no password to choose):
  a vault made in Kutup Pass gets by default a random key kept in the
  account: 25 characters of Crockford's base32 in groups of five (125 bits,
  `randomVaultKey`), used as the KeePass password. Nothing to choose or
  remember; the vault opens with the sign-in. For KeePassXC on a computer,
  the vault's menu → "Show vault key…" shows it after the account password is
  given again (`/api/user/reauth`), with copy (cleared from the clipboard
  after 30 seconds); `kutup pass show-key <file-id>` prints it. "A password I
  choose" stays offered for vaults opened by typing in KeePass apps. If the
  new key cannot be kept, the dialog shows it at once, as it is kept nowhere
  else; forgetting a generated key asks first, pointing to "Show vault key".
- Entry editing covers the KeePassXC fields (research 19 §4): standard fields,
  custom fields (protected or not), tags, attachments, TOTP (`otp`), URLs
  (`URL`, `KP2A_URL*`), expiry, history, groups, recycle bin; passkeys and SSH
  key entries shown and editable as data.
- Generator, search, and a simple security report (weak, reused) on the
  client.
- **Editing (built in K2b).** `kutup_pass::view` gives the website a plain
  snapshot (groups depth-first, entries with their fields, standard ones
  first, tags, icon, colours, expiry, times, attachments by name and size,
  auto-type as data, history count, review marks, recycle-bin flags) and
  one-time codes from KeePassXC's `otp` field. `kutup_pass::edit::Op` is the
  only way to change a vault: create, update (the entry's previous state
  into its history, trimmed to the vault's limits; nothing recorded when
  nothing changed), delete (into the recycle bin, made when first needed; for
  good from inside it or with it off, recorded in the deleted objects), move,
  restore a history item, clear a review mark, attachments, groups, empty
  the recycle bin, the vault's name. A refused operation changes nothing.
  Times come from the caller, so the browser and tests control the clock.
  New vaults get KeePassXC's defaults (recycle bin, ten history items up to
  6 MiB) and Argon2id with 64 MiB and 10 iterations: about 0.4 s per
  derivation in WASM on the development VM (`scripts/test-pass-wasm.mjs`
  prints it), against the crate's 1 GiB and 50 iterations.
- **`kutup-pass-wasm`** holds one open vault (`Vault`: `create`, `open`,
  `view`, `apply`, `history`, `attachment`, `otp`, `save`, `mergeWith`,
  `changeKey`) and runs in a worker, since key derivation blocks.
  `mergeWith` takes another key for the other side when the key changed
  elsewhere, and adopts it.

### Phones

The website in the phone browser (K2–K3). Native apps later
([`../mobile-build.md`](../mobile-build.md)).

### SSH agent (K3b)

As decided in research 19, "SSH agent in the `kutup` CLI": opt-in
`kutup ssh-agent`, KeeAgent-compatible entries from the vault `kutup sync`
keeps, approval per use, keys listed while locked, memory only,
`kutup ssh-add` push mode.

**Built in K3b:**

- `kutup_pass::ssh` (shared with the website later): KeeAgent settings
  (KeePassXC's UTF-8 and KeeAgent's UTF-16 files), the agent keys of a vault
  (entries outside the recycle bin that allow use, the key attached to the
  entry; keys in outside files are reported, not read), the public half
  without the passphrase, the private key decrypted with the entry's
  password, signatures (Ed25519, ECDSA, RSA with `rsa-sha2-256/512`; SHA-1
  `ssh-rsa` refused; RSA keys under 2048 bits refused). The RSA key is built
  from its parts here: ssh-key 0.6.7's own conversion passes `p` twice.
- `kutup ssh-agent <folder> <collection>` serves the vaults in a folder
  `kutup sync` keeps, on `$XDG_RUNTIME_DIR/kutup/ssh-agent.sock` (or
  `--socket`) in a directory only the user can enter; it prints the
  `SSH_AUTH_SOCK=…` line, refuses to replace a live agent, and serves only
  its own user (`SO_PEERCRED` / `getpeereid`). Vaults open with the key kept
  in the account, `KUTUP_VAULT_PASSWORD`, or a prompt, and are read again
  when they change on disk.
- **Approval per use** on the agent's terminal: the requesting process (on
  Linux), the key, a login as which user to which host (`session-bind`, its
  host signature verified, names from `known_hosts`) or the SSHSIG namespace
  (git), and **FORWARDED** for `ssh -A`. Allow once, for this host until the
  agent locks, or deny; without a terminal, deny. `--no-confirm` skips asking
  except for forwarded requests.
- Memory only: decrypted keys and approvals are forgotten after
  `--idle` minutes unused (15).
- `kutup ssh-add <folder> <collection> <entry>` pushes a key into the
  running agent with the entry's KeeAgent lifetime and confirm constraints,
  or `--lifetime` / `--confirm`.
- Checked by unit tests and `scripts/verify-pass-ssh.sh` against OpenSSH:
  `ssh-add -l`, a git signature through the agent verified by
  `ssh-keygen -Y verify`, a key added while running, denial without a
  terminal, and push mode into a system `ssh-agent`.
- **Asking on the desktop** (`--approve desktop`; `auto`, the default, asks
  on the terminal when there is one): the same question in a dialog that
  gives up after a minute: an OpenSSH askpass program from
  `KUTUP_SSH_ASKPASS` or `SSH_ASKPASS` (`SSH_ASKPASS_PROMPT=confirm`, as
  `ssh-agent` asks for a confirm-constrained key; allows once), else
  `zenity`, else `kdialog` on Linux, and `osascript` on macOS, with "Allow
  once", "Allow for this host" and "Deny". The text goes in as an argument
  (never through a shell or into the AppleScript), without markup or
  control characters. No dialog program, no answer or an error: denied.
- **`kutup ssh-agent install <folder> <collection>`** starts the agent at
  every login with the user's own service manager: a systemd user unit
  (`~/.config/systemd/user/kutup-ssh-agent.service`, enabled and started)
  on Linux, a launchd agent (`~/Library/LaunchAgents/dev.kutup.ssh-agent.plist`,
  bootstrapped into the GUI domain, logging to
  `~/Library/Logs/kutup-ssh-agent.log`) on macOS. Nothing system-wide and no
  secret in the file: it runs this `kutup` with `--approve desktop` on the
  default socket, and carries only the askpass program (and
  `KUTUP_INSECURE_TLS` for a test server, said when it does). As a service
  has no prompt, install checks first that you are signed in and which
  vaults open with the keys your account keeps (`kutup pass keep`), and
  refuses with `KUTUP_DEVICE_KEY` set, with nothing to ask with (unless
  `--no-confirm`), or with another agent on the socket. It prints the
  `SSH_AUTH_SOCK` line for the shell profile and the `IdentityAgent` line
  for `~/.ssh/config`, says when the shell uses another agent, and on
  Linux when systemd has no display to show dialogs on
  (`systemctl --user import-environment DISPLAY WAYLAND_DISPLAY
  XAUTHORITY`). `--print` shows the file instead. A vault that did not
  open (at login the network may not be up) is tried again, with a fresh
  sign-in, at most every 30 seconds when a client asks.
  `kutup ssh-agent status` says whether it is installed, running and
  serving (and how many keys), and whether the shell uses another agent;
  `uninstall` stops it and removes the file. Checked by
  `scripts/verify-pass-ssh.sh` (askpass allow and deny; where a systemd
  user manager runs, a real install, a signature through it, status and
  uninstall) and unit tests. macOS's launchd agent and dialog are built
  but have not been run on a Mac yet.
- **Not yet:** Windows (named pipe).

## Slices

| Slice | Contents | Done when |
|---|---|---|
| **K0a** ✅ | `crates/kutup-pass`: KDBX open/save through `keepass`, upgrade to 4.1, composite keys; the corpus round-trip test | every corpus vault in a supported format round-trips equal |
| **K0b** ✅ | Three-way merge with the report and review marks; fixtures and property tests | all merge cases and properties pass |
| **K1** ✅ | `basedOn` and parent versions on the server (+ migration); `kutup sync` saves `.kdbx` as versions and merges on conflict | two machines editing one vault offline, then syncing, lose nothing (live test) |
| **K2a** ✅ | Vault secrets: `kutup_crypto::pass_vault` (+ vectors, WASM), the server records (+ migration), `kutup sync` and `kutup pass` using them | sync merges a vault with no password given once its key is kept |
| **K2b** ✅ | Vault editing in `kutup-pass` (a view and edit operations as KeePass apps make them) and `kutup-pass-wasm` | the website's operations round-trip through KDBX and merge |
| **K2c** ✅ | The `pass.<domain>` app: vault list, unlock, entry editor, offline outbox, conflict review | a vault can be created, edited offline in the browser and merged with a KeePassXC edit |
| **K3** ✅ | Divergence handling and re-merge; the website on phone browsers | divergence is prevented by serialized conditional saves (see above); the website works at phone width (spec 76) |
| **K3b** ✅ | The `kutup` SSH agent | `ssh` and `git commit -S` work through it with approvals |
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
