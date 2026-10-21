# Pass: KeePassXC parity

**Status:** the gap list, 2026-10-20. Kutup Pass keeps vaults as KeePass
(KDBX 4.1) files, so KeePassXC is the reference for what a KeePass manager
does. This lists KeePassXC's features, where Kutup Pass stands, and the
order to close the gaps. Each slice gets its own plan before it is built
(the Pass plan is [`pass.md`](pass.md), the research and decisions
[`../research/19-password-manager.md`](../research/19-password-manager.md));
keep this list current as they land. Proton Pass stays the reference for
the account model (unlock with the sign-in, lock modes, website icons);
KeePassXC for what a vault holds and what one does with it.

Read from KeePassXC 2.8.0-beta1 (`kutup-references/keepassxc`, 2026-10-20):
`docs/topics/*.adoc` (the user guide), `src/gui`, `src/format`, `src/keys`,
`src/cli`, `src/sshagent`, `src/fdosecrets`, `src/keeshare`. Kutup Pass
read from the code on master (62067cb6), not from the plans: what the
website really does end to end. Paths in the Kutup column are under
`frontend/apps/pass/src/` unless they start with `crates/`.

**Key:** ✅ works end to end (in the website, or in the `kutup` CLI where
said) · 🟡 partial (what is missing is said) · ❌ missing. "Kept" means
Kutup reads and saves the data unchanged (other KeePass apps still see it)
but offers no way to see or change it.

**Summary** (rows per area, 2026-10-21):

| Area | ✅ | 🟡 | ❌ |
|---|---|---|---|
| The database (vault) | 10 | 9 | 20 |
| Groups (folders) | 5 | 1 | 6 |
| Entries | 8 | 6 | 8 |
| Bulk actions and the entry list | 8 | 1 | 6 |
| Search | 1 | 3 | 3 |
| Password generator | 2 | 2 | 3 |
| One-time codes, passkeys, SSH, desktop integration | 5 | 3 | 10 |
| Health report | 2 | 1 | 4 |
| Locking and unlocking | 5 | 1 | 2 |
| Sync, sharing and merges | 6 | 0 | 3 |
| Platforms | 2 | 4 | 4 |
| **All** | **49** | **31** | **74** |

## The database (vault)

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Open KDBX 4.x and 3.1 | `format/Kdbx4Reader.cpp`, `Kdbx3Reader.cpp` | ✅ | `crates/kutup-pass/src/kdbx.rs` through the vendored `keepass` crate; 3.1 is upgraded to 4.1 on the first save, as KeePassXC does; KeePassXC's test vaults round-trip (`tests/corpus.rs`) |
| Save KDBX 4.1 | `Kdbx4Writer.cpp` | ✅ | only 4.1 is written |
| Several vaults | tabs, one per database | ✅ | every `.kdbx` the account reaches in Drive, own and shared (`features/VaultsPage.tsx`, `drive/vaults.ts`) |
| Create a vault | Database → New (wizard) | ✅ | `features/CreateVaultDialog.tsx`: a folder, a random vault key kept in the account (default) or a password and/or key file; also from Drive's New menu |
| Rename a vault | Database settings → name | 🟡 | works, but only inside an **unlocked** vault, in the icon-only "…" menu of its header (`features/VaultPage.tsx`, "Rename vault"; hidden on a read-only vault). The vault list (`VaultsPage.tsx`) has no menu at all, so a locked vault can be renamed only in Drive: users report "no rename" |
| Vault name vs KDBX `DatabaseName` | the name inside the file | 🟡 | Pass shows the **file** name (`vaultTitle`, falling back to the KDBX name). Renaming in Pass renames both; renaming in Drive renames only the file, so KeePassXC then shows the old name |
| Delete a vault | delete the file | ❌ | only in Drive (to Drive's trash); nothing in Pass |
| Duplicate a vault ("Save as") | Database → Save as / Save a copy | ❌ | only Drive's copy |
| Move a vault to another folder | save elsewhere | ❌ | only in Drive (the vault keeps its file id, so its kept key still opens it) |
| Description, default user name | Database settings → General | 🟡 | the default user name fills new entries (`EntryEditor.tsx`), but neither can be changed: `updateVault` carries them and the UI only passes the current values on |
| Public metadata (name, icon, colour on the unlock screen) | Database settings → General | ❌ | kept |
| Change the password | Database settings → Security | ❌ | `changeKey` exists in `kutup-pass-wasm` and `vault/client.ts` but nothing in the UI calls it; the CLI has no command either. A vault's key cannot be changed in Kutup at all (needed too after removing a member from a shared folder, research 19 "Unlocking…") |
| Key file: **create** (generate) | Security → Add Key File → Generate | ❌ | no way to make one; `KeyFileInput.tsx` only picks an existing file |
| Key file: **open** a vault with one (alone or with a password) | unlock screen | ✅ | `UnlockVault.tsx` takes a password, a key file or both; also when another device saved under a new key (`TheirsKeyDialog.tsx`); every key-file kind (XML v1/v2, 32-byte, hex, any file) |
| Key file: **new vault** protected by one | wizard → credentials | ✅ | `CreateVaultDialog.tsx`, "A password I choose", with or without a password; an existing file only (see "create") |
| Key file: **add** to an existing vault | Security → Add Key File | ❌ | as "Change the password": `changeKey` is not wired |
| Key file: **remove** from an existing vault | Security → Remove Key File | ❌ | as above |
| Key file kept with the sign-in | (none) | ✅ | beyond KeePassXC: the derived key element sealed under the account key (`crates/kutup-pass/src/kept.rs`), so the website and `kutup sync` open it without the file |
| YubiKey / OnlyKey challenge-response | `keys/ChallengeResponseKey.cpp`, `keys/drivers` | ❌ | neither open, create, add nor remove: the crate's challenge-response feature is off, and the web would need WebHID (Chromium only; research 19 "Unlocking…") |
| KDF settings (Argon2d/id, AES-KDF; memory, iterations, parallelism; "1 second" benchmark) | Security → Encryption | ❌ | new vaults get Argon2id 64 MiB, 10 iterations, fixed (`crates/kutup-pass/src/edit.rs`); an existing vault's KDF is kept; no setting |
| Cipher (AES-256, ChaCha20, Twofish) | Encryption → advanced | ❌ | kept; new vaults the crate's default |
| Recycle bin on/off | Settings → General | 🟡 | honoured (deletes go for good with it off), made when first needed; no switch |
| History limits (items, size) | Settings → General | 🟡 | honoured on every edit; new vaults 10 items / 6 MiB as KeePassXC; no setting |
| Compression | Settings → General | 🟡 | kept as it is; no setting |
| Maintenance (purge unused icons) | Settings → Maintenance | ❌ | unused pictures stay in the vault, as KeePass apps do |
| Autosave, backup before save | Settings → Saving | ✅ | every edit saves at once as a new Drive version (`sync/vaultSession.ts`); Drive's versions are the backups |
| Merge another database into this one | Database → Merge from database | ❌ | versions of the **same** vault merge by themselves (below); there is no "merge this other `.kdbx` in" |
| Import CSV (column mapping) | `ImportExport.adoc`, CSV wizard | ✅ | `features/ImportDialog.tsx`, `crates/kutup-pass/src/import.rs`: KeePassXC, Bitwarden, 1Password, LastPass, Proton Pass, NordPass, Dashlane, Chrome/Edge/Brave, Firefox, Safari, or any CSV with named columns, into a new group of an open vault; preview first (spec 150) |
| Import 1Password (1PUX, OPVault) | `OPUXReader.cpp`, `OpVaultReader.cpp` | 🟡 | 1Password's CSV only |
| Import Bitwarden JSON | `BitwardenReader.cpp` | 🟡 | Bitwarden's CSV only (no attachments, no passkeys) |
| Import Proton Pass (ZIP/JSON) | `ProtonPassReader.cpp` | 🟡 | Proton Pass's CSV only |
| Import KeePass 1 (`.kdb`) | `KeePass1Reader.cpp` | ❌ | |
| Import KeePass XML | Import → KeePass XML | ❌ | |
| Export KDBX (the file itself) | Save a copy | 🟡 | the vault **is** a `.kdbx` in Drive, but Pass has no download: you go to Drive (user report) |
| Export CSV | `CsvExporter.cpp` | ❌ | |
| Export XML | `KdbxXmlWriter.cpp` | ❌ | |
| Export HTML (paper backup) | `HtmlExporter.cpp` | ❌ | |
| Auto-open other databases (AutoOpen group) | `DatabaseOperations.adoc` | ❌ | kept; Pass lists every vault anyway |
| Statistics (counts, sizes, passkeys, TOTP) | Reports → Statistics | ❌ | |

## Groups (folders)

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Create a group | Groups → New | ✅ | `VaultPage.tsx` group menu, `GroupDialog.tsx` |
| Nest groups | any depth | ✅ | "New group inside"; the tree indents by depth; phone width uses a picker |
| Rename | Edit group | ✅ | group menu → Rename |
| Move a group under another | drag and drop in the tree | ❌ | the core has `moveGroup` (`crates/kutup-pass/src/edit.rs`) and the merge handles moved groups, but no UI calls it |
| Delete a group (to the recycle bin) | Delete group | ✅ | asks first; for good with the bin off |
| Restore a deleted group | drag out of the bin | ❌ | the bin view lists entries only; a deleted group's entries can come back one at a time, each to the top level |
| Group notes | Edit group → Notes | ❌ | kept (rename passes them on); not shown or edited |
| Group icons: custom pictures | Edit group → Icon | ✅ | group menu → Change icon (`IconDialog.tsx`, spec 153) |
| Group icons: KeePass's built-in set | 69 standard icons | ❌ | kept; no picker |
| Per-group auto-type, search and browser settings, expiry | Edit group → Properties / Browser | ❌ | kept |
| Sort groups A–Z | Groups → Sort | ❌ | tree in the file's order |
| Show entries of subgroups | (a group shows its own entries) | 🟡 | as KeePassXC: a group shows its own entries only; "All entries" shows every entry outside the bin |

## Entries

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Title, user name, password, URL, notes | Edit entry | ✅ | `EntryEditor.tsx`, `EntryDetail.tsx`; copy buttons; the clipboard is cleared after 30 seconds if unchanged (`lib/copySecret.ts`) |
| Additional attributes (custom fields) | Advanced → Additional attributes | ✅ | add, rename, remove, protect |
| Protected fields (hidden, in-memory protection) | "Protect" per attribute | ✅ | protected values hidden with reveal; the password is always protected |
| Attachments | Advanced → Attachments | 🟡 | add (up to 50 MB), download, remove; no rename, no preview, one file at a time |
| History: list, compare, restore | History tab | ✅ | `HistoryDialog.tsx`, `restoreHistory` |
| History: delete an item, delete all | History tab → Delete | ❌ | trimmed only by the vault's limits |
| Expiry | Expires + presets | ✅ | date and time; an expired entry warns and shows in the security report; no presets ("in 3 months") |
| Tags | tag field, tag list in the sidebar | 🟡 | edited as comma-separated text and searched, shown on the entry; no tag list or tag filter in the sidebar, no suggestions |
| Icons: website icon | Download favicon | ✅ | through Kutup or off per account (spec 152); can be saved into the vault as a custom icon |
| Icons: custom pictures | Icon → Custom | ✅ | upload or reuse the vault's pictures (spec 153) |
| Icons: KeePass's built-in set | 69 standard icons | ❌ | kept; no picker |
| Foreground and background colour | Advanced → Colours | ❌ | kept |
| Auto-type sequences, window associations | Auto-Type tab | ❌ | kept, not shown (see auto-type below) |
| Several URLs | Browser integration, `KP2A_URL_n` | 🟡 | extra URLs are ordinary custom fields (the CSV import makes `KP2A_URL_n`); only `URL` gets an open button |
| URL schemes (`cmd://`, `ssh://`, `{S:…}` in URLs) | `Entry URL Handling` | 🟡 | `http(s)` opens in a new tab; other schemes are shown, not opened (deliberately: a web page cannot run commands) |
| URL override | Properties | ❌ | kept |
| References `{REF:P@I:…}` | `Reference.adoc` "Entry Cross-Reference" | ❌ | shown as the raw text; copying copies `{REF:…}`; nothing makes one |
| Placeholders (`{USERNAME}`, `{DT_…}`, `{T-CONV:…}`) | `Reference.adoc` "Entry Placeholders" | ❌ | shown as typed |
| Clone an entry (with references, with history) | Entries → Clone (Ctrl+D) | ❌ | |
| "Exclude from reports" (quality check) | Properties → Exclude | 🟡 | kept, but the security report ignores it (`lib/report.ts` reports such entries too) and it cannot be changed |
| Custom data, properties (UUID, times) | Properties tab | 🟡 | created and modified times shown; the rest kept |
| Merge review marks | (none) | ✅ | beyond KeePassXC: entries changed on two devices are marked, compared against history and marked reviewed (`EntryDetail.tsx`, spec 77) |

## Bulk actions and the entry list

Verified in `features/EntryList.tsx` (the list, its selection and the
selection bar), `features/entryDrop.ts` (groups as drop targets) and
`features/EntryDetail.tsx` (one entry). Several entries change as one edit
(one save, one merge step): `moveEntries`, `deleteEntries`,
`recycleEntries` (never for good) and `restoreEntries` in
`crates/kutup-pass/src/edit.rs`, all or nothing. A
read-only vault has no selection and no dragging.

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Select several entries (Ctrl/Shift-click) | `gui/entry/EntryView.cpp` (`ExtendedSelection`) | ✅ | a checkbox on each row (shown on hover, and always once one is selected), Ctrl/Cmd-click toggles, Shift-click takes the range from the last one clicked (`lib/selection.ts`); a plain click opens the entry; Esc clears; spec 167 |
| Select all (Ctrl+A) | Ctrl+A in the list | ✅ | what the list shows (the group and the search) |
| Move **one** entry to another group | drag to a group | ✅ | the folder button in the entry's header → "Move to" with the vault's groups (`EntryDetail.tsx`, `moveEntry`) |
| Move **several** entries (or all of a group, select all then move) | select, drag to a group | ✅ | the selection bar's "Move to group", one `moveEntries` edit |
| Move one entry to the recycle bin | Delete | ✅ | asks first; for good inside the bin or with it off |
| Move several to the recycle bin, delete several | select, Delete | ✅ | asks first, naming the count; for good (said so, "can't be undone") in the bin or with it off |
| Restore from the recycle bin | drag back | ✅ | one entry or several, each back to the group it was in (KDBX's previous parent group), or the top group when that one is gone or in the bin; or "Move to" another group |
| Empty the recycle bin | Recycle bin → Empty | ✅ | |
| Clone several | Clone | ❌ | |
| Drag and drop (entries to groups, groups into groups, Ctrl to copy) | `EntryView`, `GroupView` | 🟡 | entries (one, or the selection) onto a group, or onto the recycle bin while it is on (`recycleEntries`, which refuses rather than delete for good); not groups into groups, no Ctrl to copy |
| Sort the list | click a column | ❌ | always by title, A–Z (natural order); no other order |
| Choose columns (user name, URL, modified, expiry, attachments, TOTP…) | header menu | ❌ | each row shows the icon, title and user name (else URL) |
| Move entries up and down (manual order) | Entries → Move up/down | ❌ | |
| Keyboard shortcuts (copy user name/password/TOTP, new entry, search) | `KeyboardShortcuts.adoc`, configurable in 2.8 | ❌ | none |
| Copy across vaults (move an entry to another vault) | drag between tabs | ❌ | the core can (`crates/kutup-pass/src/refs.rs`: attachments, icons and history move with it); no UI |

## Search

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Search as you type | search box | ✅ | `VaultPage.tsx` `matches`: case-insensitive substring |
| Fields searched | all standard fields, attributes, tags, groups | 🟡 | title, user name, URL, notes and tags; not custom fields, attachments' names or group names; protected values not at all (as KeePassXC without a modifier) |
| Scope | the database or the current group | 🟡 | within the chosen group (its own entries) or "All entries"; never across vaults |
| Field modifiers (`title:`, `url:`, `user:`, `notes:`, `attr:`, `tag:`, `is:expired`, `is:weak`…) | `DatabaseOperations.adoc` "Modifiers and Fields" | ❌ | |
| Wildcards, regular expressions, `!` negation, exact `+` | "Wild Card Characters and Logical Operators" | ❌ | |
| Saved searches | tag view (`gui/tag/TagView.cpp`) | ❌ | |
| Search the recycle bin | | 🟡 | only by opening the bin and searching there |

## Password generator

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Character sets (lower, upper, digits, symbols) | `PasswordGenerator.adoc` | ✅ | `lib/generator.ts`, `features/PasswordGenerator.tsx`: `crypto.getRandomValues` without modulo bias, one of each chosen set |
| Exclude look-alikes | "Exclude look-alike characters" | ✅ | |
| Length | 1–999 | 🟡 | 8–64 |
| Extended ASCII, math, braces, quotes, dashes groups; custom "also include" and "exclude" characters | advanced options | ❌ | one fixed symbol set |
| Passphrases (word lists, separator, case, word count) | "Generating Passphrases", EFF lists | ❌ | the file's header says "passphrases" but there is none |
| Entropy display | bits and a quality bar (zxcvbn) | 🟡 | "About N bits" for generated passwords; typed passwords get a rough weak/fair/strong from the character classes, not zxcvbn |
| Standalone generator (toolbar, copy without an entry) | Tools → Password Generator | ❌ | only from the password field of the entry editor |

## One-time codes, passkeys, SSH, desktop integration

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| TOTP: set up from a secret or `otpauth://` | Entry → TOTP → Set up | ✅ | the editor's "One-time code" field (`lib/otp.ts`): a base32 key (SHA-1, 6 digits, 30 s) or an `otpauth://totp/` URI |
| TOTP: other digits, periods, algorithms | setup dialog (custom settings) | 🟡 | from a URI only (SHA-1/256/512, any period and digits, `crates/kutup-pass/src/view.rs`); no form |
| TOTP: live code, copy | TOTP column, Ctrl+T | ✅ | `EntryDetail.tsx` `OtpRow`, seconds left, copy (cleared after 30 s) |
| TOTP: show a QR code (to move to a phone) | TOTP → Show QR code (`src/qrcode`) | ❌ | |
| TOTP: read a QR code / Google Authenticator export | (no) | ❌ | not in KeePassXC either; research 19 §5.10 "later" |
| Steam Guard codes | `encoder=steam` | ❌ | the vendored crate's `TOTP` has no Steam encoder |
| Legacy TOTP fields (`TOTP Seed`/`TOTP Settings`, `TimeOtp-*`) | read | 🟡 | `otp` field only; KeePass 2's `TimeOtp-*` fields show as custom fields |
| Passkeys: kept and shown | `Passkeys.adoc`, `KPEX_PASSKEY_*` attributes | 🟡 | kept; shown only as raw custom fields (private key hidden) |
| Passkeys: use, register, import, export | through KeePassXC-Browser; Reports → Passkeys | ❌ | needs an extension or native app (research 19 §5.9) |
| SSH agent: offer KeeAgent keys | `src/sshagent`, entry SSH Agent tab | ✅ (CLI) | `kutup ssh-agent` (`crates/kutup-cli/src/sshagent`, `crates/kutup-pass/src/ssh.rs`): KeeAgent-compatible entries, approval per use (terminal or desktop dialog), forwarded requests flagged, keys listed while locked, `scripts/verify-pass-ssh.sh` |
| SSH agent: add/remove on unlock/lock, lifetime, confirm | KeeAgent settings | ✅ (CLI) | `kutup ssh-add` honours lifetime and confirm, or `--lifetime`/`--confirm`; forgotten after `--idle` |
| SSH agent: start at login | (with the app) | ✅ (CLI) | `kutup ssh-agent install` / `status` / `uninstall` (systemd, launchd; macOS not yet run on a Mac) |
| SSH agent on Windows (OpenSSH pipe, Pageant) | yes | ❌ | roadmap "SSH agent next" |
| SSH keys on the website (type, fingerprint, public key, agent switch) | SSH Agent tab | ❌ | raw attachments only (`id_ed25519`, `KeeAgent.settings`); roadmap "SSH keys shown as SSH keys" |
| Generate an SSH key | 2.8: RSA, ECDSA, Ed25519 | ❌ | roadmap (Ed25519) |
| Secret Service / FreeDesktop (`libsecret` clients) | `src/fdosecrets`, `SecretService.adoc` | ❌ | needs a desktop app |
| Browser integration (fill, save, passkeys) | KeePassXC-Browser, `BrowserIntegration.adoc` | ❌ | an extension is later (research 19 §5.14) |
| Auto-type (global hotkey, sequences, Wayland portals in 2.8) | `src/autotype`, `AutoType.adoc` | ❌ | needs a desktop app; sequences kept |

## Health report

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Weak passwords | Reports → Health check (zxcvbn score) | 🟡 | `features/SecurityPanel.tsx`, `lib/report.ts`: by character classes and length (bits), not zxcvbn |
| Reused passwords | Health check | ✅ | grouped by password, within the open vault (not across vaults) |
| Expired entries | Health check | ✅ | |
| Soon expiring, old passwords, too short | Health check | ❌ | |
| Excluded entries respected | "Exclude from reports" | ❌ | see Entries |
| Breached passwords (HIBP) | Reports → HIBP (online k-anonymity), `keepassxc-cli analyze --hibp` (offline list) | ❌ | nothing leaves the device (`pass.md`, Security report); research 19 §5.12 proposes an opt-in check proxied by the Kutup server |
| Statistics | Reports → Statistics | ❌ | |

## Locking and unlocking

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Lock by hand, lock all | Database → Lock | ✅ | the vault's menu → Lock; "Lock all vaults" in the shell |
| Lock after idle | Settings → Security → timeout | ✅ | 1, 5, 15 (default), 30, 60, 240 minutes or only at sign-out (`sync/autoLock.ts`) |
| Lock on screen lock, minimise, switch user | Settings → Security | ❌ | a browser tab cannot see these; signing out (here or in another tab) locks |
| Unlock again with the account password, the PIN or one click | (none) | ✅ | beyond KeePassXC, as Proton Pass: per device (`VaultsPage.tsx`, `UnlockVault.tsx`); the PIN checked by the server, three misses sign out (`sync/pin.ts`, spec 151) |
| Unlock with the sign-in (no vault password) | (none) | ✅ | the vault key sealed under the account key (`drive/secrets.ts`, spec 154) |
| Quick unlock: Windows Hello, Touch ID, Polkit | `src/quickunlock`, `DatabaseOperations.adoc` "Quick Unlock" | ❌ | needs native apps; WebAuthn PRF on the web would be the browser's version |
| Clipboard cleared after a delay | Settings → Security (10 s) | ✅ | 30 s, only if the clipboard still holds the value |
| Hide passwords, screenshot protection | Settings → Security | 🟡 | hidden until revealed; screenshots cannot be blocked in a browser |

## Sync, sharing and merges

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Reload when the file changes elsewhere, merge | file watcher + `core/Merger.cpp` (two-way, newest wins) | ✅ | three-way, field by field, never loses an edit; conflicts marked for review (`crates/kutup-pass/src/merge.rs`, `sync/vaultSession.ts`, spec 77); every minute and when the tab returns |
| Conditional saves (no overwrite of an unseen version) | (no) | ✅ | `basedOn` on Drive versions; a `409` merges and saves again |
| Offline editing | the local file | ✅ | the outbox keeps edits and the base version in IndexedDB, under the vault's own key; sent when back, also after the tab was closed (`sync/outbox.ts`, spec 78) |
| Desktop sync of the file | any file sync | ✅ (CLI) | `kutup sync` saves `.kdbx` as versions of the same file and merges instead of conflict copies (`crates/kutup-cli/src/vaultsync.rs`, `scripts/verify-pass-sync.sh`); KeePassXC then reloads it |
| Remote sync through external tools (2.8) | `DatabaseOperations.adoc` "Remote database support" | ✅ | Drive is the remote, as above |
| Share a whole vault with people | KeeShare to a shared file, or share the file | ✅ | a vault in a shared Drive folder; viewers get it read-only (`session.canEdit`); each member keeps the key under their own account |
| Share one group (KeeShare import/export/sync containers) | `src/keeshare`, `KeeShare.adoc` | ❌ | a separate vault in a shared folder does the job today |
| Share a single entry | (no) | ❌ | roadmap "Pass next" (research 19 §5.7) |
| Change the key after removing a member | change the password | ❌ | see "Change the password" |

## Platforms

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Desktop app (Windows, macOS, Linux) | Qt app | 🟡 | the website in a desktop browser, `kutup sync` for KeePassXC itself, `kutup ssh-agent`; no desktop app |
| Website | (none) | ✅ | `pass.<domain>`, strict CSP (spec 79) |
| Phones | (none; KeePassDX, Keepass2Android, KeePassium) | 🟡 | the website at phone width (K3); no autofill; native apps deferred ([`../mobile-build.md`](../mobile-build.md)) |
| Browser extension | KeePassXC-Browser | ❌ | later |
| CLI: open, `ls`, `show`, `clip`, `search` | `keepassxc-cli` | ❌ | `kutup pass` manages kept keys only (`keep`, `ls`, `forget`, `show-key`; `crates/kutup-cli/src/commands/pass.rs`) |
| CLI: `add`, `edit`, `rm`, `mv`, `mkdir`, `rmdir`, attachments | `keepassxc-cli` | ❌ | |
| CLI: `db-create`, `db-edit`, `db-info`, `merge`, `import`, `export` | `keepassxc-cli` | 🟡 | `merge` happens inside `kutup sync`; the rest none |
| CLI: `generate`, `diceware`, `estimate`, `analyze` | `keepassxc-cli` | ❌ | |
| CLI: SSH agent | (in the GUI) | ✅ | beyond KeePassXC: `kutup ssh-agent`, `kutup ssh-add`, headless and over SSH |
| Languages | ~40 | 🟡 | English and Turkish |

## Gaps in priority order

What people hit first, then what blocks moving from KeePassXC:

1. ✅ **Several entries at once** (user report): multi-select (Ctrl/Shift
   and checkboxes), select all, then Move to group, move to the recycle
   bin, restore each to where it was, delete for good; drag and drop of
   entries onto groups and the bin. Each as one edit (`moveEntries`,
   `deleteEntries`, `restoreEntries`). Spec 167.
2. **Vault management from the vault list** (user report): a menu on each
   vault in `VaultsPage.tsx`, also while locked: rename (today only inside
   an unlocked vault's "…" menu), move to another folder, duplicate,
   delete (to Drive's trash), "Show in Drive", and **Download the
   `.kdbx`** (for KeePassXC or a backup; user report). Keep the KDBX
   `DatabaseName` in step with a rename made in Drive (on the next save).
3. **Change the vault's key** (user report, with item 1's urgency): a
   Vault settings → Security page wiring `changeKey`: change the password,
   **generate** a key file (KeePassXC's 32-byte random key in its XML v2
   form, downloaded once), **add** or **remove** a key file, and re-keep
   the new key in the account. Needed too for shared vaults after a member
   leaves.
4. **Move groups** (`moveGroup` exists in the core) and restore deleted
   groups (entries already go back to where they were, item 1).
5. **Vault settings**: description, default user name, recycle bin on/off,
   history limits, KDF (Argon2id memory and iterations, with a "how long
   to open" test), compression.
6. **List and search**: sort (title, user name, modified, created,
   expiry), more columns, search modifiers (`title:`, `url:`, `tag:`,
   `is:expired`…), custom fields in search, a tag list in the sidebar.
7. **Clone an entry**; delete history items.
8. **SSH keys on the website** and key generation (roadmap).
9. **Generator**: passphrases (EFF word list), a standalone generator,
   custom and excluded characters, longer lengths; zxcvbn for strength
   (and in the report, which should also honour "exclude from reports").
10. **TOTP**: a setup form (digits, period, algorithm), Steam codes, show
    the QR code.
11. **Export**: CSV and KeePass XML (with the warnings KeePassXC gives);
    import KeePass XML, Bitwarden JSON, 1PUX and Proton Pass ZIP.
12. **References and placeholders**: resolve `{REF:…}` when showing and
    copying, at least `{REF:U/P@I:…}`; the common placeholders.
13. **Built-in KeePass icons** and colours, group notes.
14. **A CLI for entries** (`kutup pass ls|show|clip|add|edit|generate`),
    so scripts need not run `keepassxc-cli` on a synced copy.
15. **Breach check** (opt-in, proxied k-anonymity, research 19 §5.12) and
    statistics.
16. **YubiKey challenge-response**: CLI first, WebHID later.
17. Windows SSH agent; passkeys, autofill and quick unlock with the
    extension and the native apps.

## Out of scope / decided not to do

| Item | Why | Decision |
|---|---|---|
| WebDAV (KeePass apps' usual sync), CalDAV, CardDAV | Kutup serves no DAV; desktops sync with `kutup sync`, phones use the website until the native apps | [`../research/06-webdav-support.md`](../research/06-webdav-support.md); [`pass.md`](pass.md), "Decisions" |
| A desktop app of Kutup's own (Qt-style) now | KeePassXC already is one and opens the same file; Kutup supplies sync, merge and the agent | research 19, "Direction" and "Priorities" |
| Native phone apps now | one repository per product, after v1 | [`pass.md`](pass.md) K4; [`../mobile-build.md`](../mobile-build.md) |
| Auto-type, Secret Service, quick unlock in the website | a web page cannot type into other windows, serve D-Bus or use the OS's biometrics for a key | come with native apps |
| Using passkeys in the website | a page cannot be another site's authenticator | research 19 §5.9 |
| Opening `cmd://` and other non-web URLs | a web page cannot run commands | — |
| A breach lookup that sends anything by default | nothing leaves the device unless asked; an opt-in proxied check stays possible (gap 15) | [`pass.md`](pass.md), "Security report" |
| KeeShare group containers | a separate vault in a shared Drive folder covers it; per-entry sharing is the planned next step | research 19 §5.7; roadmap "Pass next" |
| Writing KDBX 3.1 or 4.0 | the crate writes 4.1 only; KeePassXC does the same on save | [`pass.md`](pass.md), "What exists to build on" |
| KDBX 2.x (before 2009) | the crate cannot read it; nobody uses it | as above |
