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
| The database (vault) | 31 | 1 | 8 |
| Groups (folders) | 9 | 1 | 2 |
| Entries | 16 | 4 | 2 |
| Bulk actions and the entry list | 11 | 1 | 3 |
| Search | 4 | 2 | 1 |
| Password generator | 6 | 1 | 0 |
| One-time codes, passkeys, SSH, desktop integration | 9 | 1 | 8 |
| Health report | 4 | 0 | 3 |
| Locking and unlocking | 5 | 1 | 2 |
| Sync, sharing and merges | 7 | 0 | 2 |
| Platforms | 3 | 5 | 2 |
| **All** | **105** | **17** | **33** |

## The database (vault)

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Open KDBX 4.x and 3.1 | `format/Kdbx4Reader.cpp`, `Kdbx3Reader.cpp` | ✅ | `crates/kutup-pass/src/kdbx.rs` through the vendored `keepass` crate; 3.1 is upgraded to 4.1 on the first save, as KeePassXC does; KeePassXC's test vaults round-trip (`tests/corpus.rs`) |
| Save KDBX 4.1 | `Kdbx4Writer.cpp` | ✅ | only 4.1 is written |
| Several vaults | tabs, one per database | ✅ | every `.kdbx` the account reaches in Drive, own and shared (`features/VaultsPage.tsx`, `drive/vaults.ts`) |
| Create a vault | Database → New (wizard) | ✅ | `features/CreateVaultDialog.tsx`: a folder, a random vault key kept in the account (default) or a password and/or key file; also from Drive's New menu |
| Rename a vault | Database settings → name | ✅ | the vault list's menu (`features/VaultMenu.tsx`), also while locked, and inside an open vault's "…" menu |
| Vault name vs KDBX `DatabaseName` | the name inside the file | ✅ | Pass shows the **file** name; a rename here renames both when the vault is open, and a rename made while locked or in Drive reaches `DatabaseName` at the vault's next edit (`sync/vaultSession.ts`) |
| Delete a vault | delete the file | ✅ | the vault list's menu: to Drive's trash, restorable there, its kept key kept so it opens again once restored |
| Duplicate a vault ("Save as") | Database → Save as / Save a copy | ✅ | the vault list's menu: a copy in the same folder sharing the vault's key (said so), its kept key kept for the copy too |
| Move a vault to another folder | save elsewhere | ✅ | the vault list's menu, among the owner's writable folders (Drive's `moveFile`, now in `drive-core`); the file keeps its id, so its kept key still opens it |
| Bring in an existing vault (`.kdbx` upload) | Database → Open | ✅ | "Upload a .kdbx" (`features/UploadVaultDialog.tsx`): checked by its header (KeePass 1, KDBX 3.0 and unknown formats refused with their own message) and that its password or key file opens it before anything is uploaded; up to the administrators' `passVaultMaxBytes` (64 MiB at first); its key kept in the account by default; a KDBX 3.1 or 4.0 file is said to be saved as 4.1 at its first change |
| Description, default user name | Database settings → General | ✅ | Vault settings → General (`features/VaultSettingsDialog.tsx`, [`pass-gaps-2.md`](pass-gaps-2.md) P2); the default user name fills new entries (`EntryEditor.tsx`) |
| Public metadata (name, icon, colour on the unlock screen) | Database settings → General | ❌ | kept |
| Change the password | Database settings → Security | ✅ | the vault's menu → "Change vault key…" (`features/ChangeKeyDialog.tsx`, rules in `lib/keyChange.ts`): keep, change (typed twice, or generated) or remove the password, one key part at least; saved straight to Drive or undone (`VaultSession.changeKey`, `abandonKeyChange`), then kept in the account again or the old kept key forgotten; says that Drive's earlier versions still open with the old key and copies already downloaded can't be revoked, and lets the owner delete the earlier versions and the first upload (`DELETE …/versions/original`); spec 168. Not in the CLI |
| Key file: **create** (generate) | Security → Add Key File → Generate | ✅ | `kdbx::generate_key_file`: 32 random bytes in KeePass's XML v2, byte for byte as KeePassXC writes it (`Name.keyx`); downloaded only, never sent anywhere; the change waits until the person says it is saved |
| Key file: **open** a vault with one (alone or with a password) | unlock screen | ✅ | `UnlockVault.tsx` takes a password, a key file or both; also when another device saved under a new key (`TheirsKeyDialog.tsx`); every key-file kind (XML v1/v2, 32-byte, hex, any file) |
| Key file: **new vault** protected by one | wizard → credentials | ✅ | `CreateVaultDialog.tsx`, "A password I choose", with or without a password; an existing file only (see "create") |
| Key file: **add** to an existing vault | Security → Add Key File | ✅ | "Change vault key…": generated, or one the person has; the password part kept (also when known only as its hash, opened with the kept key) |
| Key file: **remove** from an existing vault | Security → Remove Key File | ✅ | as above, while a password stays |
| Key file kept with the sign-in | (none) | ✅ | beyond KeePassXC: the derived key element sealed under the account key (`crates/kutup-pass/src/kept.rs`), so the website and `kutup sync` open it without the file |
| YubiKey / OnlyKey challenge-response | `keys/ChallengeResponseKey.cpp`, `keys/drivers` | ❌ | neither open, create, add nor remove: the crate's challenge-response feature is off, and the web would need WebHID (Chromium only; research 19 "Unlocking…") |
| KDF settings (Argon2d/id, AES-KDF; memory, iterations, parallelism; "1 second" benchmark) | Security → Encryption | ✅ | Vault settings → Encryption (`setVaultConfig`): Argon2id, Argon2d or AES-KDF with their parameters; "Benchmark 1 s" times one derivation in the worker and scales the passes or rounds; refused below the administrators' minimums (`passKdfMinimums`, Server settings → Pass; 64 MiB and 2 passes, 100,000 rounds at first) and above what any device could open; a vault already below them opens with a warning and Strengthen. A change merges by `settingsChanged`, so another device's save never undoes it. New vaults get Argon2id 64 MiB, 10 passes |
| Cipher (AES-256, ChaCha20, Twofish) | Encryption → advanced | ❌ | kept; new vaults the crate's default |
| Recycle bin on/off | Settings → General | ✅ | Vault settings → General; made when first needed; deletes go for good with it off. Choosing another group as the bin: not offered |
| History limits (items, size) | Settings → General | ✅ | Vault settings → General: items (0–1000) and MiB per entry, each or no limit; a lower limit trims every entry's history at once (said before saving); new vaults 10 items / 6 MiB as KeePassXC |
| Compression | Settings → General | ✅ | Vault settings → Encryption: GZip on or off |
| Maintenance (purge unused icons) | Settings → Maintenance | ❌ | unused pictures stay in the vault, as KeePass apps do |
| Autosave, backup before save | Settings → Saving | ✅ | every edit saves at once as a new Drive version (`sync/vaultSession.ts`); Drive's versions are the backups |
| Merge another database into this one | Database → Merge from database | ❌ | versions of the **same** vault merge by themselves (below); there is no "merge this other `.kdbx` in" |
| Import CSV (column mapping) | `ImportExport.adoc`, CSV wizard | ✅ | `features/ImportDialog.tsx`, `crates/kutup-pass/src/import.rs`: KeePassXC, Bitwarden, 1Password, LastPass, Proton Pass, NordPass, Dashlane, Chrome/Edge/Brave, Firefox, Safari, or any CSV with named columns, into a new group of an open vault; preview first (spec 150) |
| Import 1Password (1PUX, OPVault) | `OPUXReader.cpp`, `OpVaultReader.cpp` | 🟡 | 1PUX (logins, sections, one-time codes, files as attachments, vaults as groups; `crates/kutup-pass/src/import_json.rs`) and 1Password's CSV; not OPVault |
| Import Bitwarden JSON | `BitwardenReader.cpp` | ✅ | the unencrypted JSON: logins, cards, identities, SSH keys, custom fields, folders or collections as groups (as KeePassXC); a password-protected export is refused with its own message; earlier passwords and passkeys are reported, not imported |
| Import Proton Pass (ZIP/JSON) | `ProtonPassReader.cpp` | ✅ | the ZIP or its `data.json`: logins, cards, Wi-Fi, SSH keys, extra fields, vaults as groups; aliases kept as entries (said so); a PGP-encrypted export is refused |
| Import KeePass 1 (`.kdb`) | `KeePass1Reader.cpp` | ❌ | |
| Import KeePass XML | Import → KeePass XML | ✅ | the import dialog (`crates/kutup-pass/src/import_xml.rs`, through the vendored crate's `from_plain_xml`): the whole tree under a new group, with history, attachments (Meta/Binaries, compressed or not), icons and custom data, new ids throughout; values protected as the file's `ProtectInMemory` and MemoryProtection say, the password always; the source's recycle bin left out; attachments a file names but doesn't hold (KeePassXC's own KDBX 4 XML export) reported |
| Export KDBX (the file itself) | Save a copy | ✅ | the vault list's menu, "Download .kdbx", also while locked: Drive's layer opened, the KeePass file as it is; the key never in or beside it (said so), and where to see a generated one |
| Export CSV | `CsvExporter.cpp` | ✅ | the vault's menu → Export (`ExportDialog.tsx`, `crates/kutup-pass/src/export.rs`): KeePassXC's columns, made in the worker and only downloaded, after the account's password and a warning; the recycle bin left out (KeePassXC includes it) |
| Export XML | `KdbxXmlWriter.cpp` | ✅ | Export → KeePass XML (`to_plain_xml`, a documented patch to the vendored crate): history, icons and custom data, protected values marked `ProtectInMemory`, and every attachment in Meta/Binaries so the file stands alone (KeePassXC's KDBX 4 XML leaves attachments out); the recycle bin left out |
| Export HTML (paper backup) | `HtmlExporter.cpp` | ❌ | |
| Auto-open other databases (AutoOpen group) | `DatabaseOperations.adoc` | ❌ | kept; Pass lists every vault anyway |
| Statistics (counts, sizes, passkeys, TOTP) | Reports → Statistics | ❌ | |

## Groups (folders)

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Create a group | Groups → New | ✅ | `VaultPage.tsx` group menu, `GroupDialog.tsx` |
| Nest groups | any depth | ✅ | "New group inside"; the tree indents by depth; phone width uses a picker |
| Rename | Edit group | ✅ | group menu → Rename |
| Move a group under another | drag and drop in the tree | ✅ | group menu → Move to (any group outside the bin but itself and what it holds), or drag a group onto another; onto the recycle bin it is deleted (`recycleGroup`, never for good). `moveGroup` refuses the bin and moving the bin ([`pass-gaps-2.md`](pass-gaps-2.md) P1) |
| Delete a group (to the recycle bin) | Delete group | ✅ | asks first; for good with the bin off |
| Restore a deleted group | drag out of the bin | ✅ | the bin view lists its groups above the entries: Restore puts one back with everything in it where it was (KDBX's previous parent group, else the top group; `restoreGroups`), Move to another group, or Delete for good |
| Group notes | Edit group → Notes | ✅ | the group menu's Edit (`GroupDialog.tsx`), shown above the group's entries |
| Group icons: custom pictures | Edit group → Icon | ✅ | group menu → Change icon (`IconDialog.tsx`, spec 153) |
| Group icons: KeePass's built-in set | 69 standard icons | ✅ | the icon dialog's KeePass icons (`lib/builtinIcons.ts`): drawn with lucide, the number kept, so other KeePass apps show theirs |
| Per-group auto-type, search and browser settings, expiry | Edit group → Properties / Browser | ❌ | kept |
| Sort groups A–Z | Groups → Sort | ❌ | tree in the file's order |
| Show entries of subgroups | (a group shows its own entries) | 🟡 | as KeePassXC: a group shows its own entries only; "All entries" shows every entry outside the bin |

## Entries

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Title, user name, password, URL, notes | Edit entry | ✅ | `EntryEditor.tsx`, `EntryDetail.tsx`; copy buttons; the clipboard is cleared after 30 seconds if unchanged (`lib/copySecret.ts`) |
| Additional attributes (custom fields) | Advanced → Additional attributes | ✅ | add, rename, remove, protect |
| Protected fields (hidden, in-memory protection) | "Protect" per attribute | ✅ | protected values hidden with reveal; the password is always protected |
| Attachments | Advanced → Attachments | ✅ | add one or several (up to 50 MB each; names the entry has are listed once, to replace or skip), download, rename, remove; preview of images and text files in the page (no PDF: the page's CSP stays closed to it) |
| History: list, compare, restore | History tab | ✅ | `HistoryDialog.tsx`, `restoreHistory` |
| History: delete an item, delete all | History tab → Delete | ✅ | the History dialog: Delete per version, Delete all versions, asked first; remembered in the entry's `KutupHistoryDeleted` so another device's copy doesn't bring them back ([`pass.md`](pass.md)) |
| Expiry | Expires + presets | ✅ | date and time; an expired entry warns and shows in the security report; no presets ("in 3 months") |
| Tags | tag field, tag list in the sidebar | ✅ | edited as comma-separated text with the vault's tags offered; a Tags list in the sidebar with counts, a click searches `tag:"…"` |
| Icons: website icon | Download favicon | ✅ | through Kutup or off per account (spec 152); can be saved into the vault as a custom icon |
| Icons: custom pictures | Icon → Custom | ✅ | upload or reuse the vault's pictures (spec 153) |
| Icons: KeePass's built-in set | 69 standard icons | ✅ | as for groups; a non-default one shows instead of the website's icon |
| Foreground and background colour | Advanced → Colours | ✅ | the editor's Colours; the list shows the text colour on the title and the background as a bar at the row's edge |
| Auto-type sequences, window associations | Auto-Type tab | ❌ | kept, not shown (see auto-type below) |
| Several URLs | Browser integration, `KP2A_URL_n` | 🟡 | extra URLs are custom fields named `KP2A_URL`, `KP2A_URL_n` (the CSV import makes them), and each gets an open button beside its copy, as `URL` does (http and https only); no "Additional URLs" editor list, and no browser integration (Kutup has no extension) |
| URL schemes (`cmd://`, `ssh://`, `{S:…}` in URLs) | `Entry URL Handling` | 🟡 | `http(s)` opens in a new tab; other schemes are shown, not opened (deliberately: a web page cannot run commands) |
| URL override | Properties | ❌ | kept |
| References `{REF:P@I:…}` | `Reference.adoc` "Entry Cross-Reference" | ✅ | `crates/kutup-pass/src/resolve.rs` (KeePassXC's rules and test cases): fields T/U/P/A/N/I found by T/U/P/A/N/I/O, ten levels deep; shown and copied resolved, marked "from another entry"; made by Clone |
| Placeholders (`{USERNAME}`, `{DT_…}`, `{T-CONV:…}`) | `Reference.adoc` "Entry Placeholders" | 🟡 | the standard fields, `{UUID}`, `{TOTP}`, `{S:…}`, `{URL:…}` parts, `{DT_…}` and `{T-CONV:…}`; not `{T-REPLACE-RX:…}`, `{DB_DIR}` or auto-type keys (kept as typed) |
| Clone an entry (with references, with history) | Entries → Clone (Ctrl+D) | ✅ | the entry's Clone button (`CloneDialog.tsx`): " - Clone" after the title (in the person's language), the history, the user name and password as references, each if asked; beside the entry, its attachments shared. No Ctrl+D (keyboard shortcuts are their own gap) |
| "Exclude from reports" (quality check) | Properties → Exclude | ✅ | a switch in the entry editor; the report and `is:weak` leave such entries out |
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
| Clone several | Clone | ✅ | the selection bar's Clone, one `cloneEntries` edit |
| Drag and drop (entries to groups, groups into groups, Ctrl to copy) | `EntryView`, `GroupView` | ✅ | entries (one, or the selection) and groups onto a group, or onto the recycle bin while it is on (`recycleEntries` / `recycleGroup`, which refuse rather than delete for good), never a group into itself; with Ctrl (or ⌥) held they are copied instead, as KeePassXC's `CloneCopy`: new ids, times now, history kept, no " - Clone" suffix, a group with all it holds (`copyGroup`), never into the bin |
| Sort the list | click a column | ✅ | title, user name, URL, modified, created or expiry, up or down, per device (`lib/entryList.ts`); entries without the value last |
| Choose columns (user name, URL, modified, expiry, attachments, TOTP…) | header menu | ✅ | "Show in the list": user name, URL, modified, expiry, attachments, one-time code, per device; rows keep the icon and title |
| Move entries up and down (manual order) | Entries → Move up/down | ❌ | |
| Keyboard shortcuts (copy user name/password/TOTP, new entry, search) | `KeyboardShortcuts.adoc`, configurable in 2.8 | ❌ | none |
| Copy across vaults (move an entry to another vault) | drag between tabs | ❌ | the core can (`crates/kutup-pass/src/refs.rs`: attachments, icons and history move with it); no UI |

## Search

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Search as you type | search box | ✅ | the vault's own search in the worker (`crates/kutup-pass/src/search.rs`), once typing settles; folded as Kutup's other searches (Turkish I's, accents, case) |
| Fields searched | all standard fields, attributes, tags, groups | ✅ | title, user name, URL, notes, tags and unprotected custom fields; attachments' and groups' names with `attachment:` and `group:`; the password with `password:`; protected custom fields never |
| Scope | the database or the current group | ✅ | the chosen group, or "Whole vault" while searching; never across vaults |
| Field modifiers (`title:`, `url:`, `user:`, `notes:`, `attr:`, `tag:`, `is:expired`, `is:weak`…) | `DatabaseOperations.adoc` "Modifiers and Fields" | ✅ | KeePassXC's: `title:`/`t:`, `username:`/`user:`/`u:`, `password:`/`p:`, `url:`, `notes:`/`n:`, `attr:`, `attachment:`/`a:`, `group:`/`g:`, `tag:`, `uuid:`, `is:expired`, `is:expired-N`, `is:weak` (the health report's, honouring "exclude from reports"), `has:totp`; the search box's tooltip lists them |
| Wildcards, regular expressions, `!` negation, exact `+` | "Wild Card Characters and Logical Operators" | 🟡 | `*`, `-` or `!` to leave out, `+` for the whole value (combined in any order: `!+u:admin`) and `"quotes"` for spaces; no regular expressions (their engine would grow the WASM by tens of KB) |
| Saved searches | tag view (`gui/tag/TagView.cpp`) | ❌ | |
| Search the recycle bin | | ✅ | "Include the recycle bin" beside "Whole vault" while searching (KeePassXC leaves the bin out), or by opening the bin and searching there |

## Password generator

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Character sets (lower, upper, digits, symbols) | `PasswordGenerator.adoc` | ✅ | `lib/generator.ts`, `features/GeneratorPanel.tsx`: `@kutup/crypto/random` without modulo bias (a lint rule refuses `Math.random` in the Pass app), one of each chosen set |
| Exclude look-alikes | "Exclude look-alike characters" | ✅ | |
| Length | 1–999 | ✅ | 4–128 (KeePassXC's own UI caps at 128 too) |
| Extended ASCII, math, braces, quotes, dashes groups; custom "also include" and "exclude" characters | advanced options | 🟡 | "Also use" (any characters, their own set, at least one used) and "Never use"; no separate extended groups |
| Passphrases (word lists, separator, case, word count) | "Generating Passphrases", EFF lists | ✅ | `lib/passphrase.ts`: the EFF large list (7,776 words, CC BY 3.0, credited in the generator), served from Kutup's own origin and fetched on first use; 3–20 words, separator, lowercase / capitalised / mixed, an added number or symbol |
| Entropy display | bits and a quality bar (zxcvbn) | ✅ | bits for what is generated, and zxcvbn's weak / fair / strong (lazily loaded, `lib/strength.ts`) for any password |
| Standalone generator (toolbar, copy without an entry) | Tools → Password Generator | ✅ | `pass.<domain>/generator` in the sidebar, Copy, its options kept per device; the entry editor's popover is the same panel |

## One-time codes, passkeys, SSH, desktop integration

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| TOTP: set up from a secret or `otpauth://` | Entry → TOTP → Set up | ✅ | the editor's "One-time code" field (`lib/otp.ts`): a base32 key (SHA-1, 6 digits, 30 s) or an `otpauth://totp/` URI |
| TOTP: other digits, periods, algorithms | setup dialog (custom settings) | ✅ | the field's setup form (`TotpSetupDialog.tsx`): secret, 6/7/8 digits or Steam Guard, 15–300 s, SHA-1/256/512, written as KeePassXC's URI; codes in `crates/kutup-pass/src/otp.rs` (RFC 6238 vectors) |
| TOTP: live code, copy | TOTP column, Ctrl+T | ✅ | `EntryDetail.tsx` `OtpRow`, seconds left, copy (cleared after 30 s) |
| TOTP: show a QR code (to move to a phone) | TOTP → Show QR code (`src/qrcode`) | ✅ | the code's QR button (`TotpQrDialog.tsx`, `qrcode.react`), behind a warning, for `otpauth://` entries |
| TOTP: read a QR code / Google Authenticator export | (no) | ❌ | not in KeePassXC either; research 19 §5.10 "later" |
| Steam Guard codes | `encoder=steam` | ✅ | `otp.rs`: five characters of Steam's alphabet, from `encoder=steam` or `30;S`; KeePassXC's vectors from the Steam app |
| Legacy TOTP fields (`TOTP Seed`/`TOTP Settings`, `TimeOtp-*`) | read | ✅ | `otp.rs` reads KeePassXC's older fields and KeePass 2's `TimeOtp-*` (they still show as custom fields too) |
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
| Weak passwords | Reports → Health check (zxcvbn score) | ✅ | `features/SecurityPanel.tsx`, `lib/report.ts`: zxcvbn score 0–1 (the bits estimate until zxcvbn loads) |
| Reused passwords | Health check | ✅ | grouped by password, within the open vault (not across vaults) |
| Expired entries | Health check | ✅ | |
| Soon expiring, old passwords, too short | Health check | ❌ | |
| Excluded entries respected | "Exclude from reports" | ✅ | left out of weak, reused and expired |
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
| Change the key after removing a member | change the password | ✅ | "Change vault key…" (see "Change the password"); members' kept keys stop opening it and they are asked for the new one |

## Platforms

| Feature | KeePassXC | Kutup Pass | Notes / where |
|---|---|---|---|
| Desktop app (Windows, macOS, Linux) | Qt app | 🟡 | the website in a desktop browser, `kutup sync` for KeePassXC itself, `kutup ssh-agent`; no desktop app |
| Website | (none) | ✅ | `pass.<domain>`, strict CSP (spec 79) |
| Phones | (none; KeePassDX, Keepass2Android, KeePassium) | 🟡 | the website at phone width (K3); no autofill; native apps deferred ([`../mobile-build.md`](../mobile-build.md)) |
| Browser extension | KeePassXC-Browser | ❌ | later |
| CLI: open, `ls`, `show`, `clip`, `search` | `keepassxc-cli` | ✅ (CLI) | `kutup pass ls <vault> [group] [-R]`, `search`, `show` (`-s`, `-a`, `-t`), `clip` (`--clear-after`, default 10 s; the platform's clipboard tool) (`crates/kutup-cli/src/commands/pass_entries.rs`): a vault by file id or name, opened with the kept key, `KUTUP_VAULT_PASSWORD` or a prompt; entries by path or UUID, values resolved |
| CLI: `add`, `edit`, `rm`, `mv`, `mkdir`, `rmdir`, attachments | `keepassxc-cli` | ✅ | `add`, `edit` (`--move-to` moves), `rm` (`--force` for good), `mv` (an entry or a group), `mkdir`, `rmdir` (`--force` for good), `attachment-export` (`--out`, or `--stdout`), `attachment-import` (`--force` replaces), `attachment-rm`, `generate`: the website's operations, saved as a Drive version based on the one read and merged with a save that landed first |
| CLI: `db-create`, `db-edit`, `db-info`, `merge`, `import`, `export` | `keepassxc-cli` | 🟡 | `db-info`; `import` (every format the website reads, into a new group); `export` (CSV or KeePass XML, after the account's password is proved again, as the website; a new 0600 file, or standard output only with `--stdout`); `merge` happens inside `kutup sync`; no `db-create` or `db-edit` (vaults are made and set up in the website) |
| CLI: `generate`, `diceware`, `estimate`, `analyze` | `keepassxc-cli` | 🟡 | `kutup pass generate` (a password, or a passphrase from the EFF list with `--words`, as `diceware`); no `estimate` or `analyze` (the website's reports have them) |
| CLI: SSH agent | (in the GUI) | ✅ | beyond KeePassXC: `kutup ssh-agent`, `kutup ssh-add`, headless and over SSH |
| Languages | ~40 | 🟡 | English and Turkish |

## Gaps in priority order

What people hit first, then what blocks moving from KeePassXC:

1. ~~**Several entries at once**~~ (user report): done. Multi-select (Ctrl/Shift
   and checkboxes), select all, then Move to group, move to the recycle
   bin, restore each to where it was, delete for good; drag and drop of
   entries onto groups and the bin. Each as one edit (`moveEntries`,
   `deleteEntries`, `recycleEntries`, which never deletes for good, and
   `restoreEntries`). Spec 167.
2. ~~**Vault management from the vault list**~~ (user report): done. A menu
   on each vault, also while locked (rename, move, duplicate, download,
   show in Drive, delete), and uploading an existing `.kdbx`; spec 166.
3. ~~**Change the vault's key**~~ (user report, with item 1's urgency): done, spec 168. A
   Vault settings → Security page wiring `changeKey`: change the password,
   **generate** a key file (KeePassXC's 32-byte random key in its XML v2
   form, downloaded once), **add** or **remove** a key file, and re-keep
   the new key in the account. Needed too for shared vaults after a member
   leaves.
4. ~~**Move groups** and restore deleted groups~~: done
   ([`pass-gaps-2.md`](pass-gaps-2.md) P1).
5. ~~**Vault settings**~~: done ([`pass-gaps-2.md`](pass-gaps-2.md) P2).
6. ~~**List and search**~~: done ([`pass-gaps-2.md`](pass-gaps-2.md) P3);
   regular expressions later.
7. ~~**Clone an entry**; delete history items~~: done
   ([`pass-gaps-2.md`](pass-gaps-2.md) P4); references in clones wait for item 12.
8. **SSH keys on the website** and key generation (roadmap).
9. ~~**Generator**~~: done ([`pass-gaps-3.md`](pass-gaps-3.md) A1).
10. ~~**TOTP**~~: done ([`pass-gaps-3.md`](pass-gaps-3.md) A2).
11. ~~**Export and import**~~: done ([`pass-gaps-2.md`](pass-gaps-2.md)
    P5a, P5b): CSV and KeePass XML out; KeePass XML, Bitwarden JSON, 1PUX
    and Proton Pass in.
12. ~~**References and placeholders**~~: done ([`pass-gaps-3.md`](pass-gaps-3.md) B1).
13. ~~**Built-in KeePass icons** and colours, group notes~~: done
    ([`pass-gaps-3.md`](pass-gaps-3.md) A3).
14. ~~**A CLI for entries**~~: done ([`pass-gaps-3.md`](pass-gaps-3.md) B2);
    groups and attachments from the CLI later.
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
