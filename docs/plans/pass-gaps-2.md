# Pass: closing gaps 4–7 and 11

Status: approved by the main session 2026-11-17 (see "Decisions"). Plan by the third session. It covers items 4–7 and
11 of [`pass-parity.md`](pass-parity.md), "Gaps in priority order". Nothing
is built. Code starts from `wipe/final` once it is green, and merges after
the wipe.

KeePassXC is the reference for what a vault does (`kutup-references/keepassxc`):
- `src/core/EntrySearcher.cpp` for search modifiers;
- `src/format/CsvExporter.cpp` and `KdbxXmlWriter.cpp` for export;
- `BitwardenReader.cpp`, `OPUXReader.cpp`, `ProtonPassReader.cpp` and
  `KdbxXmlReader.cpp` for import;
- `src/gui/dbsettings` for vault settings.

Read from the code on `wipe/account-records`: the core (`crates/kutup-pass`)
already has `MoveGroup`, `UpdateVault {name, description, default_user_name}`,
`EmptyRecycleBin` and CSV import for 11 providers (`import.rs`). Nothing in
the UI calls `MoveGroup`. History limits are set only when a vault is
created (10 items, 6 MiB).

Rules, the same for every slice:
- Every change to a vault is one `Op` in `edit.rs`, one save and one merge
  step, all or nothing.
- Every new kept field is also checked by the merge (`merge.rs`).
- Every string is in en.json and tr.json.
- Limits are site settings where the server is involved. A vault's own
  settings live in the vault (KDBX meta), as KeePassXC keeps them.

## P1. Moving groups and restoring deleted groups (item 4)

- **Move a group:**
  - the group menu has "Move to…", with a picker of groups that excludes the
    group itself, its descendants and the bin;
  - groups can be dragged onto groups in the tree, reusing `entryDrop.ts`'s
    targets;
  - both call the existing `MoveGroup`;
  - the core refuses a cycle already (`move_to` in the vendored crate).
    `MoveGroup` will also refuse a move into the bin (use Delete instead),
    with tests for both.
- **Restore a deleted group:**
  - the bin view lists deleted groups beside entries;
  - a new `RestoreGroups {ids}` op puts each back under its previous parent
    (KDBX `PreviousParentGroup`), or the top group when that parent is gone
    or in the bin, as `RestoreEntries` does;
  - the group's entries and subgroups come back with it;
  - "Move to" another group is also offered.
- **Delete a deleted group for good:** this already happens through Empty
  bin. Add a per-group "Delete for good", which asks first.
- **Specs:** 207 (move by menu and by drag, restore with its entries).

## P2. Vault settings (item 5)

A Vault settings page (the vault menu → Settings), with the existing
Security page (key change, spec 168) as one tab. The rest follows
KeePassXC's `dbsettings`:

- **General:**
  - name, description and default user name, which `UpdateVault` already
    takes;
  - recycle bin on or off, and which group it is (new fields on
    `UpdateVault`);
  - history limits: maximum items and maximum size per entry, with "no
    limit". Lowering a limit trims at the next save, and the page says so.
- **Encryption:**
  - the KDF (Argon2id, Argon2d, AES-KDF), its memory, iterations and
    parallelism;
  - a "Benchmark 1 s" button, as KeePassXC's, measuring in WASM in a
    worker;
  - compression on or off.
  - A new `SetVaultConfig` op changes the file's config. `save` keeps
    whatever config the vault carries, which it already does.
  - Lower bounds refuse weak settings. The bounds are admin site settings
    (`passArgon2MinMemoryMib` 64, `passArgon2MinIterations` 2,
    `passAesKdfMinRounds` 100,000), read by the client and passed to the
    core's check.
  - A vault already below them still opens. It shows a warning and an offer
    to strengthen.
  - The page warns that slow settings make every device slow to open.
- **The merge:**
  - meta fields already merge by their changed times;
  - the file config is not meta: two devices that change the KDF at once
    keep the save that lands last;
  - the other device's next open shows nothing, because the key doesn't
    change;
  - add a test that a merge after a KDF change opens on both sides.
- **Specs:** 208 (change description and history limit; change Argon2
  memory, re-open).

## P3. The entry list and search (item 6)

- **Sort:** title, user name, URL, modified, created, expiry, each up or
  down. The choice is per device (local storage, wrapped in try/catch). The
  default is title, as today.
- **Columns:** user name, URL, modified, expiry, attachments, TOTP. They are
  chosen from the header menu, per device. At phone width only title and
  user name are shown.
- **Search modifiers, as KeePassXC's `EntrySearcher`:**
  - `title:` `t:`, `username:` `u:`, `password:` `p:` (only with the
    modifier), `url:`, `notes:` `n:`, `attr:`, `attachment:` `a:`,
    `group:` `g:`, `tag:`, `uuid:`;
  - `is:expired` and `is:expired-N`, `is:weak` (honouring "exclude from
    reports"), `has:totp`;
  - `-` negates, `"…"` quotes, `*` is a wildcard;
  - custom fields are searched without a modifier too (not protected ones);
  - the parser lives in the core (`view.rs`, Rust, tested), so the CLI
    (item 14) gets it for free.
  - Turkish case folding uses the same folding the other apps use.
- **Tags:** a Tags section in the sidebar lists the vault's tags with
  counts. A click filters, the same as `tag:x`. The editor suggests
  existing tags.
- **Search the whole vault:** a "Whole vault" switch beside the search box,
  as KeePassXC's. The default stays the chosen group, as today.
- **Specs:** 209 (sort and columns), 210 (modifiers, tag filter).

## P4. Clone and history items (item 7)

- **Clone, as KeePassXC's dialog (Ctrl+D):**
  - options: "Append ' - Clone' to the title", "Replace user name and
    password with references", and "Copy history";
  - a new `CloneEntries {ids, options}` op, which also covers several
    entries from the selection bar;
  - the clone gets a new UUID, and attachments and custom icons are shared
    the way the core's `refs.rs` copies them;
  - "Replace with references" writes `{REF:U@I:…}` / `{REF:P@I:…}`. Until
    item 12 resolves references, the option is hidden, so no raw `{REF:…}`
    appears where people copy passwords.
- **History items:**
  - the History dialog gets "Delete" per item and "Delete all";
  - a new `DeleteHistory {entry, indexes | all}` op;
  - the merge already takes history as a union, so a deleted item must not
    come back from another device's copy. The op records a tombstone by
    the item's modified time in the entry's custom data
    (`KutupHistoryDeleted`), and the merge drops matching items. Tests
    cover both directions.
- **Specs:** 211.

## P5. Export and import (item 11)

- **Export** (the vault menu → Export, while unlocked):
  - **CSV** in KeePassXC's columns: Group, Title, Username, Password, URL,
    Notes, TOTP, Icon, Last Modified, Created;
  - **KeePass XML** (KDBX's inner XML, unencrypted), as `KdbxXmlWriter`
    writes it, through the vendored `keepass` crate's `xml_db::to_xml` (the reader is
    `parse_xml`);
  - **KDBX:** the existing Download.
  - Both plain formats need the account's re-authentication (the
    `/user/reauth` grant that settings use for sensitive actions, as Proton
    Pass asks for the account password before export) and a warning
    as KeePassXC gives ("This file is not encrypted. Anyone who gets it can
    read every password in it."). They are built in the worker and saved
    with the browser's download; nothing goes to the server.
- **Import into a vault** (the existing Import dialog grows):
  - KeePass XML;
  - Bitwarden JSON (unencrypted; a Bitwarden export protected with a
    password is refused with a message, as KeePassXC asks for it — offer
    later);
  - 1Password 1PUX;
  - Proton Pass export (ZIP holding JSON; a PGP-encrypted Proton export is
    refused with a message).
  - Each is a parser in `import.rs` beside the CSV ones, with
    `ImportCsv` generalised to `Import {data, format, group_name}`.
  - Each parser has fixture files made from the references' test data,
    where they exist, and its own size limit (a constant in the core,
    50 MiB, as attachments).
  - What a format holds that a vault can't (1Password's documents beyond
    attachments, Proton aliases) is listed after the import, as the Sieve
    import in Mail does.
- **Specs:** 212 (CSV and XML export, then import of the XML back into a
  new vault), 213 (Bitwarden, 1PUX and Proton fixtures).

## Order and numbers

| Slice | Delivers | Specs |
|---|---|---|
| P1 | Move and restore groups | 207 |
| P2 | Vault settings | 208 |
| P3 | Sort, columns, search modifiers, tags | 209, 210 |
| P4 | Clone, history items | 211 |
| P5 | Export, more imports | 212, 213 |

- The specs are inside 200–219, after Calendar E3's 200–206.
- No migration, no account-record purpose or scope, and no label: all of
  this lives inside the KDBX file.
- Each slice is its own worktree and PR (`feat/pass-<slice>`), after the
  wipe.
- Until the full test is over: static, rust, web and unit checks only.
- When P1–P5 land, pass-parity.md gets its rows and counts updated.

## Questions

- **Q-1. Wildcards:**
  - Recommended: KeePassXC's `*`, `-` and quotes.
  - Its regular expressions (`/…/`) could come later.
- **Q-2. Weak KDF settings:**
  - Recommended: refuse below fixed minimums (Argon2 64 MiB and 2
    iterations, AES-KDF 100,000 rounds).
  - KeePassXC only warns.
- **Q-3. Exporting a plaintext file:**
  - Recommended: ask for the vault password again, as KeePassXC does.
  - Alternative: the account's re-authentication.
- **Q-4. History tombstones:**
  - Recommended: Kutup's own custom-data key, which other KeePass apps keep
    and ignore.
  - Without it, a deleted history item can come back from another device's
    copy.

## Decisions (the main session, 2026-11-17)

- **Q-1:** yes. `*`, `-` and quotes now; regular expressions later.
- **Q-2:** refuse below the minimums. The minimums are admin site settings
  with the values above as defaults. A vault opened with weaker settings
  still opens, with a warning and an offer to strengthen.
- **Q-3:** the account's re-authentication, not the vault password. Many
  vaults are quick-opened with the key kept in the account, so their owners
  may not know the vault password. Proton Pass also asks for the account
  password before an export.
- **Q-4:** yes, a Kutup custom-data key. Its name and format are written in
  [`pass.md`](pass.md) when P4 is built, so another implementation can
  honour it.
