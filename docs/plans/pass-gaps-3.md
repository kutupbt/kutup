# Pass: gaps 9, 10, 12, 13 and 14

Status: approved by the main session 2026-11-17 (see "Decisions"). Plan by the third session. It covers items 9, 10,
12, 13 and 14 of [`pass-parity.md`](pass-parity.md)'s "Gaps in priority
order", after [`pass-gaps-2.md`](pass-gaps-2.md). It stacks on
`feat/pass-xml`. There is no schema change; quick checks only.

KeePassXC is the reference, read from `kutup-references/keepassxc`:
- `src/core/PasswordGenerator.cpp`, `PassphraseGenerator.cpp` and
  `share/wordlists/`;
- `src/core/Totp.cpp`, `src/gui/TotpSetupDialog.cpp` and
  `TotpExportSettingsDialog.cpp`;
- `src/core/Entry.cpp` (`resolveMultiplePlaceholders`,
  `resolveReferencePlaceholder`) and `docs/topics/Reference.adoc`;
- `src/gui/EditWidgetIcons.cpp` and `src/cli/` (`Clip`, `Show`, `Add`,
  `Edit`, `Generate`, `Ls`).

## Part A: in the vault and on the page

### A1. Generator (item 9)

- **Passphrases.** Words from the EFF large word list (7,776 words, CC BY
  3.0, credited in the generator and in `docs/`), as KeePassXC.
  - Options: word count (default 7), separator, capitalisation (none,
    first letter, random), and add a number or a symbol.
  - The list is a static asset, fetched only when the generator opens, so
    it costs the Pass WASM nothing.
  - Words are picked with the browser's cryptographic random source and no
    modulo bias, as the password generator already does in
    `lib/generator.ts` (Q-2).
- **Passwords.**
  - Add custom characters, excluded characters and "every chosen group at
    least once".
  - Lengths up to 128.
- **A standalone generator** at `pass.<domain>/generator`, and in the
  vault's toolbar, with Copy and no vault needed. It keeps its options per
  device.
- **Strength.**
  - zxcvbn replaces `strengthOf`'s character-set estimate in the editor,
    the generator and the health report (Q-1).
  - The report honours "Exclude from reports": an excluded entry is left
    out of weak, reused and expired. The entry editor gets the switch; it
    is the KDBX `QualityCheck` flag, already kept.

### A2. One-time codes (item 10)

- **A setup form** in the entry editor, as KeePassXC's: the secret (Base32),
  digits (6, 7 or 8, or Steam), period (15 to 300 s) and algorithm (SHA-1,
  SHA-256, SHA-512). It writes KeePassXC's `otp` field (an `otpauth://`
  URI).
- **Steam codes.**
  - Five characters from Steam's alphabet, HMAC-SHA1, 30 s.
  - Written as KeePassXC writes them: `encoder=steam` in the URI, read also
    from its older `TOTP Settings` field (`30;S`).
  - Computed in `kutup-pass` (`view::otp`), with test vectors.
- **Show the QR code** of the `otpauth://` URI behind a click and a warning,
  as KeePassXC's "Export settings". It uses `qrcode.react`, which the Chat
  and Account apps already use.

### A3. Icons, colours and group notes (item 13)

- **The 69 built-in KeePass icons** get a picker in the icon dialog for
  entries and groups, next to custom pictures.
  - They are drawn with Kutup's icon set (lucide), each number mapped to
    the nearest meaning (key, globe, mail, server, folder…).
  - The number is what's saved, so KeePassXC shows its own picture for it
    (Q-3).
- **Foreground and background colours** for entries, as in KeePassXC's
  Advanced tab, shown on the entry's row. The colour is a `#rrggbb` field
  already in `EntryInput`.
- **Group notes:**
  - in the group dialog, saved through `UpdateGroup` (it already takes
    `notes`);
  - shown under the group's name when it is opened.

## Part B: references and the CLI

### B1. References and placeholders (item 12)

- **Where:** `kutup-pass` gains `resolve`, used everywhere a value is shown,
  copied or opened. Stored values are never changed.
- **References** `{REF:<field>@<search>:<text>}`, as KeePassXC:
  - fields T, U, P, A (URL) and N;
  - searches I (UUID), T, U, P, A and N (the first match in the vault's
    order);
  - nested up to 10 levels; a loop stays as the text it was. A reference
    that matches no entry resolves to empty, as KeePassXC does (decided
    2026-11-17; the plan first said it would stay as written).
- **Placeholders:** `{TITLE}`, `{USERNAME}`, `{PASSWORD}`, `{URL}`,
  `{NOTES}`, `{S:<field>}`, the URL parts (`{URL:HOST}`, `{URL:PORT}`,
  `{URL:SCM}`, `{URL:PATH}`, `{URL:QUERY}`) and the date and time
  (`{DT_SIMPLE}`, `{DT_YEAR}`… local and UTC). The time comes from the
  caller.
- **Not resolved:** auto-type keys (`{TAB}`, `{ENTER}`; Kutup has no
  auto-type) and `{CMD:…}`. They stay as written.
- **The page:**
  - a resolved value is marked "from another entry" with a link to it;
  - Clone's "Replace user name and password with references" is unhidden;
  - the editor shows the raw text and a "references another entry" note.
- **Tests:** KeePassXC's cases from `tests/TestEntry.cpp`
  (`testResolveReferencePlaceholders`, `testResolveRecursivePlaceholders`,
  `testResolveUrlPlaceholders`, `testResolveUuidPlaceholder`,
  `testResolveClonedEntry`) as Rust tests.

### B2. A CLI for entries (item 14)

`kutup pass` gains the commands below, after `keepassxc-cli`'s. The
vault is named by file id or name. It opens with the key the account keeps
(as `kutup sync` does), or `KUTUP_VAULT_PASSWORD` / `--key-file`.

| Command | Does |
|---|---|
| `ls [group]` | groups and entries, `--recursive`, `--json` |
| `search <query>` | the website's search (`kutup_pass::search`: fields, `-`, quotes, `*`) |
| `show <entry>` | the fields, protected ones hidden unless `--show-protected`; `--attribute <name>`; `--totp` for the code now |
| `clip <entry> [attribute]` | copies the password (or the attribute, or `--totp`) and clears it after `--timeout` seconds (default 10) if unchanged |
| `add <group/title>` | `--username`, `--url`, `--notes`, the password from `--generate` (generator options), a prompt or `KUTUP_ENTRY_PASSWORD` |
| `edit <entry>` | the same options, changing only what is given; `--title`, `--move-to` |
| `rm <entry>` | to the recycle bin (for good with `--force` inside it or with it off) |
| `generate` | the generator's options (`--length`, `--words`, `--exclude`…), with no vault |

- An entry is named by its UUID or its path (`Group/Sub/Title`); an
  ambiguous path is refused with the matches listed.
- Edits are the website's `Op`s. Each saves a new Drive version based on
  the one read; another device's save meanwhile is merged
  (`kutup_pass::merge`), as the website's sync does.
- `--json` and the CLI's exit codes, as the rest of `kutup`.
- Clipboard (Q-4): the platform's own tool (`wl-copy`, `xclip`/`xsel`,
  `pbcopy`, `clip.exe`) or a clear error. No new dependency.

## Order and numbers

| Slice | Delivers | Specs (when browser runs are allowed) |
|---|---|---|
| A1 | Passphrases, standalone generator, character options, zxcvbn, exclude from reports | 214 |
| A2 | TOTP form, Steam, QR | 215 |
| A3 | Built-in icons, colours, group notes | 216 |
| B1 | References and placeholders | 217 |
| B2 | CLI entries | none (Rust integration tests against a server, when docker is allowed; parsing and path tests now) |

There is no migration, purpose, scope or label. Every string goes in en and
tr. The Pass WASM grows only by the TOTP and reference code, about 5 KB;
I'll say before anything reaches the 830,000 budget.

## Questions

- **Q-1. Strength estimate.**
  - Recommended: the `zxcvbn` JS package, already in the Account app,
    lazily loaded as a separate chunk.
  - Alternative: the Rust `zxcvbn` crate in the Pass WASM. It adds a few
    hundred KB, over the budget.
  - A strength estimate isn't cryptography.
- **Q-2. Passphrase generation.**
  - Recommended: in TypeScript beside the password generator that is
    already there, using `@kutup/crypto/random`.
  - Alternative: move both generators into Rust/WASM. The EFF list then
    sits inside the WASM, about +30 KB gzipped, which is over the budget.
- **Q-3. The built-in icons.**
  - Recommended: drawn with lucide (MIT), the number kept.
  - Alternative: KeePass's own icon images. Their licences are mixed, so
    they are not recommended.
- **Q-4. CLI clipboard.**
  - Recommended: the platform's tools, cleared after 10 s, as
    keepassxc-cli does.
  - Alternative: a clipboard crate (`arboard`), a new dependency with X11
    and Wayland bindings.

## Decisions (the main session, 2026-11-17)

- **Q-1:** the zxcvbn JS package, lazily loaded.
- **Q-2:** passphrases in TypeScript beside the existing generator. All
  randomness comes from `@kutup/crypto/random`, never `Math.random`; a lint
  rule enforces it. Generation is not a persistent format, so the
  Rust/WASM rule doesn't apply.
- **Q-3:** the built-in icons are drawn with lucide, keeping the icon number.
- **Q-4:** the platform's clipboard tools. The clear delay is an option
  (`--clear-after`, default 10 s), and the CLI says plainly when no
  clipboard tool is found.
- **Also:** the EFF list is served from Kutup's own origin (the CSP allows
  no third-party fetch), with its CC BY credit on the app's about or
  licences page.
