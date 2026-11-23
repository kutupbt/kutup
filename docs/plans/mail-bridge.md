# Mail bridge for desktop mail apps (P7)

Status: approved 2026-11-19 (the main session, with the answers under
"Questions"). Built after the Pass items, B0 first; B0 and the first three
steps of B1 are built.

Thunderbird, Apple Mail, Outlook and other IMAP/SMTP apps reach a Kutup
mailbox through a local daemon that keeps mail end-to-end encrypted, as
Proton Mail Bridge does. The daemon signs in as the account, decrypts on the
device, and speaks IMAP and SMTP to apps on `127.0.0.1` only. The server
never gets an IMAP or SMTP login, and never sees a password an app stores.

The reference is Proton Mail Bridge (`kutup-references/proton-bridge`,
GPL-3.0, head 36d7b6a) and Gluon, its IMAP server library
(`kutup-references/gluon`, MIT, head d871584). Kutup follows them except
where noted below, with the reason given. Their `go-proton-api` (SRP, the
import and send packages, the fake server) is not cloned; nothing here
depends on it.

## What Proton does (the parts that shape this plan)

- **Processes:** a Go daemon (`bridge`) and a Qt GUI that drives it over
  gRPC on a local socket, plus a CLI mode (`--cli`, `--noninteractive`).
  A lock file keeps it to one instance.
- **Sign-in:** once, with SRP, 2FA (TOTP, FIDO2) and human verification. It
  keeps the refresh token and the salted key passphrase, so it never asks
  again.
- **Local state:** one "vault" file (msgpack, AES-256-GCM) whose 32-byte
  key is in the OS keychain (macOS Keychain, Windows Credential Manager,
  Secret Service or `pass`). Without a keychain it falls back to an
  unencrypted vault and warns.
- **Bridge password:**
  - 16 random bytes (22 base64url characters) per account;
  - checked in constant time against the account's enabled addresses;
  - kept in the vault in the clear, so the GUI can show it again;
  - never regenerated.
- **IMAP (Gluon):**
  - IMAP4rev1 with IDLE, UNSELECT, UIDPLUS, MOVE, ID, AUTH=PLAIN and
    STARTTLS; no CONDSTORE, QRESYNC or LITERAL+;
  - system places become top-level mailboxes with special-use attributes;
    folders appear under `Folders/` and labels under `Labels/`;
  - combined mode (one tree per account) or split mode (one login per
    address).
  - UIDs come from an AUTOINCREMENT per mailbox, so they are never reused.
    UIDVALIDITY strictly increases, and a resync makes new UIDVALIDITYs.
- **Cache:**
  - every message decrypted and cached as LZ4, then AES-GCM in 256 KiB
    blocks, under a per-user key from the vault;
  - the SQLite metadata (envelopes, subjects, addresses) is on disk in the
    clear.
  - Two flaws in its block encryption (`gluon/store/disk.go:96–149`): one
    nonce for every block of a file, and blocks not bound to their position.
- **Sync:**
  - the event API is polled every 20 s plus jitter; the cursor is saved
    only after every subscriber has applied the batch;
  - the initial sync goes newest first, can resume, and then replays the
    events since it started, so nothing is missed.
  - There is no merge: the server is authoritative, and an IMAP command
    calls the API inside the local transaction and rolls back on failure.
- **APPEND:**
  - to Drafts it makes a draft;
  - anywhere else it goes to the import API;
  - a message matching one sent over SMTP in the last 90 s (a hash of its
    headers, bodies and recipients, `imapservice/connector.go:303`) answers
    the existing sent copy, so "save to Sent" makes no duplicate.
- **SMTP:**
  - every send makes a draft, uploads its attachments, then looks up each
    recipient's keys and contact settings and sends it:
    - Proton recipients: encrypted and signed;
    - outside recipients with a key: PGP/MIME or PGP-inline;
    - everyone else: in the clear;
  - a sender the account doesn't own is refused, with a readable SMTP error.
- **Network:**
  - both protocols listen on `127.0.0.1` only, plaintext with STARTTLS by
    default (implicit TLS optional), and LOGIN is allowed before TLS;
  - one self-signed certificate per install (RSA-2048, 20 years), which can
    be exported;
  - ports: the first free from 1143 (IMAP) and 1025 (SMTP).
- **Tests:** 392 godog scenarios drive the real daemon with real IMAP and
  SMTP clients against an in-memory fake API.
- **Size:** about 13k lines of Proton-specific Go and 35k lines of Gluon,
  plus a 27k-line Qt GUI.

## Kutup's starting point

- **Stored messages are whole RFC 5322 messages, byte-exact**, encrypted
  as one OpenPGP message ([`mail.md`](mail.md), "Format"), whether from
  outside or between Kutup users. The bridge hands an IMAP app the
  decrypted original. Proton has to rebuild MIME from its parts; Kutup
  never does, so a signature over the original still verifies.
- **A change feed is already there.** `GET /api/v1/mail/search-index/changes`
  gives a cursor with tombstones and an explicit resync, and
  `GET /api/v1/mail/search-index` gives the full list
  ([`../sync-feeds.md`](../sync-feeds.md)). These are the bridge's initial
  sync and event loop. The cursor is taken before the full read, as
  Proton rewinds to the event it started from.
- **Sending** is `POST /api/v1/mail/send`, a multipart request:
  - `meta`: the readable fields, the key packets and the PGP list;
  - `data`: the shared data packet;
  - `pgp0`, `pgp1`, …: the PGP/MIME messages for outside recipients with
    keys;
  - `mime`: the plaintext for everyone else.

  It fits an SMTP send directly: the app already built the MIME.
- **The CLI already has the pieces of a local daemon:**
  - sign-in with 2FA;
  - a device key in the OS keyring (`kutup-cli/<profile>`);
  - an encrypted local store (redb, `LocalStateEnvelopeV1`);
  - the account head (`account_head.rs`);
  - `kutup ssh-agent`: a long-running service with `install` (a systemd
    user unit, a launchd agent) and desktop approval dialogs.
- **What only the web app does today, in TypeScript over the WASM crypto:**
  - the key lookup and its trust (`mail-core/keys.ts`, `keyList.ts`: signed
    key lists, identity pins, Contacts' pinned keys);
  - the per-recipient send plan (`sendDraft`, `protection.ts`: Kutup,
    PGP/MIME or Inline, readable, groups, Bcc on their own);
  - sealing folder and label names under the account head (`places.ts`).

  The bridge needs all of these in Rust.
- **Missing on the server:** a route that imports a message the client
  encrypted (Proton's import API). An IMAP APPEND that isn't a draft needs
  it.

## Decisions to approve

1. **What it is: `kutup mail-bridge`, a CLI subcommand, headless.**
   Kutup has no desktop app until the native apps are done (CLAUDE.md), and
   the CLI already signs in, keeps keys in the keychain and installs a user
   service. The commands:
   - `kutup mail-bridge serve` runs the daemon;
   - `install` / `uninstall` start it at login, as `ssh-agent install`
     does;
   - `setup` prints the IMAP and SMTP settings and the app password;
   - `status`, `password --reset`, `cert export`.

   No GUI. The Account app gets a "Desktop mail apps" page that explains
   the setup and lists the bridge's sessions; the download is the CLI's.
   Alternative: its own binary and repository with a GUI, as Proton has.
   That waits for desktop apps.
2. **A Rust mail client core: a new crate `kutup-mail-client`.**
   - What moves into it:
     - the key lookup and trust rules of `keys.ts` / `keyList.ts`;
     - the send plan of `sendDraft` / `protection.ts`;
     - opening a stored message;
     - the readable fields of a message;
     - sealing folder and label names.
   - It is written against the same JSON fixtures as the TypeScript tests,
     so the two can't drift.
   - The native Mail apps use it later through `kutup-client-ffi`.
   - The web app stays on TypeScript in this plan. Moving it onto the crate
     (WASM) is a later choice, and the fixtures keep the two in step until
     then.
3. **The protocol libraries:**
   - IMAP parsing: `imap-codec` / `imap-types` (MIT or Apache-2.0,
     standalone).
   - The IMAP server state (sessions, selected mailbox, UIDs, IDLE queues,
     held EXPUNGE) is our own, following Gluon's design (MIT, so it may be
     ported with attribution).
   - Stalwart's `imap_proto` (AGPL-3.0 or SEL) fits Kutup's AGPL licence,
     but it is tied to Stalwart's `types`, `utils` and `trc` crates.
   - SMTP: `smtp-proto` (Stalwart's, Apache-2.0 or MIT).
   - MIME: `mail-parser`, which the server already uses, and `mail-builder`
     for the PGP/MIME envelopes. Both are checked against the web app's
     output with fixtures.
4. **What it speaks:**
   - **IMAP:** Gluon's set (IMAP4rev1, IDLE, UNSELECT, UIDPLUS, MOVE, ID,
     STARTTLS, AUTH=PLAIN), plus SPECIAL-USE and LITERAL+.
     CONDSTORE/QRESYNC come later: they save bandwidth only, and Proton
     has neither.
   - **SMTP:** submission with STARTTLS and AUTH PLAIN/LOGIN.
5. **Mailboxes, as Proton maps them:**
   - Inbox, Drafts, Sent, Starred (`\Flagged`), Archive, Spam (`\Junk`),
     Trash, All Mail (`\All`, can be hidden), Scheduled, Snoozed;
   - folders under `Folders/` (three deep, as Mail nests them) and labels
     under `Labels/`.
   - Combined mode by default; split mode (one login per address) is an
     option.
   - Shared mailboxes (groups) come in phase B5.
6. **IMAP actions become Mail's own:**
   - `\Seen`, `\Flagged`, MOVE and COPY become `PATCH /api/v1/mail/messages`;
   - `\Deleted` + EXPUNGE moves to Trash, and deletes for good in Trash or
     Spam, as Proton and the web app do;
   - CREATE, RENAME and DELETE of folders and labels seal the names and
     write through the account head, as the web app does. A head that
     can't vouch for itself makes them fail, with nothing written.
7. **Local storage, encrypted throughout (better than Gluon):**
   - **Cache files:** each decrypted message is kept in a file under the
     profile's data directory, written with Kutup's block AEAD. Every
     block has its own nonce and is bound to its index and to the
     message's id, which fixes Gluon's two flaws.
   - **The index:** SQLite (`rusqlite`, bundled) holds mailboxes, UIDs,
     flags, message ids and sizes. What Proton keeps readable on disk
     (envelopes, subjects, addresses) is sealed per row.
   - **SEARCH:** works on decrypted headers in memory.
   - **The key:** a key under the CLI's device key (keychain). No keychain,
     no bridge: the daemon refuses to start rather than fall back to an
     unencrypted store, as Proton's does.
8. **The app password: shown once, stored only as a hash.**
   - 16 random bytes (base64url), per account (per address in split mode);
   - kept as Argon2id; `setup` and `password --reset` show it once and make
     a new one;
   - an app that loses it gets a new one rather than reading the old one
     back.

   This differs from Proton: a store that never holds the password can't
   leak it.
9. **TLS before login.**
   - IMAP and SMTP listen on `127.0.0.1` only. Each offers STARTTLS, and
     there is an implicit-TLS port too.
   - LOGIN and AUTH are refused before TLS (Proton accepts them).
   - One self-signed ECDSA P-256 certificate per install, exportable with
     `cert export`.
   - The ports are chosen at `setup`: the first free from 1143 / 1025, as
     Proton's, then kept. A taken port at start is an error that names it.
10. **Sync:**
    - The full list first, then the change feed, polled every 15 s while
      the daemon runs, and at once on an app's NOOP or IDLE start.
    - The cursor is saved after the changes are applied locally.
    - Resync rebuilds the index with new UIDVALIDITYs, as Proton does on a
      refresh. Apps then download again, which is the IMAP way to say
      "start over".
    - The server is authoritative, with no merge: an IMAP write calls the
      API first, and the local change commits only if it succeeds.
11. **APPEND:**
    - to Drafts: the drafts API;
    - to Sent, within 90 s of a matching SMTP send: the server's sent copy
      (Proton's hash);
    - anywhere else: the new import route.
    - What fails to import is kept in a local "Not imported" mailbox
      (Proton's "Recovered Messages").
12. **SMTP sending:**
    - The From must be one of the account's addresses. RCPT TO gives every
      recipient, Bcc included.
    - The app's MIME goes out unchanged. The send plan applies:
      - Kutup recipients get it end to end (`encrypt_split`);
      - outside recipients with a key get PGP/MIME, or Inline per their
        contact;
      - everyone else gets it readable;
      - the Autocrypt header and the signature follow the account's
        Encrypt and Sign defaults.
    - It sends at once: no undo-send hold, no scheduling (apps have
      neither).
    - The server's refusals map to SMTP replies: the sending limit and
      outside sending off to 4xx/5xx with Mail's own words.
13. **Server changes (all additive):**
    - `POST /api/v1/mail/messages/import`, Proton's import:
      - the client encrypts the whole message to its own primary key and
        sends the readable fields and the place;
      - the server checks that the key packet names that key, charges the
        pool, and refuses duplicates by Message-ID, as arrival does;
      - limits and rates are admin site settings (`mail.import_*`,
        `mail.rate.imports`).
    - A client type `mail-bridge`, so Sessions shows "Mail bridge" and it
      can be revoked on its own (`X-Kutup-Client: mail-bridge/<version>`).
      It is already in the baseline: a value of the `client_type` domain,
      with `cli`'s rules (a root session, never a fork child).

## Dependencies

Decided with the main session on 2026-11-19, for B1:

- **IMAP: `imap-next` =0.3.4 over `imap-codec` =2.0.0-alpha.10**
  (`imap-types` 2.0.0-alpha.8). All three are by the same author, licensed
  MIT OR Apache-2.0.
  - `imap-next` drives the protocol sans I/O: framing, literals, IDLE/DONE
    and AUTHENTICATE continuations. Those are the riskiest parts to write by
    hand. Our own code holds the IMAP state: mailboxes, UIDs, flags, SEARCH
    and the IDLE queues.
  - **Why an alpha pin:** `imap-next` is built on the 2.0 line of
    `imap-codec`, which is still in alpha; the stable 1.0 line has no server
    driver. Both are pinned exactly (`=`), so an update is always deliberate,
    and `cargo deny` and the four `--locked` roots check them.
  - **When to revisit:** when `imap-codec` 2.0 is stable, move to it (and to
    the `imap-next` release built on it), reading the changelog for any
    change to framing or literal limits.
  - **Fuzzing:** `fuzz/fuzz_targets/mail_bridge_imap.rs` feeds arbitrary
    bytes, cut at varying places, through a logged-in session with a mailbox
    selected. `kutup_mail_bridge::fuzzing` holds the same harness, and the
    crate's tests run it on 3,000 inputs on every `cargo test`. The first
    libFuzzer run (2 minutes, 148k executions) found nothing.
- **The index: `rusqlite` 0.32 with bundled SQLCipher** (vendored OpenSSL),
  as `kutup-chat-core`'s native store builds it, so there is one SQLite in
  the tree (MIT; SQLCipher BSD-3-Clause; OpenSSL Apache-2.0).
  - `deny.toml`'s RUSTSEC-2026-0459 note covers it: the bridge opens only
    the index file it wrote itself, under its own key.
  - The index is behind the crate's default `index` feature, so the fuzz
    build leaves it out.

## Phases

Each is its own pull request with its tests.

- **B0 `kutup-mail-client`:**
  - the key lookup and trust, opening a message, the send plan, the
    readable fields;
  - fixtures shared with `mail-core`'s TypeScript tests (keys.test.ts,
    protection/pgp tests), each run on both sides.
- **B1 read-only IMAP:**
  - LOGIN over TLS, LIST, SELECT/EXAMINE, FETCH, SEARCH, IDLE, NOOP;
  - the encrypted cache and index, the initial sync, the change feed;
  - `serve`, `setup` and `status`.
- **B2 writing over IMAP:**
  - flags, MOVE/COPY, EXPUNGE;
  - CREATE/RENAME/DELETE of folders and labels through the account head.
- **B3 SMTP:** sending with the send plan, refusals mapped to SMTP replies.
- **B4 APPEND:** drafts, the import route on the server, the Sent match,
  "Not imported".
- **B5:**
  - `install` / `uninstall` (systemd user unit, launchd agent, Windows
    task), split mode, shared mailboxes;
  - `cert export`, the Account app's "Desktop mail apps" page.

**Tests:**
- unit tests per crate, and the IMAP state machine tested as Gluon's is,
  against an in-memory backend;
- a live gate (`gate.sh live mail-bridge`): the real daemon against a lane
  stack, driven by `async-imap` and `lettre`, checked against what the web
  app's API shows (a send over SMTP read in the web app; a move in the web
  app seen over IDLE);
- a manual check with Thunderbird, Apple Mail and Outlook before each
  phase's merge, recorded in the PR.

## Out of scope

- A desktop GUI: it waits for the desktop apps.
- POP3: Proton has none.
- CalDAV and CardDAV: Kutup has no DAV ([`mail-parity.md`](mail-parity.md)
  and the standing rule).
- Calendar invitations through the bridge: they come with E4.
- SMTP tokens for direct submission: in Proton a separate business feature
  for custom domains; Bridge doesn't use them.

## Questions (answered 2026-11-19)

1. **The form:** a CLI subcommand now; a GUI with the desktop apps
   (decision 1).
2. **The client logic in Rust:** yes, `kutup-mail-client` with shared
   fixtures (decision 2), as the rule that crypto lives in Rust/WASM has
   it. The web app moves onto it through WASM later, minding Mail's WASM
   budget then.
3. **Stricter than Proton:** yes to both. The app password is shown once
   and stored as a hash (decision 8), and TLS comes before login
   (decision 9).
4. **The `mail-bridge` client type** goes into the W7 baseline now: W7 5b
   made `client_type` a domain, so it is one more value there. The import
   route comes with B4 (decision 13).
