# Mail (Phase C)

**Status:** C1 done; C2a–C2d done (2026-10-10): crypto, server, the app.
C2e (gates and docs) in progress; C2f later. Phase C of
[`../research/17-mail-calendar-contacts.md`](../research/17-mail-calendar-contacts.md),
after [`mail-address-keys.md`](mail-address-keys.md) (A) and
[`contacts.md`](contacts.md) (B).

## Goal

`name@kutup.dev` receives and sends mail. Mail from outside is encrypted to
the address key the moment it arrives (Proton's "zero-access"); mail between
Kutup users is end-to-end encrypted. Subject, addresses, dates and sizes stay
readable by the server (decision 1 of the design). Phase C has three parts:

| Part | Delivers |
|---|---|
| **C1. Infrastructure** (this plan in detail) | Stalwart in compose, inbound recipient check, LMTP receiver, encrypt-on-arrival, storage, pool accounting, DNS records except MX |
| **C2. Mail app** | `mail.kutup.dev`: folders, reading, compose and send (internal end-to-end, external over TLS through Stalwart), drafts, labels, search |
| **C3. PGP to the outside** (below) | Key lookup (WKD, Proton, keys.openpgp.org), PGP/MIME encrypt, sign and verify both ways, Autocrypt, key import and export; then the MX switch from Cloudflare |

## Stalwart 0.16: configuration is data

The design assumed a TOML configuration. Stalwart 0.16 (the current line)
replaced it: apart from a one-line `config.json` naming the data store,
every setting is a JMAP object in Stalwart's own database, changed through
`/jmap` or `stalwart-cli apply` with a declarative plan file
(`UPGRADING/v0_16.md` in the reference clone). Measured on the dev VM with
`stalwartlabs/stalwart:v0.16.23` and `stalwartlabs/cli:1.0.12`:

- A fresh server with `config.json` = `{"@type":"RocksDb","path":"/var/lib/stalwart/data"}`
  creates its defaults on first start. `STALWART_RECOVERY_ADMIN=user:secret`
  gives an administrator that `stalwart-cli` authenticates as.
- `stalwart-cli apply --stdin` takes one JSON object per line:
  `upsert` (matched on a field such as `name`), `update` for singletons,
  `reconcile` (makes the type's objects exactly the plan's, removing others)
  and `create` for actions. Re-applying is idempotent.
- Secrets in the plan can name an environment variable
  (`{"@type":"EnvironmentVariable","variableName":"…"}`), so the plan is a
  static file in the repository and the secrets stay in `.env`.
- Applied settings take effect after an `Action` `ReloadSettings`, sent as
  a second `apply` (inside one plan it runs before `reconcile` removals).
- The chain works end to end: SMTP on 25 → the RCPT hook (bearer token, the
  recipient under test is the **last** entry of `envelope.to`) → LMTP to the
  relay route, byte-exact, with Stalwart's `Authentication-Results`,
  `Received-SPF` and `X-Spam-*` headers prepended. A rejected recipient gets
  the hook's 550 and nothing else changes.
- Memory: about 220 MiB idle with the spam filter's rules loaded.

## Transport

```text
outside MTA --25--> Stalwart --hook (HTTP, bearer)--> kutup /internal/mail/rcpt : accept, 550 or 452
                        '--LMTP :2424 (AUTH PLAIN)--> kutup receiver --> encrypt to address key --> S3 + Postgres
```

- **Stalwart** runs unmodified from `docker-compose.mail.yml`, image pinned,
  data in a volume. Its plan, `stalwart/plan.ndjson`, sets:
  - a `Domain` for the server name with `allowRelaying` (no Stalwart
    accounts: the hook alone decides who exists) and sub-addressing off
    (Kutup handles `name+tag@` itself);
  - an `MtaRoute` `Relay` named `kutup`, protocol `lmtp`, to the backend,
    with AUTH credentials from the environment, and the outbound strategy's
    route sending local domains to it;
  - an `MtaHook` for the `rcpt` stage with a bearer token, failing
    temporarily (4xx) when Kutup does not answer;
  - listeners: SMTP on 25 and the management HTTP on 8080 (internal only);
    IMAP, POP3, submission, Sieve and HTTPS removed;
  - logging to stdout; message size limit 50 MB (Proton's is 25 MB for
    attachments);
  - the `mx` route IPv4 only (`ipLookupStrategy: v4Only`) and the HELO name
    `mail.<domain>`, for C2's sending.
- A `stalwart-setup` service applies the plan and then the reload on every
  start (`stalwart/setup.sh`). Its image is Alpine with the CLI's static
  binary, since the CLI image has no shell to fill the plan's domain and
  host name in. It also gives Stalwart (uid 2000) a readable copy of the
  ACME certificate, which certbot leaves root-only, and checks daily for a
  renewed one. Stalwart's management port is never published.
- **The hook** (`POST /internal/mail/rcpt`, not routed by nginx, bearer
  token compared in constant time) accepts a recipient when its address,
  after lower-casing and dropping a `+tag`, is a Kutup address on this
  server with a primary key, and the account is active and has room in its
  pool. Unknown addresses get `550 5.1.1`, a full pool `452 4.2.2` (the
  sender keeps retrying, so the mail arrives once space is freed).
- **The receiver** speaks LMTP (RFC 2033) on an internal port and requires
  AUTH PLAIN with the shared secret. It answers per recipient, as LMTP
  requires, and re-checks each one: the hook ran before the size was known.

## Encrypt on arrival

For each accepted recipient, the receiver:

1. parses the headers with `mail-parser` (Stalwart's own parser, MIT or
   Apache-2.0) for the readable fields: subject, from, to, cc, reply-to,
   date, Message-ID, In-Reply-To, References and the attachment count;
2. encrypts the **whole message, byte-exact**, to the address's primary
   key: OpenPGP, SEIPD v1 with AES-256, binary (`kutup-crypto`
   `mail_key::encrypt_binary`). The client decrypts it and parses MIME
   itself; the original bytes stay available for export and the future
   IMAP bridge;
3. stores the ciphertext under `mail/{user}/{message}` and inserts the row,
   charging the pool, in one transaction under the pool lock. A failed
   insert removes the object; the sweep removes objects whose insert never
   ran.

Plaintext never reaches Postgres, S3 or a log. The parsed header values are
the readable fields; nothing from the body is kept (no snippet: C2 shows
snippets from the client's decrypted cache, as Proton does).

- **Duplicates:** a message whose Message-ID this address already received is
  acknowledged and not stored twice (mailing-list copies, retries after a
  lost LMTP reply).
- **Spam:** Stalwart's spam filter scores inbound mail. The receiver files
  the message under Spam when Stalwart's topmost `X-Spam-Score` header
  starts with `spam`; only the first occurrence counts, since a sender can
  add a lower one.
- **Threads:** a message joins the thread of a message it names in
  `In-Reply-To` or `References`, else starts a new one.

## C2: the Mail app

Proton's web client (`kutup-references/WebClients`, `applications/mail`)
is the model; where Kutup differs, the reason is given.

### Format: the whole message, encrypted

Every stored message is one RFC 5322 message, attachments inside,
encrypted as one OpenPGP message, as mail from outside already is (C1).
Proton encrypts the body and each attachment separately; Kutup keeps one
format for all mail, so export and the future IMAP bridge get the original
bytes and the client parses MIME the same way whatever the source.

- **Between Kutup users** the sender's browser builds the MIME message,
  signs it with the sender's address key and encrypts it once
  (`mail_key::encrypt_split`): one data packet, plus a key packet for each
  Kutup recipient and one for the sender's own copy, Proton's
  `BodyKeyPacket`s. The server stores `key packet || data packet` per
  recipient, checking each key packet names the recipient's current primary
  key (409 when it changed). A copy names no other recipient's key, so Bcc
  stays hidden. The message itself has no Bcc header; the sender's row keeps
  the Bcc list as readable metadata (Proton's `BCCList`).
- **To outside recipients** the browser also sends the plaintext MIME, over
  TLS; the server checks its From is the sender, hands it to Stalwart's
  submission port (Stalwart signs DKIM and sends over IPv4), and drops it.
  Proton hands the server the body's session key instead; sending the
  plaintext alongside is simpler and the server sees the same. Outgoing
  volume per account is limited (recipients per hour and per day).
- **Readable fields** for the list come from the sender's browser (subject,
  addresses, ids); From is always the authenticated sender. The reading
  pane shows the decrypted message's own headers and its signature check.
- **Protection**, the padlock: received from outside `zero_access`; between
  Kutup users `end_to_end`, verified when the signature checks against the
  sender's key list; sent to outside "sent with zero-access encryption".

### Drafts

A draft is a message row in Drafts: its body (the message without
attachments) encrypted to the sender's own key and replaced on each save,
debounced 2 s as Proton does. Each attachment is uploaded once, as an
encrypted MIME part (`mail_draft_attachments`), so saving the text never
re-sends files. Sending assembles the final message in the browser and
deletes the draft.

### Server API

- `PATCH /api/mail/messages` `{ ids, seen?, starred?, folder? }`, at most
  500; `DELETE` permanently, only from Trash, Spam and Drafts (elsewhere the
  client moves to Trash first, as Proton does).
- `GET /api/mail/counts`: unread and total per folder.
- `GET /api/mail/threads/{id}`: a thread's messages, oldest first.
- `GET /api/mail/messages?folder=&q=`: `q` searches subject and addresses
  (readable); bodies are searched in the browser later (C2f).
- Drafts: `POST /api/mail/drafts`, `PUT /api/mail/drafts/{id}`, attachments
  under `/api/mail/drafts/{id}/attachments`.
- `POST /api/mail/send`: multipart with the metadata, the data packet, the
  key packets and, for outside recipients, the plaintext.

### The app at `mail.<domain>`

- Proton's layout: a sidebar (Compose, Inbox, Drafts, Sent, Starred,
  Archive, Spam, Trash, unread counts), the list (sender, subject, date,
  star, attachment icon, unread weight, multi-select toolbar: read/unread,
  star, archive, spam, trash, move) and the reading pane (the thread,
  header with recipients and padlock, attachments, reply, reply all,
  forward).
- HTML mail is sanitised with DOMPurify (no scripts, forms or styles that
  load anything) and shown in a sandboxed iframe; remote images are blocked
  until the reader allows them for that message (Proton proxies them; Kutup
  has no proxy yet, so blocking is the safe default); links open with
  `noopener noreferrer`. MIME is parsed with postal-mime.
- **People:** senders and recipients are named as in Contacts, with an
  avatar (photo or initials) in the list and the header. A name opens a card
  on hover or click (Proton's recipient dropdown): the address to copy, New
  message, View contact or Save to contacts, and their other mail; for a
  Kutup user (their key list, which their account signed, names the account,
  so a forged From does not count) also Chat and Call, which open their
  conversation in Chat, Call asking before it rings (`?call=audio`). A message
  from (or, in Sent, to) someone not in Contacts shows a banner with Save to
  contacts, dismissable per address on the device. Saving opens a dialog in
  Mail, not a new tab: a new contact named as their mail named them, or the
  address added to someone already there; "Add more details in Contacts"
  opens the full editor.
- **Dark theme and quotes:** plain text, and HTML that sets no background and
  no dark text colour (most personal mail, and Kutup's own), take the
  theme's colours; HTML that paints itself stays on white, as Proton shows
  it. The quoted earlier message at the end of a reply (`>` lines, Gmail,
  Proton, Apple and Outlook quotes, a closing blockquote) is folded behind a
  "…" button, with no script (`<details>`).
- The composer, docked like Proton's: From, To, Cc, Bcc with contact
  suggestions, subject, a rich-text editor (Tiptap) sent as HTML with a plain
  text alternative, attachments, autosave, Meta+Enter to send and Esc to
  close. Maximised, it dims the app behind it (Gmail's full-screen compose):
  a click on the dimmed app or Esc docks it again, and Tab stays inside.
- **Working the list** (Proton, Gmail): Shift-click chooses a range,
  Ctrl/Cmd-click one more, Shift+↑/↓ extends the choice; a right click acts on
  the chosen rows when it lands on one, else on that row (read/unread, star,
  move, delete for good, the sender's other mail, copy, Save to contacts);
  rows can be dragged onto Inbox, Starred, Archive, Spam or Trash; every move
  has Undo in its toast.
- **Shortcuts** (Proton's, listed with `?`): J/K or ↑/↓ next and previous,
  X choose, Ctrl/Cmd+A all, Esc clear or close, N new, `/` search, `*` star,
  R read, U unread, I inbox (or not spam), A archive, S spam, T or Delete
  trash, Ctrl/Cmd+Backspace delete for good in Trash, Spam and Drafts. They
  act on the chosen rows, else the open conversation.
- New mail is fetched every 30 s while the app is open; web push later.

### C2 slices

1. **C2a crypto** (done): `encrypt_split`, key packet checks, WASM
   `openMailMessage` and `encryptMailMessage`, vectors.
2. **C2b server** (done): the API above, Bcc and draft attachments in migration
   085, Stalwart's submission listener in the plan, sending limits.
3. **C2c reading** (done): `@kutup/mail-core` and the app: list, counts, thread,
   MIME, safe HTML, attachments, actions, search, shortcuts.
4. **C2d writing** (done): composer, drafts, send, reply and forward, "Add to
   contacts" for new correspondents.
5. **C2e gates and docs:** browser specs (two Kutup users, end to end), the
   mail gate extended to sending outside, docs.
6. **C2f later:** body search in the browser (research 15 and 16), labels
   and custom folders, Trash and Spam emptied after 30 days, web push.

## C3: PGP with the rest of the world

End-to-end mail with every OpenPGP user (Proton, Thunderbird, GnuPG,
Mailvelope) in both directions. Tuta uses its own protocol, so mail with
Tuta stays TLS on the way and zero-access at rest; its password-protected
messages work as for anyone. Proton's behaviour, from its web client and
help pages (checked 2026-10-10):

- Proton's **servers** look keys up for outside addresses through Web Key
  Directory and keys.openpgp.org (`core/v4/keys/all`, `API_KEY_SOURCE` WKD
  and KOO) and **encrypt to them by default** as PGP/MIME, signed, even when
  the user has not pinned the key (`encryptToUntrusted`). So Proton users
  write to `name@kutup.dev` end to end once Kutup's WKD answers and Kutup
  opens PGP/MIME.
- Proton verifies signatures only with keys its user pinned or Proton's own
  (`verificationPreferences.ts`: fetching WKD to verify would tell the
  sender's domain the mail was read). Mail from Kutup therefore shows as
  "PGP-encrypted and signed" until the Proton user trusts the key, which
  Proton offers when the mail carries it: an Autocrypt header (read, Level 1,
  `prefer-encrypt=mutual`) or an attached `.asc`.
- Proton's own users' keys come from HKP at
  `https://mail-api.proton.me/pks/lookup?op=get&search=<address>`; proton.me
  serves no WKD (both methods answer 404 or nothing). Domains whose MX is
  Proton's (`*.protonmail.ch`) are asked the same way.
- Proton signs inside the encryption (one OpenPGP message), sends no
  protected headers, and builds the RFC 3156 wrapper on its server.

### How Kutup does it

- **Finding keys** is the server's job, as at Proton (a browser cannot read
  other domains' WKD): `GET /api/mail/keys?email=` answers outside
  addresses too, from WKD (advanced, then direct), Proton's HKP for Proton
  domains and MX, then keys.openpgp.org (verified addresses only). Each key
  must carry a valid self-signed user ID for the address and a usable
  encryption subkey (`kutup-crypto` checks). Lookups go through the SSRF
  guard, are cached for an hour, and are rate-limited.
- **Trust:** a contact's pinned key (the signed contact summary's
  `pinnedKeys`) wins; otherwise a found key is used to encrypt, as Proton
  does, and marked "found through WKD" (or Proton, keys.openpgp.org).
  Signatures verify only against pinned keys; a key that comes with a
  message (Autocrypt, `.asc`) is offered for pinning.
- **Sending** is built in the browser: PGP recipients get RFC 3156
  `multipart/encrypted` (inner message signed and encrypted in one OpenPGP
  message, armored), To and Cc in one message, each Bcc in their own (key
  IDs would name them). The server receives these ready-made messages and
  submits each, never their plaintext; only recipients without keys get the
  plaintext message. Every outgoing message carries an Autocrypt header with
  the sender's key.
- **Receiving:** mail that arrives PGP-encrypted to the address key
  (`multipart/encrypted`, or an inline PGP message) is marked `end_to_end`
  on arrival and opened twice in the browser (the zero-access layer, then
  the sender's); `multipart/signed` and cleartext-signed mail is verified.
  Padlocks follow Proton's texts: "PGP-encrypted message", "…and signed",
  "…from verified sender", "Sender verification failed".

### C3 slices

1. **C3a crypto:** outside key checks, multi-recipient armored encryption
   with signature, detached and cleartext signature verification, the
   Autocrypt key; vectors and GnuPG interop both ways.
2. **C3b server:** outside key lookup (WKD, Proton HKP, keys.openpgp.org),
   PGP packages in `POST /api/mail/send`, `end_to_end` on arrival for PGP
   mail. The server checks each package is the same message and holds an
   encrypted OpenPGP message, but cannot check it is encrypted to the right
   key (a pinned key is known only to the browser). Submissions go one by
   one, the plaintext first: a refusal of the first fails the send, a later
   one marks its recipients `failed`.
3. **C3c app:** per-recipient protection in the composer, PGP/MIME
   building, Autocrypt, opening and verifying PGP mail, pinning keys to
   contacts. Done as follows. The composer shows a lock per recipient
   (Kutup, a pinned key, a found key with its source, a pinned key that no
   longer works); a pinned key that no longer works stops the send rather
   than sending in clear, and so does a failed lookup. PGP/MIME encrypts the
   body entity (`buildBody`) to the recipients' keys and the sender's own,
   signed inside; the header fields, subject included, stay readable as at
   Proton. Every message (plaintext, PGP/MIME, and between Kutup users)
   carries `Autocrypt: addr=…; prefer-encrypt=mutual; keydata=…`. Reading
   opens `multipart/encrypted` (also when signed in a second
   `multipart/signed` layer), inline PGP, `multipart/signed` over the exact
   signed part, and cleartext signatures; header fields repeated inside the
   encrypted part win (protected headers). A key from an Autocrypt header or
   an attached key file is offered for trusting when it is usable for the
   sender and is not the pinned one ("sent a different public key" when it
   would replace it).
4. **C3d gates:** the mail gate with a GnuPG correspondent (a WKD server and
   a sink that decrypts with `gpg`), both ways; a manual check against a real
   Proton account, documented. Done: `scripts/test-mail-inbound.sh` makes
   Dave's key with GnuPG and serves it from a WKD stand-in (the backend's
   `MAIL_TEST_KEY_ORIGIN` on a test stack); the live test finds it, sends
   PGP/MIME (refusing plaintext dressed as PGP and plaintext nobody needs),
   and receives Dave's GnuPG reply as `end_to_end`, opening and verifying
   it; the gate checks the copy at the sink is PGP/MIME, DKIM-signed, has no
   plaintext, and that GnuPG opens it with a good signature. The Proton
   check is [`docs/test/mail-proton.md`](../test/mail-proton.md).
5. **C3e:** key import and export; then the MX switch from Cloudflare
   (DNS, done by the operator). Done: Account → Settings → Encryption keys
   creates a new key (it becomes primary; older keys stay to open older
   mail, which Mail now tries them for), imports one from an OpenPGP secret
   key file (Kutup's export, Proton's, GnuPG's; Curve25519 with one user ID
   for the address, unlocked in the browser and sealed like a generated
   key), exports one locked with a passphrase (iterated and salted S2K,
   AES-256; Proton's file name), and marks keys obsolete or compromised
   through `PUT /api/mail/addresses/{id}/key-list`; Mail no longer trusts
   signatures by a key its owner marked compromised. WKD gains the advanced
   method on `openpgpkey.<server name>`, which GnuPG and Proton ask first
   whenever the name resolves. The MX switch checklist is in
   [`../self-hosting.md`](../self-hosting.md) ("Moving MX to Kutup"). For
   kutup.dev (checked 2026-10-10): the website Worker on `kutup.dev` must
   pass `/.well-known/openpgpkey/` through (it answers 404 today), and
   `openpgpkey.kutup.dev` (resolved by the wildcard record) needs the
   certificate; MX is still Cloudflare Email Routing, with its SPF include.

## Sending safety

Decided 2026-10-10. One account sending spam can get the server's IPv4
address blocklisted, and then nobody's mail arrives, so before the MX switch:

1. **Limits** on outside recipients: 100 an hour and 500 a day; 50 a day in an
   account's first week (most abuse comes from new accounts); per-account
   overrides by an administrator. Mail between Kutup users is never limited.
2. **Bounces:** Stalwart's delivery reports come back as ordinary mail; one
   that names a message the account sent outside counts (a forged report
   naming someone else's message does not). 10 in a day that are also 10 % of
   what was sent pause sending; 5 and 5 % flag the account.
3. **Spam:** a submission Stalwart refuses as spam flags the account; three in
   a day pause it. Stalwart's filter is not switched on for outgoing mail:
   tried with a reject score, its rules weighed the connection more than the
   content (an ordinary message scored like GTUBE, which it does not know) and
   refused ordinary incoming mail too. Content scoring of outgoing mail needs
   another filter; recipients' providers judge it meanwhile.
4. **Administrator:** Administration → Mail sending: counts per account (never
   content), pause, resume, own limits, flags; in the audit log.
5. **Role addresses:** `postmaster@` and `abuse@` reach the administrator;
   those and `hostmaster`, `mailer-daemon` and `security` cannot be registered.
   Google Postmaster Tools and Microsoft SNDS before the MX switch.

Migration 087: `mail_sending_policies` (overrides, pause, flag) and
`mail_sending_events` (bounces and spam refusals, kept 30 days).

## Data (migration 085)

- `mail_messages`: id, user id, address id, thread id, folder (`inbox`,
  `drafts`, `sent`, `archive`, `spam`, `trash`), `seen`, `starred`,
  protection (`zero_access` now; `end_to_end` with C2), object key,
  ciphertext size, received at, sent at (the Date header), subject,
  from (address and name), to, cc and reply-to (JSON lists, bounded),
  Message-ID, In-Reply-To, References (bounded), attachment count.
  Indexes for the folder list by date, the thread, and Message-ID per
  address.
- Mail counts in the one storage pool: `mail_bytes` in the reconcile sums
  and "Mail" on the Storage page.
- Deleting an account deletes its mail rows and the `mail/{user}/` prefix.

## Configuration

| Variable | Use |
|---|---|
| `MAIL_INBOUND_TOKEN` | the hook's bearer token and the LMTP password; mail is off without it |
| `MAIL_LMTP_BIND` | the receiver's address, default `0.0.0.0:2424` when mail is on |
| `MAIL_HOSTNAME` | Stalwart's name (`mail.<domain>`), matching the IPv4 PTR |
| `STALWART_ADMIN_SECRET` | the setup service's administrator password |
| `MAIL_SMTP_PORT` | where port 25 is published, default `25` (the gate uses a loopback port) |

The backend publishes nothing new; Stalwart publishes port 25 only.

## Reading (for C2)

`GET /api/mail/messages?folder=` lists a folder's readable fields, newest
first, and `GET /api/mail/messages/{id}/content` returns the stored OpenPGP
message (`docs/api.md`, "Mail"). C2 adds moving, flags, deletion and
sending.

## DNS (except MX)

Documented in [`../self-hosting.md`](../self-hosting.md): `mail.<domain>` A
record and PTR, SPF `v=spf1 ip4:<address> -all`, the DKIM records Stalwart
generates (read from its `Domain.dnsZoneFile`), DMARC `p=none` with reports,
MTA-STS and TLS-RPT. The MX switch waits for C3.

## Slices

1. **C1a crypto and data:** `encrypt_binary` with vectors; migration 085;
   the pool, reconcile and Storage page entries; account deletion.
2. **C1b receiver:** the hook endpoint and the LMTP server with
   encrypt-on-arrival, threads, spam and duplicates, and the two read
   endpoints; unit tests for the protocol and the headers.
3. **C1c Stalwart:** `docker-compose.mail.yml`, plan, setup service,
   `.env.example`, self-hosting DNS; the gate below.

## Tests and gates

- `kutup-crypto`: `encrypt_binary` round trip and vectors (Rust and WASM).
- Server: LMTP state machine (pipelining, dot-stuffing, per-recipient
  replies, AUTH required, size limit), header extraction (encoded words,
  Turkish, missing fields), hook decisions, duplicates, threads, spam.
- `scripts/test-mail-inbound.sh` (`tests/mail_inbound_live.rs`): a real
  Stalwart and backend; mail to an account through port 25 with a `+tag`
  and capitals, an unknown address refused at RCPT, a duplicate not stored
  twice, a reply joining its thread, the stored message decrypting with the
  account's key to the bytes sent, another account refused, the pool
  charged; then, as administrator, a full pool deferring (452), a disabled
  account refusing (550) and a deleted account leaving no mail rows or
  objects.
