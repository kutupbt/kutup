# Mail, Calendar and Contacts on one account

**Status:** design, October 2026. Nothing here is built yet. Decisions marked
"decided" were made by the product owner on 2026-10-09; the rest is proposal.
Entries in [`../roadmap.md`](../roadmap.md) will track the work once slices
start.

**Method:** a deep-research pass (Proton's support pages and security posts,
Proton WebClients, Stalwart's source, EteSync), the reference repositories in
`kutup-references/` (WebClients, stalwart, tutanota, roundcubemail,
snappymail), measurements on the production host, and Kutup's own design
documents ([`../architecture.md`](../architecture.md),
[`../plans/unified-profile.md`](../plans/unified-profile.md),
[`16-browser-storage-architecture.md`](16-browser-storage-architecture.md)).

## Goal

Mail, Calendar and Contacts join Drive, Office, Photos, Maps and Chat as
apps of **one Kutup account**, the way Proton Mail, Calendar and Drive share
one Proton account:

- one sign-in, one recovery phrase, one master key;
- one storage pool ([`../architecture.md`](../architecture.md), "Storage
  Layer");
- one address, `name@kutup.dev`, that is at once the mail address, the Chat
  address and the Drive sharing address;
- one address book, used by every app that names a person;
- apps on their own origins, `mail.kutup.dev`, `calendar.kutup.dev` and
  `contacts.kutup.dev`, receiving the session by the existing fork.

## Decisions (2026-10-09)

1. **Readable fields follow Proton.** Mail subjects, sender and recipient
   addresses, dates and sizes, and contact display names and email addresses
   are readable by the server. Bodies, attachments, and every other contact
   field are encrypted. This keeps standard mail working and lets the server
   thread, sort, autocomplete and filter spam.
2. **Build order:** address keys on the account and a unified Contacts app
   first, then Mail, then Calendar. Calendar needs Mail for invitations to
   people outside Kutup.
3. **Mail leaves the server directly** from `mail.kutup.dev`, with SPF, DKIM,
   DMARC, MTA-STS and a slow warm-up. No third-party relay sees mail.
4. **Groups are per recipient, not MLS.** Group mail, shared calendars and
   contact groups encrypt to each member. See the Chat groups decision
   recorded with the roadmap.

## What Proton does (the model)

Verified in the research pass (sources in the closing section):

- **Between Proton users**, bodies and attachments are end-to-end encrypted
  with OpenPGP. Subject, sender, recipients and time are encrypted at rest but
  readable by the server (`Message.ts` in WebClients returns them in clear).
- **Mail from outside** arrives over TLS. The server reads it once and stores
  it encrypted to the recipient's public key ("zero-access", not end-to-end).
- **Mail to outside** is TLS-only by default. End-to-end options are OpenPGP
  (key from WKD, key servers or pasted) and password-protected messages.
- **Search** of bodies runs on the client: an index encrypted in IndexedDB
  (`packages/encrypted-search`). Without it, search covers metadata only.
- **Calendar** splits each event: title, description, location and attendees
  encrypted and signed; times, recurrence, UID and status signed but readable;
  alarms readable so the server can remind. Each calendar has its own key,
  whose passphrase is encrypted to each member's address key
  (`calendarKeys.ts`). Invitations travel as iTIP over mail (iMIP).
- **Contacts** split each vCard: `FN`, `EMAIL`, `UID` and key preferences
  signed and readable; everything else encrypted and signed; `CATEGORIES`
  readable (`contacts/constants.ts`, `contacts/encrypt.ts`).
- **IMAP, SMTP, CalDAV and CardDAV** for third-party clients go through a
  bridge on the user's machine, never a server endpoint that sees plaintext.

Tuta differs mainly by encrypting subjects and sender names too, and by not
using OpenPGP. Kutup follows Proton (decision 1), which keeps PGP
interoperability.

## One account: address keys

Today everything derives from the master key: the account authority, the
incarnation, the Drive X25519 keypair and the Drive signing key, under fixed
HKDF labels. `AccountManifestV1`, signed by the account authority, publishes
those public keys and the device list. Contacts see a gray shield on first
contact, a green one after a QR comparison, and a red one on an unexpected
change ([`../architecture.md`](../architecture.md), "Account identity").
Other apps get the master key and the Drive private key through the session
fork (`frontend/packages/session/src/fork.ts`).

Mail adds **address keys**, one OpenPGP key per address:

- **Format.** OpenPGP v4 keys with Ed25519 signing and X25519 encryption
  subkeys. These are what Gmail-adjacent tools, Thunderbird, GnuPG and
  Proton read today. Version 6 keys (RFC 9580) can follow once the outside
  world reads them.
- **Random, not derived.** Address keys are generated randomly, not derived
  from the master key. An address can be added, rotated or removed (aliases,
  later custom domains) without touching the master key, and an OpenPGP
  fingerprint depends on a creation time that a derivation would have to fix
  forever. The private key is stored in a typed `AccountEnvelopeV1` under the
  master key with a new purpose, `MailAddressPrivateKey`, bound to the
  address.
- **Bound to the account.** Each address key's fingerprint goes into the
  signed `AccountManifestV1`. A Kutup user who has verified you in Chat or
  Drive therefore also has your mail key verified, with no second
  verification step. This is lighter than Proton's Key Transparency and uses
  what Kutup already has.
- **Published.** The server serves Web Key Directory (WKD) at
  `openpgpkey.kutup.dev` (or the direct method under `kutup.dev`) so that
  outside PGP users find `name@kutup.dev`'s key, and attaches an Autocrypt
  header to outgoing mail.
- **Owned by Rust.** Kutup's crypto rule is that `kutup-crypto` owns every
  persistent format. OpenPGP therefore comes from a Rust library compiled into
  `kutup-crypto` and its WASM build. The candidate is **rPGP** (the `pgp`
  crate): pure Rust, MIT/Apache-2.0, used by Delta Chat, WASM-friendly.
  Sequoia is the alternative, but its LGPL licence and native crypto backends
  fit worse. Before adoption, record the choice and its audit history in
  [`../cryptographic-dependencies.md`](../cryptographic-dependencies.md).

The fork list grows by `mail`, `calendar` and `contacts`. Each new app opens
its address keys from the master key it already receives.

## Contacts: one address book

Today "people" live in three places: Chat's relationship state (accepted,
blocked, message requests, held by the chat client and its backup), Drive's
profile-key exchange (`drive_profile_keys`, `/api/drive/people`), and the
encrypted profile from the unified-profile plan. None of them is an address
book you can edit.

**Contacts becomes the one address book.** Each contact is one person with
any number of addresses:

| Part | Fields | Server sees |
|---|---|---|
| Signed, readable | contact id, display name, email addresses, Kutup addresses (`user@server`), groups | yes (decision 1) |
| Signed, readable key data | pinned account authority and incarnation for Kutup users; pinned OpenPGP fingerprints and preferences (encrypt, sign, scheme) for outside people | yes |
| Encrypted and signed | phone numbers, postal addresses, organisation, birthday, notes, photo, custom fields | no |

- **Encryption.** The encrypted part is a vCard 4.0 (RFC 6350), so import
  and export are lossless. It is sealed with a contacts key wrapped by the
  master key, like the browser stores of
  [`16-browser-storage-architecture.md`](16-browser-storage-architecture.md),
  and signed with the account authority.
- **One identifier.** For a Kutup user, the mail address and the Chat and
  Drive address are the same string, `name@kutup.dev`, because the Chat
  address is `username@server` and the server name is `kutup.dev`. A contact
  therefore joins Mail, Chat and Drive with no mapping table. A federated
  user (`ali@other.example`) is the same: one address for every app.
- **Verification is shared.** The shield on a contact is the existing
  account-authority pin. Verifying someone in Chat verifies them in Mail and
  Drive. For outside PGP users the contact pins their key fingerprint
  instead.
- **Everyone uses it.** Chat's people list, Drive's share picker, Mail's
  recipient field and Calendar's invitee field all read the same contacts
  through one API, with autocomplete on the readable fields. Chat keeps its
  relationship state (accepted, blocked), keyed by address. The contact adds
  your own name for the person and their other details.
- **Created automatically, never silently.** Accepting a Chat request,
  sharing a folder or replying to mail offers "Add to contacts". Nobody is
  added without the user's action, so an address book never fills with every
  sender.
- **Groups** are a readable `groups` field (Proton's `CATEGORIES`). A group
  message or invitation is encrypted to each member separately.
- **Server.** A `contacts` table holds the readable columns, the encrypted
  card and its signature, a revision for edit conflicts, and is charged to
  the storage pool. CardDAV for phones comes later through the bridge.

## Mail

### Transport: Stalwart beside Kutup

```text
outside MTA --25--> Stalwart (container) --RCPT hook (HTTP)--> Kutup: does this address exist? room in the pool?
                         |                                      <-- accept / reject
                         '--LMTP--> Kutup mail receiver --> encrypt to the address key --> R2 + Postgres
Kutup client --HTTPS--> Kutup server --submission 587--> Stalwart --25 + DKIM--> outside MTA
```

- **Stalwart** runs unmodified in its own container under a compose profile
  `mail`. It handles SMTP, queues and retries, TLS, DKIM signing, DMARC,
  MTA-STS and TLS reports, and inbound spam filtering. Kutup keeps the keys,
  the mailbox, the storage pool and the product. Kutup talks to it only over
  SMTP, LMTP and HTTP, which keeps the two programs separate under the AGPL.
  Both are AGPL-3.0, and Stalwart runs unmodified. A legal check before
  launch is still advised.
- **Inbound.** Stalwart's MTA Hooks call Kutup at the RCPT stage to accept or
  reject each recipient (unknown address, account disabled, pool full). The
  DATA-stage hook cannot carry the message itself, because its body passes
  through a lossy UTF-8 conversion in Stalwart (`from_utf8_lossy`). Accepted
  mail is therefore delivered to Kutup over LMTP, byte-exact.
- **Encrypt on arrival.** The Kutup receiver reads the readable fields
  (subject, from, to, cc, date, message id, size), encrypts the whole message
  to the recipient's address key as PGP/MIME, and stores the ciphertext in R2
  and the row in Postgres in one step. Plaintext never touches Postgres, R2
  or a log. Mail that arrives already encrypted to the user's key is stored as
  it came.
- **Between Kutup users**, mail never goes through SMTP. The sender's client
  encrypts to the recipient's address key and the server files it directly,
  so it is end-to-end encrypted.
- **To outside recipients** the client encrypts with OpenPGP when it has their
  key (from WKD, a key server, Autocrypt or the contact). Otherwise it sends
  the message to the server, which hands it to Stalwart over TLS. The server
  sees that message once in passing, exactly as with Proton.
  Password-protected messages come later.
- **Sent and draft copies** are encrypted to the sender's own key.
- **Bounces and reports** arrive as ordinary inbound mail.
- **Abuse.** Kutup limits each account's outgoing volume and new-recipient
  rate, so one compromised account cannot burn the IP's reputation.

### Storage, folders and search

- Folders and labels as Proton has them: Inbox, Sent, Drafts, Archive, Spam,
  Trash, plus user labels. The server stores which message has which label
  and its flags (read, starred). Those are metadata, readable like the
  subject.
- Every message, attachment and draft is charged to the one storage pool and
  appears on the Storage page as "Mail".
- Search: subject, sender and date on the server (they are readable);
  bodies in the browser through the encrypted index planned in
  [`15-client-side-search-index.md`](15-client-side-search-index.md) and
  [`16-browser-storage-architecture.md`](16-browser-storage-architecture.md).

### Deliverability and DNS

Checked on 2026-10-09:

| Item | State |
|---|---|
| IPv4 `95.217.238.230` | PTR `mail.kutup.dev` ✓; on none of 12 blocklists checked (Spamhaus, Barracuda, SpamCop, SORBS, PSBL, Mailspike, UCEPROTECT 1–3, Manitu, GBUdb, DroneBL) |
| IPv6 `2a01:4f9:c014:4d29::1` | the box's sending address; **no PTR** yet. Hetzner has `mail.kutup.dev` on `…4d29::` instead. Add rDNS for `::1` in the Hetzner console |
| Outbound port 25 | **blocked** (IPv4 and IPv6 to Gmail time out; 465, 587 and 53 open). Hetzner lifts it on a limit request from accounts older than a month with a paid invoice, case by case |
| `mail.kutup.dev` A/AAAA | direct to the box (not proxied) ✓ |
| MX `kutup.dev` | Cloudflare Email Routing. Switch only once Mail is ready |

Before the MX switch:

1. Hetzner limit request to unblock outbound 25, stating personal mail for
   the server's own users, low volume, no bulk.
2. IPv6 PTR for `::1`. Until then, or if Gmail is unhappy, send over IPv4 only.
3. SPF `v=spf1 ip4:95.217.238.230 ip6:2a01:4f9:c014:4d29::1 -all`.
4. DKIM: RSA-2048 and Ed25519 selectors, signed by Stalwart, rotated yearly.
5. DMARC: `p=none` with aggregate reports, then `quarantine`, then `reject`.
6. MTA-STS (`mta-sts.kutup.dev`) and TLS-RPT. DANE later, with DNSSEC on
   Cloudflare.
7. Register the domain with Google Postmaster Tools and Microsoft SNDS.
8. Warm up: Kutup's own staff accounts first, low daily volume, watch the
   reports before opening Mail to everyone.

### Third-party clients

IMAP and SMTP for Thunderbird, Apple Mail or Outlook come through a Kutup
bridge on the user's machine, after the web app works. The bridge is a Rust
program sharing `kutup-crypto`, likely the same program as the CalDAV/CardDAV
bridge and the Drive WebDAV idea in [`06-webdav-support.md`](06-webdav-support.md).

## Calendar

- **Event split** as Proton: title, description, location, conference link
  and attendees encrypted and signed; UID, start and end with time zone,
  recurrence rule and exceptions, organiser, sequence, status and
  transparency signed but readable; alarms readable so the server can send
  reminders.
- **Calendar keys.** Each calendar has its own key. Its secret is encrypted
  to each member's address key, so sharing a calendar re-encrypts one secret,
  not every event.
- **Free/busy** comes from the readable times. Kutup users can see each
  other's busy blocks if allowed. Nothing else is shown.
- **Invitations.** Between Kutup users they are end-to-end encrypted. With
  outside people they are iTIP over mail (`METHOD:REQUEST`, `REPLY`,
  `CANCEL`), with a random token per outside invitee to match replies.
  Invitations from Google or Outlook are encrypted on arrival like any mail.
- **Reminders** are sent by the server, from the readable alarm times, as web
  push and optionally email. Web push is on the Chat roadmap.
- **Chat meetings** get real scheduling, recurrence and email invitations
  here, replacing today's `.ics` download.
- **CalDAV** for phones comes through the bridge, with import and export in
  iCalendar (RFC 5545).

## Apps and screens

- `contacts.kutup.dev`: a list with search, a person page (addresses, keys
  and shield, details), groups, and vCard import and export.
- `mail.kutup.dev`: Proton's layout, with the folder and label sidebar, a
  conversation list and a reading pane, plus compose, keyboard shortcuts and
  a padlock showing how each message was protected (end-to-end, zero-access,
  PGP-signed). Roundcube and SnappyMail serve as reference for MIME edge
  cases.
- `calendar.kutup.dev`: day, week and month views, an event editor and
  invitation replies.
- All three use the shared session, storage meter, app switcher and design
  system of the other apps. Every string is in English and Turkish.

## Phases

| Phase | Delivers | Depends on |
|---|---|---|
| **A. Address keys** | rPGP in `kutup-crypto` (and WASM) with test vectors; address key generation at sign-up and an upgrade for existing accounts; manifest binding; WKD; the list of your addresses and keys in Account | — |
| **B. Contacts** | `contacts` table and API; Contacts app; vCard import and export; Chat, Drive and Account pickers reading it; shield shared with Chat | A (for key fields) |
| **C1. Mail infrastructure** | Stalwart in compose (profile `mail`), RCPT hook and LMTP receiver, encrypt-on-arrival, DNS except MX, Hetzner port-25 unblock, IPv6 PTR | A |
| **C2. Mail app** | read, labels, compose and send (internal end-to-end, external TLS), storage-pool accounting, encrypted search | C1, B |
| **C3. PGP to the outside** | WKD and Autocrypt lookup, PGP encrypt, sign and verify, key import and export; then the MX switch from Cloudflare | C2 |
| **D. Calendar** | calendars and keys, events, sharing, invitations over Mail, reminders | C2 |
| **E. Bridges and more addresses** | IMAP/SMTP and CalDAV/CardDAV bridge; aliases; custom domains; password-protected mail | C3, D |

Each phase follows the usual gates: Rust and WASM vectors for every new
format, browser specs, and the two-server gate where federation is touched.

## Open questions

- **Sizing.** How much memory does Stalwart with its spam filter take beside
  the current stack on 2 vCPU and 4 GB? Measure on the dev VM; move mail to
  its own small VPS if it does not fit.
- **Spamhaus.** Public resolvers are refused by Spamhaus, so the blocklist
  check must be repeated from the box's own resolver before launch.
- **Federated Kutup servers.** Mail between two Kutup servers could skip SMTP
  and travel over the existing signed federation, end-to-end. This is a
  natural extension but not needed for the first version.
- **Mobile.** iOS does not allow a background local bridge, so native apps
  need built-in mail and calendar sync rather than the bridge.
- **Spam filtering of encrypted mail.** Filtering runs in Stalwart before
  encryption on arrival. User feedback ("this is spam") is metadata the server
  sees; content-based learning on stored mail is not possible.

## Sources

- Proton: [encryption explained](https://proton.me/support/proton-mail-encryption-explained),
  [what is encrypted](https://proton.me/support/what-is-encrypted-within-protonmail),
  [content search](https://proton.me/support/search-message-content),
  [calendar security model](https://proton.me/news/protoncalendar-security-model),
  [calendar invitations](https://proton.me/blog/proton-calendar-event-invitations),
  [contacts](https://proton.me/support/proton-contacts),
  [key transparency](https://proton.me/support/key-transparency).
- WebClients (in `kutup-references/`): `packages/shared/lib/interfaces/mail/Message.ts`,
  `packages/encrypted-search/lib/esIDB/`, `packages/shared/lib/calendar/constants.ts`,
  `packages/shared/lib/calendar/crypto/keys/calendarKeys.ts`,
  `packages/shared/lib/contacts/constants.ts`, `packages/shared/lib/contacts/encrypt.ts`.
- Stalwart (in `kutup-references/`): `crates/smtp/src/inbound/hooks/`;
  [MTA Hooks](https://stalw.art/blog/tags/mta-hooks/).
- EteSync: [etesync-dav](https://github.com/etesync/etesync-dav) (the bridge pattern).
- Hetzner outbound SMTP policy, quoted in
  [Discourse Meta](https://meta.discourse.org/t/ports-blocked-hetzner-cloud-server/225146)
  and [sudonix](https://sudonix.org/post/8489). Re-check Hetzner's current FAQ
  before filing.
