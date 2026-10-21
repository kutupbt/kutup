# Kutup Chat protocol V1

**Status:** normative pre-v1 protocol

Kutup Chat provides Direct Chat, Note to Self, private MLS groups, encrypted
profiles, signed account/device manifests, federated ciphertext delivery and
contacts-only sealed sender, encrypted media, and continuous account-local
display-history backup. A capability is advertised only when its complete local
and federated path is configured.

V1 has no global key-transparency log, witness, auditor or monitor. It uses a
stable account self-authority, complete hash-linked manifest history, durable
TOFU pins, and face-to-face safety-number verification. This is deliberately
simple for open-source self-hosting and makes no false claim that first contact
is independently authenticated.

## 1. Implementation ownership

- `libsignal-protocol` v0.97.2 owns PQXDH, Triple Ratchet, sealed-sender
  envelopes and sender/server certificate primitives for Direct Chat.
- OpenMLS 0.8.1 owns the RFC 9420 group state machine and TreeKEM.
- `hpke-rs` 0.6.1 owns RFC 9180 outer delivery encryption for MLS.
- `kutup-chat-proto` owns strict public DTOs, canonical signing bytes, suite
  identifiers and byte limits.
- `kutup-chat-core` owns account-manifest verification, durable pins,
  libsignal/OpenMLS orchestration, atomic persistence and safety numbers. It is
  the canonical Rust implementation used by browser WASM and native FFI.
- Browsers own authenticated HTTP/WebSocket plumbing only. JavaScript cannot
  approve a key, manufacture a verified roster, or mutate ratchet/MLS state.

Kutup does not fork or copy selected pieces of libsignal or OpenMLS. Their
types do not cross Kutup's public API boundary.

## 2. Accounts, addresses and conversation types

A person is their **account**: the pair `{server, accountId}`, where
`accountId` is the permanent random id the server minted with the account
(Signal's ACI; docs/plans/account-ids.md). It survives renames, password
changes, recovery and an administrator's reset, and ends only with the
account. It is the key of every durable Chat record: the direct
conversation (`{"kind": "direct", "account": {"server", "accountId"}}`,
key `direct:aci:<uuid>@<server>`), the libsignal `ProtocolAddress` name,
the local stores, contact state (a block follows the person), sent
transcripts (`peer`, Signal's `destinationServiceId`), mentions, group
actors, view-once senders, invite join requests, the attachment ledger and
backup records. Where one string is needed it is `aci:<uuid>@<server>`,
which no address parser accepts and which is never shown to a person.

An **address**, canonical lowercase `username@server`, is a handle: what a
person types to find someone and what the app shows. It can change (a
rename) and, once freed, belong to someone else, so no durable record keys
on it or carries it. A client resolves an address to an account once, when
a person starts a conversation; everything after uses the account. A bare
username is refused wherever an address is decoded; a client qualifies what
a person types (a bare name means the home server) before it reaches Chat.
Display names and avatars are encrypted, mutable and non-unique; they are
never routing keys.

V1 conversation types are:

- Direct: two accounts, libsignal session per device pair.
- Note to Self: the local account addressed to itself, using Direct Chat and
  authenticated linked-device synchronization.
- Group: RFC 9420 MLS, 1-256 accounts and at most ten active devices per
  account, therefore at most 2,560 independent leaves.

Million-account announcement channels are a different pull/fan-out protocol.
They are never oversized MLS groups. Calls and group calls are separate.

## 3. Typed suites and primitive portfolio

Separate registries remain separate because their keys, formats and migration
boundaries differ. Kutup-owned constructions reuse a small primitive palette:
SHA-256, HKDF-SHA256, Ed25519, X25519 and XChaCha20-Poly1305 where the governing
standard permits it.

| Registry | V1 value | Construction |
|---|---:|---|
| `DirectChatSuiteId` | 1 | pinned libsignal PQXDH + Triple Ratchet |
| `AccountIdentitySuiteId` | 1 | Ed25519 self-authority/share signing + X25519 Drive key |
| `MlsCipherSuiteId` | `0x0003` | X25519 / ChaCha20-Poly1305 / SHA-256 / Ed25519 |
| `AnonymousMlsDeliverySuiteId` | 1 | RFC 9180 X25519 / HKDF-SHA256 / ChaCha20-Poly1305 |
| `SealedSenderSuiteId` | 1 | pinned libsignal sealed sender |
| `FederationAuthProfileId` | 1 | Ed25519 HTTP message signatures |

Unknown values fail closed. There is no in-band “try an older suite” fallback.
The preproduction clean break expires at the first stable `v*` tag; afterward,
registry read/migrate/reject lanes provide backward-compatible evolution.

## 4. Account identity and active devices

The client derives purpose-separated keys from the 32-byte account master key:

```text
HKDF-SHA256(
  salt = "kutup/account-identity/v1\0",
  IKM  = masterKey,
  info = purpose-specific label
)
```

Purposes are self-authority Ed25519, Drive HPKE X25519 and Drive named-share
Ed25519. Keys are never reused across purposes.

An account may have 1-10 active devices. `CHAT_MAX_ACTIVE_DEVICES` may lower
the local limit but cannot exceed ten. Device wire IDs remain 1-127 and are not
reused as an assertion of active-device capacity.

### 4.1 Web installation continuity

A browser installation is a cryptographic device, not merely a login session.
IndexedDB/site-data loss, a private window, a new browser profile or storage
eviction therefore creates a new device key tuple. Password-derived account
authority proves that the account may authorize the tuple; it does not make
old per-device libsignal ciphertext decryptable by the replacement.

Clients provide explicit active-installation review, last-seen information and
revocation. Chat display history is protected separately by the always-on,
account-local E2EE backup described in [`chat-backup.md`](chat-backup.md).
A recovered installation verifies and restores the signed encrypted base plus
its ordered event tail; it never restores device keys, Direct ratchets, MLS
epochs, mailbox cursors or outboxes. Device-to-device history transfer and its
relay are not supported.

The backup-specific trust boundary and residual fresh-device rollback risk are
normative in
[`chat-backup-security-threat-model.md`](chat-backup-security-threat-model.md).

`AccountManifestV1` contains:

- canonical account and account-identity suite;
- authority key ID and public key;
- incarnation ID derived from that authority;
- account-scoped Drive public keys;
- sequence and exact predecessor hash;
- issued-at value;
- 1-10 strictly ordered complete device records;
- Direct Chat identity/registration data and optional MLS credential/delivery
  keys for each device;
- Ed25519 signature by the account self-authority.

The signing representation is domain-separated deterministic binary encoding
with fixed-width integers and big-endian length-prefixed UTF-8/byte fields.
JSON is transport only.

## 5. Manifest history and trust

The server stores the mutable manifest head and every complete accepted
manifest in one transaction. Every manifest device must exactly match a
registered key tuple and all account keys remain stable. Registration rows not
selected by the authority-signed manifest are pruned in that transaction, so
an interrupted registration cannot permanently block the account or gain
manifest membership. A normal update increments by one and names the exact
previous hash.

Clients persist history by `(peer, incarnation, sequence)` and the current
anti-rollback pin in one transaction. First observation above sequence 1 or a
skipped update fetches every missing sequence in pages of at most 64. Missing,
duplicate, reordered, conflicting, malformed or invalidly signed history does
not clear the gap.

Trust states are:

- gray / `Tofu`: a valid stable account signature and complete history are
  pinned, but the users have not independently compared keys;
- green / `Verified`: the user scanned the exact face-to-face safety QR;
- red / `Quarantined`: rollback, equivocation, stable-key contradiction, or a
  signed replacement incarnation blocks new sends/shares.

A replacement is stored separately from the retained pin with its complete
history. The browser and native bindings derive the expected QR in Rust. Only
an exact scan atomically promotes the candidate and keeps the old incarnation
history. A network status label or blind “verify” button cannot promote trust.

The first quarantine of a pinned identity, and each new identity offered in
its place after that, writes a local-only `safetyNumberChanged` line into the
peer's thread (one per change; its id names the pinned and the offered
incarnation), as Signal shows the change in the conversation. Native clients
also get a `SafetyNumberChanged` engine event.

The safety number is Signal's fingerprint (version 2 of libsignal's
`NumericFingerprintGenerator`, 5200 iterations of SHA-512 per side): each
side's stable id is the account's `AccountRef` bytes (server and permanent
account id) and its identity key the raw Ed25519 account authority key; the
two 30-digit halves show as twelve five-digit groups, the lower half first.
The QR is `kutup://verify/v3/` and the base64url `CombinedFingerprints`
protobuf, this side's half first, so a scan is compared with the other side's
code. It names no address, as Signal's names only the ACI and identity key: a
rename keeps the number, and another account under a name (a new incarnation,
a new holder of a released name) has another authority and so another number.
The derivation lives in `kutup-crypto` (`safety_number`), so Drive and the CLI
show the same number.

Chat also keeps to the account's synced identity pins, the list Drive, Office,
Photos and the CLI share (docs/plans/drive-identity-pins.md). Right after the
engine accepts a contact's identity, and before anything is sealed to them:

- a first-seen contact whose account the list holds with another authority is
  quarantined (the send fails with a trust error), not trusted on first use;
- an authority the list holds for another account is quarantined, and never
  written for this one;
- an authority the list holds as verified (compared in person in another app
  or on another device) becomes `Verified` here;
- a contact new to the list is added to it, and one verified here is written
  as verified.

The list never lifts a quarantine: only an exact scan does, and its result is
written back as verified. Chat's own in-person verification also outranks a
list entry that was only accepted elsewhere without comparing. The web and
native engines read and store the list (`GET/PUT /api/user/identity-pins`)
with the key derived from the master key at start-up.

Relevant routes:

| Route | Meaning |
|---|---|
| `POST /api/chat/device` | restart-safe device registration |
| `PATCH /api/chat/device/{deviceId}` | rename the account-private device label without changing its identity |
| `DELETE /api/chat/device/{deviceId}` | revoke one device |
| `POST/GET /api/chat/backup` | provision or inspect the encrypted history archive |
| `POST/GET /api/chat/backup/segments` | append or restore ordered encrypted event segments |
| `POST /api/chat/backup/bases` | stage a client-compacted encrypted base |
| `GET /api/chat/backup/bases/{id}` | stream the currently committed encrypted base |
| `PUT /api/chat/backup/manifest` | atomically CAS-commit a signed restore point |
| `POST /api/chat/backup/media/copy` | outer-encrypt an existing Chat-media ciphertext for history |
| `POST/GET /api/chat/backup/media[/{id}]` | upload or lazily restore backup-media ciphertext |
| `POST /api/chat/backup/media/reconciliation` | page the exact next restore-point media reference set |
| `POST /api/chat/manifest` | publish exact next signed manifest |
| `GET /api/chat/accounts/{accountId}/manifest?server=` | current local/federated manifest |
| `GET /api/chat/accounts/{accountId}/manifest-history?server=` | bounded complete history page |
| `GET /api/fed/chat/accounts/{accountId}/manifest` | signed-federation current manifest |
| `GET /api/fed/chat/accounts/{accountId}/manifest-history` | signed-federation history page |

## 6. Direct Chat and Note to Self

Every device publishes one libsignal identity key, signed prekey, last-resort
ML-KEM prekey, and bounded one-time EC/PQ prekeys. Session establishment and
steady-state ciphertext are generated only by libsignal. A bundle is unusable
until its exact device identity matches the accepted account manifest.

### Prekeys

Registration publishes the signed EC prekey and the last-resort ML-KEM prekey
as id 1, with a pool of one-time EC and ML-KEM prekeys. The client tops
each pool back up to its target whenever the server reports it below the low
watermark (`PUT /api/chat/keys`); replenished ids are random.

The signed and last-resort pair is used by every first message that finds no
one-time key left, so it is replaced on a schedule, as Signal does
(`kutup-chat-core/src/prekey_rotation.rs`):

- **Every two days** (checked at start, on each reconnect and hourly while
  open) the client generates a new pair, signs both with the
  identity key, and uploads it in the same `PUT /api/chat/keys` request as
  any top-up. The pair and the upload are staged in one transaction before
  the request, so a client that crashes or goes offline mid-upload sends the
  same pair again; it becomes current only when the server accepts it.
- **A replaced pair is kept** for as long as a first message made with it can
  still sit in the mailbox: the server's `mailboxRetentionDays` (from
  `GET /api/chat/capabilities`) plus seven days for clocks, late delivery
  and devices that were offline. A server that keeps mail for ever (`0`)
  means replaced pairs are kept for ever too.
- **A used one-time ML-KEM prekey is deleted** 14 days after a message first
  used it, the same grace as a used one-time EC prekey, so a late copy of
  that message still reads. Only the last-resort key is ever reused, and its
  reuse is guarded against replay by the base keys already seen.

libsignal's records carry no usable time, so a small rotation record kept
beside the keys, and written in the same transactions, says which key is
current, which is staged, which are retired and since when. A device made
before rotation existed starts that record on its first check and rotates
two days later.

Plaintext is padded before encryption with Signal's scheme: the content, one
`0x80` byte, then zeros up to a multiple of 160 bytes
(`kutup-chat-core/src/padding.rs`). A receiver refuses anything that is not a
whole number of blocks ending in that terminator.

Sending is multi-device fan-out. Each destination device has an independent
ratchet. A client-generated UUID `sendId` and durable outbox make retries
idempotent. A 409 device mismatch causes a bounded manifest/bundle refresh; a
manifest contradiction stops rather than encrypting to an untrusted key.

Note to Self is a self-addressed Direct conversation. Sent-message sync to
linked devices is authenticated and identified. It never uses anonymous
delivery or creates an MLS group.

Every content document, of every kind, carries a stable sender-generated
`messageId` inside the ciphertext; content without it does not decode. For a
sent message it equals the durable transport `sendId` (a UUID), and the engine
refuses to send content whose `messageId` differs. A text reply adds an optional canonical non-nil UUID `replyTo`
that references that logical ID. The reference uses the same encrypted content
shape for Direct, Note to Self and MLS; it is never copied into mailbox,
attachment or federation metadata. Clients resolve it only within the current
conversation and show an unavailable placeholder when bounded local history no
longer contains the target.

A reaction is a hidden `reaction` content operation encrypted by the same
Direct, Note-to-Self or MLS channel. Its typed body contains only a canonical
non-nil `targetMessageId`, one V1 emoji from `👍 ❤️ 😂 😮 😢 🙏`, and an
`active` boolean. Setting, replacing and removing a reaction therefore reveal no reaction
metadata to either homeserver. Clients never render these operations as
messages or conversation previews. Within the target conversation each reactor
account has one last-writer-wins reaction register per message. Clients retain
the latest operation for each `(targetMessageId, reactor account)` by the
deterministic tuple `(sentAt, seq, senderDeviceId, operation ID)`, discard that
account's older emoji, then aggregate active reactors by the surviving emoji.
An inactive latest operation clears that account's reaction. Targets absent
from bounded local history are ignored without affecting the encrypted
operation history.

Edits and deletions use a hidden `messageMutation` operation with a canonical
`targetMessageId`, an `edit` or `delete` discriminator, and replacement text
only for edits. An edit is bounded to 16,000 characters. A client applies the
operation only when its authenticated account actor is the original target
author; another group member cannot mutate someone else's message. Valid edits
use the same deterministic operation ordering as reactions. A valid delete is
an irreversible display tombstone and wins over every edit regardless of
arrival order, preventing a stale linked device from resurrecting deleted
content. Mutation operations remain encrypted history and never appear as
messages or previews. Deleting an attachment tombstones its descriptor in the
conversation; it does not claim cryptographic erasure of ciphertext already
retained or downloaded under the Chat-media policy.

Delivery and read state use hidden `receipt` operations. One operation contains
an exact `delivered` or `read` state and 1–64 unique canonical logical message
UUIDs, all inside the Direct or MLS ciphertext. Direct clients automatically
emit a delivery receipt after successful local decryption. Read receipts are
disabled by default and emitted only when the user enables the per-browser
privacy setting, the conversation is selected, and the page is visible. MLS
groups emit only this opt-in `read` state: automatic group delivery receipts
would consume a claimed one-time KeyPackage for every recipient device and
double the anonymous delivery rate of an active group. `read` subsumes
`delivered`. A receipt affects only existing outgoing targets in the same
conversation and is attributed to its authenticated account actor; MLS views
aggregate recipient accounts rather than devices. Receipt operations are never
rendered or used as conversation previews, and no homeserver or MLS ordering
authority receives the target IDs or state in plaintext.

Typing state uses a hidden `typing` operation whose strict body contains only
an `active` boolean. It is accepted only from an already accepted contact or an
authenticated MLS roster member, so a stranger cannot create/reopen a message
request with typing traffic. The operation is live-only product state: it is
excluded from messages, previews, linked-device sent transcripts and exported
history, and expires six seconds after local receipt. An ordinary authenticated
application message from the same account clears it immediately. Browsers emit
at most one active operation every four seconds while a visible composer stays
non-empty; expiry replaces an explicit stop operation so one MLS typing burst
does not consume a second set of claimed one-time KeyPackages. Stale durable
typing outboxes are discarded after ten seconds rather than delivered late.
The homeservers and MLS ordering authorities see only the ordinary padded
ciphertext delivery, never the typing kind or state.

### Renames

A thread is keyed by the peer's account, so a username change keeps it. The
app follows a direct peer to the address its server says it has now along
the peer's own rename chain (signed by the authority pinned for them,
extending the chain the pin list holds), and for each rename issued since
the list first met them writes a local-only `peerRenamed` line (`{previous,
current, sequence}`), once per rename: its id names the account and the
sequence. A few peers are checked per pass, newest conversations first, at
most every five minutes each. Someone who later takes the old name is
another account and another thread.

### Which devices a message is taken from

An identified envelope is read only when its sender device is in the
verified signed manifest of the authority pinned for the sender account, as
for a sealed one (whose certificate must also match it). An unknown sender's
manifest is fetched and verified first. A session-starting (PreKey) message
must carry that device's identity key. This account's own devices are checked
against the manifest this device verified under its own authority, never one
a server offers first. Otherwise a server could start a session in a pinned
person's name, or as a "new own device" (a transcript or a contact control),
with a device of its own. A refused envelope is kept for retry, not acked.

### Unreadable messages and session repair

A Direct envelope from a known sender device (named on an identified
envelope, or proven by a sealed envelope's certificate) that cannot be
decrypted because the session is missing or the ciphertext does not
authenticate is not retried for ever. In one transaction the receiver:

- sets the current session with that device aside, at most once an hour per
  device and only if there is one. The old state is kept as a previous
  session, so messages already on their way under it still decrypt;
- writes a local-only `undecryptable` record in the message's place, in an
  open conversation only (accepted, or a request this side sent). A stranger
  cannot make records or requests appear this way. The server passes each
  envelope's `sendId` along; with it there is one record per unreadable
  message, carrying that id. Without it (a row stored before the server did
  so) there is one record per reset, which nothing replaces;
- marks the envelope for acknowledgement.

It then sends the peer a hidden `sessionControl` message
(`{action: "refresh", sendIds}`), in an open conversation only. Encrypting it
starts a fresh session from a newly fetched bundle, and the peer adopts that
session by decrypting it; everything either side sends afterwards is
readable. `sendIds` (at most 64 per message) names what could not be read.

The peer answers from its sent history. For each named message that it sent
to that account and that was history on both sides, it sends a hidden
`resend` wrapping the original content whole, under a new transport id; for
the rest (a typing indicator, a receipt it no longer has, an id it never
sent) it sends one `sessionControl` `{action: "unavailable", sendIds}`;
for a message it did send but cannot send again (too large to wrap, one
stored before the size check below) it sends `{action: "lost", sendIds}`. A
message is sent again at most once an hour per peer. Both once-an-hour
limits (resetting a session, sending a message again) are kept in the device's
store, not in memory, so a reload or a second tab does not start them over.
The receiver handles a
`resend` as the message inside it: it is stored and shown with its original
id and sender time, so it takes its place in the conversation, and the
record that waited for it is removed. A device that had read the message the
first time drops the copy. `unavailable` removes the waiting records and
shows nothing (a typing indicator can be the unreadable thing, and a device
that does have the message still sends it, which then arrives as a
message). `lost` keeps the record but no longer waits: it says the message
could not be recovered and asks the reader to have it sent again.

The request can be lost (a send that fails, a key fetch that fails, a tab
closed before it went out), so the waiting records themselves drive it:
every ten minutes, and at once after a reload, each record waiting longer
than two minutes is asked for again, at most every half hour. A record still
waiting after a week is given up on and shown as lost.

`sessionControl` and `resend` travel like `typing`: never history on the
sending side, never a linked-device transcript, and they cannot open or
reopen a message request. If one cannot be delivered it stays queued without
blocking the conversation.

The `sendId` on an envelope is not authenticated. A server that changes it
can make a device ask for, and receive again, a message of the same sender
it already has (which it drops) or one that does not exist; it cannot make a
peer send anything that peer did not already send to this account.

Within the hour, further unreadable envelopes from the same device do not
reset the session again. The interval is kept in memory, so a reload allows
one more. An envelope that fails for another reason (an untrusted identity,
an unknown suite, a malformed envelope, a sealed envelope whose outer layer
or certificate does not verify) is not repaired this way and stays in the
attention journal as before.

A send reuses the device list it last fetched and verified for an account
for as long as it has a current session with every listed device under the
identity key that list served; it then takes no keys from the server. The
server still checks the exact device set on every send, so a list that went
stale is corrected by the usual `409` amendment, which fetches again. Two
things drop a held list earlier: the server's `devicesChanged` frame (this
account's own devices changed), the list being an hour old (it is then
fetched and verified again, so a server that withholds the `409` cannot keep
a revoked device in longer than that; each fetch takes one of the account's
one-time prekeys), and a message whose `deviceListVersion`
(the sender's signed manifest sequence, a top-level field inside the
ciphertext of every ordinary Direct message) is above the sequence this
device has pinned for that sender. The server never learns who an account's
contacts are; a contact hears of a change with the next message it reads.

### Size of a direct message

The server takes at most 64 KiB of content per envelope. A direct message
must fit not only as itself but also as what may carry it again: a
`resend` (sent after a session repair, so as a sealed first message, the
largest kind) and the sent transcript to the account's other devices.
Encryption adds at most about 2.1 KB, so before anything is queued the
sender checks that the message, its `resend` wrapping (with the longest ids
it can carry) and its transcript each stay within 64 KiB less 2,560 bytes,
rounded down to the padding step, and refuses the message otherwise ("too
large to send"). The web composer limits direct-message text to 30,000
bytes, well inside that, and says so. A message stored before this check
that is too large to wrap is not sent again; its notice waits as before.

### Disappearing-message V1 contract

A hidden E2EE `disappearingTimer` operation changes the duration for future
messages in one conversation. Its strict body is either an integer
`durationSeconds` or an omitted value meaning off. V1 accepts 30 seconds
through 30 days. Direct sends use the normal linked-device transcript and MLS
sends use the normal authenticated application path, so the timer is never a
homeserver setting.

Every affected `text` or `attachment` also repeats the chosen duration as the
authenticated top-level `expiresAfterSeconds` field. This per-message binding
is authoritative: delayed, duplicated or reordered timer controls cannot
retime a message, disabling a timer cannot resurrect old content, and an edit
does not restart the countdown. Reactions, receipts, mutations, typing and
control messages cannot carry the field.

The sender counts from its durable local creation time. The recipient counts
from the first time the message is actually visible on any of their devices,
not from mailbox receipt or background decryption. That device emits a hidden
`disappearingExpiryStart` operation containing the conversation, target
message UUID and absolute start time through the normal encrypted
Note-to-Self linked-device path. The earliest authenticated start wins across
the recipient's devices. Alice's sender countdown and Bob's recipient
countdown are intentionally independent, and this account-internal operation
is independent of optional read receipts and is never sent back to Alice.

An unread offline recipient therefore still receives the full viewing window.
Once viewing has started, continuous history backup and browser-device
replacement preserve the absolute deadline and cannot restart or extend it.
At expiry the client removes the local plaintext, derived
previews/reactions/receipts and releases any unsaved Chat-media reference.
Replies remain as independent messages but show their expired target as
unavailable. Expiry does not emit a deletion control to the other account or
reveal a timer to a server.

This is cooperative recipient-side deletion, as in other E2EE messengers. It
does not prevent screenshots, notification capture, a modified recipient,
external backups or a user copying plaintext before expiry, and the UI must not
claim otherwise. Saved-to-Drive copies are new recipient-owned objects and do
not expire with the Chat message.

### Message extras

A visible message (text or attachment) may carry, beside its body, Signal's
DataMessage extras as authenticated top-level content fields — the same way
as `expiresAfterSeconds`, so an older reader keeps the message and ignores
them, while a present but malformed field rejects the whole message on every
receive path (Direct, sync transcript, MLS):

| Field | On | Rule |
| --- | --- | --- |
| `mentions` | text | 1–64 ordered, non-overlapping `{start, length, member}` ranges in UTF-16 units of the text; `member` an account `{server, accountId}`. Readers show "@" and the member's current name. |
| `linkPreview` | text | `{url, title, description?, image?}`: an `https://` URL that appears in the text, title ≤ 300 and description ≤ 1000 characters, an optional JPEG/PNG/WebP image ≤ 24 KiB inline. Made by the sender; recipients never contact the site. |
| `forwarded` | text, attachment | `true` or absent. A forwarded attachment is a new upload, since the original is on its sender's server. |
| `viewOnce` | photo or video attachment | `true` or absent. Sent without a thumbnail; never enters the backup; the recipient opens it once, and closing the viewer sends `viewOnceOpened` to their own devices. Like Signal's, this is a courtesy against casual re-viewing, not protection from a screenshot or a modified client. |
| `sticker` | photo attachment | `{emoji?}`: the attachment is a WebP or PNG of at most 512 KiB, not view-once. Readers draw it without a bubble and may save it to their own stickers. |

### Calls

`call` carries one 1:1 call signal (`CallSignalV1`: offer, answer, ICE
batch, hang-up, busy) and is ephemeral like `typing`: never history, never
a linked-device transcript, dropped from the outbox after 60 s, suppressed
from people not accepted, refused in Note to Self and in MLS. `callLog` is a
local-only record of a finished call, like `groupUpdate`, `undecryptable`,
`safetyNumberChanged` and `peerRenamed`:
none of them is ever sent, and one that arrives from anyone is refused. `groupCall`
(`GroupCallBody`) announces a group call starting or ending, MLS only. See
[`chat-calls.md`](chat-calls.md).

### Polls

Three content kinds, in Direct chats and groups alike:

- `poll` (visible): `{question, options, allowMultiple?}`, a question of
  1–200 and 2–10 distinct options of 1–100 characters, on one line each. It
  may carry `expiresAfterSeconds` like a text.
- `pollVote`: `{targetMessageId, options}`, the voter's current choice as
  ascending distinct indexes; empty takes the vote back. Each voter's latest
  vote (sender order) counts; a vote naming a missing option, or several in
  a single-choice poll, is ignored.
- `pollTerminate`: `{targetMessageId}`; only the poll's author ends it, and
  votes after that do not count. It shows as "Alice ended the poll".

A receiver refuses a poll-kind message whose body does not validate; votes
and ends are purged with their poll.

### Locations

`location` (visible), in Direct chats, Note to Self and groups: a place sent
once, `{lat, lon, label?}` — finite degrees within ±90 and ±180 (clients
send at most six decimals), and an optional label of 1–100 characters on one
line. It may carry `expiresAfterSeconds` like a text; a receiver refuses a
body that does not validate. Each viewer's own map settings decide how it is
shown (docs/plans/maps.md): a map drawn in the browser, or the coordinates
with "Open in maps". Choosing the place (tapping a map, the device's
location, or a city found in a list searched on the device) sends nothing
anywhere. Live location is a separate channel, not a stream of these.

### Live locations

A live location is a short-lived stream on the sharer's server, not a series
of messages (docs/plans/maps.md "Live location"):

- `liveLocation` (`LiveLocationBody`): `{shareId, generation, server,
  streamId, key, readCapability, untilMs}`. Generation 1 starts the share,
  is visible, and may carry `expiresAfterSeconds`. Each later generation (a
  new stream and key, every hour and as soon as anyone leaves a group) is
  hidden and folded into the share; it counts only from the same sharer in
  the same conversation and never extends `untilMs`. A share lasts at most
  8 hours.
- `liveLocationStop`: `{shareId}`, the sharer ending it early (hidden).
- The stream holds only the latest update: a fixed 88-byte
  `LiveLocationUpdateV1` (`kutup-crypto/src/live_location.rs`, vector
  `liveLocation`), XChaCha20-Poly1305 under `key`, authenticating the
  stream id and a counter that must increase. The server stores hashes of
  the write secret (kept by the sharing device) and of `readCapability`,
  the update and times; no account, conversation or position.
- Readers poll every 10 s while the message is on screen; a reader on
  another server reads through its own (`/api/fed/chat/live-locations`).
  After a new generation the old stream is deleted, so someone who left has
  a key to nothing new.
- The sharing device writes about every 15–30 s while moving and every
  3 minutes while still, only while its tab is open (browsers give pages no
  location in the background).

### Account state across devices

Signal keeps pinned, archived and muted chats in a storage service and syncs
reads with sync messages. Kutup carries the same state as more hidden
same-account controls on the Note-to-Self linked-device path, next to
`contactControl` and `disappearingExpiryStart`:

| Kind | Body | Merge |
| --- | --- | --- |
| `conversationState` | conversation, `revision`, `sourceDeviceId`, `updatedAtMs`, `pinned`, `archived`, `mutedUntilMs` (2^53−1 = until unmuted), `markedUnread` | whole record; highest `(revision, sourceDeviceId)` wins |
| `readPosition` | conversation, `throughMessageId`, `readThroughMs` | furthest wins; the anchor message places it on each device, `readThroughMs` (the reading device's clock) when the anchor is missing |
| `deleteForMe` | conversation, 1–64 `messageIds` | union; the named messages (and reactions, edits, receipts to them) are purged like expired ones, also when a copy arrives later |
| `viewOnceOpened` | conversation, `messageId`, `sender`, `timestampMs`, `video` | like `deleteForMe` for that message; the control stays as the "Viewed photo/video" placeholder |
| `stickerSaved` | `stickerId`, `emoji?`, `contentType` (WebP or PNG), `data` (base64, ≤ 48 KiB) | the account's stickers, newest first; a later save of the same id replaces it |
| `stickerRemoved` | `stickerId` | removes that sticker; the purge then drops both records |

All six are rejected unless they arrive as a transcript from another device
of the same account addressed to Note to Self, are rejected as MLS
application content, and a device sends them only to its own Note to Self
(`conversationState` must name the sending device). They stay in the local
history, hidden from every view, so the continuous backup restores them to a
replacement browser. The purge keeps only the newest `conversationState` and
the furthest `readPosition` per conversation, so the history holds one of
each; `deleteForMe` controls are kept so a late copy is still removed, and a
`stickerSaved` is dropped once a later `stickerRemoved` names it.

A chat archived before a newer incoming message counts as unarchived unless
it is muted, as in Signal; nothing is written for that. The server sees only
ordinary Note-to-Self sync traffic.

### Local search contract

Chat search is a client-only operation over decrypted history already present
on that installation. Queries, result terms and plaintext indexes are never
sent to or persisted by a homeserver, federation peer or MLS ordering
authority.

The chat core keeps a search index beside its per-conversation timelines
(`kutup-chat-core/src/search.rs`, `docs/research/16-browser-storage-architecture.md`):
an inverted index from words to entries in SQLite FTS5's layout: per 30-day
period, each entry stored once under a small number, and per word the
numbers holding it as compact differences, in shards by a word's first three
characters (so a write rewrites only the current period's records), all
sealed under the store key like every other record,
and written in the same transaction as the messages it indexes. A store from
before the index is indexed once on open. Words are folded before indexing and
querying: İ, I, ı and i are alike, accents are removed (canonical
decomposition, combining marks dropped) and text is lowercased; every word of a
query must begin a word of the message ("kitap" finds "kitaplar", "tap" does
not). The browser and native clients fold identically (shared vectors in
`kutup-chat-core/tests/vectors/search_fold.json`). Restored backup history,
held in memory, is matched the same way without an index; a replacement
browser can search only history it has recovered through the normal
server-hosted encrypted backup restore.

The index only proposes candidates; the searchable view applies product state
before matching: hidden controls, deleted messages and expired disappearing
content are excluded; an edit replaces rather than supplements the original
text (each hit comes back with the edits and deletions that act on it). Text,
attachment filenames and captions, and place labels are searchable. Results are
bounded and ordered newest first, and selecting one navigates to the local
conversation copy without a network lookup.

Incoming strangers are message requests. Accept/reject/block/unblock are
client relationship state. First-contact/request traffic stays identified.

## 7. Encrypted profiles and sealed sender

`ProfileSuiteId = 1` fixes `ProfileEnvelopeV1`: XChaCha20-Poly1305 with
HKDF-SHA256 purpose subkeys and a canonical header binding profile owner,
profile-key-derived version, revision, source device and field purpose. Display
names retain the fixed 53/257-byte Signal-style padding buckets. The optional
"about" line (purpose 4, one line of at most 140 characters) uses Signal's
128/254/512-byte buckets. The random
profile key is distributed only inside E2EE messages together with the exact
numeric profile suite; a missing or unknown suite never authorizes a profile
fetch. From that key the client derives:

```text
HKDF-SHA256(
  salt = canonicalRecipient,
  IKM  = profileKey,
  info = "kutup/sealed-delivery-capability/v1"
)[0..16]
```

The destination stores only `SHA-256(capability)` and compares it in constant
time. Capability publication and encrypted-profile revision are atomic.
Blocking rotates both before the new profile key is sent to remaining contacts.
The blocked contact keeps the old capability, so the server refuses their
sealed sends with its uniform 404 (`sealed delivery unavailable`). As in Signal,
their client is not told why: the message counts as sent, is never delivered,
and leaves the queue so it does not hold the conversation back. Unblocking an
accepted contact sends them the current profile key, and their next message
goes through.
Unrestricted anonymous delivery is forbidden.

A root signs an online server certificate: an operator's offline root, or,
with none configured, a root the server generates, uses once and drops
(`docs/self-hosting.md`, "Contacts-only sealed sender"). The online signer issues
sender certificates valid for at most 24 hours and binding canonical account,
device ID, Signal identity public key, expiry and server certificate. Root
rotation publishes old+new, activates a new server certificate, waits at least
the certificate lifetime plus skew, then removes the old root in a later signed
policy.

Local anonymous bundle/send requests carry no bearer token, cookie or
authenticated session. A federated sealed transaction contains origin domain,
recipient, random send ID, capability and opaque device envelopes—but no sender
account or device. The origin may retain authenticated sender metadata only in
its retry state. Destination transaction, mailbox, audit and logs may not.

After outer decrypt, the recipient verifies certificate root/policy, expiry,
canonical account/domain, envelope identity and the exact manifest-bound device
identity before processing the inner Signal ciphertext.

There is no identified fallback after sealed delivery is established. Note to
Self and linked-device sync remain identified.

Default abuse limits are 60 anonymous attempts/minute/IP, 30 capability bundle
requests/minute, 120 sealed sends/minute and 10,000/day/capability, 600
federated sends/minute/origin, 32 envelopes and 1 MiB/request. Unknown recipient
and invalid capability return the same response shape.

**Sealed batches.** `POST /api/chat/anonymous/messages/batch?server=` carries
1–64 sealed sends to accounts of one server (`SealedBatchSubmissionV1`: each
recipient's `accountId` and its single-route submission), at most 4 MiB, in one
request: a group message reaches every member device without one request per
member. The address's bytes a minute count (an administrators' setting
shared with multi-recipient sends; `429` past it). For this server's
accounts the address's anonymous limit counts the request once, so a message
to many members is one request and neighbours behind one address aren't
starved; for another server's, each send is queued and charged at the
destination against this whole server, so the limit counts each recipient
(those past it answered `rateLimited`). Each recipient's capability is
checked and counted on its own, and each gets its own result in order:

- `delivered`;
- `deviceMismatch`, with the single route's mismatch body;
- `unavailable`, for a wrong capability or an unknown account alike;
- `pending`, only for a send that was queued for the recipient's server;
- `refused`, refused for good by that server, or too large for one federated
  transaction (1 MiB encoded), and then never queued;
- `peerUnsupported`;
- `rateLimited`, over the capability's or the recipient's limit (or, to
  another server, the address's); nothing was stored or queued, so it is
  resent later;
- `conflict`, other content under this `sendId` still queued; nothing was
  queued, so it is resent once that one is answered.

A recipient over a limit doesn't stop the others. A server error fails the
whole request, which is safe to repeat because `sendId`s dedupe.

**Multi-recipient sends** (docs/plans/pairwise-groups.md, slice 2; Signal's
`PUT /v1/messages/multi_recipient`). `POST
/api/chat/anonymous/messages/multi?server=` carries one group message to
member accounts of one server, sent once: `SealedMultiSubmissionV1` with
`sendId`, `payload` (libsignal's sent sealed-sender v2 message, version
`0x23`, recipients as 17-byte account service ids, no excluded recipients),
`capabilities` (each recipient account's raw 16-byte group capability, exactly
the payload's accounts) and `urgent` (default `true`). The checks, in order:
1. the payload and its size: `400 malformed` for a payload that doesn't parse,
   a device listed twice, a recipient with no devices or capabilities that
   don't name exactly the payload's accounts; `413` past the recipient limit
   (256), the request size (256 KiB plus 132 bytes per recipient) or one
   recipient's message (96 KiB), each an administrators' setting;
2. each account's capability against its published set
   (`/api/chat/group-capabilities`): an account that isn't an active one here
   and a capability that doesn't hold are one answer, `refused`;
3. budgets: the address's anonymous limit counts the request once, and its
   bytes a minute (`429` past them); each capability its sends a minute and a
   day, `rateLimited` past them;
4. devices, for the accounts that passed: missing or extra devices are `409`
   (`devices`), else changed registrations `410` (`stale`); nothing is stored
   on either, and both carry `refused` and `rateLimited` too.

Otherwise the answer is `200 { "refused", "rateLimited" }` and the rest are
stored: the shared part (`e_pub ‖ ciphertext`) once, and a mailbox row per
device with its account's key material. A device drains each as its ordinary
sealed envelope, `0x22 ‖ C_i ‖ AT_i ‖ e_pub ‖ ciphertext`; drain pages are
capped at 4 MiB as well as by count. Connected devices are nudged
(`drainMailbox`) rather than sent the message; an urgent send also wakes
offline devices by web push. A `sendId` already stored for a device stores
nothing again for it, while a device added since gets its copy on a retry.
The budgets are charged whatever the answer: a send answered `409` or `410`
counts too. The shared part goes once no row names it (after an ack,
or the maintenance sweep).

For another server's members, this server forwards the send at once to that
server's `POST /api/fed/chat/sealed/multi` (signed federation), waits for its
answer (the usual federation timeout) and relays it as it is: `200`, `409`,
`410`, or the destination's `400`/`413`. A destination that is slow,
unreachable or unwilling is `503 peerUnavailable`: nothing is queued and
nothing of the body is kept, so the client sends those members' copies over
the pairwise path, which is durable. The destination checks and stores the
send as a local one, and budgets its origin per request and per byte a
minute, all of the origin's users together (`chatMultiOriginRequestsPerMin`,
6000, and `chatMultiOriginBytesPerMin`, 512 MiB, at first), never per stored
recipient. A request that doesn't authenticate is limited per address
(`RATE_LIMIT_FED_MULTI_FAILURES_PER_MIN`, 60): each is charged before its body
is read and given back once it authenticates, so a known peer is bounded by
its origin budgets alone.

For another server, the origin queues each send exactly as a single sealed
send (same outbox, sequence and `sendId` dedup), then flushes the
destination's queue. One flush per destination runs at a time: in each
backend a set of the destinations being flushed, and across backends sharing
the database a session advisory lock held on a small pool of its own, so no
flush holds a main-pool connection or a transaction across its network calls.
A send that meets a flush under way in the same backend makes that flush run
again before it ends, a few passes at most; one that finds every lock
connection taken (`SEALED_FLUSH_LOCK_CONNECTIONS`) skips at once, and the
retry worker sends it. Nobody waits for that lock: a client whose send meets a flush under way is
answered from its outbox row, which keeps the destination's final answer, so
it reads its real answer if another flush (the retry worker's) settled it, and
`pending` only while it is still queued. A flush runs in its own task, so a
client that goes away doesn't cut it short. A flush sends nothing while the queue's head waits for
the peer to support `chat.v2`. While the head is backing off after an error,
the retry worker waits it out, but a client's send may try the head alone,
at most once every 5 seconds per head whichever backend asks
(`SEALED_PROBE_SECONDS`, claimed by stamping the row): a server that is back
is noticed at once, and the rest of the queue follows when the head settles.
Otherwise it sends the run of
consecutive pending sends from the head, sized before it is loaded, in signed
`POST /api/fed/chat/sealed/batch` requests (`FederatedSealedBatchV1`, at most
64 transactions and 4 MiB). The destination checks the batch's shape first
(one origin, consecutive sequences) and refuses a malformed batch before
applying any of it. Otherwise it applies the transactions one by one as
single transactions and stops after the first answer that doesn't use up its
sequence, answering each it tried.

**Version 2.** Every sealed transaction and batch carries
`version` 2 (`SEALED_FEDERATION_VERSION`), the version in which every answer
uses up its sequence. A server refuses another version's transactions for
good, by sequence, with `code: sealedVersionUnsupported`, and logs it; an
origin logs every refusal it gets, with the peer's code and error. A peer that
reads sequences differently is refused, never waited on. A send refused this
way stays refused: an identical resend gets the stored `refused` again. A
send queued before version 2 goes out at version 2, so an upgrade loses
nothing in flight. Federating servers upgrade together (`docs/self-hosting.md`,
Updating).

**Every answer uses up its sequence.** The destination records each final
answer to an origin's sequence (a delivery, the uniform 404, a device
mismatch, a refusal naming the sequence) in the same transaction, under the
origin's lock, as what it answers. Every one of them is charged to the
origin's sealed rate, a mismatch, a refusal and the 404 included, so none is
a free probe. A replay of that sequence then gets the
same answer, and the next sequence follows. Only an unknown result (a timeout,
a passing error, a rate limit, a gap) is tried again under the same sequence.

A send answered with a device mismatch is corrected by its client and goes
again under a new sequence with the same `sendId`; the recipient's mailbox
deduplicates deliveries by `sendId`. So a send whose client never corrects it
can't hold the origin's later sends to that server.

The origin moves an outbox row only on an answer to the sequence the row
still has, so a late answer to an old sequence changes nothing. A peer that
answers a single send but not a batch (a server from before batches) gets
singles for an hour. The retry worker flushes due queues the same way.

## 8. Private MLS groups

The complete group protocol is specified in [`chat-mls.md`](chat-mls.md). V1
uses OpenMLS ciphersuite `0x0003`, one independent leaf per device, a mandatory
group-private control extension, identified consent/invitation, anonymous
established delivery, owner-approved critical governance and replaceable
multi-server control ordering.

Account roster bounds and leaf bounds are distinct:

```text
maximum accounts             = 256
maximum active devices/account = 10
maximum MLS leaves           = 2,560
```

The server may set a lower active-device limit. It may not advertise a higher
group/account/tree capacity than the compiled protocol supports.

## 9. Federation

All server-to-server calls use the unified federation identity, discovery,
DNS/SSRF admission, timeout/size limits, destination/body-bound signatures,
contiguous inbound sequence reservation and durable retry outbox described in
[`federation-protocol.md`](federation-protocol.md).

Direct identified, sealed, manifest/profile and MLS endpoints are feature
adapters over that one transport. Clients never provide remote URLs. The local
server derives the destination from a canonical address and performs the
signed request.

Federation identity is independently TOFU/administrator-verifiable transport
identity. It is not the user safety number and cannot promote a user account
from gray to green.

## 10. Persistence and failure rules

Client crypto changes accumulate in one pending transaction. The following
must be atomic:

- ratchet mutation + plaintext history + inbound receipt/ack state;
- exact outbox ciphertext + retry metadata;
- manifest history + current pin/quarantine;
- OpenMLS provider snapshot + group control pin + mailbox receipt;
- profile revision + delivery capability verifier;
- contact block + profile/capability rotation state.

Decrypt precedes durable commit; acknowledgement follows it. A crash may cause
an exact replay, never acknowledgement of uncommitted plaintext or ratchet
state. Malformed/untrusted envelopes remain in a bounded attention/dead-letter
journal and are never silently acknowledged. The one exception is an
unreadable message from a known sender device, which is acknowledged together
with the session repair and the visible record described in §6.

### Browser storage

The browser store is encrypted at rest (`kutup-chat-core/src/db/store_cipher.rs`,
`docs/research/16-browser-storage-architecture.md`). A random 256-bit store key
is wrapped with XChaCha20-Poly1305 under a key derived from the account master
key (HKDF-SHA256, `kutup/chat-store/wrap/v1`) and bound to the database name;
the wrapped key and a format marker are the only plain entries. Each record is
stored under `HMAC-SHA256(index key, object store ‖ key)`, so no address or id
is readable, and its value (CBOR) is sealed with XChaCha20-Poly1305 together
with its original key, the object store and hashed key bound as associated
data, so a record moved to another key or store does not open. A database
without the wrapped key is a new store: on first open every object store is
cleared and the key and marker are written in one durable transaction; any
records it held are never read. The database is at IndexedDB version 13,
which dropped the former history-transfer stores. The key opens
only with the account master key, so a signed-out browser keeps an unreadable
store and stays the same device when the account signs in again. Native
clients use SQLCipher.

In the browser every commit is one IndexedDB transaction opened with
`durability: "strict"`: it completes only once the browser reports the data on
disk. (Chrome's default, relaxed, can lose a commit to a power cut after the
code acted on it: a ratchet step after its message went out.)

Every tab runs its own engine over the same store, and they take turns under
one Web Lock. The holder announces itself every 5 seconds on a
BroadcastChannel while it holds the lock. A tab waiting for it takes the lock
over once the holder has been silent for 30 seconds (a tab the browser froze
mid-operation); one that is merely busy keeps announcing and keeps the lock.
Taking over moves a writer generation kept in the store on, and every write
checks, inside its own transaction, that its tab still holds the current
generation: a frozen tab that resumes has its writes refused instead of
writing over the new holder's. A tab runs its own operations one after
another before reaching the lock, so it never takes the lock from itself.
Browser spec 46 injects this fault.

Network unavailability retains the last valid pin and retries. Cryptographic
contradictions block. Unknown suites and malformed canonical encodings return
explicit errors. No code path silently exports an HSM key, replaces a pin,
downgrades delivery or regenerates supposedly durable ciphertext.

## 11. Privacy and traffic shape

V1 protects content and removes sender identity from established destination
delivery. Direct and MLS message sizes are rounded up to 160-byte steps
(Signal's padding), so short messages of any kind look alike; longer ones
still reveal their approximate length. V1 does not hide timing, IP address,
origin domain, recipient, or device fan-out.

The post-v1 advanced traffic-inspection profile may add fixed cells, dummy
cells, persistent multiplexed connections, controlled-rate batching/delay and
padded acknowledgements/control traffic. Data-saving and timing controls will
be optional, explicitly configured, and shared by Chat and Drive transport.
Protected mode will never silently downgrade. See the platform TODO in
[`roadmap.md`](roadmap.md#platform--advanced-traffic-inspection-protection-todo-post-mls-v1).

## 12. Completion gates

Before a capability is advertised, its deterministic vectors, parser bounds,
property/adversarial tests, restart atomicity, Rust/WASM/native builds,
browser flow, fresh-database migrations and two-server federation path must
pass. The group gate covers 256 accounts and enforces the 2,560-leaf hard bound.
Broadcast remains unadvertised until its separate 1,000,000-account / up to
10,000,000-device grant and fan-out protocol passes equivalent gates.
