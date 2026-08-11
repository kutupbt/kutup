# Kutup Chat protocol V1

**Status:** normative pre-v1 protocol

Kutup Chat provides Direct Chat, Note to Self, private MLS groups, encrypted
profiles, signed account/device manifests, federated ciphertext delivery and
contacts-only sealed sender. A capability is advertised only when its complete
local and federated path is configured.

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

## 2. Addresses and conversation types

The stable address is canonical lowercase `username@server`. Display names and
avatars are encrypted, mutable and non-unique; they are never routing keys.

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

Before V1, clients must provide explicit active-installation review, last-seen
information and revocation. Linking a new installation while an authorized
device survives must offer an authenticated one-time E2EE history transfer.
The old device packages a bounded local history and recent-media snapshot,
encrypts it to an ephemeral key authenticated by both exact manifest devices,
and the new device verifies the transcript before import. The homeserver may
relay and temporarily retain only opaque bounded transfer frames; it never
receives plaintext or a reusable history key.

History transfer is distinct from message delivery. Senders fan out only to
the exact signed destination manifest observed for that send. Adding a device
does not authorize the server to copy or transform an older device's mailbox.
If no authorized old device or E2EE backup survives, old device-addressed
ciphertext is unrecoverable and the UI must disclose that condition. It must
not silently render an empty history as proof that no messages were sent.

The canonical handshake, framing, snapshot/import boundary and relay lifecycle
are specified in [`draft/v1/chat-history-transfer.md`](draft/v1/chat-history-transfer.md).

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

The shared safety encoding sorts both `(canonical account, raw authority key)`
pairs, encodes them under `kutup/chat/safety-number/v1`, hashes with SHA-256,
and renders the full digest as sixteen lossless five-digit groups. The QR is a
versioned `kutup://verify/chat/v1/…` encoding of the canonical public payload.

Relevant routes:

| Route | Meaning |
|---|---|
| `POST /api/chat/device` | restart-safe device registration |
| `DELETE /api/chat/device/{deviceId}` | revoke one device |
| `POST/GET /api/chat/history-transfers` | create/list account-local signed transfer requests |
| `PUT /api/chat/history-transfers/{id}/acceptance` | one existing device explicitly accepts |
| `PUT/GET /api/chat/history-transfers/{id}/frames[/index]` | upload/drain bounded opaque frames |
| `POST /api/chat/history-transfers/{id}/completion` | record destination completion and erase frames |
| `DELETE /api/chat/history-transfers/{id}` | cancel and erase a participant's transfer |
| `POST /api/chat/manifest` | publish exact next signed manifest |
| `GET /api/chat/users/{username}/manifest` | current local/federated manifest |
| `GET /api/chat/users/{username}/manifest-history` | bounded complete history page |
| `GET /api/fed/chat/users/{username}/manifest` | signed-federation current manifest |
| `GET /api/fed/chat/users/{username}/manifest-history` | signed-federation history page |

## 6. Direct Chat and Note to Self

Every device publishes one libsignal identity key, signed prekey, last-resort
ML-KEM prekey, and bounded one-time EC/PQ prekeys. Session establishment and
steady-state ciphertext are generated only by libsignal. A bundle is unusable
until its exact device identity matches the accepted account manifest.

Sending is multi-device fan-out. Each destination device has an independent
ratchet. A client-generated UUID `sendId` and durable outbox make retries
idempotent. A 409 device mismatch causes a bounded manifest/bundle refresh; a
manifest contradiction stops rather than encrypting to an untrusted key.

Note to Self is a self-addressed Direct conversation. Sent-message sync to
linked devices is authenticated and identified. It never uses anonymous
delivery or creates an MLS group.

User-visible content carries a stable sender-generated UUID `messageId` inside
the ciphertext. A text reply adds an optional canonical non-nil UUID `replyTo`
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
Once viewing has started, linked-device history transfer and browser-device
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

### Local search contract

Chat search is a client-only operation over decrypted history already present
on that installation. Queries, result terms and plaintext indexes are never
sent to or persisted by a homeserver, federation peer or MLS ordering
authority. V1 performs an ephemeral in-memory scan, so a replacement browser
can search only history it has recovered through the normal encrypted
linked-device transfer.

The searchable view applies product state before matching: hidden controls,
deleted messages and expired disappearing content are excluded; an edit
replaces rather than supplements the original text. Text, attachment filenames
and attachment captions are searchable. Results are bounded and ordered newest
first, and selecting one navigates to the local conversation copy without a
network lookup.

Incoming strangers are message requests. Accept/reject/block/unblock are
client relationship state. First-contact/request traffic stays identified.

## 7. Encrypted profiles and sealed sender

`ProfileSuiteId = 1` fixes `ProfileEnvelopeV1`: XChaCha20-Poly1305 with
HKDF-SHA256 purpose subkeys and a canonical header binding profile owner,
profile-key-derived version, revision, source device and field purpose. Display
names retain the fixed 53/257-byte Signal-style padding buckets. The random
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
Unrestricted anonymous delivery is forbidden.

An offline root signs an online server certificate. The online signer issues
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
journal and are never silently acknowledged.

Network unavailability retains the last valid pin and retries. Cryptographic
contradictions block. Unknown suites and malformed canonical encodings return
explicit errors. No code path silently exports an HSM key, replaces a pin,
downgrades delivery or regenerates supposedly durable ciphertext.

## 11. Privacy and traffic shape

V1 protects content and removes sender identity from established destination
delivery. It does not hide message length, timing, IP address, origin domain,
recipient, or device fan-out.

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
