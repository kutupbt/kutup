# Chat media protocol

**Status:** implemented and required-PR-gated. The local, federated, restart,
browser, scale, quota-recovery, metadata-privacy, and clean-browser backup gates
passed from clean deployments through 2026-08-14.

This document defines files, photos, recorded videos and voice-note objects for
Direct Chat and Note to Self (groups take media in a later slice of
pairwise groups). It deliberately reuses
Kutup's object storage, tus transport, unified federation stack and canonical
Rust/WASM crypto implementation. It does not make a mutable Drive file into a
message attachment and it does not introduce a second S3 client or federation
transport.

## 1. Locked V1 decisions

- A sent attachment is an immutable client-encrypted snapshot. Renaming,
  replacing or deleting a source Drive file never mutates a previously sent
  message.
- One ciphertext is produced per logical attachment. Direct Chat, groups,
  linked devices and future broadcast distribute the random object key through
  their existing E2EE content; they never encrypt or store one blob per device.
- The sender homeserver retains an authenticated retry copy. After federation,
  each destination homeserver owns a durable opaque copy so later reads do not
  depend on the origin remaining online.
- Clients communicate only with their own homeserver. A remote client never
  follows an origin URL supplied by message content.
- V1 device download is manual. Message requests do not cause destination blob
  allocation before explicit acceptance.
- Chat media, protected history media, and message-history ciphertext count
  against the account's one storage pool. Drive, Photos, Office and Maps use
  the same pool. Its administrator-configured default is 10 GiB per account.
- The attachment limit is 2 GiB of plaintext-class content plus the exact
  bounded framing overhead of the block format. A server may advertise a lower local limit but not
  a larger V1 limit.
- The server never interprets a filename, MIME type, caption, dimensions,
  duration, conversation ID, message ID or media class. Those values exist
  only in E2EE content and the encrypted account ledger.

## 2. Typed suites and keys

`ChatMediaSuiteId` is a purpose-specific registry. It is not a universal
Kutup suite and it does not reuse a Drive, Direct Chat, group, profile or ledger
key.

| Code | Construction | New writes |
|---:|---|---|
| `2` | The block format (docs/plans/drive-block-format.md §2): 4 MiB XChaCha20-Poly1305 blocks bound to their index, a sealed manifest of their SHA-256 hashes (`KUTPCM2`) | required |

Code `1`, a secretstream with 5 MiB frames, is gone: it no longer parses
(slice 7 of the block format).

For each attachment the sender generates a fresh random 32-byte
`attachmentKey`. HKDF-SHA256 derives the block, nonce and manifest keys from
it with the `kutup/chat-media/blocks/…` labels and the complete object header.
The raw key appears only inside the encrypted logical message and the
sender's encrypted linked-device transcript. The parser refuses any other
magic or suite: a `KUTPCM2` header naming suite 1 fails.

The attachment ledger's records are account records (`KUTPAR1`, purpose
`ChatAttachmentLedger`, [`plans/w1-account-record.md`](plans/w1-account-record.md))
under the recoverable master key, bound to the account's key binding. A Drive
root, profile key, Signal session key or group sender key never seals one.

## 3. The attachment object (suite 2)

The object bytes are the block format's (docs/plans/drive-block-format.md §2):

```text
[28-byte header][block 0]…[block n−1][sealed manifest][12-byte trailer]
```

The fixed header is:

```text
magic             8 bytes  "KUTPCM2\0"
suite             u16      big-endian ChatMediaSuiteId (2)
purpose           u8       1 = attachment blob
reserved          u8       must be zero
attachment_id     16 bytes random UUID
```

An attachment is immutable, so the header names no revision. Each 4 MiB
block is sealed with a synthetic nonce and the header, its index and a
`last` flag as associated data; the sealed manifest (`u32` block size, `u32`
count, `u64` plaintext size and each sealed block's SHA-256) ends the object,
and the trailer gives its length. The manifest is **unsigned**: the E2EE
descriptor commits to its SHA-256, as Signal's attachment pointer carries its
incremental MAC. An empty file is one empty last block. Wrong ids, unknown
suites or purposes, non-zero reserved bytes, a manifest other than the
committed one, a block whose hash or AEAD fails, reordered, missing or extra
blocks and bytes after the trailer all fail closed.

The sender computes SHA-256 over the complete object. Storage and federation
admission bind the attachment UUID, suite, exact ciphertext length and complete
digest before accepting quota or making the object visible, as before the
block format. The server also checks the public structure: the header against
the attachment at the first part, and at finalization the trailer's manifest
length against the block count the length implies
(`crates/kutup-server/src/handlers/chat_media.rs`). It cannot check an AEAD.
A digest is an integrity/index value, not an access capability, and must not
appear in metric labels or ordinary logs.

## 4. E2EE attachment descriptor

Direct Chat and group messages carry the same `ChatContent` kind `attachment`.
The outer message protocol changes; the logical attachment body does not.

`ChatAttachmentDescriptorV1` contains:

- version and `ChatMediaSuiteId` (2);
- random attachment UUID;
- canonical origin domain and random origin retrieval token;
- exact ciphertext length and the whole object's SHA-256 digest (hex);
- the sealed manifest's SHA-256 (`manifestSha256`, canonical base64): what
  every reader opens the object against;
- 32-byte attachment key;
- plaintext length (the manifest's size must be this);
- filename, MIME type and optional caption;
- optional width, height and duration; and
- an optional bounded inline E2EE preview.

The retrieval token is random, single-purpose and bound at the origin to the
attachment, exact recipient account, destination domain,
expiry and object digest. It is never accepted as a bearer URL and never sent
to an arbitrary client-provided host. The recipient gives the descriptor only
to its own authenticated server, which resolves the origin through the unified
federation transport.

All strings use existing Chat content encoding and strict byte limits. Unknown
content kinds remain renderable as a newer-client placeholder, but an unknown
media suite never authorizes retrieval or decryption. Preview generation is
client-side. The preview is inside E2EE content, capped at 32 KiB and never
treated as evidence for the full object.

## 5. Local upload and send lifecycle

1. The client generates an attachment UUID and key, seals the immutable
   snapshot block by block in Rust/WASM (`chatMediaBlockEncryptor`), and
   calculates its exact length, its digest and its manifest's digest while
   streaming. A tus PATCH carries two sealed blocks.
2. Authenticated tus creation reserves the exact ciphertext bytes against the
   sender's account storage pool and writes only under a random temporary key.
3. Finalization validates the public object header and framing bounds, then the
   server independently streams the completed object through SHA-256. The final
   tus response returns that digest; the client compares it to its streaming
   digest before constructing the E2EE descriptor. A mismatch deletes the
   object and never sends a message. The matching digest, exact length, object
   row, quota, and idempotent upload receipt commit atomically.
4. The sender writes the attachment message to its history and asks its own
   server for the destination's copy (an authenticated media-delivery
   request). The message is encrypted and sent only once the answer is
   `stored` or `alreadyStored` (Signal's model,
   docs/plans/federation-outbox.md): on `queued` it waits, showing as
   sending, in a job the client keeps across restarts, and asks the same
   operation again with backoff (at most five minutes between asks, and when
   the app comes back online or reopens) for at most
   `chatAttachmentSendLifetimeSeconds` (a site setting, one day by default).
   `storageFull`, a refusal (`404`, `422`) or the end of that lifetime shows
   the message as not delivered, with a retry; a retry after a refusal asks
   under a new operation. The origin may retain the local sender and
   recipient internally for retry; they never enter a destination
   transaction or log.
5. A send is complete for one destination only after that homeserver has
   reserved recipient quota, fetched and verified the object, committed its
   durable reference and returned a signed acknowledgement.
6. The origin retry copy is released only after every required destination has
   acknowledged or the explicit request/retention policy expires. Partial group
   delivery is represented per destination without rolling back successful
   destinations.

Exact retries use the same UUID and operation ID. The origin keeps each
operation's final answer: a repeat gets the stored receipt or refusal once it
is settled, or `queued` (and the destination's queue tried at once) while it
is pending. A repeat may carry a new expiry; a changed digest, length, suite,
token, capability, recipient or destination under an existing operation ID is
a terminal conflict.

Offers to one destination go in order, one sequence each, through the one
federation outbox (docs/plans/federation-outbox.md). The destination records
every final answer, a refusal included (an offer invalid or expired by the
time it arrives, an operation or object identity reused, the origin no longer
serving the object), so a refused offer never blocks the ones behind it.

## 6. Federation transfer

Media uses the existing RFC 9421/9530-authenticated federation identity,
destination and feature binding, DNS/SSRF policy, admission rules, replay
reservation, timeouts and retry queue. There is no media-specific federation
identity or unsigned object URL.

The small signed offer contains origin domain, destination domain, canonical
recipient, random operation ID, attachment UUID, suite, ciphertext length,
digest, expiry and a recipient delivery capability. It contains no sender
account/device, certificate, conversation name or plaintext media metadata.

After admission, the destination pulls through a signed federation streaming
route. It verifies the signed response metadata before release, hashes the
bounded stream while writing a temporary object, compares exact length/digest,
then atomically commits the object/reference/quota. A disconnect or mismatch
deletes or sweeps the temporary object and releases the reservation. Response
bytes are never buffered in full.

An established Direct Chat offer requires the contacts-only media capability.
Message
requests carry the encrypted descriptor but no destination storage offer. After
acceptance, the recipient client authorizes its own homeserver to retrieve the
object. An origin keeps that pending object for at most 30 days.

Uniform `404` semantics cover an unknown attachment, expired retrieval token,
wrong recipient and invalid capability. Quota exhaustion is a typed
authenticated recipient error and cannot be used for anonymous enumeration.

## 7. Destination storage, quotas and references

One physical object may be reference-counted for multiple local recipients,
but every recipient is charged the complete logical ciphertext length against
their own account storage pool. Physical deduplication never changes user quota,
authorization or deletion semantics.

Quota reservation and reference creation occur in one database transaction.
The server must not increment quota without a durable reference or create a
reference without quota. Lowering a quota preserves existing objects and blocks
new reservations; it never silently evicts media.

Every write locks the account row and checks used plus reserved plus new bytes
against the quota. Reserved bytes are open Drive tus uploads, the unreceived
part of open Chat media uploads, and pending federated inbound hand-overs. The
uploads sweep deletes a stale inbound hand-over and releases its reservation.

When the recipient's storage pool is full, the message descriptor may remain
in E2EE history while the attachment is visibly unavailable. The destination
does not partially store it. Sender and recipient receive stable `storageFull` state,
and retry requires available quota plus an unexpired origin object.

Normal accepted media remains until the recipient clears it, its disappearing
message expires, an authenticated delete-for-everyone control releases it, or
the account is terminated. Explicit clearing removes only that recipient's
reference and releases their quota. Other recipients and saved Drive copies are
unchanged.

`Save to Drive` decrypts and re-encrypts into a recipient-owned visible Drive
collection. The Drive file is a second copy and is charged to the same pool
separately. If the recipient then clears the Chat copy, its Chat reference and
charge are released. The
operation never adopts
server ciphertext by changing metadata because Drive headers bind a different
file, collection and epoch.

## 8. Encrypted attachment ledger

The homeserver's quota rows know only recipient, opaque object/reference IDs,
namespace, byte counts and lifecycle state. Named per-conversation totals are a
client projection over `ChatAttachmentLedgerV1` encrypted entities.

Each ledger entity is one account record in the account-records store's
`chatAttachments` scope ([plans/account-records.md](plans/account-records.md),
W3 slice 6), kept at its newest revision only
(`kutup_crypto::chat_attachment_ledger`):

```text
header (KUTPAR1)  suite 1, purpose ChatAttachmentLedger (14), master-key
                  generation, the account's key binding,
                  object = the entity's record id (32 random bytes),
                  revision (non-zero),
                  key commitment, nonce, ciphertext length
ciphertext        the entry, padded to a 256-byte bucket, plus the tag
```

The whole header is the AEAD's associated data and the record key's input;
the server checks it (this account's binding, the item's record id, the
revision above the stored one) without opening anything. An envelope
plaintext is capped at 16 KiB and uses the project canonical big-endian
length-prefixed encoding, not signed JSON. It binds version, conversation
kind/reference, logical message UUID, attachment UUID, opaque
storage-reference UUID, exact logical ciphertext bytes, state, media class,
bounded display name, update time and an optional promoted Drive file UUID.
States are `active`, `cleared`, `savedToDrive` and `expired`. The server
cannot classify or join an entry to a sender or conversation.

Writes are batches of `POST /api/v1/account/records` with the next account head:
each entity's put names the revision it read, so a retried or raced write is
refused (`revision_conflict`) and the client reads again and redoes it. The
account head covers the scope (a count and digest of every `(id, revision)`),
so a server that rolls an entity back, drops one or brings an old one back is
caught when the client checks the scope's index against the verified head.
The private hash chain, the history table, the operation ids and the ledger's
own cursor are gone: the records feed (`GET /api/v1/account/records/chatAttachments`)
and the head replace them.

Clients decrypt the scope and build a disposable in-memory projection; they
do not persist decrypted conversation or attachment metadata. The number of
entities an account keeps is a site setting
(`account_records_chat_attachments`).

## 9. Client behavior

- The composer offers the platform-native rear-camera photo/video capture UI.
  Camera permission remains browser/OS-owned; Kutup does not retain a media
  stream. The resulting `File` enters the exact attachment encryption and
  upload path above, so captured plaintext never receives a separate server
  route or plaintext fallback.
- Voice notes use the browser `MediaRecorder` API with browser/OS-owned
  microphone permission. Cancel discards the collected chunks, and cancel,
  send, failure, size overflow and component teardown all stop every microphone
  track. V1 bounds the in-memory recording to 10 minutes and 64 MiB (or the
  lower advertised server limit). The completed audio `File` and its measured
  duration then enter the same immutable encryption/upload path; no raw audio
  stream or separate voice endpoint reaches a server.
- V1 never automatically downloads full attachment bytes to a device. The user
  taps **Download** or **View**.
- Reading opens the header and the manifest first, against the descriptor,
  then each block with its hash checked before its AEAD; no plaintext is
  released before the manifest is the descriptor's. A download into the
  private cache is authenticated without decrypting (length, whole digest,
  header and manifest); opening it from the cache reads it twice, the
  manifest from the end first.
- A video or song plays without that download: its viewer streams it from the
  account's own server through Kutup's service worker
  (`/sw/stream/{id}`, docs/plans/drive-block-format.md §4), the same
  stateless route Drive uses, with the block reader opened on a Chat source.
  A seek fetches one block. Without a service worker it opens whole from the
  private cache, within the viewer's in-memory bound. Voice notes still play
  from the cache.
- The recipient server may already hold the durable encrypted copy. Device
  caching is local storage and is not charged again as server quota.
- The Chat storage screen shows the account pool split into message history,
  delivery media, protected history media, and "Drive and other apps", plus
  client-computed per-conversation totals and review/clear actions. It links to
  the Account app's Settings → Storage page for the full breakdown.
- Post-V1 may add per-device mobile/Wi-Fi/roaming and media-class auto-download
  policies. Those settings never weaken destination durable storage after an
  accepted delivery and never cause an identified-delivery downgrade.
- Unsafe preview decoders run behind strict byte/dimension/time bounds. A MIME
  string is presentation input, not authority to invoke an unsafe parser.
- OpenTelemetry emits only the closed `stage`/`outcome` dimensions on
  `kutup.chat.media.events`. The `chat_media.*` spans skip handler arguments.
  Domains, accounts, attachment/message IDs, filenames, MIME values,
  capabilities, digests, certificates, ciphertext and storage paths are never
  metric attributes or span fields.

## 10. Advertisement and completion record

The server advertised `ChatMediaCapabilitiesV1` only after all of the
following passed:

- [x] canonical Rust vectors and WASM parity for object/ledger headers, HKDF,
  encryption, manifest validation and descriptor parsing (the block
  format's in `tests/vectors/blocks-v1.json`);
- [x] parser fuzzing for objects, descriptors, offers, acknowledgements, ledger
  envelopes and diff pages;
- [x] transaction-failure and restart tests for upload reservation/finalization,
  destination fetch, refcounting, quota, ledger revision and deletion;
- [x] replay, changed-idempotency, stolen/rotated capability, wrong destination,
  digest/length mismatch, truncation, trailing data, oversized stream and
  storage-full tests;
- [x] Direct Chat and Note to Self browser send/download/clear paths;
- [x] browser/OS photo-video capture UI through the same encrypted attachment
  path (this is not a dedicated-native-app readiness claim);
- [x] bounded voice-note recording, cancel cleanup and two-server encrypted
  exact-byte delivery through that path;
- [x] two-server offline/retry delivery with origin restart and destination object
  durability after origin deletion;
- [x] message-request non-allocation before acceptance;
- [x] destination schema/log/trace scans proving no sender identity, certificate,
  filename, MIME type, conversation ID, capability or digest is emitted; and
- [x] exact quota-category and client-side per-chat accounting across linked-device
  restart/rebuild.
