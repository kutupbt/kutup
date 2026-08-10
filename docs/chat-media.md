# Chat media protocol

**Status:** implemented and advertised on `codex/chat-architecture-hardening`.
The local, federated, restart, browser, scale, quota-recovery and
metadata-privacy gates below passed from a clean two-server deployment on
2026-08-03.

This document defines files, photos, recorded videos and voice-note objects for
Direct Chat, Note to Self and private MLS groups. It deliberately reuses
Kutup's object storage, tus transport, unified federation stack and canonical
Rust/WASM crypto implementation. It does not make a mutable Drive file into a
message attachment and it does not introduce a second S3 client or federation
transport.

## 1. Locked V1 decisions

- A sent attachment is an immutable client-encrypted snapshot. Renaming,
  replacing or deleting a source Drive file never mutates a previously sent
  message.
- One ciphertext is produced per logical attachment. Direct Chat, MLS groups,
  linked devices and future broadcast distribute the random object key through
  their existing E2EE content; they never encrypt or store one blob per device.
- The sender homeserver retains an authenticated retry copy. After federation,
  each destination homeserver owns a durable opaque copy so later reads do not
  depend on the origin remaining online.
- Clients communicate only with their own homeserver. A remote client never
  follows an origin URL supplied by message content.
- V1 device download is manual. Message requests do not cause destination blob
  allocation before explicit acceptance.
- One administrator-configured account quota covers Drive and Chat. Drive and
  Chat media are accounting categories, not reserved partitions. The current
  default remains 10 GiB per account.
- The V1 attachment limit is 2 GiB of plaintext-class content plus the exact
  bounded framing overhead. A server may advertise a lower local limit but not
  a larger V1 limit.
- The server never interprets a filename, MIME type, caption, dimensions,
  duration, conversation ID, message ID or media class. Those values exist
  only in E2EE content and the encrypted account ledger.

## 2. Typed suites and keys

`ChatMediaSuiteId` is a purpose-specific registry. It is not a universal
Kutup suite and it does not reuse a Drive, Direct Chat, MLS, profile or ledger
key.

| Code | Construction | New writes |
|---:|---|---|
| `1` | HKDF-SHA256 plus libsodium-compatible XChaCha20-Poly1305 secretstream, 5 MiB plaintext frames | required |

For each attachment the sender generates a fresh random 32-byte
`attachmentKey`. HKDF-SHA256 derives the secretstream key using
`kutup/chat-media/object-key/v1` and the complete object header. The raw key is
zeroized after use and appears only inside the encrypted logical message and
the sender's encrypted linked-device transcript.

`ChatAttachmentLedgerSuiteId` is independent even though its V1 construction
also uses HKDF-SHA256 and XChaCha20-Poly1305. The client derives a stable
32-byte account ledger key from the recoverable master key under the locked
label `kutup/chat-attachment-ledger/account-key/v1`; it never stores that key
remotely. A Drive root, profile key, Signal session key or MLS exporter is never
accepted as a ledger key.

## 3. `ChatMediaObjectV1`

The object bytes are:

```text
[28-byte object header][24-byte secretstream header][one or more frames]
```

The fixed object header is:

```text
magic             8 bytes  "KUTPCM1\0"
suite             u16      big-endian ChatMediaSuiteId
purpose           u8       1 = attachment blob
reserved          u8       must be zero
attachment_id     16 bytes random UUID
```

The complete 28-byte header is both the HKDF context and associated data for
every secretstream frame. Every object, including an empty object, ends in an
authenticated final frame. Missing final tags, trailing frames, reordered or
duplicated frames, wrong IDs, unknown suites/purposes, non-zero reserved bytes,
oversized objects and noncanonical UUIDs fail closed.

The sender computes SHA-256 over the complete object. Storage and federation
admission bind the attachment UUID, suite, exact ciphertext length and complete
digest before accepting quota or making the object visible. A digest is an
integrity/index value, not an access capability, and must not appear in metric
labels or ordinary logs.

## 4. E2EE attachment descriptor

Both libsignal and OpenMLS carry the same `ChatContent` kind `attachment`. The
outer message protocol changes; the logical attachment body does not.

`ChatAttachmentDescriptorV1` contains:

- version and `ChatMediaSuiteId`;
- random attachment UUID;
- canonical origin domain and random origin retrieval token;
- exact ciphertext length and SHA-256 digest;
- 32-byte attachment key;
- plaintext length;
- filename, MIME type and optional caption;
- optional width, height and duration; and
- an optional bounded inline E2EE preview.

The retrieval token is random, single-purpose and bound at the origin to the
attachment, exact recipient account or MLS delivery scope, destination domain,
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

1. The client generates an attachment UUID and key, encrypts the immutable
   snapshot, and calculates its exact length and digest while streaming.
2. Authenticated tus creation reserves the exact ciphertext bytes against the
   sender's total quota and writes only under a random temporary key.
3. Finalization validates the public object header and framing bounds, then the
   server independently streams the completed object through SHA-256. The final
   tus response returns that digest; the client compares it to its streaming
   digest before constructing the E2EE descriptor. A mismatch deletes the
   object and never sends a message. The matching digest, exact length, object
   row, quota, and idempotent upload receipt commit atomically.
4. The sender submits one logical E2EE message and a separate authenticated
   media-delivery request. The origin may retain the local sender and recipient
   internally for retry; they never enter a destination transaction or log.
5. A send is complete for one destination only after that homeserver has
   reserved recipient quota, fetched and verified the object, committed its
   durable reference and returned a signed acknowledgement.
6. The origin retry copy is released only after every required destination has
   acknowledged or the explicit request/retention policy expires. Partial group
   delivery is represented per destination without rolling back successful
   destinations.

Exact retries use the same UUID and operation ID. A changed digest, length,
suite, recipient or destination under an existing operation ID is a terminal
conflict.

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

An established Direct Chat offer requires the contacts-only media capability;
an MLS offer requires the recipient's current group-delivery scope. Message
requests carry the encrypted descriptor but no destination storage offer. After
acceptance, the recipient client authorizes its own homeserver to retrieve the
object. An origin keeps that pending object for at most 30 days.

Uniform `404` semantics cover an unknown attachment, expired retrieval token,
wrong recipient and invalid capability. Quota exhaustion is a typed
authenticated recipient error and cannot be used for anonymous enumeration.

## 7. Destination storage, quotas and references

One physical object may be reference-counted for multiple local recipients,
but every recipient is charged the complete logical ciphertext length against
their own total account quota. Physical deduplication never changes user quota,
authorization or deletion semantics.

Quota reservation and reference creation occur in one database transaction.
The server must not increment quota without a durable reference or create a
reference without quota. Lowering a quota preserves existing objects and blocks
new reservations; it never silently evicts media.

When total quota is unavailable, the message descriptor may remain in E2EE
history while the attachment is visibly unavailable. The destination does not
partially store it. Sender and recipient receive stable `storage_full` state,
and retry requires available quota plus an unexpired origin object.

Normal accepted media remains until the recipient clears it, its disappearing
message expires, an authenticated delete-for-everyone control releases it, or
the account is terminated. Explicit clearing removes only that recipient's
reference and releases their quota. Other recipients and saved Drive copies are
unchanged.

`Save to Drive` decrypts and re-encrypts into a recipient-owned visible Drive
collection. After the new Drive object and encrypted ledger transition commit,
the recipient's Chat reference may be released so the logical usage moves from
Chat to Drive rather than remaining double-counted. The operation never adopts
server ciphertext by changing metadata because Drive headers bind a different
file, collection and epoch.

## 8. Encrypted attachment ledger

The homeserver's quota rows know only recipient, opaque object/reference IDs,
namespace, byte counts and lifecycle state. Named per-conversation totals are a
client projection over `ChatAttachmentLedgerV1` encrypted entities.

Each ledger entity is a `ChatAttachmentLedgerEnvelopeV1`:

```text
magic                    8 bytes  "KUTPCL1\0"
suite                    u16      ChatAttachmentLedgerSuiteId
purpose                  u8       1 = attachment entry
reserved                 u8       must be zero
account_incarnation_id   32 bytes SHA-256 incarnation identifier
entity_id                16 bytes random UUID
revision                 u64      non-zero, big-endian
previous_envelope_digest 32 bytes SHA-256, all-zero only at revision 1
nonce                    24 bytes XChaCha nonce
ciphertext_length        u32      big-endian
ciphertext               variable AEAD bytes including tag
```

The complete 128-byte fixed header is AEAD associated data and HKDF context.
An envelope plaintext is capped at 16 KiB and uses the project canonical
big-endian length-prefixed encoding, not signed JSON. It binds version,
conversation kind/reference, logical message UUID, attachment UUID, opaque
storage-reference UUID, exact logical ciphertext bytes, state, media class,
bounded display name, update time and an optional promoted Drive file UUID.
States are `active`, `cleared`, `saved_to_drive` and `expired`. The server
cannot classify or join an entry to a sender or conversation.

The server assigns a monotonically increasing account cursor after validating
an exact revision/predecessor transition. It preserves every opaque encrypted
revision append-only; a separate current pointer exists only for transactional
compare-and-swap. Bounded diff pages therefore replay the complete revision
chain, including authenticated encrypted tombstones. Operation IDs make retries
idempotent. A missing/skipped revision, stale revision, predecessor mismatch,
changed replay or unknown suite is rejected rather than last-write-wins.

Clients decrypt diff pages and build a disposable in-memory projection. A
new/recovered device rebuilds from cursor zero. The browser persists only a
compact identifier-free hash-chain pin over the ordered opaque revision feed;
it does not persist decrypted conversation or attachment metadata. On reload,
the client replays from zero and requires the exact pinned cursor and chain
digest before accepting any later revisions. Server withholding is an
availability failure; it cannot forge a valid entity. If a browser denies all
persistent local storage, the authenticated revision chains still verify but
cross-restart rollback pinning is unavailable on that device.

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
- The recipient server may already hold the durable encrypted copy. Device
  caching is local storage and is not charged again as server quota.
- The storage screen shows total quota, Drive bytes, Chat-media bytes and
  client-computed per-conversation totals, with review/clear actions.
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
  encryption, final-frame validation and descriptor parsing;
- [x] parser fuzzing for objects, descriptors, offers, acknowledgements, ledger
  envelopes and diff pages;
- [x] transaction-failure and restart tests for upload reservation/finalization,
  destination fetch, refcounting, quota, ledger revision and deletion;
- [x] replay, changed-idempotency, stolen/rotated capability, wrong destination,
  digest/length mismatch, truncation, trailing data, oversized stream and
  storage-full tests;
- [x] Direct Chat, Note to Self and MLS browser send/download/clear paths;
- [x] native photo/video capture through the same encrypted attachment path;
- [x] bounded voice-note recording, cancel cleanup and two-server encrypted
  exact-byte delivery through that path;
- [x] two-server offline/retry delivery with origin restart and destination object
  durability after origin deletion;
- [x] message-request non-allocation before acceptance;
- [x] destination schema/log/trace scans proving no sender identity, certificate,
  filename, MIME type, conversation ID, capability or digest is emitted; and
- [x] exact quota-category and client-side per-chat accounting across linked-device
  restart/rebuild.
