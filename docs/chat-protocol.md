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
manifest in one transaction. Publication requires exact registered-device and
stable account-key agreement. A normal update increments by one and names the
exact previous hash.

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
