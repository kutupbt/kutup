# kutup chat ("ileti") — wire protocol v1 (normative)

**Status:** normative v1 contract implemented by the server, shared Rust
engine, and web/WASM reference client. Android and iOS will freeze against the
same contract after the web feature milestone. It supersedes the
wire-affecting parts of `docs/research/11-federated-chat.md`,
`12-chat-improvements-for-clients.md`, and `13-chat-architecture-comparative-research.md`
— read those for *why*; read this for *what*.

The authenticated remote-policy, manifest-range, witness-audit, and
contacts-only sealed-sender extensions are also implemented. Their threat and
failure model is normative in
[`chat-security-threat-model.md`](./chat-security-threat-model.md).

**Normative language:** MUST / MUST NOT / SHOULD / MAY per RFC 2119.

The phase-2 server, shared Rust engine, and browser WASM client now consume this
contract. Kutup remains pre-production, but wire changes are no longer isolated
server reshapes: they require a coordinated proto/core/web change, shared
fixtures, and a deliberate protocol-version decision. Android and iOS bind the
same engine after the web feature and protocol milestones are complete.

**Element status tags** (every field/endpoint below carries one):
- **[IMPL]** — built in the server and/or shared client engine. The web client
  freezes against these shapes now.
- **[ADD]** — folded into the base v1 shape now (content schema, `sendId`,
  `cursor`, `Option` sender, capability block, per-account rate limit).
- **[RSV]** — a later *subsystem* (groups, receipts, typing, or
  attachments), but its **fields/shapes are baked into the v1 base types now**
  so building the subsystem later touches handlers, not the wire. Clients MUST
  tolerate reserved fields (accept, round-trip, ignore).

The [IMPL]/[ADD] distinction records implementation history; both are the v1
base. Later work is additive unless `protocolVersion` changes.

---

## 1. Versioning model (the compatibility contract)

Four things version **independently**. A change to one MUST NOT force a
lockstep change to the others.

| Axis | Where | Rule |
|---|---|---|
| **Suite** | `suite: u16` in bundles/envelopes; `DirectChatSuiteId` in Rust | Pins the whole crypto construction (KA + ratchet + KEM + libsignal wire). A new construction is a **new registry number**, never a mutation of an existing one. §4. |
| **Content schema** | `v: u16` inside the decrypted plaintext | The application payload shape. Unknown `kind` or higher `v` → render a placeholder, never drop. §6. |
| **Protocol/API** | `protocolVersion` in the capability block | The REST+WS envelope contract in this document. Additive by default; breaking bumps the integer and is advertised. §10. |
| **Federation** | `fedVersion` in `.well-known` + per-transaction | Server-to-server delivery format. §13. |

**Golden rules for every axis:**
1. **Unknown-but-newer degrades, never drops.** An unknown enum value,
   `kind`, or object field MUST be tolerated: ignore unknown fields; render a
   "message from a newer client" placeholder for an unknown `kind`; surface a
   "your client is out of date" hint for an unknown `suite`/`protocolVersion`
   rather than failing silently.
2. **No in-band downgrade a middleman can force.** Capability is advertised by
   *what a party publishes* (a bundle for a suite, a capability block). A
   client's explicit allowed-suite policy is enforced locally. The one
   permitted downgrade is libsignal's session-start SPQR negotiation, which is
   MAC-authenticated and locked in for the session (§4).
3. **Reserved fields are load-bearing.** A v1 implementation MUST serialize
   `Option`/absent reserved fields and MUST accept them when present, so a vN
   peer that populates them interoperates without a protocol bump.

JSON is camelCase; binary is base64 STANDARD; protocol ids (`registrationId`,
prekey ids) are `u32` matching libsignal's wire format; timestamps are RFC 3339.

---

## 2. Identity model

Three independent asymmetric identities exist per user. **Do not conflate them.**

| Identity | Purpose | Lifetime |
|---|---|---|
| Account X25519 keypair (`users.public_key`) | wraps drive collection keys | account |
| Collab device Ed25519 key (`devices` table) | signs collab frames | per collab device |
| **Chat device libsignal `IdentityKeyPair` + `registrationId`** | chat E2EE | per chat device |

### 2.1 Account and conversation addressing — [ADD]

An account has one stable routing identity: the existing server-local
`username`, rendered as `username@server` when federation is enabled. Usernames
remain lowercase ASCII (`[a-z0-9_-]{3,32}`); federation server names are
canonical lowercase DNS names. A pre-federation local store may retain the bare
username form and upgrades it when its home-server identity is known.

There is deliberately no second alias/handle namespace and no reserved alias
field or resolution endpoint. A changeable, non-unique display name and avatar
are profile data: neither may be used for routing, session keys, safety numbers,
blocking, group membership, or transparency proofs. QR codes and contact links
encode the canonical `username@server` address as
`kutup://contact/<percent-encoded-address>`. This URI is only a portable wrapper
for the canonical identity; it adds no alias or resolution layer.

Client APIs and persisted UI state identify conversations as the tagged union
`Direct { address: AccountAddress } | Group { groupId }`. The current `peer`
string remains a compatibility projection for direct-message history while web
callers migrate; it is not the long-term conversation key.

**[IMPL] Account self-authority key (device-list authenticity).** The research
(`13-…` §4.3) makes device-list authenticity a v1 requirement: server-assigned
device lists otherwise reproduce the malicious-homeserver break that defeated
Matrix/Megolm. v1 introduces a **self-signing account key** and a **signed
device manifest** (§5.3). The server and shared engine publish and verify this
manifest, and key transparency wraps each accepted version. Safety-number and
directory-change UX may continue to improve without changing the signed wire
format.

---

## 3. Suite registry — [IMPL], one correction

`suite` is a `u16` registry code point (like a TLS ciphersuite) and a closed
`DirectChatSuiteId` in Rust, never a Rust variant name on the wire. Unknown
selected suites fail closed; database rows cannot omit or default this value.

| Code | Name | Construction |
|---|---|---|
| `1` | `PqxdhTripleRatchetV1` | libsignal message-version 4. **PQXDH handshake:** X25519 + **ML-KEM-1024**. **Triple Ratchet messaging:** Double Ratchet + SPQR using **ML-KEM-768**. |

**Correction from `13-…` §4.4:** the ongoing SPQR ratchet uses **ML-KEM-768**,
not 1024. ML-KEM-1024 is the PQXDH *handshake* parameter only. Docs and
comments describing "the ratchet" as ML-KEM-1024/Kyber1024 are wrong. Wire and
mailbox sizing MUST budget kilobyte-scale ratchet headers (measured:
`PreKeySignalMessage` ~1.8 KB, steady `SignalMessage` ~100 B) arriving as
erasure-coded chunks.

A future suite (e.g. a post-libsignal migration) receives a new code point when
its complete construction is specified; no future value is reserved here. It
MUST NOT change the meaning of code point `1`.

---

## 4. Prekey directory — [IMPL] manifest + transparency

Endpoints (authenticated unless marked public; the WS validates its token
pre-upgrade):

| Method | Path | Status |
|---|---|---|
| `POST /api/chat/device` | register/re-register a chat device | [IMPL] |
| `GET /api/chat/device` | list caller's chat devices | [IMPL] |
| `DELETE /api/chat/device/{deviceId}` | revoke | [IMPL] |
| `PUT /api/chat/keys` | rotate signed / last-resort; replenish one-time | [IMPL] |
| `GET /api/chat/keys/count` | pool sizes | [IMPL] |
| `GET /api/chat/transparency/checkpoint` | public signed monitor head + consistency proof | [IMPL] |
| `POST /api/chat/transparency/witness` | public allowlisted witness submission | [IMPL] |
| `GET /api/chat/users/{username}/keys` | fetch bundles (consumes one-time keys; authenticated self-sync mode below) | [IMPL] |
| `POST /api/chat/users/{username}/messages` | multi-device send | [IMPL] |
| `POST /api/chat/sync/messages` | encrypted sent transcript to caller's other devices | [IMPL] |
| `GET /api/chat/messages` | drain (oldest-first) | [IMPL] |
| `POST /api/chat/messages/ack` | batch ack | [IMPL] |
| `POST /api/chat/ws-ticket` | mint one-time browser WS credential | [IMPL] |
| `GET /api/chat/ws` | WebSocket | [IMPL] |

**Rules that stay:** device ids are server-assigned lowest-free `1..=127`;
re-registration replaces the directory entry and wipes that device's mailbox;
every bundle MUST carry a `kyberPreKey` (one-time or last-resort — PQ is never
optional); one-time EC prekeys unsigned, signed prekey + all Kyber prekeys
signed (XEd25519 by the device identity key); upload batches ≤ 100.

**[IMPL] Bundle-fetch rate limits.** `GET …/keys` is limited to 30/min per
authenticated account (`RATE_LIMIT_CHAT_KEYS_PER_MIN`), with a deliberately
coarser 120/min IP outer wall (`RATE_LIMIT_CHAT_KEYS_IP_PER_MIN`). Mobile
clients behind CGNAT therefore do not share the primary budget, while a
hostile account cannot drain pools by moving across IPs. (`13-…` §7.)

**[IMPL] Own-device bundle mode.** A client preparing a linked-device
transcript calls its own bundle URL with `?syncDeviceId=<current>`. The response
still contains every device in the signed manifest, so verification remains
exact. The server serves the current device with its reusable last-resort Kyber
key and no one-time EC key; it consumes one-time keys only for the other
devices. The engine verifies the complete response and then omits the current
device from encryption.

Every bundle request also sends `transparencyTreeSize=<u64>` using the highest
checkpoint durably verified for that homeserver (`0` on first observation).
The response carries inclusion of the exact manifest and an append-only
consistency proof from that size (§5.4). The counter is serialized losslessly;
browser/WASM transports pass it as a decimal string.

**[IMPL] Staged local EC-prekey deletion.** A server stops serving a one-time
prekey as soon as it allocates that key to one bundle fetch. The client does not
physically delete the corresponding private EC prekey when libsignal consumes
it: it marks it used, keeps it loadable for late concurrent prekey messages, and
sweeps it after a 14-day grace window (matching the conservative OMEMO practice
in `13-…` §6). The current crypto operation's overlay still sees the key as
consumed, preserving libsignal semantics.

**[IMPL] Crash-safe low-watermark refill.** `Engine::maintain_prekeys` checks
the server pool, refills below a caller-selected watermark (recommended 20,
target 100), and caps each key-type batch at 100. It atomically persists the new
private keys and the exact `ReplenishKeysRequest` before networking. A lost
response or app restart retries that same idempotent request; the server enforces
the 100-key-per-type limit.

### 4.x Device manifest in the bundle response — [IMPL]

`UserPreKeyBundlesResponse` carries an optional `manifest` (§5.3) and
`transparency` proof (§5.4). A verifying
client checks each returned `deviceId` against the signed manifest before
establishing a session, so the server cannot inject a device. When the server
advertises `manifests: true` / `keyTransparency: true`, absence or any mismatch
is a hard failure. A
development client may explicitly permit TOFU only against a server that
advertises `manifests: false`.

---

## 5. Keys, prekeys, and the device manifest

### 5.1 `EcPreKey` / `KemPreKey` — [IMPL]

```
EcPreKey  { keyId: u32, publicKey: b64, signature: b64? }   // signature None only for one-time EC
KemPreKey { keyId: u32, publicKey: b64, signature: b64 }    // always signed
```

### 5.2 `RegisterChatDeviceRequest` — [IMPL] + [RSV] fields

```
{ suite, registrationId, identityKey, signedPreKey, lastResortKyberPreKey,
  oneTimePreKeys[], oneTimeKyberPreKeys[], name,
  deviceSignature: b64?   // [RSV] identity key signed by the account self-authority key (§5.3)
}
```
`deviceSignature` is reserved for a future atomic registration attestation. The
implemented manifest already signs the exact identity and registration id for
every device, so clients do not rely on this optional field in v1.

### 5.3 Device manifest — [IMPL], the device-list-authenticity primitive

A client that holds the account self-authority private key publishes a signed
manifest of its current chat device set:

```
DeviceManifest {
  version: u64,                 // monotonic; higher wins
  previousHash: hex?,           // absent only in v1; hash-links each update
  devices: [ { deviceId: u32, identityKey: b64, registrationId: u32 } ],
  issuedAt: rfc3339,
  authorityKeyId: hex,          // SHA-256(raw selfAuthorityKey)
  selfAuthorityKey: b64,        // account self-signing PUBLIC key
  signature: b64                // Ed25519 over the domain-separated canonical record
}
```

- The Ed25519 self-authority is deterministically derived from the account
  master key with HKDF-SHA-256 (`kutup/chat/self-authority/v1`). Every recovered
  account obtains the same authority; the server never sees its private half.
- `POST /api/chat/manifest` publishes it after verifying the signature, strict
  version/hash continuity, stable authority, and an exact match with the
  registered device set. `GET /api/chat/users/{username}/manifest` and the
  `manifest` field in the bundles response serve the latest record.
- On first install the client signs only its locally generated device. A newly
  linked/reinstalled client verifies the prior account manifest, then adds or
  replaces only its own locally held identity; it MUST NOT sign a device list
  learned from the server. The server's exact-match check turns any additional
  injected directory entry into a publication conflict. Device removal is a
  separate explicit account action, not automatic reconciliation.
- Peers verify `signature` against `selfAuthorityKey` and refuse to encrypt to
  any bundle device not in the signed set, or when registration/identity values
  differ. The server distributes but cannot forge membership. Device changes
  temporarily fail closed until an authenticated client publishes the next
  manifest.
- **Key transparency** (§5.4) wraps every accepted manifest version in an
  append-only log in the same transaction as publication.

Clients pin the first valid self-authority (TOFU), persist the highest observed
manifest version/hash, and reject rollback, same-version equivocation, authority
replacement, or a bad link between consecutive versions. A valid signed jump
across versions missed while offline is safe to use but records a continuity
gap for later transparency auditing. Clients retain the existing safety-number-
change interstitial for identity changes. The implemented log removes silent
history rewriting for a returning client, and the authenticated current map
prevents an operator from selecting an old manifest inside the checkpoint it
serves. Operator-signed checkpoints and optional independent witness quorum
(§5.4) now make a fork attributable and detectable when the application obtains
those verifier keys independently. A web app that downloads both its code and
trust policy from the same compromised origin cannot create that independence
by itself; safety-number comparison remains the user-visible out-of-band path.

### 5.4 Signed manifest transparency and independent witnesses — [IMPL]

Each homeserver database owns a stable random 32-byte `logId`. Publishing a
non-idempotent manifest appends this canonical leaf:

```
ManifestTransparencyLeaf {
  username, manifestVersion, manifestHash, authorityKeyId
}
```

Leaves and nodes use RFC 6962 domain separation (`SHA-256(0x00 || leaf)` and
`SHA-256(0x01 || left || right)`). The database stores every complete aligned
subtree, so appends plus inclusion/consistency proofs are logarithmic. A bundle
response contains:

```
ManifestTransparencyProof {
  leafIndex, leaf,
  checkpoint: { logId, treeSize, rootHash },
  inclusion[], consistencyFrom, consistency[],
  map: {
    rootHash, checkpointLeafIndex, checkpointInclusion[],
    siblings[]: { depth, hash }
  },
  authentication: {
    issuedAt, operatorKeyId, operatorPublicKey, operatorSignature,
    witnesses[]: { witnessId, observedAt, keyId, publicKey, signature }
  }
}
```

The client verifies that the leaf exactly names the requested account and
served signed manifest and verifies its chronological inclusion. The server
also maintains a 256-level sparse Merkle map keyed by a domain-separated
SHA-256 of the canonical local username. Its value commits to the manifest
version/hash and authority id. Default siblings are omitted from the wire. A
map-root commitment is always appended as the **final** chronological-log leaf
of a publication transaction; the client verifies both sparse membership and
that final-leaf inclusion before accepting the value. This closes the
"included somewhere, but not current" gap without creating a second trust root.

The client then verifies consistency from its highest durable checkpoint for
that homeserver. It also persists the accepted manifest event position per
account: an unchanged value must retain that position and an update must move
forward. Manifest trust, the per-account monitor position, and the global
checkpoint advance atomically before any session is created. A smaller server
tree, changed `logId`, same-size different root, stale map-root commitment,
malformed audit/map path, monitor-position rollback, or omitted proof fails
closed. Federated directory reads carry the remote proof unchanged and
destination-bind `transparencyTreeSize` in the signed request URI.

Every non-empty checkpoint is signed once by a persistent, dedicated Ed25519
operator key over the exact `logId`, tree size/root, sparse-map root, issuance
time, and operator key id. The signed record is stored transactionally rather
than regenerated per request. The server refuses a silent operator-key change.
Clients verify the signature, pin the operator identity and issuance time with
the checkpoint, and reject rollback, same-size mutation, or key replacement
without a future authenticated rotation record.

An independently deployed `kutup-transparency-witness` polls the public
`GET /api/chat/transparency/checkpoint?fromTreeSize=N` endpoint, verifies the
operator policy and consistency from its own durable state, signs that exact
operator statement, submits it to `POST /api/chat/transparency/witness`, and
only then advances its local state. The server accepts only configured witness
identities/keys, makes replay idempotent, and rejects a contradictory statement
at the same tree size. A client policy contains verifier keys and a quorum per
homeserver scope; response-carried keys never add trust. Missing quorum fails
closed before manifest or session state mutates.

The web client independently polls local and remote checkpoints on chat open,
first remote use, network recovery, foreground return, WebSocket reconnect, and
before stale evidence is used. Remote requests go to a same-origin domain route;
the server resolves the destination through the unified federation transport,
never from a client URL. The client verifies the complete federation identity
and typed policy history before accepting the checkpoint. Endpoint
unavailability retains the last valid pin and is displayed as a warning;
rollback, signature/proof, policy-chain, silent key/log replacement, or signed
fork failure persists across reload and blocks new sends for that domain.
Existing durable ciphertext may still retry, and receiving an established
session does not require a new directory lookup.

This is materially closer to Signal's distinguished-head/auditor trust shape,
but it is not wire-compatible with Signal's private KT service. Kutup uses a
domain-separated username hash rather than Signal's VRF-derived index, so it
does not claim Signal's VRF index-privacy property.

Every accepted manifest is retained in append-only history. A skipped client
version remains pending while the client retrieves checkpoint-bound pages of at
most 64 complete manifests, transparency leaves, individual RFC6962 inclusion
paths, consistency proof, and latest sparse-map proof. Exact version increments,
`previousHash`, signatures, authority continuity, leaves, one shared checkpoint,
and current-map binding must all verify before one atomic commit. First
observation above version 1 starts at version 1.

Each witness serves a bounded signed `WitnessViewV1`. The scheduled server
auditor and independently deployable `kutup-transparency-auditor` use the same
verifier for operator/witness and witness/witness comparisons. A
`TransparencyForkEvidenceV1` retains the original signed statements. Only a
directly verifiable contradiction blocks; unavailable or withholding witnesses
warn without overriding a checkpoint that already meets quorum. Safety numbers
remain the explicit out-of-band verification path throughout.

---

## 6. Inner content schema — [ADD], the top cross-client item

The single biggest compatibility risk: nothing today defines what's *inside*
the ciphertext. `content` is a libsignal envelope around opaque plaintext, and
three clients would otherwise invent that plaintext independently. v1 defines
it, owned by `kutup-chat-proto` (server never sees it, but one definition
serves all clients + fixtures).

**Decrypted plaintext MUST be a JSON object:**

```jsonc
{
  "v": 1,                        // content schema version (independent of suite)
  "kind": "text",                // registry below
  "sentAt": "2026-07-13T10:00:00Z", // SENDER clock (serverTimestamp is arrival only)
  "seq": 41,                     // per-(sender,senderDevice) monotonic; enables per-sender ordering
  "messageId": "018f…",          // stable logical id; equal to transport sendId
  "profileKey": "base64…",       // optional 32-byte profile capability, inside E2EE
  "body": { /* per-kind */ }
}
```

**[ADD] `messageId`.** Every newly authored user-visible event carries its
sender-generated logical `sendId` inside the ciphertext as `messageId`. Receipts,
replies, reactions, edits, and tombstones reference this stable id, not a
recipient mailbox id. Legacy v1 plaintext without `messageId` remains readable;
the client may use its local history id for display but MUST NOT emit a remote
reference to that synthetic id.

**`kind` registry:**

| kind | phase | body |
|---|---|---|
| `text` | 2b [ADD] | `{ "text": string }` |
| `sentTranscript` | 2b [IMPL] | `{ "sendId", "peer", "timestampMs", "content": ChatContent }` — encrypted own-device synchronization wrapper (§7.3), never rendered directly |
| `contactControl` | 4 [IMPL] | `{ "peer", "state", "previousState?", "revision", "sourceDeviceId", "updatedAtMs" }` — authenticated encrypted linked-device relationship update (§7.4), never rendered directly |
| `profileKeyUpdate` | 4 [IMPL] | `{}` with the key in top-level `profileKey` — Signal-style invisible capability update (§7.5), never rendered directly |
| `receipt` | later [RSV] | `{ "type": "delivered"\|"read", "ids": [seq…] }` — E2EE content, never a server feature |
| `typing` | later [RSV] | `{ "state": "started"\|"stopped" }` — ephemeral; a client MAY drop |
| `attachment` | 5 [RSV] | `{ "fileId", "key", "digest", "size", "mimeType", "name" }` — pointer into the E2EE drive (tus); the blob rides the drive, not the mailbox |
| `groupControl` | 4 [RSV] | encrypted group-state operations (§12) |
| `sessionControl` | later [RSV] | e.g. explicit session-reset notice |

**Rules:**
- Unknown `kind` → render "message from a newer client"; **never drop.**
- Unknown top-level field → ignore, preserve on round-trip where practical.
- `v` bumps only for an incompatible shape change; a vN reader handles v1.
- **Ordering:** a UI MUST order by `(sender, senderDevice, seq)` within a
  sender and interleave senders by `sentAt`, using `serverTimestamp` only as a
  tiebreak. `serverTimestamp` is arrival order and, under federation, a
  *different* server's clock — never the sole sort key.

---

## 7. Send, fan-out, idempotency — [IMPL] + [ADD]

### 7.1 `OutgoingEnvelope` / `SendMessagesRequest` — [IMPL] + [ADD]

```
OutgoingEnvelope { deviceId, registrationId, envelopeType, suite, content }
SendMessagesRequest {
  senderDeviceId,
  envelopes: [OutgoingEnvelope],
  sendId: uuid   // [ADD] idempotency key
}
```

**[ADD] `sendId`.** A client-generated UUID prevents a timeout followed by a
retry from storing duplicate mailbox rows (the request can succeed while the
response is lost — the mobile norm). The server dedupes per
`(senderUser, senderDevice, sendId, deliveryScope)` within a retention window
(unique constraint on the insert batch; `ON CONFLICT DO NOTHING`; return the
original 200). `deliveryScope` separates the recipient delivery from the
same-send-id own-device transcript delivery. This makes each durable outbox leg
safe to retry blindly — the property every mobile client needs. (`12-…` §2.)

### 7.2 Device-list contract — [IMPL]

The `deviceId` set MUST exactly match the recipient's active devices or the
server rejects the whole send with **409 `DeviceListMismatch`**:

```
{ missingDevices: [u32], staleDevices: [u32], extraDevices: [u32] }
```

`staleDevices` = wrong `registrationId` (peer reinstalled) → drop the session,
re-fetch the bundle, re-establish. On 409 the client re-fetches for
missing/stale, re-encrypts, resends. Retry only on non-2xx (with `sendId`,
even a blind retry is now safe).

### 7.3 Note to Self and sent transcripts — [IMPL]

Note to Self is a special self-recipient direct conversation, not a one-member
group. The originating device atomically persists the original `ChatContent` as
outgoing history and, for linked devices, encrypts a `sentTranscript` wrapper
to each other active device. The wrapper carries the stable logical `sendId`,
conversation `peer`, original history timestamp, and original content. It is
opaque libsignal ciphertext to the server.

`POST /api/chat/sync/messages` authenticates the sending device and applies the
same missing/stale/extra exact-set check as a direct send, except the expected
recipient set is the caller's active devices **minus `senderDeviceId`**. It
stores rows only in those devices' mailboxes. A receiving client treats a
`sentTranscript` as outgoing history only when libsignal decryption succeeds
and the envelope sender is another device of the local account; otherwise it
cannot acquire this privileged meaning. Decrypt, outgoing-history persistence,
inbound-journal transition, and later ack retain the normal atomic ordering.

For a single-device account, encryption produces no envelopes. The original
note is marked delivered locally and no mailbox POST is made. A crash between
outbox persistence and that completion is still recoverable from the durable
outbox.

An ordinary direct send atomically stages two independently durable legs under
one logical `sendId`: ciphertext for the peer's active devices and, when linked
devices exist, an encrypted sent transcript for the sender's other devices.
Each leg has its own exact-device recovery and retry state. Recipient success is
the user-visible delivery result and is not downgraded by a transcript transport
failure; the outbox retains the transcript leg for a later reconcile or restart.
Conversely, a successful transcript leg is not repeated while a failed recipient
leg is retried.

### 7.4 Contact state, message requests, and blocking — [IMPL]

Relationship state is client-owned E2EE metadata keyed by the canonical account
address. It is never uploaded as a server-side social graph. Absence means an
unknown peer; persisted states are `pendingIncoming`, `pendingOutgoing`,
`accepted`, `rejected`, and `blocked`.

- A first decrypted message from an unknown or previously rejected peer is
  atomically stored with `pendingIncoming` and shown only in the request inbox.
  A first outbound message records `pendingOutgoing`; a valid reply promotes it
  to `accepted`. A pending incoming request MUST be accepted before replying.
- Reject atomically changes the relationship to `rejected` and deletes that
  request's retained plaintext. A later valid message may create a new request.
- Block retains prior history and the pre-block state for an explicit unblock.
  New envelopes are still authenticated and decrypted so libsignal's ratchet,
  replay protection, mailbox cursor, and acknowledgement advance normally, but
  their plaintext is not retained or surfaced. The server cannot distinguish
  this from ordinary successful delivery.
- Existing pre-contact-state stores bootstrap peers already present in local
  history as `accepted`; an upgrade MUST NOT reclassify established chats as
  requests.

Explicit accept/reject/block/unblock transitions, plus observed request/reply
transitions that supersede an older explicit revision, are synchronized to
linked devices as a `contactControl` nested inside a `sentTranscript`. A receiver grants
that control meaning only after successful libsignal decryption from another
device of the local account, with `sourceDeviceId` equal to the envelope sender.
Controls converge by lexicographic `(revision, sourceDeviceId)`; a local explicit
change increments the highest observed revision. The deterministic control
`sendId`, contact record, and pending marker are durable before networking, so
offline/restart retries are idempotent. Ordinary first-send transcripts let a
linked device infer `pendingOutgoing` without a separate plaintext social graph.

Receipts and typing are not used as implicit acceptance signals.

### 7.5 Encrypted profiles and automatic visibility — [IMPL]

Display names and avatars are non-identifying profile data. Each account has a
random 32-byte profile key generated on a client. Names use AES-256-GCM with a
fresh 12-byte nonce after zero-padding UTF-8 to Signal's first fitting 53- or
257-byte bucket. Avatars are separately encrypted; v1 accepts PNG, JPEG, or
WebP plaintext up to 512 KiB. The server stores only ciphertext.

The profile key derives two domain-separated capabilities with HKDF-SHA-256: a
32-byte lowercase-hex `version` and a 16-byte fetch access key. Each versioned
server row contains the version, `(revision, sourceDeviceId)`, encrypted name/avatar, a
SHA-256 verifier for the access key, and the random profile key encrypted under
an account-master-key-derived wrapping key for owner linked-device recovery.
One row is the owner-visible current head; older ciphertext versions remain
capability-readable so an in-flight rotation does not break peers still holding
the old key. A pending new key is never included in an outgoing message before
its encrypted profile upload is confirmed.
The owner uses `GET|PUT /api/chat/profile`; a peer presents version plus
`X-Kutup-Profile-Access-Key` to
`GET /api/chat/users/{username}/profile/{version}`. Federated lookup uses the
same bearer capability over the destination-bound signed server channel.

Visibility is automatic, matching Signal rather than a server-hosted privacy
matrix:

- ordinary first/outgoing messages carry the key inside their existing E2EE
  `ChatContent`, so an incoming request can show the sender's profile;
- accepting a request and later profile edits send an invisible
  `profileKeyUpdate` to accepted or pending-outgoing contacts;
- a dedicated update from a merely pending-incoming sender is ignored and
  remains invisible;
- blocking first commits the local block, then rotates and republishes the
  random key and redistributes it only to the remaining authorized contacts.

The durable client store records the exact pending opaque upload and profile-key
fan-out marker before networking. Concurrent linked-device revisions converge
by `(revision, sourceDeviceId)`; a stale pending edit rebases on the owner-only
current profile without undoing a profile-key rotation. Old capabilities can
still read their old ciphertext version, but cannot read future profile changes;
rotation cannot erase profile plaintext a peer already received or copied.

### 7.6 [IMPL] sealed-delivery capability

Contacts derive a 16-byte capability with HKDF-SHA-256 from the profile key,
canonical recipient address, and `kutup/sealed-delivery-capability/v1`. The
profile transaction stores only its SHA-256 verifier. Anonymous bundle and send
requests carry the raw capability in their bounded JSON body; it never appears
in a URL, log, metric label, or mailbox. Unknown recipients and invalid
capabilities return the same response.

---

## 8. Mailbox drain / ack — [IMPL] + [ADD] cursor

### 8.1 `DeliveredEnvelope` — [IMPL] + [ADD]

```
DeliveredEnvelope {
  id: uuid,                 // mailbox id = ack handle
  sender: string?,          // [ADD→RSV] see below
  senderDeviceId, envelopeType, suite, content,
  serverTimestamp: rfc3339,
  cursor: u64               // [ADD] monotonic order key (see 8.3)
}
```

**[ADD→RSV] `sender` becomes `Option`.** Today `sender` is a bare username; it
becomes `user@domain` under federation. Per `13-…` §4.2, model it as
**`Option<String>` in all clients now** so sealed sender (which removes it)
later is not a breaking change. v1 servers still populate it.

### 8.2 Drain / ack — [IMPL]

`GET /api/chat/messages?deviceId=N&limit=M` (M ≤ 500), oldest-first, returns
`MailboxPage { envelopes, more }`. Loop while `more`. `POST
/api/chat/messages/ack` with `{ ids: [uuid…] }` deletes processed envelopes.
**The mailbox is the source of truth; WS push is a latency optimization** —
clients MUST drain and ack over REST even for WS-delivered envelopes.

### 8.3 [ADD] monotonic cursor (from XMPP MAM)

Add a server-assigned **monotonic `cursor`** (bigint) per mailbox row, ordered
`(cursor)`. It is the **paging cursor and the dedup key** (`13-…` §6, XEP-0359
practice). Drain accepts `?after=<cursor>`; the server returns `limit+1`
internally to compute `more`. Clients dedupe by `cursor` (or `id`), tolerating
a WS envelope and its REST-drained twin. Servers MUST strip any client-supplied
ordering/id fields — the server assigns them.

### 8.4 [IMPL] retention + device expiry

Mailbox rows expire after `CHAT_MAILBOX_RETENTION_DAYS` (default 30), send-id
dedup rows after `CHAT_SEND_RETENTION_DAYS` (default 30), and chat devices with
no authenticated device-scoped activity expire after
`CHAT_DEVICE_EXPIRY_DAYS` (default 90) with their prekeys and mailbox. `0`
disables each policy. Device expiry deliberately makes the signed manifest
fail closed until an active account device explicitly authorizes that removal.
Unbounded mailboxes for dead devices are an abuse vector and a fan-out tax.
Mailbox/device windows are exposed via the capability block (§10).

---

## 9. WebSocket — [IMPL]

Browsers first call authenticated `POST /api/chat/ws-ticket?deviceId=N`, then
connect to `GET /api/chat/ws?ticket=<opaque>`. The ticket contains 32 random
bytes, expires after 60 seconds, is stored only as a SHA-256 hash, is bound to
the authenticated user/device, and is atomically consumed once. Native clients
use `GET /api/chat/ws?deviceId=N` with `Authorization: Bearer <jwt>` and MUST
NOT put the JWT in a query string. On connect the server sends exactly
one `{"type":"drainMailbox"}` (drain the backlog over REST), then pushes
`{"type":"envelope", envelope}` frames. Server ignores client frames. Server
MAY force-close on backpressure or revocation → reconnect with jittered
backoff and re-drain.

```
ChatWsServerMessage (tagged "type"):
  { type: "envelope", envelope: DeliveredEnvelope }
  { type: "drainMailbox" }
```

Reusable JWTs are never accepted in the chat WebSocket query string because
URLs land in browser history, proxy logs, and tracing. (`12-…` §5.)

---

## 10. Capability advertisement — [ADD]

Clients feature-gate chat per server and must not show chat UI on a server
lacking the routes. The server publishes a `chat` block in the existing public
`GET /api/auth/settings`:

```jsonc
"chat": {
  "enabled": true,
  "protocolVersion": 1,
  "suites": [1],
  "maxContentBytes": 65536,        // enforced on send (closes a mailbox-abuse hole)
  "mailboxRetentionDays": 30,
  "deviceExpiryDays": 90,
  "serverName": "chat.example",   // present exactly when federation is true
  "federation": true,
  "manifests": true,               // signed device directory is available
  "profiles": true,                // encrypted profiles + capability lookup
  "keyTransparency": true,         // manifest inclusion + consistency proofs
  "transparencyOperatorKeyId": "<64 lowercase hex>",
  "transparencyOperatorPublicKey": "<base64 Ed25519 public key>",
  "transparencyWitnesses": [
    { "witnessId": "audit.example", "keyId": "<hex>", "publicKey": "<base64>" }
  ],
  "transparencyWitnessQuorum": 1,
  "sealedSender": true             // only with a complete authenticated service policy
}
```

This public block advertises server availability, not an authenticated device
capability. Clients select only locally implemented suite codes; unknown extra
codes are ignored and never treated as supported. Authenticated per-device
suite capability belongs in the next signed-manifest format and must ship
before a second Direct Chat suite.

`maxContentBytes` is enforced on send and is the budget clients use for
attachment-pointer payloads.
The optional `serverName` is the stable suffix used to render local accounts as
`username@server`; clients reject an advertised federation capability without
it. A production client also rejects `keyTransparency: true` without a valid
operator key or with a witness quorum larger than the advertised verifier set.
These capability values describe deployment policy; a high-assurance client
must obtain/pin the same values independently of the homeserver response.
Clients use sealed delivery only when the flag and authenticated service policy
are both present and locally supported. (`12-…` §3.)

---

## 11. Sealed sender — [IMPL], contacts only

Per `13-…` §4.2, sealed sender ships as one gated three-part system:

1. **Sender certificates** — a trust-root key signs a server certificate,
   which signs short-lived per-user sender certs (identity key + expiry). Fully
   self-hostable from libsignal primitives; the recipient validates
   client-side.
2. **Delivery-capability abuse gate** (§7.6): the only spam signal once
   server-side sender auth is dropped.
3. **Contacts-only delivery** with profile-key/capability rotation on block.

The offline trust root signs an online libsignal server certificate; normal
operation has only the online private key. Its authenticated federation feature
policy publishes roots, activation/revocation windows, server-certificate IDs,
suite, 24-hour sender-certificate lifetime, and clock skew. A sender certificate
binds canonical `username@server`, device ID, manifest identity key, expiry, and
server certificate. After outer decryption the recipient validates the policy
chain, root/server/sender chain, time/domain/suite, envelope identity, and the
transparency-verified complete manifest before advancing the inner ratchet.

Local anonymous routes send no bearer token, cookie, or authenticated session.
Federated transactions contain only origin domain, recipient, random send ID,
capability, origin sequence, and opaque per-device envelopes. Destination
transactions, mailbox rows, pushes, and logs have no sender identity. The
origin may retain its authenticated sender only in its private retry outbox.
First contact remains identified; Note to Self and linked-device sync remain
authenticated. Once a relationship establishes sealed delivery, failure never
causes identified fallback.

Database counters enforce 30 bundle requests/minute per capability; 120 sealed
sends/minute and 10,000/day per recipient capability; 600/minute per federation
origin; 32 envelopes and 1 MiB/request. A 60/minute/IP process-local limiter is
only an outer wall. Local dedupe binds recipient, capability hash, and UUID send
ID; federation retains signed origin sequences. Sealed sender is metadata
*minimization*, not traffic-analysis resistance.

---

## 12. Groups — [RSV], the GV2 pattern (NOT client blobs)

Per the decisive `13-…` §4.1 finding: **do not ship client-managed membership
blobs** (Signal shipped that exact design in 2014 and abandoned it — update
races, unenforceable roles). v1 reserves the shape for the **GV2 pattern**:
server-held *authoritative, versioned, encrypted* group state.

Reserved shape (phase 4):

```
GroupState {
  groupId: b64,                 // random, opaque to server
  version: u64,                 // optimistic-concurrency counter (anti-race)
  encryptedState: b64,          // membership + metadata, sealed under a client-only GroupMasterKey
  membershipManifest: b64       // signed by an admin device (chains to §5.3 authority) — enforceable roles
}
```

- Message crypto: **sender keys** (`SenderKeyDistributionMessage` +
  `group_encrypt`/`group_decrypt`) — adoptable independently of anonymous
  credentials.
- State writes use **optimistic concurrency** (compare-and-set on `version`),
  not last-writer-wins — the fix for the race that killed the blob model.
- The server sees group size and access patterns (accepted GV2 leakage), never
  membership plaintext.
- Full zkgroup anonymous-credential issuance (`13-…` §7) is a later upgrade the
  data model does not preclude; v1 uses the signed membership manifest for
  roles. `groupControl` content messages (§6) carry state-change operations.

No group endpoints in v1. The fields exist so phase 4 is additive.

---

## 13. Federation — [PARTIAL], transport-only, no room DAG

Confirmed by CVE-grade evidence (`13-…` §3): **reject** Matrix's replicated
room DAG + state resolution; keep signed-ciphertext delivery between mailbox
servers. Discovery, server authentication, canonical routing, remote device
discovery, durable message delivery, and gap replay are implemented. A server
advertises `chat.federation: true` only when its administrator configures a
persistent signing identity:

- **Discovery:** `GET /.well-known/kutup/federation.json` returns the signed
  federation v2 document: canonical server, delegated `apiBase`, typed
  capabilities, current identity document/hash, validity window, and
  signature. Immutable history lives at
  `/.well-known/kutup/federation/identity/{sequence}.json`. See the normative
  common transport contract in [`federation-protocol.md`](federation-protocol.md).
- **Addressing:** `sender`/recipient become `user@domain`. Clients model
  account addresses as `{ username, server: Option }` and conversations as a
  tagged `Direct`/`Group` identity, so phase 3 changes routing, not identity.
- **Request auth (`13-…` §3):** the strict federation v2 RFC 9421/9530 profile
  binds the method, authority, path/query, exact-body digest, content type,
  version, typed feature, origin, destination, time window, key ID, and nonce.
  The receiver MUST reply **401 on destination mismatch**. Every authenticated
  success or typed application error is response-signed and request-bound.
- **Remote device directory [IMPL]:** the authenticated local endpoint accepts
  `username@server`, discovers the remote server, and makes a signed lookup.
  The remote read returns the account-signed manifest, its remote-log
  transparency proof, and reusable last-resort PQ bundles without consuming
  one-time keys, so replay cannot exhaust a recipient's prekey pool. Clients
  verify both manifest and proof; server signing authenticates transport, not
  the device set.
- **Delivery [IMPL] — adopt Matrix's retry rule *plus* what Matrix gets for free from
  its DAG and kutup does not:** a sending server MUST retry a transaction until
  `200 OK` before sending the next transaction to that destination (in-order
  per destination), backed by a **durable** queue. Because kutup has **no DAG
  backfill safety net**, each s2s stream MUST carry a **per-destination
  monotonic sequence number**, and the receiver MUST detect and request missing
  ranges (explicit gap detection). A never-give-up durable queue + sequence
  gaps replaces backfill; without it a long partition silently loses messages.
  Kutup persists a transaction before attempting HTTPS; transient failure stays
  queued but also returns 503 so the web engine retains its own encrypted
  outbox. A remote device mismatch blocks that sequence and is returned to the
  engine for signed-directory refresh and re-encryption under the same
  `sendId`. Accepted transactions, mailbox rows, and the inbound sequence
  advance commit atomically. Retained delivered transactions can be replayed
  when a receiver reports `sequenceGap`. A missing recipient or an account with
  no active devices is a typed terminal rejection that still advances the s2s
  sequence; the originating client sees a delivery error, while later messages
  to other accounts on that server remain unblocked. If a replay record has
  expired, the receiver's contiguous sequence high-water mark safely
  acknowledges the already-consumed sequence without replaying ciphertext.
- **Current abuse and trust controls [IMPL]:** authenticated request/response
  signatures, clock/replay/body bounds, DNS-rebinding/SSRF rejection, coarse
  per-IP rate limiting, a global stop, feature-scoped `disabled`, `allowlist`,
  `blocklist`, and `open` modes, trust floors, and per-domain directional
  admission/trust rules. Cryptographically verified first contact creates an
  immutable TOFU pin; administrators can verify the full fingerprint. Valid
  dual-signed rotation advances automatically, while rollback, gaps, silent
  replacement, and competing history quarantine the peer. Disabled Chat also
  hides discovery.
- **Remaining federation controls [TODO]:** general per-remote shapers and an
  overload circuit breaker. Sealed delivery has its own durable per-origin
  shaper; authenticated remote transparency policy/monitoring is implemented.

The transport foundation is exercised by `scripts/test-chat-federation.sh` in
an isolated `a.test`/`b.test` Docker topology. The live contract covers signed
discovery and directory reads, canonical sender delivery, replay-safe bundles,
send-id deduplication, remote device-mismatch recovery, terminal recipient
rejection, and durable retry across destination outage plus origin restart. The
harness also covers the four admission modes, directional inbound/outbound
rules, disabled discovery/capabilities, and policy audit entries. Its common
transport private-network/HTTP allowance is explicit and rejected unless
`APP_ENV=test`; production continues to require HTTPS and public resolved
destinations.

---

## 14. Reserved-fields summary (bake into v1 now)

| Field / shape | Where | Unlocks | Phase |
|---|---|---|---|
| `sender: Option<String>` | `DeliveredEnvelope` | sealed sender / federation addr | **implemented** |
| `sendId: uuid` | `SendMessagesRequest` | idempotent retries | **2b [ADD]** |
| `cursor: u64` | `DeliveredEnvelope` + `?after=` | paging + dedup | **2b [ADD]** |
| content schema `{v,kind,sentAt,seq,body}` | decrypted plaintext | all app payloads | **2b [ADD]** |
| `chat` capability block | `/api/auth/settings` | per-server feature gating | **2b [ADD]** |
| `deviceSignature` + `DeviceManifest` + manifest endpoints | device reg + directory | device-list authenticity | 2/3 |
| capability body field | anonymous bundle/send DTOs | sealed-sender abuse gate | **implemented** |
| `ws-ticket` endpoint | WS auth | keep JWT out of logs | 2b/later |
| `GroupState { groupId, version, encryptedState, membershipManifest }` | group endpoints | GV2 groups | 4 |
| `.well-known` + `user@domain` addr + per-destination sequence | federation | transport federation | 3 |

---

## 15. Open questions (carried from `13-…` §11)

- Key transparency uses authenticated remote policy chains, independent
  witnesses, range recovery, scheduled monitoring, and shared cross-view
  auditing without depending on one global service.
- Does GV2-pattern server-held encrypted group state compose with a future
  MLS migration, or does choosing sender keys now foreclose it?
- Future metadata work includes anonymous relays and traffic obfuscation;
  sealed delivery itself is capability-gated across federation.
- Mailbox retention + device-expiry defaults, and interaction with quota.

---

## 16. Implementation history and current boundary

1. **✅ Proto + server base:** content schema types in `kutup-chat-proto`;
   `sendId` dedupe; `cursor` + `?after=` paging; the `chat` capability block +
   `maxContentBytes` enforcement; per-account bundle rate limit. Plus reserve
   `sender: Option` and the legacy reserved `accessToken` in identified DTOs;
   sealed delivery uses its dedicated capability-authenticated DTOs.
2. **Trust and groups:** the device-manifest/self-authority scheme (§5.3),
   authenticated remote transparency policies, range recovery, witnesses,
   scheduled web/server monitoring, and cross-view auditing are implemented.
   The GV2 group-state model (§12) remains the next major product subsystem.
3. **`kutup-chat-core`**: engine skeleton (transport/db ports, event stream,
   durable outbox with `sendId`, decrypt→persist→ack ordering, 409 recovery) —
   the artifact the Android/iOS clients link. **✅ Done** (branch
   `claude/chat-phase1`): `ChatDb` port + native bundled-SQLite impl behind
   it (web gets IndexedDB); libsignal's six store traits over a unit-of-work
   overlay giving atomic decrypt→persist; real clock; the async `ChatTransport`
   port; `Engine::{register, send, receive, flush_outbox}` with a durable
   `sendId` outbox, full `409 DeviceListMismatch` recovery (missing/extra/stale
   — the reinstalled-peer path re-keys TOFU and surfaces a `SafetyNumberChanged`
   event, the Signal-faithful hybrid, with the verified-peer hard-block reserved
   for when manifests land), and a drain/ack receive loop with cursor dedup and
   persisted history. Covered by roundtrip/send/receive test suites. Federation
   uses the same client transport with canonical remote addresses and is routed
   server-to-server; no separate federation client stack is needed. Contacts-
   only sealed sender is implemented with libsignal outer envelopes,
   transparency-bound sender certificates, and no identified fallback. Not yet
   in core: groups and the attachment `kind`.
4. **web wasm adapters + minimal 1:1 UI — ✅ implemented**: account-scoped
   IndexedDB, a DTO-only wasm-bindgen transport facade, Web Locks around every
   ratchet transaction, capability-gated navigation, WebSocket hints feeding
   REST reconciliation, durable inbound/outbound history, bilingual UI, and a
   two-account Playwright roundtrip/reload spec. Web is now the reference client
   through federation, groups, privacy, media, and PWA completion. Native app
   integration is intentionally deferred until that shared protocol and
   conversation model are stable. The engine's public API (kutup types only —
   libsignal never leaks) remains the eventual UniFFI/wasm binding surface.

### 16.1 Hardening gate before client bindings — [IMPL]

The phase-2b engine proof established the crypto and durable-send invariants,
but its first receive loop treated every decrypt error as skippable and acked
the envelope. That is not a production contract: a missing session, changed
verified identity, local-store failure, or temporarily unavailable prekey can
be recoverable. Client bindings MUST NOT freeze against that behavior.

The engine uses this durable inbound pipeline before web/native adapters ship:

1. Persist the raw delivered envelope locally before advancing the fetch
   cursor. WebSocket delivery remains only a reconciliation hint.
2. On successful decrypt, atomically persist the ratchet advance, plaintext,
   and a `pendingAck` state; ack over REST only after that commit.
3. Persist a typed failure category (`malformedEnvelope`,
   `malformedCiphertext`, `missingKeyMaterial`, `untrustedIdentity`,
   `unsupportedSuite`, `missingSender`, `store`, `duplicate`, or `unknown`).
   Authenticated duplicate replay moves directly to pending-ack. All other
   failures remain durable and unacked until repaired or explicitly quarantined.
4. A successful REST ack removes the local raw envelope. A lost ack response
   is safe: retrying the ack never re-decrypts the message.
5. No failure path silently discards ciphertext. Explicit quarantine commits a
   `deadLetterPendingAck` state before the server ack, then retains a local
   `deadLetter` record until the application/user resolves it.

`ChatDb` and the engine/store orchestration are async (`?Send`) so browser
IndexedDB may yield while native SQLite completes immediately, without changing
the atomic unit-of-work semantics. Tests/dev use the explicit plaintext
`sqlite-bundled` feature. Native releases use the mutually selected `sqlcipher`
feature and `open_encrypted` with a 256-bit platform-keystore key; the constructor
checks `cipher_version` and refuses to open if ordinary SQLite was linked. The
remaining native task is binding each app's Keychain/Keystore key plumbing to
that constructor.

### 16.2 Device-directory transaction boundary — [IMPL]

The account row is the serialization point for the authenticated device set.
Registration, revocation, and manifest publication take an update lock; bundle
allocation and message delivery hold a shared lock from the device snapshot
through their transaction commit. Bundle devices and their signed manifest are
therefore one snapshot, and a send cannot pass exact-set validation while a
device is concurrently added or removed. First-manifest publication also locks
the account row because `FOR UPDATE` cannot lock a manifest row that does not
exist yet.

The server claims `(sendId, deliveryScope)` before checking the current recipient
set. `direct` and `sync` requests for the same logical send therefore do not
deduplicate each other. An already-accepted retry within its scope returns
deduplicated success even if the recipient added a device after the original
commit; a new send that finds a mismatch rolls the claim back with the
transaction. Requests with duplicate envelopes for one device are rejected.
