# kutup chat ("ileti") — wire protocol v1 (normative)

**Status:** normative target for chat phase 2b. This is the contract the three
clients (web/wasm, Android, iOS) freeze against. It supersedes the
wire-affecting parts of `docs/research/11-federated-chat.md`,
`12-chat-improvements-for-clients.md`, and `13-chat-architecture-comparative-research.md`
— read those for *why*; read this for *what*.

**Normative language:** MUST / MUST NOT / SHOULD / MAY per RFC 2119.

**No clients consume the contract yet** (the phase-2 server slice was
smoke-tested against the dev stack but nothing builds against it). So v1 is
built **correctly in one breaking pass** — the phase-2 shape is reshaped, not
extended for backward compatibility. This matches kutup's pre-production
posture (change DB schema directly, no compat shims).

**Element status tags** (every field/endpoint below carries one):
- **[IMPL]** — already built in the phase-2 server (`crates/kutup-chat-proto`,
  migration 021, `handlers/chat.rs`). Reshapeable — *not* frozen, since no
  client depends on it.
- **[ADD]** — folded into the base v1 shape now (content schema, `sendId`,
  `cursor`, `Option` sender, capability block, per-account rate limit).
- **[RSV]** — a later *subsystem* (device manifests, sealed sender, groups,
  federation), but its **fields/shapes are baked into the v1 base types now**
  so building the subsystem later touches handlers, not the wire. Clients MUST
  tolerate reserved fields (accept, round-trip, ignore).

Once a client ships against v1, the contract locks and the [IMPL]/[ADD]
distinction stops mattering — everything below becomes the frozen base, and
only [RSV] → implemented remains.

---

## 1. Versioning model (the compatibility contract)

Four things version **independently**. A change to one MUST NOT force a
lockstep change to the others.

| Axis | Where | Rule |
|---|---|---|
| **Suite** | `suite: u16` in bundles/envelopes | Pins the whole crypto construction (KA + ratchet + KEM + libsignal wire). A new construction is a **new registry number**, never a mutation of an existing one. §4. |
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
   client's "require PQ / require ≥ vN" policy is enforced locally. The one
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

**[RSV] Account self-authority key (device-list authenticity).** The research
(`13-…` §4.3) makes device-list authenticity a v1 requirement: server-assigned
device lists otherwise reproduce the malicious-homeserver break that defeated
Matrix/Megolm. v1 introduces a **self-signing account key** and a **signed
device manifest** (§5.3). The manifest format is in v1; verification UX MAY
land incrementally, but the signed manifest MUST be part of the wire contract
now so a key-transparency log can later wrap it without a break.

---

## 3. Suite registry — [IMPL], one correction

`suite` is a `u16` registry code point (like a TLS ciphersuite), never a Rust
variant name on the wire.

| Code | Name | Construction |
|---|---|---|
| `1` | `PqxdhTripleRatchetV1` | libsignal message-version 4. **PQXDH handshake:** X25519 + **ML-KEM-1024**. **Triple Ratchet messaging:** Double Ratchet + SPQR using **ML-KEM-768**. |

**Correction from `13-…` §4.4:** the ongoing SPQR ratchet uses **ML-KEM-768**,
not 1024. ML-KEM-1024 is the PQXDH *handshake* parameter only. Docs and
comments describing "the ratchet" as ML-KEM-1024/Kyber1024 are wrong. Wire and
mailbox sizing MUST budget kilobyte-scale ratchet headers (measured:
`PreKeySignalMessage` ~1.8 KB, steady `SignalMessage` ~100 B) arriving as
erasure-coded chunks.

A future suite (e.g. a post-libsignal migration) is code point `2`, added to
this table; it MUST NOT change the meaning of code point `1`.

---

## 4. Prekey directory — [IMPL] + [RSV] manifest

Endpoints (all authenticated; the WS validates its token pre-upgrade):

| Method | Path | Status |
|---|---|---|
| `POST /api/chat/device` | register/re-register a chat device | [IMPL] |
| `GET /api/chat/device` | list caller's chat devices | [IMPL] |
| `DELETE /api/chat/device/{deviceId}` | revoke | [IMPL] |
| `PUT /api/chat/keys` | rotate signed / last-resort; replenish one-time | [IMPL] |
| `GET /api/chat/keys/count` | pool sizes | [IMPL] |
| `GET /api/chat/users/{username}/keys` | fetch bundles (consumes one-time keys) | [IMPL] |
| `POST /api/chat/users/{username}/messages` | multi-device send | [IMPL] |
| `GET /api/chat/messages` | drain (oldest-first) | [IMPL] |
| `POST /api/chat/messages/ack` | batch ack | [IMPL] |
| `GET /api/chat/ws` | WebSocket | [IMPL] |

**Rules that stay:** device ids are server-assigned lowest-free `1..=127`;
re-registration replaces the directory entry and wipes that device's mailbox;
every bundle MUST carry a `kyberPreKey` (one-time or last-resort — PQ is never
optional); one-time EC prekeys unsigned, signed prekey + all Kyber prekeys
signed (XEd25519 by the device identity key); upload batches ≤ 100.

**[ADD] Per-account bundle-fetch rate limit.** `GET …/keys` is currently
IP-limited (30/min). Change to **per authenticated account** (the limiter has
the user id), keeping a coarse IP limiter only as an outer guard — mobile
clients behind CGNAT share an IP; a hostile account can drain pools across
IPs. (`13-…` §7.)

**[RSV] Staged prekey deletion.** From XMPP/OMEMO practice (`13-…` §6): a
consumed one-time prekey MUST NOT be physically deleted while in-flight
messages may target it. Mark used with a timestamp; sweep after a grace window
(≥ 24 h). Never yank a prekey from the served set the instant it's consumed.

### 4.x Device manifest in the bundle response — [IMPL]

`UserPreKeyBundlesResponse` carries an optional `manifest` (§5.3). A verifying
client checks each returned `deviceId` against the signed manifest before
establishing a session, so the server cannot inject a device. When the server
advertises `manifests: true`, absence or any mismatch is a hard failure. A
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
- **Key transparency** (future) wraps this: the manifest becomes a leaf in an
  append-only log. The format above is chosen so that is additive.

Clients pin the first valid self-authority (TOFU), persist the highest observed
manifest version/hash, and reject rollback, same-version equivocation, authority
replacement, or a bad link between consecutive versions. A valid signed jump
across versions missed while offline is safe to use but records a continuity
gap for later transparency auditing. Clients retain the existing safety-number-
change interstitial for identity changes. Key transparency will later replace
first-contact TOFU without changing this leaf.

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
  "body": { /* per-kind */ }
}
```

**`kind` registry** (reserve all now; only `text` ships in 2b):

| kind | phase | body |
|---|---|---|
| `text` | 2b [ADD] | `{ "text": string }` |
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

**[ADD] `sendId`.** No idempotency today: a client that times out and retries
`POST …/messages` stores duplicate mailbox rows (the request can succeed while
the response is lost — the mobile norm). v1 adds a client-generated `sendId`
(UUID). The server dedupes per `(senderUser, senderDevice, sendId)` within a
retention window (unique constraint on the insert batch; `ON CONFLICT DO
NOTHING`; return the original 200). This makes a durable client outbox safe to
retry blindly — the property every mobile client needs. (`12-…` §2.)

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

### 7.3 [RSV] sealed-sender access token

`SendMessagesRequest` gains a **[RSV] `accessToken: b64?`**. When sealed sender
ships (§11), an authenticated send MAY omit sender auth and instead prove a
delivery token derived from the recipient's profile key; the server gates
delivery on it. Absent in v1; MUST be accepted when present.

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

### 8.4 [RSV] retention + device expiry

Define now (implement with the sweeper family): mailbox rows expire after a
configured window; chat devices unseen > N days are expired with their prekeys
(Signal-style). Unbounded mailboxes for dead devices are an abuse vector and a
fan-out tax. Exposed via the capability block (§10).

---

## 9. WebSocket — [IMPL] + [RSV] ticket

`GET /api/chat/ws?deviceId=N&token=<jwt>`. On connect the server sends exactly
one `{"type":"drainMailbox"}` (drain the backlog over REST), then pushes
`{"type":"envelope", envelope}` frames. Server ignores client frames. Server
MAY force-close on backpressure or revocation → reconnect with jittered
backoff and re-drain.

```
ChatWsServerMessage (tagged "type"):
  { type: "envelope", envelope: DeliveredEnvelope }
  { type: "drainMailbox" }
```

**[RSV] WS ticket.** `?token=<jwt>` exists because browsers can't set headers
on `WebSocket`, but query strings land in access logs. v1 reserves `POST
/api/chat/ws-ticket` → a one-time, short-TTL opaque token accepted only by the
WS upgrade. **Native clients MUST use `Authorization: Bearer`** (both
hubs accept it) and MUST NOT put the JWT in the query string. Until the ticket
ships, nginx MUST scrub `token=` from the chat-WS log format. (`12-…` §5.)

---

## 10. Capability advertisement — [ADD]

Clients feature-gate chat per server and must not show chat UI on a server
lacking the routes. Add a `chat` block to the existing public
`GET /api/auth/settings`:

```jsonc
"chat": {
  "enabled": true,
  "protocolVersion": 1,
  "suites": [1],
  "maxContentBytes": 65536,        // enforced on send (closes a mailbox-abuse hole)
  "federation": false,             // [RSV] flips true in phase 3
  "manifests": true,               // signed device directory is available
  "sealedSender": false            // [RSV] flips true when sealed sender ships
}
```

`maxContentBytes` MUST be **enforced** on send (today an envelope can be
arbitrary size) and is the budget clients use for attachment-pointer payloads.
The `[RSV]` booleans let a client light up features per server without a
protocol bump. (`12-…` §3.)

---

## 11. Sealed sender — [RSV], ship whole or not at all

Per `13-…` §4.2, sealed sender is a **three-part system**; if kutup ever drops
plaintext sender it MUST ship all three together:

1. **Sender certificates** — a trust-root key signs a server certificate,
   which signs short-lived per-user sender certs (identity key + expiry). Fully
   self-hostable from libsignal primitives; the recipient validates
   client-side.
2. **Delivery-token abuse gate** — the `accessToken` (§7.3): the only spam
   signal once server-side sender auth is dropped.
3. **Contacts-only default** with profile-key rotation on block.

v1 reserves the fields (`sender: Option`, `accessToken`, capability flag). It
does **not** implement sealed sender. Sealed sender is metadata *minimization*,
not elimination (it does not defeat traffic analysis) — document honestly.
Sealed-sender-across-federation (a remote server enforcing the token gate
without learning the sender) is an open research question (§14).

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

## 13. Federation — [RSV], transport-only, no room DAG

Confirmed by CVE-grade evidence (`13-…` §3): **reject** Matrix's replicated
room DAG + state resolution; keep signed-ciphertext delivery between mailbox
servers. Reserved for phase 3:

- **Discovery:** `GET /.well-known/kutup/federation.json` → `{ fedVersion,
  server: "domain", signingKeys: [ { keyId, publicKey } ] }`.
- **Addressing:** `sender`/recipient become `user@domain`. Clients model
  addresses as `{ user, domain: Option, deviceId }` **now** so phase 3 changes
  routing, not types.
- **Request auth — adopt X-Matrix verbatim (`13-…` §3):** sign `{method, uri,
  origin, destination, body}` as a JSON object with the origin server's Ed25519
  key; transmit in an authorization header; the receiver MUST reply **401 on
  destination mismatch** (destination binding defeats cross-server replay).
- **Delivery — adopt Matrix's retry rule *plus* what Matrix gets for free from
  its DAG and kutup does not:** a sending server MUST retry a transaction until
  `200 OK` before sending the next transaction to that destination (in-order
  per destination), backed by a **durable** queue. Because kutup has **no DAG
  backfill safety net**, each s2s stream MUST carry a **per-destination
  monotonic sequence number**, and the receiver MUST detect and request missing
  ranges (explicit gap detection). A never-give-up durable queue + sequence
  gaps replaces backfill; without it a long partition silently loses messages.
- **Abuse controls (from XMPP servers, `13-…` §5/§7):** pre-auth vs post-auth
  size/element caps; per-remote shapers; an overload circuit breaker
  (auto-temporary-block a failing/overloaded remote); a proof-of-contact gate
  before accepting messages from strangers (the delivery token doubles as this).

---

## 14. Reserved-fields summary (bake into v1 now)

| Field / shape | Where | Unlocks | Phase |
|---|---|---|---|
| `sender: Option<String>` | `DeliveredEnvelope` | sealed sender / federation addr | 3 / later |
| `sendId: uuid` | `SendMessagesRequest` | idempotent retries | **2b [ADD]** |
| `cursor: u64` | `DeliveredEnvelope` + `?after=` | paging + dedup | **2b [ADD]** |
| content schema `{v,kind,sentAt,seq,body}` | decrypted plaintext | all app payloads | **2b [ADD]** |
| `chat` capability block | `/api/auth/settings` | per-server feature gating | **2b [ADD]** |
| `deviceSignature` + `DeviceManifest` + manifest endpoints | device reg + directory | device-list authenticity | 2/3 |
| `accessToken: b64?` | `SendMessagesRequest` | sealed-sender abuse gate | later |
| `ws-ticket` endpoint | WS auth | keep JWT out of logs | 2b/later |
| `GroupState { groupId, version, encryptedState, membershipManifest }` | group endpoints | GV2 groups | 4 |
| `.well-known` + `user@domain` addr + per-destination sequence | federation | transport federation | 3 |

---

## 15. Open questions (carried from `13-…` §11)

- Device-list authenticity: signed manifest (§5.3) now; is a full key-
  transparency log the phase-3 wrapper, and does the manifest format above
  admit it cleanly? (Believed yes — that's why it's shaped this way.)
- Does GV2-pattern server-held encrypted group state compose with a future
  MLS migration, or does choosing sender keys now foreclose it?
- Sealed sender across federation: how does a remote server enforce the
  delivery-token gate without learning the sender? (Signal is single-server;
  genuinely new territory.)
- Mailbox retention + device-expiry defaults, and interaction with quota.

---

## 16. Phase-2b implementation order

1. **[ADD] proto + server, additive, ship first** (safe against the current
   server, unblocks clients): content schema types in `kutup-chat-proto`;
   `sendId` dedupe; `cursor` + `?after=` paging; the `chat` capability block +
   `maxContentBytes` enforcement; per-account bundle rate limit. Plus reserve
   `sender: Option` and `accessToken` in the DTOs.
2. **Design docs, then implement** (the two consequential pieces): the device
   manifest / self-authority scheme (§5.3), and the GV2 group-state model
   (§12) — short decision docs before code (`13-…` §4.1/§4.3).
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
   persisted history. Covered by roundtrip/send/receive test suites. Not yet in
   core: sealed sender, groups, federation transport (all reserved), and the
   attachment `kind`.
4. **web wasm adapters + minimal 1:1 UI**; then native clients follow their
   plans (`kutup-android`, `kutup-ios`). The engine's public API (kutup types
   only — libsignal never leaks) is the UniFFI/wasm binding surface.

### 16.1 Hardening gate before client bindings

The phase-2b engine proof established the crypto and durable-send invariants,
but its first receive loop treated every decrypt error as skippable and acked
the envelope. That is not a production contract: a missing session, changed
verified identity, local-store failure, or temporarily unavailable prekey can
be recoverable. Client bindings MUST NOT freeze against that behavior.

Before the web/native adapters ship, the engine MUST use a durable inbound
pipeline:

1. Persist the raw delivered envelope locally before advancing the fetch
   cursor. WebSocket delivery remains only a reconciliation hint.
2. On successful decrypt, atomically persist the ratchet advance, plaintext,
   and a `pendingAck` state; ack over REST only after that commit.
3. Classify failures. Duplicate or authenticated-permanently-malformed input
   MAY be dead-lettered and acked; missing session/prekey, identity change,
   unsupported suite, database failure, and unclassified internal failures
   MUST remain durable and unacked until repaired or explicitly quarantined.
4. A successful REST ack removes the local raw envelope. A lost ack response
   is safe: retrying the ack never re-decrypts the message.
5. No failure path silently discards ciphertext. A client surfaces a durable
   attention event for quarantined input.

The current synchronous `ChatDb` proof port is also not a valid IndexedDB
boundary: browser IndexedDB calls complete asynchronously. Before WASM lands,
`ChatDb` and the engine/store orchestration MUST become async (`?Send` is
allowed), retaining the atomic unit-of-work semantics. Native SQLite may
complete those async methods immediately. The bundled SQLite implementation is
not encrypted at rest; SQLCipher/platform-secure keying is a separate native
hardening requirement.
