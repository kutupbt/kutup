# Chat ("ileti") architecture — comparative research and verdict

**Status:** research complete; feeds the phase-2b protocol freeze and the
native-client plans (`kutup-android`, `kutup-ios`)  
**Method:** adversarially-verified web research (Signal/Matrix primary sources
+ peer-reviewed papers + CVEs) plus read-only study of four reference
codebases checked out locally: `libsignal`, Prosody, ejabberd, Monal.  
**Companion docs:** `11-federated-chat.md` (original design), `12-chat-improvements-for-clients.md` (wire-contract fixes)

> **Implementation status (2026-07-17):** The verdict remains the design
> rationale. Its signed device manifest, durable in-order federation,
> authenticated request, mailbox-durability, encrypted-profile, key-
> transparency, and witness recommendations are implemented in the server,
> shared core, and web client. GV2-pattern private groups, complete sealed
> sender, richer messaging/media, remote federation-policy distribution, and
> native integration remain. Current normative behavior lives in
> [`../chat-protocol.md`](../chat-protocol.md).

This document answers one question: **is kutup's chat architecture correct,
and what must change before the wire contract freezes?** The bar is
enterprise-grade — no invented crypto, no quick hacks, every security item
that touches the wire designed for now even if implemented later.

---

## 0. Executive verdict

The core architecture is **validated by strong, adversarial evidence** and
should be kept: a dumb Signal-style mailbox server, a single pinned
formally-analyzed crypto library (libsignal) instead of composed bespoke
subprotocols, and transport-only federation that rejects Matrix's replicated
room DAG. Two independent bodies of evidence confirm these were the right
calls (§2, §3).

But the research surfaced **three design changes that are cheap now and
breaking later**, plus **one top-priority unmitigated security gap**:

1. **Groups: adopt the GV2 pattern, not client-managed membership blobs.**
   Signal shipped exactly kutup's planned design in 2014 and abandoned it for
   cause (races, unenforceable roles). This is the single strongest change
   signal. (§4.1)
2. **Sealed sender is a three-part system, not envelope encryption.** If
   kutup ever drops the plaintext sender it must ship the delivery-token
   abuse gate and contacts-only default *at the same time*. (§4.2)
3. **Device-list authenticity is kutup's top unmitigated risk.** Server-
   assigned device lists reproduce the exact vector that broke Matrix/Megolm
   against a malicious homeserver — which is precisely a self-hosted system's
   threat model. (§4.3)
4. **Doc correction:** the ongoing ratchet uses **ML-KEM-768** (SPQR), not
   ML-KEM-1024; ML-KEM-1024 is the PQXDH *handshake* parameter only. Mailbox
   sizing must budget kilobyte-scale ratchet headers. (§4.4)

The four local codebases then gave us **mechanisms to adopt near-verbatim**
for stability, performance, and the mobile story (§5–§8) — the parts the web
research explicitly could not verify.

---

## 1. Baseline at research time

From `claude/chat-phase1`: pinned libsignal (PQXDH X25519+ML-KEM + Triple
Ratchet, PQ always-on, numeric suite registry); a Postgres-backed prekey
directory + per-device mailboxes; REST drain (oldest-first, `limit`≤500) +
REST ack as source of truth, WebSocket push as latency optimization; device
ids 1–127 server-assigned; multi-device fan-out with a 409
`DeviceListMismatch` contract; sender plaintext to the server (sealed sender
deferred); federation planned as transport-only, signed server-to-server
delivery, explicitly rejecting the Matrix room DAG; groups planned as
client-managed encrypted membership blobs; media planned to reuse the E2EE
drive; one shared Rust engine (`kutup-chat-core`) for web/Android/iOS; no
push yet.

---

## 2. Signal — what it actually does, and what it teaches

**Why Signal rejected federation** (`signal.org/blog/the-ecosystem-is-moving`,
verified verbatim): federating a protocol makes it "very difficult to make
changes"; it cites SMTP/XMPP/IRC as "frozen in time circa the late 1990s".
The argument is contested (XMPP RFCs were revised in 2011; DNS gained
DNSSEC/DoH) but it is the argument kutup must consciously answer. kutup's
answer is deliberate: **transport-only federation with a versioned suite
registry** confines the "hard to change" problem to a thin, versioned
delivery layer rather than the whole protocol — which is the correct
mitigation, provided the versioning is real (§9).

**Sealed sender** (`signal.org/blog/sealed-sender` + libsignal
`rust/protocol/src/sealed_sender.rs`, both verified) is a **three-part
system**:
1. Short-lived server-issued **sender certificates** the recipient validates
   client-side (two-level chain: a trust-root key signs a `ServerCertificate`,
   which signs per-user `SenderCertificate`s containing identity key +
   expiry). A minimal self-hosted issuance is entirely in-crate — no SGX, no
   zk: hold a trust-root keypair, one-time-issue a server cert, issue sender
   certs per login, embed the trust-root public key in clients.
2. An **abuse-control replacement** for server-side sender auth: a delivery
   token derived from the recipient's profile key (deployed as a 96/128-bit
   unidentified-access key) that the server checks before accepting a sealed
   message — the server 401s sealed sends lacking it.
3. A **contacts-only default** with profile-key rotation on block to revoke
   delivery capability.
libsignal also ships a **v2 multi-recipient sealed-sender** format
(`SealedSenderV2SentMessage`) built for group fan-out: one shared ciphertext
plus per-recipient `C||AT` tags, which the server splits per recipient.

**Groups (GV2/zkgroup)** — the decisive finding. Signal's **2014 groups were
kutup's exact planned design**: no server-side group state, membership
exchanged client-to-client tagged with a random 128-bit Group ID
(`signal.org/blog/private-groups`, verified). Signal **abandoned it** for two
reasons quoted verbatim: concurrent state updates race as messages cross
paths (member views diverge), and role-based access control is impossible
(any member can claim any role). The replacement (GV2, CCS 2020 paper +
`rust/zkgroup`) puts **authoritative group state on the server but encrypted
under a `GroupMasterKey` the server never sees** — each membership entry is a
ciphertext of a member UID; anonymous credentials (`AuthCredentialWithPni`)
let the server authenticate "a member of this group" without learning who.
Accepted residual leakage: the server sees group size and access patterns.
**Realistic adoption cost (from reading `rust/zkgroup`): heavy** — libsignal
provides only the client-side crypto and verification primitives; the
encrypted-group-state storage engine, the change-log/versioning semantics,
and the credential-issuance endpoints all live in Signal's Java server and
would be reimplemented. Critically, **sender keys for group fan-out
(`SenderKeyDistributionMessage`, `group_cipher.rs`) are orthogonal to
zkgroup** and can be adopted without it.

**Multi-device (Sesame)** — `rust/protocol/src/session_management.rs`: one
`SessionRecord` per `(recipient, deviceId)`; `previous_sessions` capped at 40;
sessions unacknowledged past **30 days** are soft-archived and force a fresh
prekey fetch. This validates kutup's per-device mailbox model. Verified
privacy cost (ACNS 2020, WOOT'24): the pairwise-per-device model leaks device
topology to correspondents, and kutup's 409 device-list contract broadcasts
device-list changes by design — kutup is currently *worse* than Signal here
because the server also sees plaintext sender identity (§4.3).

**Prekey lifecycle** (`rust/protocol/src/state/*`, `keys.proto`): Kyber
prekey is **mandatory** in the bundle; one-time EC prekey optional; upload
batch capped at **100**; libsignal makes no type-level distinction between
one-time and last-resort keys (a store-policy detail — last-resort is not
deleted on use). kutup's design matches this.

**PQ downgrade nuance** (`signal.org/blog/spqr`, verified) — important for a
federated deployment: real libsignal **does** allow a constrained SPQR
downgrade, but only at session start, only on first contact with a
non-supporting peer, MAC-protected against a middleman, then locked in for
the session. kutup's "no downgrade toggle" tenet should mean *no user-facing
or mid-session downgrade* — not "no versioned rollout." kutup cannot flag-day
all federated servers at once the way Signal can flag-day its clients, so
this authenticated-negotiate-then-lock-in pattern is **more** load-bearing
for kutup, not less (§9).

---

## 3. Matrix — what to avoid, and the two mechanisms to steal

**Avoid the replicated room DAG** (verified against the spec + CVEs +
Matrix's own post-mortems). Matrix orders events in a DAG via `prev_events`;
every server re-evaluates auth rules three ways and "soft-fails" events. In
production this produced **state resets** in high-profile rooms
(CVE-2025-49090 and coordinated fixes across all major implementations):
users re-added to rooms they left, access control reverting to earlier
states. Matrix's own Project Hydra post admits the root cause is
architectural — "Matrix optimistically applies changes to room state without
waiting for all servers to achieve consensus" — and that a malicious
homeserver can deliberately craft sequences to reset a room. **Replicating
authorization state across untrusted servers is the mistake.** kutup's
signed-ciphertext-delivery-between-mailboxes model avoids the entire class.
Keep the rejection.

**The malicious-homeserver break** (IEEE S&P 2023, verified): as deployed in
2022, Matrix/Element provided "neither authentication nor confidentiality
against homeservers that actively attack the protocol." The confidentiality
break was **by design, not a bug** — the homeserver's control over room
membership and device lists let it force clients to share Megolm keys with
attacker-controlled devices. This is the exact threat model a self-hosted
federated E2EE system must survive, and it validates (a) one pinned
formally-analyzed library over composed bespoke subprotocols, and (b)
client-managed membership. **But the attack also works via device-list
control alone** — and kutup's device lists are server-assigned. **kutup
reproduces the Megolm attack surface until it ships device-list
authenticity.** (§4.3)

**Adopt near-verbatim (two mechanisms, verified against the normative spec):**
1. **In-order transaction retry:** the sending server must retry a
   transaction until 200 OK before sending the next transaction (different
   `txnId`) to that destination — per-destination in-order delivery.
2. **X-Matrix-style request signing:** sign `{method, uri, origin,
   destination, body}` as JSON with the server's Ed25519 key; **mandate 401
   on destination mismatch** — the destination binding prevents signature
   replay against other servers. This matches kutup's planned Ed25519 s2r
   signing; adopt the destination-binding + 401 rule exactly.

**Critical adaptation:** Synapse does *not* rely on the retry rule alone — it
bounds retries (~11), marks the destination down with exponential backoff,
and recovers via DAG **backfill** (`/get_missing_events`). kutup rejects the
DAG, so it has **no backfill safety net**. Therefore kutup's s2r queues must
be **durable and gap-detecting**: pair the retry semantic with
per-destination **sequence numbers** so a receiver can detect and request
missing ranges. Without this, a long partition silently loses messages. (§5)

**MLS:** Matrix-over-MLS is still in progress and unproven for federation
semantics — not a basis to build on now, but the group layer should not
foreclose it (§9, open question).

---

## 4. The four design decisions

### 4.1 Groups — CHANGE to the GV2 pattern

**Do not ship pure client-managed membership blobs.** Adopt server-held
authoritative group state encrypted under a client-only `GroupMasterKey`
(the GV2 pattern), which gives a single source of truth and enforceable admin
roles while keeping membership unreadable to the server. It composes cleanly
with transport-only federation: the group's home server hosts the encrypted
state; remote members read/update it via signed s2r calls.

Given the verified "heavy" cost of full zkgroup, the recommended **staged**
path (no hacks, but scoped):
- **Group message crypto:** sender keys (`SenderKeyDistributionMessage` +
  `group_encrypt`/`group_decrypt`), adopted independently of zkgroup. This is
  the fan-out mechanism.
- **Group state:** server stores an encrypted, **versioned** group-state blob
  with an append-only change log (the anti-race mechanism — optimistic
  concurrency with a version check on write, not last-writer-wins). Members
  hold the `GroupMasterKey`; the server never sees membership plaintext.
- **Authorization:** start with a **signed membership manifest** (the current
  membership set, signed by an admin device whose key chains to the account
  identity — see §4.3) rather than full anonymous credentials. Full zkgroup
  anonymous-credential issuance is a later upgrade the data model should not
  preclude. This gives enforceable roles now without the full Ristretto
  credential server on day one.

This is explicitly *not* Signal's dead-end design and *not* the full
Signal-server reimplementation — a defensible enterprise-grade middle that
the wire contract must be shaped for now (group id, version counter,
change-log entry types reserved).

### 4.2 Sealed sender — design the whole system before dropping plaintext sender

kutup ships plaintext sender today. That is honest and fine for phase 2b, but
the moment sealed sender lands it must land as all three parts (§2): sender
certificates (trivially self-hostable from libsignal primitives), the
**delivery-token abuse gate** (without it, dropping sender identity removes
the *only* spam/abuse signal), and the contacts-only default. Reserve the
wire fields now: `DeliveredEnvelope.sender` becomes `Option<String>` across
all client models (so hiding it later is not a breaking change), and the send
path reserves an access-token field. Note the verified caveat (NDSS 2021):
sealed sender does not defeat statistical traffic analysis — it is metadata
*minimization*, not elimination; document that honestly.

### 4.3 Device-list authenticity — the top unmitigated gap, design it now

This is the most important finding for an enterprise-grade self-hosted system.
Server-assigned device lists mean a malicious or compromised home server can
add an attacker device to a user's list and clients would encrypt to it — the
exact Megolm break. Client-managed group membership does **not** close this
(the attack works at the device-list layer). kutup must ship device-list
authenticity:

- **Per-account device manifest signed by a self-authority key.** Adopt
  Signal/Matrix-style cross-signing: the account holds a long-lived
  self-signing identity (derived from and protected like the master key);
  each chat device's identity key is signed into a manifest by that
  self-authority; peers verify the manifest signature, not the server's word.
  The server distributes the manifest but cannot forge membership of it.
- **Safety numbers / key-change surfacing** (TOFU with verification), as
  libsignal's `IdentityChange::ReplacedExisting` already models — clients show
  a "safety number changed" interstitial on identity change (the
  native-client plans already specify this UX).
- **Key transparency** (an append-only, auditable log of account→device-key
  bindings) is the strongest answer and where Signal/WhatsApp are heading;
  scope it as a **designed-for** future phase, but shape the manifest format
  so a transparency log can wrap it later without a breaking change.

The manifest must be in the v1 wire contract even if verification UX lands
incrementally — retrofitting device-list authenticity after clients trust
server-assigned lists is a breaking, trust-resetting change.

### 4.4 PQ parameters — CORRECT the docs

The Triple Ratchet runs SPQR (Sparse Post-Quantum Ratchet) alongside the
Double Ratchet using **ML-KEM-768** (encapsulation keys 1184 B, ciphertexts
1088 B), amortized across messages via erasure-coded chunks. **ML-KEM-1024 is
the PQXDH handshake parameter only.** Every kutup doc describing "the ratchet"
as ML-KEM-1024 is wrong and must be corrected. Consequence: mailbox row
sizing and per-message overhead budgets must account for kilobyte-scale
ratchet headers arriving as interleaved chunks, and the `PreKeySignalMessage`
(~1.7 KB) vs steady `SignalMessage` (~100 B) split (measured in the spike).

---

## 5. Stability — federation delivery and offline queues (from ejabberd/Prosody)

Neither XMPP server does durable long-term s2s retry; both **bounce fast** and
rely on the client/archive to resend. That is not available to kutup (no DAG
backfill), so kutup takes the *shape* of their queues but makes them durable:

- **Bounded per-remote outbound queue that flushes on connect** (Prosody
  `sendq`, default 32768; ejabberd `p1_queue`). On overflow, Prosody
  force-closes with `resource-constraint` rather than silently dropping —
  adopt "overflow fails loudly," never a silent gap.
- **On failure: drain as delivery failures + a randomized backoff window**
  before the next attempt (ejabberd `get_delay` = `rand(s2s_max_retry_delay)`),
  jittered to avoid thundering herds. kutup makes the queue **durable** and
  pairs it with **per-destination sequence numbers + gap detection** (the
  replacement for Matrix backfill, §3).
- **Per-remote circuit breaker:** ejabberd auto-temporarily-blocks an
  overloaded remote for 60 s (`external_host_overloaded`). Adopt a small
  in-memory per-domain breaker keyed on failure/overload.
- **Ack/resumption discipline** (XEP-0198, the closest analogue to kutup's
  drain/ack): steal the `smqueue` head/tail structure with the explicit
  "client acked more than sent ⇒ protocol error, close" rule (both servers
  treat a lying `h` as fatal); make resume **fail cleanly on queue overflow
  rather than deliver a gap**; adopt ejabberd's enumerated resumption-failure
  taxonomy (`session_not_found | timed_out | invalid_previd | …`) as kutup's
  typed reconnect errors. Keep a small replicated "last-handled counter" so a
  client reconnecting after a server restart learns the true drain point.

---

## 6. Performance — mailbox, paging, prekeys (from ejabberd/Prosody + libsignal)

- **Monotonic server-assigned id as both dedup key and paging cursor** (XEP-
  0359 stanza-id / MAM). kutup's mailbox UUID already serves as the ack
  handle; add a monotonic ordering column and use it as the cursor.
- **`limit = requested + 1` next-page probe** (Prosody MAM) plus an explicit
  `complete` flag + first/last/count so the client knows when it is caught up.
  kutup already returns `{envelopes, more}`; keep it and add the cursor.
- **"Archive is the source of truth; offline is a thin counter/index"**
  (ejabberd `use_mam_for_storage`) — kutup's mailbox already is the single
  store; never introduce a second copy.
- **Strip client-supplied server-authored ids** to prevent spoofing (both
  servers strip foreign `stanza-id by=us`).
- **Prekey pool policy** (libsignal + OMEMO practice): upload batch cap 100;
  monitor pool counts and top up below a threshold; **stage prekey removal**
  — mark-used-then-delete after a grace window (Monal keeps used prekeys 14
  days), never yank a prekey from the published bundle while in-flight
  messages target it. This closes the classic OMEMO prekey-exhaustion/race
  failure.
- **Mailbox growth:** define retention + device expiry now (Prosody expires
  MAM after a configurable window with a daily per-user-indexed sweep;
  ejabberd via admin command). Unbounded mailboxes for dead devices are both
  an abuse vector and a fan-out tax. Add device expiry (unseen N days → prune
  device + prekeys, Signal-style) to kutup's existing sweeper family.

---

## 7. Security & metadata (synthesis)

- **Device-list authenticity first** (§4.3) — the top gap.
- **Sealed sender with its abuse gate** (§4.2) — metadata minimization, ship
  the whole system or none of it.
- **Abuse controls for open federation:** pre-auth vs post-auth size/element
  caps (both servers cap unauthenticated bytes hard — Prosody 10 KB unauthed
  vs 512 KB authed; billion-laughs element caps); per-remote shapers; the
  overload circuit breaker (§5); a proof-of-contact gate before accepting
  messages from strangers (the delivery-token mechanism doubles as this).
- **PEP lesson (what kutup already got right):** OMEMO couples key discovery
  to the presence graph (`access_model=presence`) and to entity-caps hashes,
  which is the source of its device-list races and "can't start a session
  with someone who hasn't accepted my subscription" bugs. kutup's first-class,
  presence-independent, explicitly-versioned device-list/prekey resource
  **avoids this entire class** — keep it. Add a "fetch current device set on
  session resume" reconciliation (the equivalent of XMPP's
  `send_last_published_item` healing).

---

## 8. The mobile story — Monal's hard-won iOS lessons (no-push reality)

Monal is the reference for exactly kutup's hard problem: a full messaging
engine on iOS with a self-hosted, push-constrained backend. The transferable
lessons, several of which change the native-client plans:

- **NSE and main app are two instances of the same engine, arbitrated by a
  file lock + IPC handshake** — never both draining concurrently. This is the
  correct model for kutup's shared `kutup-chat-core`: the iOS Notification
  Service Extension links the same engine and coordinates socket/mailbox
  ownership with the app via a lock, rather than a separate relay.
- **Content-free / mutable-content push; the NSE connects and drains, and can
  *silence* the notification after inspecting fetched data** (needs Apple's
  push-filtering entitlement). This confirms kutup's "content-free wake ping"
  direction and adds the requirement that the NSE can suppress a
  now-irrelevant notification (read elsewhere, muted, LMC-edited).
- **Persist the outbound message to durable storage *synchronously before* it
  hits the wire** (Monal's anti-loss firewall), and dedup on the server id
  with an origin-id fallback for your own reflections. kutup's engine must do
  the same: enqueue to the durable outbox before any network (already in the
  `12-` brief's durable-outbox design — this validates it).
- **Explicit catchup-vs-live state with a DB-backed delay queue** so drained
  history and live pushes merge deterministically; only declare "synced"
  after a server round-trip ack. kutup's engine needs the same state machine,
  not ad-hoc interleaving.
- **A single `idle` predicate drives background disconnect** (catchup done +
  empty queues + no unacked) — "connected only while there's work" is the
  whole battery story.
- **E2EE hygiene:** queue session repairs until initial sync completes;
  silently ignore duplicate-decrypt errors (libsignal dedup); force a periodic
  key-transport message (Monal: 1-in-50) so ratchets stay live on receive-only
  devices; publish the bundle *before* the device manifest so no peer sees a
  device id without a fetchable bundle.
- **Push keepalive is a state machine, not timers** (ejabberd
  `mod_push_keepalive` + Prosody `mod_cloud_notify`): asleep→extended-TTL →
  pushed→normal-TTL → dead. Both projects show this is the easiest place to
  leak sessions; kutup should implement it explicitly when push lands.

Push architecture recommendation (unchanged direction, now grounded): content-
free wake pings, UnifiedPush for Android (self-host-friendly), an opt-in
hosted APNs relay for iOS with the NSE doing the real drain. Reserve a future
`POST /api/chat/push-subscriptions`; build nothing yet — drain-on-open is the
honest v1 story and the client plans say so.

---

## 9. Modularity, versioning, agility

- **Message pipeline as an ordered typed middleware/hook chain** (ejabberd
  `run_fold` / Prosody events), not hardcoded calls — archive → offline →
  push composed cleanly this way for 20 years. In Rust: `Vec<dyn Handler>`
  ordered by priority, each returning a `ControlFlow`.
- **Declarative module registration** (ejabberd `start/2` returns a list of
  hooks/routes/jobs) for teardown symmetry; **storage behind a trait with
  runtime-selected backends** and declared **capabilities** (Prosody's
  `archive.caps`) so generic code adapts.
- **Suite agility done right:** the numeric suite registry is correct; pair it
  with the authenticated-negotiate-then-lock-in downgrade discipline (§2) so a
  federated network without flag-days can still migrate. **Version everything
  independently:** suite id, inner content schema (`12-` brief §1),
  federation API, and store schema — each with explicit compatibility rules.
  Unknown-but-newer must degrade to a placeholder, never a drop.

---

## 10. Consolidated verdict table

| Area | Verdict | Action |
|---|---|---|
| Dumb mailbox server | **KEEP** | Validated vs Matrix DAG failures |
| Pinned libsignal (one analyzed lib) | **KEEP** | Validated vs Matrix bespoke-subprotocol break |
| Transport-only federation, no room DAG | **KEEP** | CVE-grade evidence the DAG is the mistake |
| REST drain/ack = source of truth, WS = hint | **KEEP** | Matches XMPP MAM+SM division of labor |
| First-class device-list/prekey resource | **KEEP** | Avoids OMEMO's presence-coupled races |
| PQ always-on + numeric suite registry | **KEEP** (refine) | Add authenticated-negotiate-then-lock-in for federated rollout |
| Groups = client-managed blobs | **CHANGE** | Adopt GV2 pattern: server-held encrypted+versioned state, sender keys for fan-out, signed membership manifest |
| Sender plaintext to server | **CHANGE (staged)** | Reserve `Option` sender + access-token fields now; ship sealed sender as all 3 parts together |
| Server-assigned device lists | **CHANGE (priority)** | Signed per-account device manifest (cross-signing) in the v1 wire; key-transparency-ready |
| s2r delivery semantics | **ADD** | Durable in-order retry + per-destination sequence numbers + gap detection (Matrix retry minus its DAG backfill) |
| s2r request auth | **ADOPT verbatim** | X-Matrix-style Ed25519 signing with destination binding + 401-on-mismatch |
| Mailbox paging/dedup | **ADD** | Monotonic id as cursor+dedup key; `limit+1` probe; `complete` flag; strip foreign ids |
| Prekey lifecycle | **ADD** | Staged mark-then-delete with grace window; pool monitoring; device expiry + retention sweep |
| Ratchet PQ parameter in docs | **FIX** | ML-KEM-768 for SPQR ratchet; ML-KEM-1024 is PQXDH-only |
| iOS engine model | **ADOPT** | NSE + app = same engine, file-lock arbitration; content-free push, NSE drains & can silence |
| Client outbox/catchup | **ADOPT** | Persist-before-send; catchup-vs-live delay queue; single `idle` predicate |
| Group anon credentials (full zkgroup) | **DEFER (don't preclude)** | Signed manifest now; zkgroup issuance later without wire break |
| MLS group layer | **DEFER (don't preclude)** | Immature for federation; keep group format migratable |

---

## 11. Open questions (carried forward)

- Device-list authenticity mechanism: cross-signed manifest vs full key-
  transparency log — which for v1, and the manifest format that lets the
  latter wrap the former later?
- Does server-held encrypted group state (GV2 pattern) compose with a future
  MLS migration, or does choosing sender keys now foreclose it?
- Sealed sender across federation: how does a remote server enforce the
  delivery-token gate without learning the sender? (Signal is single-server;
  this is genuinely new territory kutup must design.)
- Mailbox retention + device-expiry policy defaults, and their interaction
  with quota.

---

## 12. Sources

Primary + peer-reviewed (verified verbatim): signal.org blog (the-ecosystem-
is-moving, sealed-sender, private-groups, signal-private-group-system, spqr);
zkgroup CCS 2020 (eprint 2019/1416); Triple Ratchet (Dodis et al., RWC 2025);
Multi-Device for Signal (ACNS 2020, eprint 2019/1363); WhatsApp device
topology (USENIX WOOT'24); Matrix S&P 2023 (nebuchadnezzar-megolm.github.io);
Matrix Project Hydra + security pre-disclosure (CVE-2025-49090); Matrix
server-server spec (v1.9 + unstable). Local codebases studied read-only:
`libsignal` (rust/protocol, rust/zkgroup, rust/net, rust/account-keys),
Prosody trunk (mod_s2s, mod_smacks, mod_mam, mod_cloud_notify, mod_pep, core
event/module system), ejabberd (ejabberd_s2s*, mod_stream_mgmt, mod_mam,
mod_offline, mod_push*, gen_mod, ejabberd_hooks, node_pep), Monal (xmpp.m,
NotificationService.m, MonalAppDelegate.m, MLOMEMO.m, MLSignalStore.m,
MLProcessLock.m, MLIQProcessor.m, DataLayer.m).
