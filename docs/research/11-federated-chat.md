# Research: Federated E2EE chat ("ileti") — Signal protocol core, Matrix-style transport federation, single-port 443

**Captured:** 2026-07-12
**Status:** Architecture recommendation, approved as the direction. Code-grounded against a local libsignal checkout at **v0.97.2** (2026). **Phase-1 wasm spike: done same day — verdict GO** (see §5 and `spikes/libsignal-wasm/`); phases 2+ not started.
**Scope:** A WhatsApp/Signal-class chat feature for kutup — 1:1 + group text, media, voice/video — federated between kutup instances (like Matrix), E2EE with the Signal protocol as the reference (libsignal checkout studied at `~/_e/development/libsignal`), with algorithm agility (post-quantum negotiable at the protocol level), media stored in the user's existing E2EE drive, and **clients + servers needing only port 443**. Working name: **ileti** (`ileti.kutup.dev` for the chat UI, `depo.kutup.dev` for the drive UI — same backend, same port).

Priorities set by the user: **#1 security, #2 stability. No quick hacks; enterprise-grade.**

---

## 1. What libsignal actually is (code-grounded, v0.97.2)

The 2026 checkout includes machinery the published Signal specs don't cover yet. Layering, bottom-up (paths relative to the libsignal repo):

### 1.1 Key agreement — PQXDH behind a `Handshake` trait

`rust/protocol/src/pqxdh.rs`: 4× X25519 DH + 1 ML-KEM-1024 encapsulation/decapsulation, KDF label `WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024`. As of 2026 it sits behind a **`Handshake` trait** (`rust/protocol/src/handshake.rs`) explicitly documented as abstracting "PQXDH, and hypothetical future variants" — key agreement is decoupled from ratchet initialization. **This trait is exactly the seam our algorithm-agility requirement needs.**

### 1.2 Messaging — Triple Ratchet (Double Ratchet + SPQR)

`rust/protocol/src/triple_ratchet.rs`: the Double Ratchet combined with **SPQR** (Sparse Post-Quantum Ratchet — separate crate, pinned `signalapp/SparsePostQuantumRatchet` tag v1.5.1 in the workspace `Cargo.toml`). Signal in 2026 is post-quantum in *both* the handshake (PQXDH) and the ongoing ratchet (SPQR): forward secrecy **and** post-compromise security hold against harvest-now-decrypt-later.

### 1.3 How Signal does algorithm "negotiation" — the part that matters most for us

There is **no in-band cipher negotiation**. Instead:

- **Version nibbles**: every message leads with `(message_version << 4) | CURRENT_VERSION` (`rust/protocol/src/protocol.rs:106`; `CIPHERTEXT_MESSAGE_CURRENT_VERSION = 4`, v3 = pre-Kyber/X3DH era). Decoders reject versions above what they speak.
- **Typed key registry**: `kem::KeyType` (`rust/protocol/src/kem.rs`) assigns wire type bytes — `0x07` Kyber768, `0x08` Kyber1024, `0x0A` ML-KEM-1024 behind a cargo feature. New KEMs slot in without protocol redesign.
- **Capability = published prekey bundle**: a device advertises what it supports by what its bundle contains (Kyber prekey present ⇒ PQXDH-capable). The *initiator* picks from the bundle; no negotiation round-trip exists.
- **Policy, not user choice**: `SessionUsabilityRequirements` bitflags (`rust/protocol/src/state/session.rs:112` — `NotStale | EstablishedWithPqxdh | Spqr`) let a client refuse to keep using downgraded sessions. `should_use_nonpq_session(require_pq_ratio, session_key)` (`rust/protocol/src/protocol.rs:991`) implements **deterministic fleet-wide gradual enforcement**: both sides independently derive the same keep/expire decision from 4 bytes of the session key vs. a rollout ratio.
- **Documented downgrade hazard**: the `Spqr` flag's doc comment warns a peer can strip SPQR from a session unless the local client rejects downgrades. Signal's stance throughout: **ratchet-up-only policy, never symmetric negotiation.**

### 1.4 Groups — two independent layers

- **Sender Keys** (`rust/protocol/src/group_cipher.rs`, `sender_keys.rs`): per-sender symmetric ratchet for fan-out efficiency; the `SenderKeyDistributionMessage` is delivered to each member over pairwise (Triple-Ratchet) sessions; membership changes force re-key.
- **zkgroup** (`rust/zkgroup`, paper: "The Signal Private Group System"): group state lives server-side as an **encrypted blob**; membership is proven with zero-knowledge credentials so the server never learns who's in a group. Optional for us at v1 of chat — the encrypted-blob part matters, the zk part can come later.

### 1.5 Metadata protection — sealed sender

`rust/protocol/src/sealed_sender.rs`: server-issued `SenderCertificate` (chained from a `ServerCertificate` trust root) travels *inside* the encrypted envelope; v2 does multi-recipient fan-out (one ciphertext body + per-recipient key slots; the server splits it). **Depends on a trusted certificate root — inherently harder federated** (§7).

### 1.6 Identity verification

- `rust/protocol/src/fingerprint.rs` — safety numbers (displayable + scannable) for user-level verification.
- `rust/keytrans` — full **key transparency** implementation (VRF prefix tree + Merkle log tree) so clients can audit the server's key directory. In federation KT matters *more* than at Signal: you must distrust the remote server's directory too.

### 1.7 Transport and storage

- Signal's entire client transport is TLS to hostnames (`chat.signal.org`, `grpc.chat.signal.org` — `rust/net/src/env.rs`) on **443**, WebSocket + gRPC, with censorship-circumvention routing in `rust/net/infra`. Signal is existence proof that a full messenger (minus media) needs only 443/tcp.
- The protocol crate persists **nothing**: the app implements `SessionStore`, `PreKeyStore`, `SignedPreKeyStore`, `KyberPreKeyStore`, `IdentityKeyStore`, `SenderKeyStore` traits (`rust/protocol/src/storage.rs`). That's our integration surface.

### 1.8 License

libsignal is **AGPL-3.0-only; kutup is AGPL-3.0** — compatible. Caveats: the README states use outside Signal is unsupported, and APIs churn without notice. Mitigation: pin a git tag, wrap behind our own facade crate, never let libsignal types leak into kutup APIs.

---

## 2. How Matrix does it — take vs. leave

Matrix = **replicated state machine**: rooms are DAGs of signed events replicated onto *every* participating homeserver, with a state-resolution algorithm merging concurrent membership/power-level changes. Federation is HTTPS + Ed25519-signed server-to-server requests; `.well-known/matrix/server` delegation lets port 8448 become plain 443. E2EE is Olm (pairwise) + Megolm (group sender keys).

**Take:**
- `.well-known` discovery → 443-only federation, arbitrary domain delegation.
- `user@domain` addressing.
- Ed25519 server signing keys + signed s2s requests.
- Store-and-forward with retry/backoff for offline servers.

**Leave — the replicated room DAG.** It is the source of Matrix's worst problems: state-resolution bugs have caused real security incidents (membership resurrection), room state is plaintext metadata on every participating server (who's in what room), and state res is a huge stability liability. Megolm is also weaker than Signal's ratchet (keys reused across messages until rotation ⇒ weaker FS/PCS).

**Key architectural insight:** Matrix needs replicated rooms because rooms are *server-side* objects. If group membership is a **client-managed encrypted blob** (Signal's private-group model), federation collapses to *dumb signed-ciphertext delivery between mailbox servers* — enormously simpler, more stable, leaks far less metadata. That is the right model for kutup.

(MLS / RFC 9420 was considered: native ciphersuite negotiation and O(log n) group operations are attractive, and Matrix itself is migrating toward it. Rejected as the v1 core because the user's reference point is the Signal protocol, the audited reference implementation is sitting on disk in our stack's language, and sender-keys groups are sufficient at kutup's expected group sizes. MLS remains the escape hatch if huge rooms become a requirement — the envelope's suite registry (§4) leaves room for it.)

---

## 3. Requirements recap

1. E2EE chat, 1:1 + groups, federated across 2+ kutup instances.
2. Signal protocol as the reference; changeable/negotiable encryption algorithms (PQ or not).
3. Media/files stored in the user's existing E2EE drive quota.
4. Architecture reusable by a future native WhatsApp-like iOS/Android client, exactly as Signal apps consume libsignal.
5. **Single port**: clients need only 443; the server exposes only 443 — for drive, chat, and voice/video. Separate domains OK (`depo.` / `ileti.`).
6. Enterprise-grade: security #1, stability #2.

---

## 4. Recommended architecture

### 4.1 Identity & trust

- Address: `user@server` (e.g. `maya@kutup.example.org`). Multi-device from day one — libsignal's `ProtocolAddress` is (user, device-id), and every kutup user already has an asymmetric keypair (`users.public_key`, used today for wrapping federated collection keys).
- Each server holds an **Ed25519 server signing key**, published with its API endpoint at `/.well-known/kutup/federation.json`. Server-to-server requests are signed (Matrix-style, or RFC 9421 HTTP Message Signatures) and verified over TLS.
- User identity keys: TOFU + safety numbers (libsignal `fingerprint.rs`) at chat-v1; **key transparency** (libsignal `keytrans` as reference) as the follow-up hardening.

### 4.2 Protocol core

- **Consume `libsignal-protocol` (git-pinned tag) as the engine**, wrapped in our own crate. Security priority #1 rules out reimplementing a ratchet; this is among the most audited implementations in existence, in Rust, AGPL-compatible.
- 1:1 and groups: pairwise **Triple Ratchet**; groups via **Sender Keys distributed over pairwise sessions**, group state as an encrypted blob on the group-owner's server (client-managed membership; zkgroup's zero-knowledge layer optional/later).
- **Algorithm agility, done safely** — a versioned **suite registry** in our envelope:
  - Suite v1 = `X25519 + ML-KEM-1024 (PQXDH) / Triple Ratchet (DR + SPQR)` — i.e. exactly libsignal message-version 4.
  - Future suites slot in via libsignal's `Handshake` trait seam (or a fork thereof).
  - Capability advertisement = what's in the device's published prekey bundles, **signed by the device identity key** so a malicious (remote) server can't strip PQ prekeys to force a downgrade.
  - Enforcement = client policy floors à la `SessionUsabilityRequirements`, configurable per server/org ("require PQ"), with `require_pq_ratio`-style deterministic rollout if we ever need gradual migration.
- **⚠️ Explicit design decision — PQ is not a user toggle.** Hybrid PQ costs only bundle/message size, and every "negotiate down" path is a downgrade-attack surface; this is precisely why Signal hard-codes hybrid and ratchets policy up-only (§1.3). We build the *mechanism* (suite registry + versioning — genuinely needed to migrate off X25519 someday) but ship PQ **always-on** with policy floors. "Users can negotiate no-PQ" would contradict priority #1.

### 4.3 Federation — transport-only, no shared state

Per recipient domain, the sender's server:

1. **Discovers** the peer via `/.well-known/kutup/federation.json` — SSRF-validated exactly like today's `crates/kutup-server/src/ssrf.rs` + `handlers/fedproxy.rs` discipline (no redirects, address checks).
2. **Delivers**: `POST /api/fed/chat/messages`, request signed with the server key, body = opaque sealed envelopes. The receiving server drops them into per-device **mailboxes**.
3. **Queues + retries** with backoff while the peer is down; per-sender ordering preserved.

Clients drain their mailboxes over a **WSS stream on 443** (the collab hub already proves WS-through-nginx-443 in this stack). No shared room state, no event DAG, no state resolution: a downed federation peer means "messages queue and retry" — a stability property Matrix structurally cannot offer.

### 4.4 Media & attachments — reuse the drive

Signal attachments already work exactly like kutup's E2EE files: encrypt client-side → upload to dumb blob storage → send *pointer + key + digest* through the E2EE channel. So:

- Attachments are encrypted client-side and uploaded via the existing **tus** path into the **sender's drive quota**.
- Cross-server recipients fetch via **per-object capability tokens** — the same mechanism `handlers/federation.rs` uses for federated shares today.
- Quota, retention, and `orphan-sweep` come free from existing drive machinery.

### 4.5 Voice/video on 443

- **Signaling**: over the chat channel itself (E2EE call setup — RingRTC's model).
- **Media**: WebRTC. 1:1 P2P where possible; group calls through an **SFU that never sees plaintext** — E2EE frame encryption (insertable streams in browsers), frame keys distributed over the Signal-protocol channel. This is Signal's own group-call design; their SFU (**Signal Calling Service**) is open-source **Rust, AGPL** — the natural candidate. Alternative: LiveKit (more turnkey, Go, embedded TURN, E2EE frame support).
- **Port story**: media runs entirely over tcp/443 via **TURN-over-TLS**, SNI-demuxed (§4.6). Reality check: real-time media over TCP degrades under packet loss (head-of-line blocking). Enterprise answer: **udp/443 for TURN as the preferred path, tcp/443 TLS as the guaranteed fallback** — still "only port 443" in every firewall rule, both protocols. (Cloudflare/Google run TURN this way.)

### 4.6 Single-443 topology

One nginx `stream` listener with `ssl_preread` routes by SNI, so one IP:443 serves everything; clients never dial anything else:

```
                      :443 (tcp, + optional udp for TURN)
                              │  nginx stream + ssl_preread (SNI demux)
        ┌─────────────────────┼──────────────────────┐
   depo.example.org      ileti.example.org      turn.example.org
        │                     │                      │
   HTTP vhost            HTTP vhost             coturn (TLS / DTLS)
   (drive SPA,           (chat SPA,                  │
    /api/*,               /api/chat/*,            SFU media relay
    tus, WSS collab)      WSS mailbox stream,
                          /api/fed/chat/*)
        └──────────┬──────────┘
             kutup-server (one binary)
```

Federation s2s is plain HTTPS on the same 443. `.well-known` keeps domain naming free.

### 4.7 Repo structure

```
crates/
  kutup-chat-proto     # envelope formats, suite registry, federation types (no I/O)
  kutup-chat-core      # client engine: wraps libsignal-protocol + spqr behind our facade,
                       #   implements the store traits, session policy —
                       #   used by the CLI, Tauri, and (via wasm) the web client
  kutup-server         # + chat module: prekey directory, mailboxes, group blobs,
                       #   federation delivery queues, WSS — same binary, same 443
frontend/              # ileti app: separate entry/domain, shared design system
```

- **One server binary, one port.** Chat is a module in `kutup-server` (clean boundary so it can split into its own service later if scale demands). `depo.` vs `ileti.` is pure nginx vhost routing.
- **The future native mobile client**: `kutup-chat-core` is our libsignal-analog — Tauri mobile (or any future native app) links it natively, exactly like Signal-Android links libsignal over JNI.
- **The web client is the one real unknown**: libsignal ships **no wasm bridge** (bridges are `jni`/`ffi`/`node` only — Signal Desktop is Electron). The protocol crate is pure Rust (curve25519-dalek + RustCrypto), so wasm32 is *plausible*, but SPQR + ML-KEM under wasm and IndexedDB-backed stores need a **spike to verify**. This is the #1 technical risk; retire it first.

---

## 5. Phasing

1. **Spike (go/no-go)**: `libsignal-protocol` + `spqr` on `wasm32-unknown-unknown`, thin wasm-bindgen wrapper, IndexedDB store impls. Falls out: whether the web client shares `kutup-chat-core` or needs another plan.
   **→ Done 2026-07-12, verdict GO** (`spikes/libsignal-wasm/`): compiles for `wasm32-unknown-unknown` on stable rustc (831 KB release `.wasm`); full PQXDH(Kyber1024) + Triple-Ratchet round-trip with `SessionUsabilityRequirements::all()` verified *executing in wasm* (Node WASI, 28 ms). Wire sizes: 1762 B PreKeySignalMessage / 105 B steady-state. Friction (all resolved, see the spike README): protoc at build time, dual getrandom-major feature opt-ins, browser clock discipline (`SystemTime::now()` panics on wasm32-unknown-unknown — pass timestamps explicitly, avoid `KyberPreKeyRecord::generate`), IndexedDB stores ⇒ wasm-bindgen-futures. Web client shares `kutup-chat-core`.
2. **`kutup-chat-proto` + local 1:1 chat**: prekey directory endpoints, per-device mailboxes, WSS drain, sealed envelopes — single server.
   **→ Server slice done 2026-07-12** (same PR series): proto crate (numeric suite registry), migration 021 (devices/pools/mailbox — public keys + opaque ciphertext only), 10 chat endpoints incl. the Signal missing/stale/extra device-set contract and pool-consuming bundle fetch with last-resort Kyber fallback (rate-limited: `RATE_LIMIT_CHAT_KEYS_PER_MIN`), chat WS hub + nginx upgrade location. Client engine (`kutup-chat-core`) is the remaining half of this phase.
3. **Federation**: server signing keys, `.well-known/kutup/federation.json`, signed s2s delivery, retry queues, per-domain rate limits.
4. **Groups**: sender keys + encrypted group blobs, membership changes → re-key.
5. **Media**: drive/tus integration + federated capability-token fetch.
6. **Calls**: 1:1 WebRTC → SFU group calls; TURN + SNI demux on 443 (+ optional udp/443).
7. **Hardening**: key transparency, sealed-sender-in-federation, zkgroup, censorship-resilient routing.

---

## 6. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| ~~libsignal wasm compile fails / too heavy for browsers~~ | ~~High~~ **Retired** | Spike passed 2026-07-12: 831 KB browser-target `.wasm`, protocol executes in wasm (§5) |
| libsignal API churn ("unsupported outside Signal") | Medium — maintenance tax | Pin git tags; facade crate; upgrade deliberately |
| Downgrade attacks via federated prekey directories | High if unmitigated | Sign bundles with device identity keys; client policy floors; ratchet-up-only |
| TURN-over-TCP call quality | Medium — UX | udp/443 preferred path; document the tradeoff for self-hosters |
| Federation spam/abuse | Medium | Extend `ratelimit.rs` per remote domain; allowlist/blocklist knobs |
| Metadata visible to servers (who talks to whom, when) | Inherent to store-and-forward | Honest documentation; sealed-sender research (§7); don't promise what E2EE doesn't give |

---

## 7. Open questions (parked, not blocking)

- **Sealed sender across federation** — Signal's design assumes one trusted certificate root; with N mutually-distrusting servers, who signs sender certificates and what does the recipient's server accept? Possibly per-server roots + recipient-side policy, or drop sealed sender initially and document sender-visibility honestly.
- **Mailbox retention under E2EE** — how long do undelivered ciphertexts live? Interaction with quotas and abuse.
- **Group-blob placement** — owner's server (simple, but owner-server outage blocks membership changes) vs. replicated (Matrix territory — avoid). Leaning: owner's server, messages still flow peer-to-peer-ish through mailboxes during outages.
- **MLS migration path** — if kutup ever needs 1000+ member rooms, sender-keys re-key cost becomes painful; the suite registry should leave a slot for an MLS-based group suite.
- **WebAuthn/passkey interplay** — the roadmap already flags passkey research; a chat device-registration flow should share that story.

---

## 8. Summary

**Signal-protocol crypto** (libsignal as a pinned, wrapped dependency — not a reimplementation) + **Matrix-style *transport-only* federation** (signed HTTPS s2s + `.well-known`, but **no replicated room state**) + **kutup's existing drive/tus/fed-token machinery for media** + **SNI-demuxed single-443** with TURN(-over-TLS/UDP-443) for calls. Algorithm agility ships as a versioned suite registry with signed capability advertisement and policy floors — **PQ always-on hybrid, never a user-facing downgrade toggle**. That's the difference between crypto-agility and a downgrade attack.
