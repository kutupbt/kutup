# Research: Modern Collaborative-Edit Stack for kutup (text/markdown path)

**Captured:** 2026-05-04
**Scope:** Production-ready, end-to-end-encrypted, real-time collaborative editing of text/markdown/code files inside kutup (Go + React/TS + libsodium). Initial target: a single shared markdown document with multiple authenticated users editing live. Surveys CRDT engines, editor libraries, sync transports, and the E2EE wrapper pattern, then recommends a stack.

---

## Layer 1 — CRDT / sync engine

|  | **Yjs** | **Y-CRDT (yrs)** | **Automerge 3** | **Loro** | **chainpad** |
|---|---|---|---|---|---|
| Algorithm | YATA (linked list) | YATA (Rust port) | RGA + rich-text spans | Fugue (Rust) | OT-on-blockchain |
| Maturity | Stable since 2015, v13.6.x in 2026 | Stable, ~1.0 line | Stable since Automerge 2.0 (Jan 2023); 3.x | v1.x but project still warns "API may break" | Stable but legacy |
| Wire format | Compact binary `Uint8Array`, opaque to anything but a Yjs decoder | byte-compatible with Yjs | Compact binary, opaque | Compact binary, opaque, often smallest in benchmarks | JSON-ish patches over WebSocket |
| Encoding size | Excellent for text (best-in-class) | Same | Slightly heavier than Yjs for pure text | On par with Yjs after compaction | Larger; not designed for compactness |
| E2EE-friendly? | **Yes** — updates are pure binary blobs that are commutative/associative/idempotent. Encrypting the whole update preserves convergence as long as the server delivers all blobs to all peers. | Same | Yes | Yes | Yes, but tied to its own crypto |
| Editor bindings | Huge: y-prosemirror, y-tiptap, y-codemirror.next, @lexical/yjs, y-monaco, y-quill, y-milkdown | Reuses Yjs JS bindings via WASM | ProseMirror binding (Automerge 2.2+) and `@automerge/prosemirror`; no Lexical/Tiptap bindings | loro-prosemirror, loro-codemirror — newer, smaller community | Custom CodeMirror 5 binding only |
| Server-side | Node (yjs), Rust (yrs), Python (pycrdt), Elixir (y_ex), Go via `k_yrs_go` (Postgres+Redis, 2025) or yrs over CGO | First-class Rust server (yrs-warp, July 2025) | `automerge-go` (cgo wrapper) | Rust core, JS/Swift bindings; no idiomatic Go binding | Node only |
| Awareness | y-protocols/awareness (state-based CRDT) | Compatible | None built-in (DIY) | Built-in ephemeral state | Custom |
| License | MIT | MIT | MIT | MIT | AGPL-3.0 |
| Bundle (gzip) | ~45 kB core | ~120 kB Wasm | ~150 kB Wasm | ~120 kB Wasm | n/a |

**Recommendation: Yjs.** Largest editor-binding ecosystem (swap editors later without changing the CRDT), smallest bundle, most diverse server implementations including a Rust port (yrs) embeddable from Go via FFI for server-side compaction, most battle-tested wire format. Loro is exciting but not production-ready by its own admission. Automerge 3 is solid but lacks Lexical/Tiptap bindings. chainpad is the worst of all worlds for a 2026 build (legacy + AGPL).

**Sources:** [yjs/yjs](https://github.com/yjs/yjs), [Yjs license docs](https://docs.yjs.dev/license), [y-crdt/y-crdt](https://github.com/y-crdt/y-crdt), [yrs-warp](https://github.com/y-crdt/yrs-warp), [k_yrs_go](https://github.com/kapv89/k_yrs_go), [Automerge 2.2 Rich Text](https://automerge.org/blog/2024/04/06/richtext/), [Automerge 3](https://automerge.org/blog/automerge-3/), [automerge-go](https://github.com/automerge/automerge-go), [loro-dev/loro](https://github.com/loro-dev/loro), [Loro changelog](https://loro.dev/changelog), [crdt-benchmarks](https://github.com/dmonad/crdt-benchmarks).

---

## Layer 2 — Editor library

For markdown specifically (with potential expansion to rich text + code later):

|  | **CodeMirror 6** | **ProseMirror** | **Tiptap 3** | **Lexical** | **Monaco** | **Milkdown** |
|---|---|---|---|---|---|---|
| Model | Markdown-as-source | Tree/schema (WYSIWYG) | Tree/schema (ProseMirror under the hood) | Tree/schema | Markdown-as-source (heavy) | WYSIWYG markdown over ProseMirror |
| Min bundle (gzip) | ~75 kB minimal, ~150 kB with markdown+lint | ~110 kB with schema-basic | ~90 kB Tiptap StarterKit (tree-shakable) | ~80 kB core | ~700 kB+ — too heavy for a notes app | ~150 kB+ |
| Accessibility | Excellent, keyboard-first | Excellent | Inherits ProseMirror's A11y | Strong | OK for code, weaker for prose | Inherits ProseMirror |
| Mobile/touch | Excellent | Good | Good | Best-in-class on iOS | Poor | Good |
| Awareness/cursor | y-codemirror.next renders peer cursors as decorations | y-prosemirror canonical cursor plugin | y-tiptap (extends y-prosemirror) | @lexical/yjs has cursor support but extra wiring | y-monaco exists but heavy | Inherits y-prosemirror |
| Yjs binding | y-codemirror.next — actively maintained | y-prosemirror — the reference binding | y-tiptap — first-party, supports comments | @lexical/yjs — official but more glue code | y-monaco — works but huge | Built-in collab plugin uses y-prosemirror |
| Markdown story | `@codemirror/lang-markdown`: source-mode editing, GFM, syntax highlighting; `.md` stays canonical | Need a markdown schema + serializer | Bidirectional CommonMark since v3 | `@lexical/markdown` shortcuts; round-trip lossier | n/a | Markdown-native |
| Maintenance | Continuously released, MIT, very stable | Same maintainer, mature | v3.0 stable July 2025, MIT, backed by Tiptap GmbH | Active monthly through v0.43.x | Backed by Microsoft | MIT, active |

**Recommendation: CodeMirror 6 + `@codemirror/lang-markdown` + `y-codemirror.next`.** The user's mental model is `.md`; CodeMirror's source-mode keeps the on-disk format identical to what's edited — no schema/round-trip lossiness. The Yjs binding is to a `Y.Text`, the simplest possible CRDT shape to encrypt and reason about. Layer richer affordances later (live preview pane, slash commands, embedded code blocks).

If WYSIWYG is needed later, **Tiptap 3** with bidirectional markdown serialization keeps the same on-disk format and the same Yjs document survives the migration.

**Avoid Lexical for v1** (lossier markdown round-trip, more DIY Yjs glue). **Avoid Monaco** (700 kB+). **Milkdown** is interesting but fewer eyes than Tiptap.

**Sources:** [Liveblocks 2025 RTE comparison](https://liveblocks.io/blog/which-rich-text-editor-framework-should-you-choose-in-2025), [y-codemirror.next](https://github.com/yjs/y-codemirror.next), [@codemirror/lang-markdown](https://github.com/codemirror/lang-markdown), [y-prosemirror](https://github.com/yjs/y-prosemirror), [y-tiptap](https://github.com/ueberdosis/y-tiptap), [Tiptap 3.0](https://tiptap.dev/tiptap-editor-v3), [Tiptap bidirectional markdown](https://tiptap.dev/blog/release-notes/introducing-bidirectional-markdown-support-in-tiptap), [Lexical Yjs FAQ](https://lexical.dev/docs/collaboration/faq).

---

## Layer 3 — Sync transport / signaling

|  | **y-websocket** | **Hocuspocus** | **PartyKit (Cloudflare)** | **Custom Go relay** | **y-webrtc** | **Liveblocks / Y-Sweet** |
|---|---|---|---|---|---|---|
| Stack | Node, reference impl | Node (Bun/Deno/Workers compatible) | Cloudflare Durable Objects | Go (you write it) | Browser P2P + signaling | Hosted |
| Scalability | Single-process, needs Redis fan-out (`y-redis`) | Pluggable Redis backend; scales | Per-room Durable Object — automatic horizontal scaling | Whatever you build (goroutine-per-conn) | N peers = N² connections | Edge-distributed |
| Persistence | Pluggable (LevelDB default) | Database/S3/Redis extensions; debounced `onStoreDocument` | Built into Durable Object storage (SQLite-backed in 2025) | You decide — fits kutup's existing Postgres | None server-side | Built-in |
| **Server reads plaintext?** | **Yes** — server merges Yjs updates and serves syncStep1/2 | **Yes** — Hocuspocus instantiates a `Y.Doc` server-side to apply updates | **Yes** — Durable Object holds `Y.Doc` | **No (if dumb relay)** — opaque bytes, broadcast + persist | No — peers communicate directly; signaling sees only room IDs | Yes |
| Backpressure | WebSocket-level; weak by default | Better — built-in throttling/debouncing | Durable Object queues | You control | n/a | Managed |
| Awareness | Built-in y-websocket protocol | Same | Same | You forward (still binary, can be encrypted) | Built-in | Managed |
| License | MIT | MIT | MIT | yours | MIT | proprietary |

**The critical fact for E2EE:** y-websocket, Hocuspocus, PartyKit, Liveblocks all instantiate a `Y.Doc` on the server. They merge updates server-side because that's how `syncStep1` (state-vector exchange) works in the standard Yjs sync protocol. **If the server can't decrypt, it can't compute that diff** — adopting any of those servers as-is breaks E2EE.

**Recommendation: custom Go relay** in kutup's existing Fiber backend (~300 LOC):
- One room per file_id; each room is `map[connID]*Conn`.
- Every binary frame from peer A is forwarded to all other peers + appended to a per-room log (Postgres `bytea` table).
- New peers send their last-seen sequence number; server replays the log tail.
- Server treats every payload as opaque ciphertext with a small unencrypted header (room id, sender public key, sequence number, MAC).

This is exactly the architecture used by **CryptPad's history keeper** and **StealthRelay** for E2EE WebSocket relay — except in Go and skipping chainpad.

**Sources:** [Hocuspocus](https://github.com/ueberdosis/hocuspocus), [Hocuspocus database extension](https://tiptap.dev/docs/hocuspocus/server/extensions/database), [y-redis](https://github.com/yjs/y-redis), [Y-Sweet](https://jamsocket.com/y-sweet), [y-partykit](https://docs.partykit.io/reference/y-partykit-api/), [y-webrtc](https://github.com/yjs/y-webrtc), [y-protocols PROTOCOL.md](https://github.com/yjs/y-protocols/blob/master/PROTOCOL.md), [StealthRelay](https://github.com/Olib-AI/StealthRelay), [CryptPad architecture](https://github.com/cryptpad/cryptpad/blob/main/docs/ARCHITECTURE.md).

---

## Layer 4 — E2EE wrapper

### The shape of the problem

Yjs updates are commutative, associative, and idempotent binary blobs. So:

- If every peer encrypts each update with the *same* per-document symmetric key, the encrypted blobs are still commutative/associative/idempotent **as a set of opaque ciphertexts**. Convergence is preserved.
- The server's job collapses to: "broadcast this opaque blob to all room members; persist in append-only log; replay to new joiners." Never sees plaintext.
- Awareness updates are also small binary frames per the [y-protocols spec](https://github.com/yjs/y-protocols/blob/master/PROTOCOL.md) and can be encrypted with the same key.

### Concrete patterns from prior art

**Serenity Notes** ([serenity-kit/serenity-notes-clients](https://github.com/serenity-kit/serenity-notes-clients), [Tag1 deep dive](https://www.tag1consulting.com/blog/deep-dive-end-end-encryption-e2ee-yjs-part-2)) — the canonical reference for E2EE Yjs by Nik Graf and Kevin Jahns. Pattern: per-document symmetric key derived from a per-collection root key (matches kutup's existing collection-key model); every Yjs update encrypted with libsodium `crypto_secretbox` (XSalsa20-Poly1305 — kutup uses XChaCha20-Poly1305 which is a strict upgrade); each ciphertext signed by the sending device's signing key; server stores ciphertexts and signatures; new clients fetch all ciphertexts, verify signatures, decrypt, and `applyUpdate`. They discovered the linear-history performance problem: decrypting thousands of small updates on join is slow → periodic snapshot merging.

**ChainSafe Files E2EE study** ([research.chainsafe.io](https://research.chainsafe.io/featured/Publications/E2E-Encrypted-Doc/)) — recommends checkpointing every N patches where the checkpoint "deletes the entire document and re-inserts it" — a fresh `encodeStateAsUpdate` written as a new ciphertext that supersedes prior ones.

**CryptPad** ([whitepaper](https://blog.cryptpad.org/images/whitepaper.pdf)) — ships the reference relay model: server is a "history keeper" pseudo-joining each channel as a participant, stores encrypted messages.

**Notesnook** ([streetwriters/notesnook](https://github.com/streetwriters/notesnook)) — E2EE but no real-time collab; uses XChaCha20-Poly1305 + Argon2 for at-rest encryption (validates the crypto choices).

### Pitfalls

1. **Compaction problem.** Server can't compact (blind to content). Pattern: any peer with the doc key posts a "snapshot" ciphertext that supersedes prior updates up to a sequence number; server truncates the log. Trust is symmetric — any holder of the doc key can already overwrite content, so letting them post snapshots is no worse than the existing trust model.

2. **Replay protection / authenticity.** Encrypting alone doesn't authenticate the *sender*. A malicious co-editor could re-broadcast an old encrypted message. Mitigation: every update has a small AEAD-protected header with `(sender_device_pubkey, sequence_number)` as Additional Authenticated Data, and is Ed25519-signed by the sending device. Clients reject duplicates and reject signatures that don't chain to a current device key.

3. **Awareness leaks metadata.** Cursor positions encode struct IDs (clientID + clock); even encrypted, frequency analysis leaks "user is typing now." Acceptable for most threat models; throttle/pad if stronger needed.

4. **Key distribution / revocation.** Use kutup's existing collection-key model: each document gets a symmetric key wrapped per-recipient with their device public key (libsodium `crypto_box_seal`). Revocation requires *rekeying*: drop a new doc key, re-wrap for remaining members, force a fresh snapshot under the new key. Server can refuse to broadcast updates from revoked devices via signed ACL — integrity, not confidentiality, but useful.

5. **Schema validation impossibility.** Hocuspocus etc. let the server validate "does this Yjs update only touch fields the user is allowed to edit?" An E2EE relay cannot. Trust co-editors (acceptable for shared docs) or replicate checks on every client.

### Recommended E2EE wire envelope

```
struct EncryptedFrame {
  u8   version;                // 1
  u8   kind;                   // 1=update, 2=awareness, 3=snapshot
  u32  doc_key_id;             // for rotation
  u32  sender_device_id;
  u64  sequence;
  u8   nonce[24];              // XChaCha20 nonce
  u8   ciphertext[];           // AEAD over the Yjs update bytes;
                               // AAD = (version,kind,doc_key_id,sender,seq)
  u8   signature[64];          // Ed25519 over the entire frame above
}
```

Server stores frames as-is. To answer "give me everything since seq N" on join, server replies with a stream of frames; the new client verifies each signature, checks `doc_key_id` against its current key, decrypts, applies via `Y.applyUpdate`. Snapshot frames carry `Y.encodeStateAsUpdateV2` ciphertext and tell the server to truncate the log up to a given seq.

**Sources:** [Yjs document updates](https://docs.yjs.dev/api/document-updates), [y-protocols PROTOCOL.md](https://github.com/yjs/y-protocols/blob/master/PROTOCOL.md), [Yjs E2EE challenges thread](https://discuss.yjs.dev/t/end-to-end-encryption-challenges/1424), [Tag1: Deep Dive into E2EE in Yjs Part 2](https://www.tag1consulting.com/blog/deep-dive-end-end-encryption-e2ee-yjs-part-2), [ChainSafe E2EE doc editor](https://research.chainsafe.io/featured/Publications/E2E-Encrypted-Doc/), [Yjs GC + snapshots](https://discuss.yjs.dev/t/garbage-collection-and-version-snapshotting/1839).

---

## Final synthesis — recommended stack

**Use Yjs** (`Y.Text` for the markdown body, `Y.Map` if metadata needed) with **CodeMirror 6** + `@codemirror/lang-markdown` + `y-codemirror.next` for the editor. `.md` stays the literal source format, smallest bundle, best mobile IME story, Yjs binding bolts straight onto a `Y.Text`. Build a **custom Go WebSocket relay** (~300 LOC) that treats every frame as opaque ciphertext: per-room append-only log persisted to Postgres, broadcast-to-others on receive, replay-from-N on join, no `Y.Doc` server-side. Wrap every Yjs update and awareness frame in an **XChaCha20-Poly1305 AEAD envelope** (libsodium `crypto_aead_xchacha20poly1305_ietf_encrypt`) with `(version, kind, doc_key_id, sender_device_id, sequence)` as AAD, signed by the sender's Ed25519 device key; per-document symmetric key derived from the existing collection key, wrapped per-recipient via `crypto_box_seal`. Compaction is client-driven: any holder of the doc key periodically posts a "snapshot" frame with `Y.encodeStateAsUpdateV2` of the merged state and a `truncate_before` sequence number; the server truncates the log on receipt.

**Runner-up:** swap CodeMirror 6 for **Tiptap 3** with `y-tiptap` + bidirectional markdown if a richer authoring surface is needed. Same Yjs core, same Go relay, same envelope. Cost: ~30 kB more JS and slightly lossier markdown round-trip on uncommon constructs.

**Don't pick** Hocuspocus / PartyKit / Liveblocks at any tier — they all instantiate a `Y.Doc` server-side and that is structurally incompatible with E2EE in a self-hosted, zero-knowledge deployment.
