# Collab architecture comparison: kutup vs CryptPad vs Google Workspace

**Date:** 2026-05-07
**Purpose:** Establish a deep, citable understanding of how each system handles realtime collaborative editing — wire format, conflict resolution, persistence, encryption, presence — before we keep iterating on kutup's outstanding xlsx sync issue. No fixes proposed in this document; the goal is shared vocabulary and a clear map of where the three systems diverge.

---

## Executive summary

Three different architectures, three different bets:

| Bet | Google Workspace | CryptPad | kutup |
|---|---|---|---|
| **Trust model** | Server is canonical, sees plaintext | Server is content-blind | Server is content-blind |
| **Conflict resolution** | Server-arbitrated OT (Wave-derived) | Client-side hash-chain consensus (ChainPad) | Client-side Yjs CRDT (notes) + relay-ordered OnlyOffice OT (office) |
| **Wire transport** | Custom HTTP-channel (post-BrowserChannel), protobuf-as-JSON | WebSocket via Netflux multiplex | WebSocket per file |
| **ACK semantics** | Server returns transformed op + new revision | "Receive your own broadcast back" two-level ACK | Fire-and-forget; reconcile on resume |
| **Op log** | Yes (server-side, replayable per-revision) | Yes (history-keeper bot stores chained patches) | Yes (`file_update_log`, AEAD-sealed) |
| **Cell-edit semantics (sheets)** | Server-arbitrated last-writer-wins per cell, no per-cell lock | Per-cell lock acquired by `getLock`/`releaseLock`, propagated through `content.locks` | OnlyOffice expects locks; bridge currently fakes empty `locks: []` |

**Practical implication for the xlsx stall:**

Kutup combines an *OnlyOffice editor that expects per-cell locks* with a *content-blind relay that can't run OT or arbitrate locks server-side*. CryptPad makes the same combination work because their bridge maintains the full `content.locks` state machine on every client and propagates lock acquire/release through the encrypted message stream. Our bridge stubs out the lock plumbing entirely (`getLock` returns `[]`, `releaseLock` is a no-op, every outbound `saveChanges` carries `locks: []`). After commits 843718a / 66fd9ed / b78c7d6 fixed wire-format mismatches, the lock state machine remains the only major CryptPad-shaped primitive we don't replicate. That is the most likely remaining cause of the second-direction stall.

Google's contrasting design is informative: Sheets has *no per-cell locks at all*, because the server runs OT. Each `setCellValue(A1, x)` is an atomic op, the server sequences arrivals, last-writer-wins by sequence number. We can't copy that path because we're content-blind. So we have one structural choice ahead: replicate CryptPad's lock state machine, or move toward a CRDT-on-the-server model (Yjs-style) that doesn't need locks at all. (Yjs has experimental sheet/spreadsheet bindings via `y-sheet` etc., none production-ready for OnlyOffice.)

---

## 1. Wire layer

### Google Workspace
- **Transport.** Not WebSocket. Historically `BrowserChannel` (long-poll/streaming-XHR multiplex). Modern is a custom HTTP-based push/pull channel that resembles long-polling/SSE. (Joseph Gentle, ex-Wave.)
- **Format.** Protocol Buffers serialised as JSON. Op shape is small and tabular: `{"ty":"is","ibi":24,"s":"."}` = `{type: insert-string, insert-begin-index: 24, string: "."}`. Multiple ops bundle into a "multi" envelope.
- **Stop-and-wait composition.** While waiting for the server's ACK of op N, all subsequent local ops are *composed* into a single pending op and shipped on ACK. So at fast typing on a slow link you get one op per RTT, not one op per keystroke.
- **No per-message client→server ACK.** The server's response to a client op is the *transformed op + new revision number*, which is itself the ACK.

### CryptPad — Netflux
- **Transport.** WebSocket multiplex. Channels are addressed by 32-char IDs (`STANDARD_CHANNEL_LENGTH = 32`, `lib/hk-util.js:38`). Special channel lengths flag ephemeral / admin variants.
- **Message envelope.** Array `[seq, senderId, messageType, channelId, payload, …]`. Message types: `JOIN` / `LEAVE` / `MSG` / `ACK` (`lib/historyKeeper.js:38-43`).
- **History-keeper bot.** A server-side process registered as `Env.id`. On a client's first `JOIN`, it streams history via `handleGetHistory` (`hk-util.js:631`) — every prior message tagged with the channel's stable hash for dedup.
- **Two-level ACK.**
  - Server-level: `Server.send(userId, [seq, 'ACK'])` (`hk-util.js:577`) — confirms the RPC was accepted.
  - Application-level: when a client calls `rtChannel.sendMsg(msg, _, callback)`, the callback fires when the message is *broadcast back to the sender as part of the live stream*. The "ACK" is in fact "I saw my own message reach all peers, including me."
- **Checkpoint dedup.** Checkpoints prefixed `cp|<id>|` (`hk-util.js:1015`); the history-keeper rejects duplicates by id.

### kutup
- **Transport.** WebSocket per file. URL `wss://…/api/files/{fileId}/collab/ws?token=…&deviceId=…`.
- **Wire format.** A binary `CollabFrame` envelope (`backend/services/envelope/envelope.go:10-63`):
  - 30-byte header (version, kind, docKeyID, senderDeviceID, sequence, first 8 nonce bytes) — used as AEAD AAD.
  - 16-byte nonce remainder.
  - 4-byte ciphertext length.
  - Ciphertext (XChaCha20-Poly1305).
  - 64-byte Ed25519 detached signature covering everything before it.
- **Kind byte demuxes.** `KindYjsUpdate=1`, `KindYjsAwareness=2`, `KindSnapshotAnnounce=3`, `KindOOOp=4`, `KindOOLock=5` (defined but unused), `KindOOCheckpointMeta=6` (defined but unused).
- **Server-side validation.** `handleFrame()` (`backend/handlers/collab.go:300-340`):
  1. `Unpack` — must succeed.
  2. `SenderDeviceID == c.deviceID` — rejects forged sender.
  3. Ed25519 `Verify` against `device.public_signing` — rejects tampered or replayed-from-other-device.
  4. Doc-epoch check — rejects frames signed under stale `doc_key_id`.
- **No per-message ACK.** Frames are fire-and-forget. Loss between client and server is detected only on `resume` after reconnect, by replay diff.

---

## 2. Persistence + replay

### Google Workspace
- **Op log.** Server-side, immutable, indexed by revision number. Endpoint `revisions/load?id=…&start=N&end=M` (community-attested).
- **Snapshot cadence.** Periodic; not publicly documented. "Snapshot at revision K + ops since K" is what new clients hydrate from.
- **Reconnect.** Client's offline ops have `baseRevision`; server transforms each against intervening server-side ops and assigns a fresh revision per accepted op. Client also receives the ops it missed.
- **No log truncation.** Op log is intentionally retained — that's how Draftback can replay any keystroke of a doc you own.

### CryptPad
- **Op log.** Stored by the history-keeper. Each entry is the encrypted message blob; the server can't read it.
- **Hash chain inside.** ChainPad patches reference parent state hashes; the server orders by arrival but cryptographic causality is in the patch metadata.
- **Checkpoint cadence.** `FORCE_CHECKPOINT_INTERVAL` ~100 ops (`inner.js:71`). At a checkpoint, the document is encoded to a `.bin`, encrypted, uploaded to a blob store, and the checkpoint metadata is committed to the channel (`content.hashes[index] = {file, hash, …}`).
- **Reconnect.** Client requests history from its `lastKnownHash`; server streams in order; ChainPad's hash-chain detects divergence and applies transformations.

### kutup
- **Op log.** `file_update_log` table (migration `012_collab_edit.up.sql:16-25`):
  - PRIMARY KEY `(file_id, seq)` — the global per-file order.
  - UNIQUE `(file_id, sender_device, sender_seq)` — replay protection (`013_sender_seq.up.sql:10-11`).
- **Sequence assignment.** `seq = COALESCE(MAX(seq), 0) + 1` non-atomic (line 357). Two concurrent inserts can both compute the same seq; the second fails on PK and the frame is dropped. The sender notices on resume and retransmits.
- **Snapshots.** Client-driven — when idle >30s or ≥200 updates or explicit Save, the client encodes Yjs state via `Y.encodeStateAsUpdateV2` (`frontend/src/collab/snapshot.ts:78`), encrypts, PUTs to S3 via `/files/{fid}/snapshot-blob`, registers the version via `/files/{fid}/versions`. Backend stores `seqAtSnapshot`.
- **Log truncation.** Not implemented in v1; logs grow.
- **Replay.** Resume control message with `lastSeenSeq` triggers `replayLog()` streaming all `seq > lastSeenSeq` frames in order.

---

## 3. Conflict resolution

This is the layer where the three systems diverge most.

### Google Workspace — server-arbitrated OT
Wave-derived. The server holds the canonical state; every client op is sent with its `baseRevision`; the server runs `xform(c, s) → (c', s')` against any concurrent ops it has accepted in the meantime, applies `c'`, assigns a new revision number, and broadcasts.

The transformation function (TP1 property): `op1 ∘ T(op2, op1) ≡ op2 ∘ T(op1, op2)`. For a text insert at index 5 vs a concurrent insert at index 10, the second insert gets rewritten to "insert at 11" so both clients converge.

**Sheets-specific.** Per-cell op atomicity. `setCellValue(A1, x)` is the unit; OT *transforms the address* against intervening structural ops (insert row, delete column shift indices) but *not the value* — last-writer-wins on concurrent same-cell edits. **No per-cell lock.** When two users open the same cell in edit mode, neither blocks the other; the commit (Enter / click away) is the atomic op, and one will overwrite the other (visible in version history, no modal dialog).

### CryptPad — client-side ChainPad consensus
Hash-chain consensus, neither pure OT nor pure CRDT. Each patch carries `parentHash`, `hash`, `author`, `timestamp`. When two peers' patches diverge, both have the same `parentCount`; the system uses lexicographic hash comparison to break the tie deterministically, applies the winner, and queues the loser for transformation.

For OnlyOffice integration, the "patch" is an OnlyOffice OT change object wrapped in a CryptPad envelope. ChainPad orders the wrappers; OnlyOffice runs the actual OT inside the wrapper.

**Lock state machine** (`inner.js:1080-1142`, `1108-1141`). The client maintains `content.locks` as a map `{userId: {lockId: {time, user, block}}}`. Lifecycle:

1. User clicks cell A1. OnlyOffice fires `getLock({block: {guid: "A1-uuid"}})`.
2. Bridge adds `content.locks[myId][lockId] = {time, user: myUniqueOOId, block}`.
3. Bridge broadcasts via `rtChannel.sendMsg({type: 'getLock', …})`.
4. Other peers receive, store in their `content.locks`, and re-emit to OnlyOffice via `ooChannel.send({type: 'getLock', locks: […]})` so OO greys out the locked range.
5. User finishes; OnlyOffice fires `releaseLock`. Bridge deletes from `content.locks`, broadcasts the new state.
6. **`handleNewLocks`** (`inner.js:1108-1141`) — the *receive-side* lock differ. On every inbound message, it diffs the new `content.locks` against the previous `oldLocks` snapshot and emits `releaseLock` to OO for any lock that disappeared. Critical for offline-peer cleanup.

This is the primitive kutup doesn't have.

### kutup — Yjs CRDT (notes) + relay-ordered OnlyOffice OT (office)

**Notes (`.md` etc.) — Yjs.**
A CRDT. Local edits trigger Yjs's `'update'` event (`TextCollabEditor.tsx:207`); `onLocalUpdate` increments the per-tab outbound seq, encrypts, signs, ships. Remote frames are decrypted and `Y.applyUpdate(ydoc, upd, 'remote')`'d. Yjs guarantees:
- **Strong eventual consistency under arbitrary reorder + duplicate.** The relay's append-only log is *not strictly necessary* for Yjs — random delivery still converges via vector clocks.
- **Idempotent applies.** Same update applied twice has no effect.
- **Awareness via `KindYjsAwareness` frames.** Broadcast-only, never persisted.

Yjs's known weakness: concurrent inserts at the same logical position get a deterministic tiebreaker (clientID-based) — fine, never loses data, but the *relative order* may surprise users.

**Office (`.docx` / `.xlsx` / `.pptx`) — OnlyOffice's own OT.**
Kutup's bridge does *not* implement OT. OnlyOffice does, inside its iframe. Kutup's role:
1. Capture OnlyOffice's `saveChanges` postMessage (`inner.html:354-441`).
2. Wrap as `{type: 'saveChanges', changes, changesIndex, locks: [], …}`.
3. Encrypt as `KindOOOp`, sign, ship.
4. Receive remote `KindOOOp` frames, decrypt, postMessage to bridge as `oo-remote-op`.
5. Bridge calls `docEditor.sendMessageToOO(payload)`; OO runs its OT to merge.

The relay's append-only log gives OnlyOffice the **total order** its OT requires. Without that ordering guarantee OO will diverge — its OT was designed assuming a central coordinator (DocumentServer) imposes order.

**The lock plumbing is stubbed.**
- `getLock` from OO is answered with `{type: 'getLock', locks: []}` — every lock request granted immediately.
- `releaseLock` from OO is a no-op.
- Outbound `saveChanges` always carries `locks: []`.
- Inbound `saveChanges` is re-emitted to OO via `sendToOO(payload)` then `cpIndex++`. No lock differ — we never synthesise `releaseLock` from peer state changes.

This is the gap commit `b78c7d6` did *not* close, despite fixing the related `connectState` peer-list issue.

---

## 4. Encryption

### Google Workspace
- TLS in transit, encryption at rest in Google's storage, server holds plaintext.
- No E2EE for Workspace docs (Client-Side Encryption is a separate enterprise feature with managed KMS).

### CryptPad
- Per-channel symmetric key derived from the URL hash (`Hash.getSecrets`, `sframe-common-outer.js:427`).
- Every Netflux message is wrapped via `Crypto.encrypt` (`sframe-chainpad-netflux-outer.js:53`). Decrypt with the same channel key on receive.
- Validate keys (in restricted-channel metadata) sign messages so the server can verify writer-allowlist without seeing plaintext.
- Threat model: server cannot decrypt; cross-channel isolation by key uniqueness.

### kutup
- **Per-file content key.** HKDF-SHA256 derivation:
  ```
  content_key = HKDF-SHA256(
    ikm  = collection_master_key,
    salt = "kutup/file-content/v1",
    info = file_id_string,
  )
  ```
  Anyone with the collection key derives the file key — no separate key exchange.
- **AEAD: XChaCha20-Poly1305 (IETF).** 24-byte nonce, plaintext sealed with the 30-byte envelope header as AAD. Tampering with kind/sender/sequence/doc-epoch is detected on decrypt.
- **Signature: Ed25519 detached.** Covers the whole packed frame minus the trailing 64 signature bytes. Server verifies against `user_devices.public_signing`. Replay protection lives in the `(file_id, sender_device, sender_seq)` UNIQUE index, not the signature.
- **Key rotation.** `doc_key_id` increments on collection membership change. Server rejects frames with `doc_key_id < current_doc_key_id`. Old log entries deleted by vacuum once a snapshot under the new epoch exists. Removed members can't decrypt new updates.

---

## 5. Presence + cursors

### Google Workspace
- Same persistent connection as ops, separate logical pub/sub.
- **Ephemeral.** Cursors disappear when collaborators close the tab.
- **Out-of-order = newest wins.** No transformation on cursor positions.
- Cursor color is per-session per-document; anonymous viewers get the "anonymous quokka" identity.

### CryptPad
- Cursors flow via OnlyOffice's awareness + a separate metadata-only Netflux channel.
- Cursor wrapping at `inner.js:1563-1572`: `cursor.updateCursor({type: 'cursor', messages: [{cursor: pos, time, user: myUniqueOOId, useridoriginal: myOOId}]})`.
- Transient — never stored in history; dropped on disconnect.

### kutup
- **Notes (Yjs awareness).** `KindYjsAwareness` frames, broadcast-only, never persisted (`collab.go:325`). The `awareness.on('change')` handler encodes diffs via `encodeAwarenessUpdate()` and sends encrypted frames. Peers apply via `applyAwarenessUpdate()`. y-codemirror.next renders remote cursors with the peer's chosen color.
- **Office.** OnlyOffice's own users dropdown is now fed by the `oo-peers` server push (commit `b78c7d6`) and the bridge's `connectState` emission. Cursor presence inside the document itself is whatever OnlyOffice does internally — kutup doesn't touch it.
- **No throttling.** Awareness fires on every cursor move. A fast typist generates dozens of frames per second. Production would sample to ~10 Hz.

---

## 6. The architectural trilemma

Three properties any collab system would like:

- **(A) Server-arbitrated correctness** — server runs OT/CRDT and is the canonical source of truth. Easy semantics, easy ACLs, clear conflict resolution.
- **(B) Content-blind server** — the server can't read user data. Required for E2EE.
- **(C) Reuse of off-the-shelf editors** — embed something like OnlyOffice or Quill, not write a custom editor for every format.

**You can pick at most two:**
- Google has A + C, sacrifices B (server sees plaintext).
- CryptPad has B + C, sacrifices A (relies on client-side ChainPad consensus + OnlyOffice's tolerance for being told what order to apply ops in).
- Kutup currently has B + C, mirrors CryptPad's choice. The "second-direction stall" is exactly the cost of B+C: OnlyOffice expects either (A) — server arbitration via DocumentServer — or a fully replicated lock state machine on every client. We provide neither.

The three live options ahead, in order of effort:

1. **Replicate CryptPad's `content.locks` state machine** (smallest delta). Build the lock differ in the bridge, propagate `getLock`/`releaseLock` through `KindOOLock` envelopes (the kind constant already exists), and synthesise `releaseLock` to OO on inbound state changes. Maintains B + C. Effort: a focused 2-3 day implementation following CryptPad's reference verbatim.
2. **Move office to a CRDT-backed editor** (e.g. Yjs spreadsheet bindings, Quill+Yjs for docs). Drops dependency on OnlyOffice's lock plumbing. Maintains B + C, drops the OnlyOffice surface. Effort: 1-2 months; loses OOXML round-trip via x2t.
3. **Run a trusted OnlyOffice DocumentServer** for office docs only. Pivots to A + C for office. Drops B for office (server sees plaintext xlsx). Effort: 1-2 weeks integration; design compromise on E2EE for the office subtree only.

These are listed for completeness; this document is research, not a decision. The first option is the smallest delta to the current stack and is the natural continuation of the line of work in commits `843718a` / `66fd9ed` / `b78c7d6`.

---

## 7. Diagnostic angles for the standing xlsx stall (no proposed fix yet)

Five things worth instrumenting before the next attempt at a fix, derived from the comparison above:

1. **Capture every postMessage between OnlyOffice and the bridge during a known-bad sequence** (A type → B receives → B types → A doesn't receive). Save raw to a file. Repeat against CryptPad's working integration. The first divergent message is the bug. The previous research notes flagged this as the missing CryptPad-side instrumentation.

2. **Log `content.locks`-equivalent state on both sides.** Today our bridge has no such variable. Add a transient one (in-memory Map keyed by deviceId → set of locked block IDs) and observe whether OO sends `getLock` events at all in our failing trace. If OO is sending lock acquisitions and we're discarding them, that's the immediate fix candidate.

3. **Verify `m_bFast` is truthy in our setup.** CryptPad gates its `themeLocked` rebroadcast on `AscCommon.CollaborativeEditing.m_bFast` (`inner.js:1613`). If our editor isn't engaging fast-coediting mode despite the config, the state machine may degrade after the first remote apply.

4. **Watch the receive-side OnlyOffice logs.** OnlyOffice emits `clientLog` debug events (we already see `unhandled OO msg type=clientLog` in our traces). On the failing second-direction edit, scan for any `clientLog` referencing "lock", "permission", "denied", "out of order", "rejected", or numerical sequence values that don't match what we sent.

5. **Run with the Strict coediting mode** (vs Fast). OnlyOffice ships both. Strict adds explicit per-section locking with no real-time merge — if it works under Strict, it confirms the issue is in Fast-mode merge logic, not in our wire format.

These are observations to gather, not fixes. The Phase 6 lock plumbing remains the most likely structural fix.

---

## Sources

### CryptPad source (clone at `/home/aa/_e/development/cryptpad`)
- `lib/historyKeeper.js:13-140, 142, 38-43, 106` — Netflux server hooks
- `lib/hk-util.js:38, 39, 43, 537, 577, 631-763, 1015-1020, 1109` — message types, ACK, history streaming
- `www/components/chainpad/chainpad.dist.js` — hash-chain consensus
- `www/common/sframe-chainpad-netflux-inner.js:9-180` — Netflux ↔ ChainPad glue
- `www/common/sframe-chainpad-netflux-outer.js:39-72` — encryption wrap/unwrap
- `www/common/onlyoffice/inner.js:71, 91-206, 951-1016, 1028-1064, 1080-1142, 1108-1141, 1166-1177, 1179-1184, 1187-1249, 1251-1338, 1340-1443, 1538, 1562-1572, 1596-1652, 1613, 2002-2024, 2342, 2631-2637` — OnlyOffice integration
- `www/common/sframe-common-outer.js:427` — key derivation from URL hash

### kutup source (clone at `/home/aa/_e/development/kutup`)
- `backend/services/envelope/envelope.go:10-63` — wire format
- `backend/services/envelope/sign.go` — Ed25519 verify
- `backend/handlers/collab.go:300-340, 351-385` — frame validation + persist
- `backend/handlers/collab.go:262-279` — `broadcastPeers` (commit b78c7d6)
- `backend/handlers/collab_hub.go:52-104` — Hub Join/Leave/Broadcast
- `backend/db/migrations/012_collab_edit.up.sql:16-25` — `file_update_log` schema
- `backend/db/migrations/013_sender_seq.up.sql:10-11` — `(file_id, sender_device, sender_seq)` unique
- `backend/handlers/file_versions.go` — snapshot persistence
- `frontend/src/collab/cryptoFrame.ts:61-67, 119-157` — AEAD wrap/unwrap
- `frontend/src/collab/transport.ts:57-113` — WS client
- `frontend/src/collab/snapshot.ts:78` — Yjs snapshot encoding
- `frontend/src/components/editors/TextCollabEditor.tsx:107-322` — Yjs binding
- `frontend/src/components/editors/office/OfficeEditor.tsx:159-300` — OnlyOffice React wrapper
- `frontend/public/onlyoffice/inner.html:354-441, 687-731` — OnlyOffice bridge

### Google Workspace
- [Wave Operational Transformation whitepaper (Apache)](https://svn.apache.org/repos/asf/incubator/wave/whitepapers/operational-transform/operational-transform.html) — canonical OT description
- [Operational Transformation (Wikipedia)](https://en.wikipedia.org/wiki/Operational_transformation)
- Nichols et al. 1995 — "High-Latency, Low-Bandwidth Windowing in the Jupiter Collaboration System" (UIST) — central-server OT roots
- [Joseph Gentle — "I was wrong. CRDTs are the future"](https://josephg.com/blog/crdts-are-the-future/) — ex-Wave engineer's account
- [Joseph Gentle — node-browserchannel](https://github.com/josephg/node-browserchannel) — BrowserChannel transport
- [James Somers — "How I reverse-engineered Google Docs"](https://features.jsomers.net/how-i-reverse-engineered-google-docs/) — wire format details
- [Google Docs API — Document structure](https://developers.google.com/workspace/docs/api/concepts/structure) — segment + index model
- [Google Drive blog: "What's different about the new Google Docs: Conflict resolution" (2010)](https://drive.googleblog.com/2010/09/whats-different-about-new-google-docs_22.html) — confirms OT
- [HelloInterview — Design a Collaborative Document Editor Like Google Docs](https://www.hellointerview.com/learn/system-design/problem-breakdowns/google-docs)
- [Tanmay Nale — "The Invisible Engine"](https://medium.com/@tnale/the-invisible-engine-how-google-docs-syncs-your-offline-edits-28896ea0ab09) — offline reconciliation

### OnlyOffice + CRDT alternatives
- [OnlyOffice Co-editing API](https://api.onlyoffice.com/docs/docs-api/get-started/how-it-works/co-editing/)
- [OnlyOffice — Fast vs Strict co-editing](https://www.onlyoffice.com/blog/2020/07/freedom-to-choose-your-collaboration-fast-vs-strict-co-editing-modes-in-onlyoffice)
- [OnlyOffice DocumentServer GitHub](https://github.com/ONLYOFFICE/DocumentServer)
- [Yjs](https://github.com/yjs/yjs)
- [ShareDB](https://github.com/share/sharedb) — open-source spiritual successor to Wave OT
- [Etherpad EasySync changeset library](https://docs.etherpad.org/api/changeset_library.html)
