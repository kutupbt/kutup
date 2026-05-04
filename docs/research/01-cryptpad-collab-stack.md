# Research: CryptPad's Collaborative Editing Stack (text / markdown / code path)

**Captured:** 2026-05-04
**Source:** Code-grounded analysis of `/home/aa/_e/development/cryptpad`, supplemented by CryptPad's published architecture docs.
**Scope:** Only the text-shaped editing path (Pad, Code, Markdown). Office docs (Sheet/Presentation) and Whiteboard are covered in a separate research file.

---

## 1. Sync algorithm: ChainPad

ChainPad is a custom CRDT — *not* OT in the classical sense — based on a Nakamoto-blockchain-style chain of patches.

- Each patch references the SHA-256 hash of the previous document state.
- Clients verify patch authenticity and applicability at every position in history.
- Invalid patches are rejected without the server seeing plaintext.
- A patch is a list of three-tuples: `(offset, removeCount, insertString)` — minimal but sufficient for OT-style replay.

**On-the-wire format** (`lib/hk-util.js:1007-1011`):
```
msgStruct = [seqNum, userId, action, channelId, encryptedPayload, timestamp]
```
Checkpoints are prefixed `cp|<checkpointHash>|<payload>` (line 1007-1009).

**Authentication & chaining:**
- Patches signed with Ed25519 (tweetnacl, `lib/crypto.js:5-28`).
- Server validates signatures via `Env.validateMessage(signedMsg, metadata.validateKey)` (`hk-util.js:1063`) without decrypting content.
- Duplicate checkpoints rejected via `channel.lastSavedCp` deduplication (`hk-util.js:1015-1020`).

**Conflict resolution** is purely client-side. From `www/common/sframe-common-codemirror.js:66-69`:
- `ChainPad.Diff.diff()` computes ops between old and new state.
- `TextCursor.transformCursor()` applies OT to preserve cursor position when remote ops arrive.
- No server-mediated merge.

**Performance & limits:**
- Lag monitor (`www/common/sframe-chainpad-netflux-inner.js:71-81`) fires "bad state" alarm at 30 s default.
- Per `docs/ARCHITECTURE.md:236-238`: full history must be downloaded before participating; malicious clients can spam junk patches; long-running pads accumulate unbounded history.
- No published concurrent-editor cap.

**Files of interest:**
- `lib/commands/core.js` — server-side support
- `www/debug/chainpad.dist.js` — bundled client
- npm dep: `chainpad@5.3.1` (per `package.json:21`)

---

## 2. Transport / signaling: Netflux + WebSocket

Netflux is CryptPad's WebSocket-based mesh signaling layer.

- **Client:** `chainpad-netflux@1.3.0` wrapping `netflux-websocket@1.3.0` (`package.json:24,47`).
- **Server:** custom integration in `lib/api.js` + RPC in `lib/commands/channel.js`.
- **Wire protocol:** WebSocket carrying a custom bencoded envelope.

**Message flow** (`www/common/sframe-chainpad-netflux-outer.js:39-72`):
- Incoming: `Crypto.decrypt(msg, validateKey, isHk)` — decrypts if not already plaintext.
- Outgoing: `Crypto.encrypt(msg)`. If checkpoint, prepend `cp|<hash8>|`.

**Server's role: dumb relay + signature validator.**
- `lib/historyKeeper.js:23-27` — `channelMessage()` validates signatures (line 1063 in `hk-util.js`), then stores the encrypted blob without reading plaintext.
- `lib/api.js:143-146` — server registers historyKeeper as a WebSocket handler; all messages flow through it.
- Netflux-server handles join/leave broadcast.

**Channel discovery:**
- `padRpc.joinPad({channel, readOnly, versionHash, metadata})` (`sframe-chainpad-netflux-outer.js:143-148`).
- Channel-ID length determines storage model:
  - 32 chars: standard, persistent.
  - 33 chars: admin, write-only via RPC.
  - 34 chars: ephemeral, not stored (`hk-util.js:1000`).

---

## 3. Crypto layer (E2EE — most critical)

**Library:** `tweetnacl@1.0.3` + `tweetnacl-util@1.0.3` + `chainpad-crypto` (the encryption shim).

**Per-document key hierarchy** (`src/common/common-hash.js:48-95`):
- `createEditCryptor2(key, userKeyString, password)` derives a symmetric key (deterministic or random).
- `editKeyStr` — symmetric key for encrypted patches (URL-safe base64, `/` and `=` removed).
- `viewKeyStr` — read-only symmetric key.
- `fileKeyStr` — file binary encryption key.
- Channel ID is derived from a hash, not from the key itself.
- Metadata contains a `validateKey` (Ed25519 public key for signature verification).

**Doc sharing mechanism** (`src/common/common-hash.js:155-173`):
- **Hash-based:** URLs embed the channel + symmetric key in the URL fragment, e.g. `/code/#/2/code/edit/<editKeyStr>/`. The server never sees the fragment.
- **Password-protected:** `/2/code/edit/<key>/p/` — client derives the actual key from password + URL fragment.
- **Pre-shared link:** there is no per-user ACL by default. If you have the URL, you have access.
- **Safe links** (`/3/`, `src/common/common-hash.js:81-95`): channel-derived deterministically from key — not widely deployed.

**Patch encryption & authentication:**
- Per patch: `Crypto.encrypt(msg)` from `chainpad-crypto`.
- Each patch is then signed by the user's Ed25519 signing key (derived from the doc key).
- Server verifies signatures with `Nacl.sign.open(signedMsg, validateKey)` — does not decrypt the payload.
- History is stored encrypted at rest.

**Server verification without plaintext:**
- `msgStruct[4]` carries the encrypted payload + signature.
- `lib/crypto.js:11-12` server-side: `Nacl.sign.open()` returns plaintext if valid, throws if invalid.
- Patches are stored encrypted; signatures are visible to the server but reveal nothing about content.

---

## 4. Editor binding

**Pad (rich text):** CKEditor 4.22.1 (`package.json:26`). Binding at `www/pad/inner.js`.

**Code (plain text + markdown):** CodeMirror 5.19.0 (`package.json:27`). Binding at `www/common/sframe-common-codemirror.js:224-640`.

Markdown reuses the Code binding with `gfm` mode.

**The sync loop** (`sframe-common-codemirror.js`):
- `contentUpdate` (line 538-546): receives remote doc as a string, computes `ChainPad.Diff.diff(oldDoc, remoteDoc)`, applies to editor preserving cursor.
- `setValueAndCursor` (line 55-84): splits cursor into `(line, ch)`, applies diff, transforms cursor via `TextCursor.transformCursor(pos, ops)`.
- `getContent` (line 548-551): returns `{content: canonicalize(editor.getValue())}`.
- `onLocal`: triggered by `editor.on('change')` → `cpNfInner.chainpad.contentUpdate(JSONSortify(content))` (`sframe-app-framework.js:450`).

**Cursor (presence) handling** (`sframe-common-codemirror.js:584-637`):
- `setRemoteCursor()` renders peer cursors as bookmarks (line 621) or text selections (line 628), with name + color.
- Cursor data flows on a separate channel.

---

## 5. Persistence

**Server storage: NDJSON files.**
- Path: `lib/storage/file.js:51-65` — `<root>/<channelId[0:2]>/<channelId>.ndjson`.
- One JSON line per message (`[seqNum, userId, action, channel, encryptedPayload, timestamp]`).
- All content encrypted; server cannot read plaintext.

**Write buffering:**
- `CHANNEL_WRITE_WINDOW = 300s`
- `STREAM_CLOSE_TIMEOUT = 120s`

**Offline cache (client-side):**
- Optional via the `Cache` parameter passed to chainpad-netflux (`sframe-app-framework.js:91`).
- Backed by `localforage` (per `package.json:44`) → IndexedDB if available.
- `onCacheReady()` (`sframe-app-framework.js:507-537`) loads from cache before syncing; warns on corruption.

**History trim / compaction:**
- Checkpoints emitted by clients every ~50 patches (per CryptPad docs) or ~100 messages (per `hk-util.js:73-82` `sliceCpIndex`).
- Checkpoint hash recorded as `channel.lastSavedCp` to deduplicate.
- Old messages archived (not deleted) on channel removal/expiry (`hk-util.js:134-163`).
- Replay from **penultimate** checkpoint, not last, to recover from partial writes.

---

## 6. Auth & access control

**No per-user ACL by default.** "If you have the URL, you have access."

**Restricted channels** (opt-in, `lib/historyKeeper.js:34-104`):
- Metadata sets `restricted: true`.
- Server validates incoming user's session key against an `allowed` list (line 91).
- Returns error with valid keys list if rejected.
- Only standard 32-char channels can be restricted.

**Account model:** CryptPad accounts are separate from collaborative editing — accounts pin docs but don't gate access. URL-only access remains the default.

**Implication for kutup:** This is the single biggest model mismatch. Kutup is account-first; we'd need to wrap channel creation in our auth middleware and use the restricted-channel model.

---

## 7. Scaling / production knobs

**Concurrency:** No hardcoded limits. Bottleneck is disk I/O for NDJSON appends.

**Server architecture:**
- `server.js:110-218` — Node cluster mode, `maxWorkers = CPU count` default.
- Each worker handles separate HTTP/WS connections; no shared memory.

**Known footguns:**
1. **Full history sync on join.** Every joining client downloads the entire log. Slow for large docs.
2. **No server-side patch validation.** Malicious clients can inject garbage; server can't reject without decryption.
3. **No snapshot API.** Compaction is time-based (channel expiry), not content-based.
4. **Untested concurrent-editor count.** Lag monitor may trigger "bad state" if updates arrive too slowly.
5. **Filesystem sharding** by first 2 chars of channel ID — scales to millions but may hit inode limits.

**Production recommendations (inferred):**
- Use external storage backend (S3 etc.) via the adapter pattern referenced in `ARCHITECTURE.md:86-88`.
- Monitor `Env.store.closeChannel()` timeouts.
- Archive/purge channels (none auto-expire unless `metadata.expire` set).
- Tune `badStateTimeout` and `maxWorkers` per deployment.

---

## 8. Build vs. borrow summary

**Worth keeping conceptually:**
1. Blockchain-style patch chain (proven, elegant).
2. Symmetric-key-in-URL-fragment + signature validation (no PKI infrastructure).
3. Dumb-relay server design (scales, supports multi-server).
4. Cursor-preserving OT for position stability.

**Likely to replace/wrap:**
1. **Full history sync** — redesign with snapshot+delta and client-side checkpoints.
2. **No doc-level ACL** — add account-aware access control.
3. **No user auth** — integrate kutup's user model.
4. **CodeMirror 5** — modern stack uses CodeMirror 6 (better mobile, bundle, A11y).
5. **Single-channel assumption** — kutup needs multi-doc per connection.

**Code entry points worth studying:**
- `www/common/sframe-chainpad-netflux-inner.js:41-62` — `makeChainPad`, `onMessage`.
- `www/common/sframe-app-framework.js:415-458` — onLocal/onRemote loops.
- `src/common/common-hash.js:48-95` — key derivation.
- `lib/historyKeeper.js:988-1116` — message validation & storage.
