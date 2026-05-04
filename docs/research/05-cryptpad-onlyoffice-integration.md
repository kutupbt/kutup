# Research: How CryptPad Integrates OnlyOffice for E2EE Office-Doc Collaboration

**Captured:** 2026-05-04
**Source:** Code-grounded analysis of `/home/aa/_e/development/cryptpad`. Targets the exact pattern kutup needs to replicate.
**Reading order:** This file is the deepest research artifact. Read `04-office-collab-engines.md` first for the high-level decision rationale.

---

## 1. Directory layout

CryptPad organizes office apps under `www/`:

| Path | Purpose |
|---|---|
| `www/doc/` | Word-document app (`.docx`) — `index.html`, `inner.html`, `export.js` |
| `www/sheet/` | Spreadsheet app (`.xlsx`) — same shape |
| `www/presentation/` | Presentation app (`.pptx`) — same shape |
| `www/common/onlyoffice/` | **Shared OnlyOffice integration layer** (the heart of the integration) |
| `www/common/onlyoffice/inner.js` | 172 KB. Critical sync/bridge logic (~3400 LOC) |
| `www/common/onlyoffice/main.js` | Outer-frame RPC handlers + crypto |
| `www/common/onlyoffice/ooiframe.js` | OnlyOffice iframe bootstrap |
| `www/common/onlyoffice/history.js` | Checkpoint/version management |
| `www/common/onlyoffice/oocell_base.js`, `oodoc_base.js`, `ooslide_base.js` | Empty doc templates |
| `www/common/onlyoffice/dist/v1..v9/web-apps/` | Multiple bundled OnlyOffice client versions side-by-side |
| `www/common/onlyoffice/dist/x2t/` | x2t WASM converter (separate iframe) |

The OnlyOffice client JS is bundled as a static download from `cryptpad/onlyoffice-builds` (a CryptPad-maintained fork of OnlyOffice's `web-apps`). It is **not** an npm dep.

`install-onlyoffice.sh` (root) clones `cryptpad/onlyoffice-builds`, installs versions v1, v2b, v4, v5, v6, v7, v8, v9, and x2t, then runs `rdfind` to hardlink-deduplicate (saves ~650 MB).

`src/common/onlyoffice/current-version.js:7` hardcodes v9 as the current default.

---

## 2. The OnlyOffice client editor

**Version bundled:** v9 (default), with v1–v8 retained for legacy doc compatibility.

**Loading model:** **iframe**, not web component. Each app:
1. Outer page (`/sheet/index.html`) → loads sframe-boot
2. Boot creates a sandboxed iframe with `inner.html`
3. `inner.html` itself loads the OnlyOffice editor from `/www/common/onlyoffice/dist/v9/web-apps/{spreadsheeteditor|documenteditor|presentationeditor}/main/index.html` inside *another* iframe
4. CryptPad ↔ OnlyOffice communication via `postMessage` over a custom channel (`Channel.create(msgEv, postMsg, ...)`, `inner.js:1733`)

**CryptPad's modifications to upstream OnlyOffice:**
- Branding hidden with CSS (`inner.js:2027`: `#app-title { display: none !important; }`) — not source-level removal.
- Versions are pinned by commit hash in `install-onlyoffice.sh`.
- No formal upstream-tracking process; drift is managed manually.

---

## 3. The x2t WASM converter

**What it does.** Converts between OOXML (`.docx`/`.xlsx`/`.pptx`) and OnlyOffice's internal binary format (`.bin`). The `.bin` is what the OnlyOffice client editor actually loads/edits.

**Where it lives.** `/www/common/onlyoffice/dist/x2t/` — separate from the versioned OnlyOffice editors. Installed at `install-onlyoffice.sh:102`.

**Loaded as.** A Web Worker inside a separate "unsafe iframe" (`Utils.initUnsafeIframe()` from `main.js:172`).

**Bundle size.** ~650 MB across all OnlyOffice versions before deduplication; CryptPad uses `rdfind` to hardlink-dedupe identical files. x2t itself is a sizable WASM module (estimated multi-MB).

**JS API surface (via sframe channel):**
- `inner.js:1942` — `sframeChan.query('Q_OO_CONVERT', { data, outputFormat, ... })`
- Used in two directions:
  - **Import:** `x2tImportData()` (`inner.js:2807`) converts OOXML → `.bin` for OnlyOffice on initial load.
  - **Export:** `x2tConvertData()` (`inner.js:1942`) converts `.bin` → OOXML on checkpoint save.
- Returns `{ data: Uint8Array, images: <embedded media URLs> }`.

---

## 4. The sync bridge: chainpad ↔ OnlyOffice

This is the most subtle piece. CryptPad does **not** diff document state — it captures OnlyOffice's native OT operations and pushes them through chainpad as opaque payloads.

**Flow when a local user edits:**

1. User edits in the OnlyOffice editor.
2. OnlyOffice's internal change tracking fires and emits a `saveChanges` postMessage to CryptPad.
3. `fromOOHandler()` (`inner.js:1538`) switch case `"saveChanges"` (line 1596) catches it.
4. `handleChanges()` (`inner.js:1357`) wraps each change in metadata (user ID, timestamp, `docid="fresh"`) via `parseChanges()` (line 1340).
5. `rtChannel.sendMsg()` (line 1395) sends the wrapped change.
6. `rtChannel` is a wrapper over `sframeChan.query('Q_OO_COMMAND', { cmd: 'SEND_MESSAGE' })`.
7. Outer frame `main.js:138` encrypts the message before transmission: `obj.data.msg = Utils.crypto.encrypt(JSON.stringify(obj.data.msg))`.
8. Hash of ciphertext returned as ACK (`main.js:139`).
9. Chainpad validates patch, server stores opaque ciphertext.

**Flow when a remote operation arrives:**

1. Server relays encrypted patch to all peers.
2. Client decrypts; `onPatch()` callback (`inner.js:3225`) deserializes.
3. `ooChannel.send(JSON.parse(patch.msg))` pushes the operation back into OnlyOffice.
4. OnlyOffice applies the remote change atomically via its native collab API.

**Key observations:**
- **No diff.** OnlyOffice's native OT operations are the wire format. CryptPad does not run any CRDT/OT of its own on the operation contents.
- **Per-op encryption.** Each operation is JSON-serialized (`inner.js:1349`: `'"' + change + '"'`), tagged with user+timestamp metadata, stringified, encrypted by chainpad-crypto, then sent over the wire as a chainpad patch.
- `rtChannel` (lines 323–354) — the encrypted sender wrapper.
- `ooChannel` (lines 356–361) — accumulates pending sends until OnlyOffice is ready.
- `ooChannel.send()` (`inner.js:1520` / `inner.js:1736`) — calls `APP.docEditor.sendMessageToOO(obj)` or `chan.event('CMD', obj)` depending on init state.

---

## 5. Loading and saving (the checkpoint dance)

### Load (user opens an `.xlsx` they have access to)

1. Server returns chainpad patch history (encrypted).
2. Client decrypts, reconstructs a `content` object containing the **last checkpoint hash**.
3. `loadLastDocument()` (`inner.js:709`) fetches the encrypted `.bin` checkpoint blob from the file server (separate from chainpad messages).
4. `FileCrypto.decrypt()` (`inner.js:735`) decrypts the blob with the file-specific symmetric key (derived from the URL fragment).
5. `x2tImportData()` (`inner.js:2807`) converts `.bin` → OnlyOffice's internal format.
6. `resetData()` (`inner.js:556`) calls `destroyEditor()`, then recreates the editor with the checkpoint blob.
7. Subsequent in-flight patches from `ooChannel.queue` are applied on top via `onPatch()`.

### Save / checkpoint

**Trigger:** every ~10,000 ops (`inner.js:628`: `FORCE_CHECKPOINT_INTERVAL`). No idle-debounce on the client side that I could find — checkpoint is purely operation-count-driven.

**Steps:**

1. `makeCheckpoint()` (`inner.js:621`) acquires save lock: `content.saveLock = myOOId`.
2. `saveToServer()` (`inner.js:582`) calls `getContent()` → `getEditor().asc_nativeGetFile()` to extract OnlyOffice's binary.
3. `x2tConvertData()` (`inner.js:1942`) converts `.bin` → output OOXML format.
4. `APP.FM.handleFile()` uploads the encrypted OOXML blob to the file server (returns `{file: <url>, hash: <cp_hash>}`).
5. `onUploaded()` (`inner.js:465`) stores the hash + URL in `content.hashes[i]`, syncs back to chainpad, releases the save lock.

**Checkpoint metadata stored in chainpad:**
```js
content.hashes = {
  0: { file: <url>, hash: <cp_hash>, index: <op_count>, version: 9 },
  1: { ... },
  // ...
}
```
Only the metadata lives in chainpad. The actual binary `.bin`/OOXML blob is encrypted separately and stored on the file server as just another encrypted file.

**Reconnect path.** Client fetches the latest checkpoint metadata from chainpad → fetches & decrypts the binary blob → applies any chainpad patches with `index > checkpoint.index` on top.

---

## 6. E2EE specifics

**Same crypto layer as Pad/Code path:**
- `chainpad-crypto` (npm) for symmetric encryption with TweetNaCl/NaCl.
- Per-document URL fragment carries `channel_id`, `encryption_key`, `validateKey` (Ed25519 public key for signature auth).
- Each chainpad message encrypted before sending; server is content-blind.

**Per-operation encryption flow (annotated):**
1. OnlyOffice change object → JSON string.
2. `rtChannel.sendMsg()` → `sframeChan.query('Q_OO_COMMAND', cmd: 'SEND_MESSAGE')` (`main.js:137`).
3. Outer-frame `main.js:138`: `obj.data.msg = Utils.crypto.encrypt(JSON.stringify(obj.data.msg))` — symmetric encryption.
4. Hash of ciphertext returned as ACK (`main.js:139`).
5. Chainpad validates patch hash; server stores ciphertext only.

**File checkpoint encryption:**
- `FileCrypto.decrypt()` (`inner.js:735`) decrypts the `.bin` checkpoint with `secret.keys.cryptKey`.
- Same mechanism as any other file attachment in CryptPad — separate symmetric key per document, derived from the URL fragment.

---

## 7. Performance and known limits

Brittle points documented in the source:

| Issue | Where | Impact |
|---|---|---|
| **TOO_LARGE checkpoint** | `inner.js:481`, `inner.js:485` | If binary exceeds server quota, checkpoint fails. `APP.cantCheckpoint = true` → user becomes read-only |
| **Doc size practical limit** | implicit | ~50 MB per checkpoint depends on server config; no streaming |
| **Browser memory pressure** | implicit | Entire doc loaded into OnlyOffice; 100+ MB docs choke the browser |
| **Image cache leak** | `inner.js:121` `mediasData` | No cleanup on unload; 1000 images = real memory pressure |
| **Lock deadlock** | `inner.js:680` (~20 s timeout) | If save-lock holder disconnects without releasing, others blocked until timeout |
| **Patch validation is JSON-only** | `inner.js:2925` `validateContent` | Schema not enforced; bad ops just logged, no rollback. State divergence possible. |
| **Offline 30 s reload** | `inner.js:1371` | If patch doesn't send in 30 s, force reload |
| **OnlyOffice private API drift** | `inner.js:380` `asc_nativeGetFile`, `:151` `asc_setRestriction` | Direct calls to OnlyOffice private API. Upstream change = silent break, no version check |
| **Migration fragility** | `inner.js:105`, `:511-514` | Older format versions (v1-v3) have different content shapes; migration code assumes seamless upgrade |
| **Manual version pinning** | `install-onlyoffice.sh` commit hashes | If OnlyOffice upstream breaks a version, the fork doesn't auto-follow |

In-source warnings:
- `inner.js:2730`, `:2856` — `oo_unstableMigrationWarning`
- `inner.js:1232` — TODO "make sure we don't have new popups that can break our integration"
- `inner.js:3160` — FIXME "degraded mode unsupported (no cursor channel)"
- `inner.js:3964` — FIXME "lock the document or ask for page reload?"

---

## 8. OnlyOffice's locking, mapped through chainpad

OnlyOffice has native cell-range / paragraph locks. CryptPad surfaces them through chainpad metadata:

1. OnlyOffice sends `getLock` postMessage (`inner.js:1589`) → `handleLock()` (`inner.js:1251`).
2. Lock stored in `content.locks[userId][blockId] = { time, user, block }`.
3. State synced to all peers via chainpad.
4. Remote locks pushed back into OnlyOffice via `ooChannel.send({ type: 'getLock', locks: ... })`.
5. OnlyOffice respects the lock UI (greys out locked cells/paragraphs).

**Release:** user releases → OnlyOffice sends `releaseLock` (`inner.js:1129`) → removed from `content.locks`, synced, others notified.

**Offline cleanup:** `deleteOfflineLocks()` (`inner.js:1144`) runs on user disconnect, clears their locks from state.

**Special case for presentations:** theme is global; the user editing the theme holds an exclusive lock to prevent conflicts (`inner.js:1272`).

---

## 9. License compatibility

- **OnlyOffice client JS:** AGPL with branding restrictions (per upstream).
- **CryptPad:** AGPL-3.0-or-later (same family).
- The bundled OnlyOffice JS is shipped as-is. Branding is hidden with CSS, not stripped at the source level.
- Distributing AGPL OnlyOffice JS from an AGPL CryptPad server is license-compatible.

**Implication for kutup:** kutup is licensed under AGPL-3.0-only, so bundling AGPL OnlyOffice JS is license-compatible. The integration files (`frontend/public/onlyoffice/`, `frontend/src/components/editors/office/`) carry the upstream's `AGPL-3.0-or-later` SPDX header to stay compatible with the OnlyOffice client they link against. The actual OnlyOffice client JS is downloaded by `./install-onlyoffice.sh` into `frontend/public/onlyoffice/dist/` (gitignored), not vendored in the repo.

---

## 10. Surprising footguns / things an implementer must know

1. **Single-file integration.** ~3400 LOC of mixed concerns (load, save, lock, cursor, sync, history) in one `inner.js`. Replicating cleanly will require modularizing.
2. **No diff layer of our own.** OnlyOffice's OT operations are passed through verbatim. We can't reuse Yjs here — the wire format must be OnlyOffice's native ops or x2t-converted OOXML chunks.
3. **The "single docid" hack.** `parseChanges()` tags every change with `docid="fresh"` to satisfy OnlyOffice's collab protocol. If we get this wrong, OnlyOffice rejects remote ops as if they were from a stale doc.
4. **x2t is a hairball.** ~650 MB pre-dedupe, multi-MB WASM module, runs in a third iframe. Boot time is non-trivial.
5. **Checkpoint binary all-or-nothing.** If x2t fails mid-conversion (`inner.js:1987`), user sees an alert and the checkpoint is **not** saved. If they force-reload before retry, recent ops may be lost.
6. **Three iframes deep.** Outer page → CryptPad inner sandbox → OnlyOffice editor iframe → x2t WASM iframe. Cross-iframe `postMessage` plumbing for everything.
7. **OnlyOffice's API is private.** `asc_nativeGetFile()`, `asc_setRestriction()`, `sendMessageToOO()` are not documented public APIs. Upstream changes are not announced.
8. **Per-version drift.** v1-v9 each potentially behave differently; the `current-version.js` and content version migrations matter.
9. **No streaming.** Whole-document load + whole-document save. Big files hurt.
10. **Checkpoint trigger is op-count, not idle-time.** Continuous editing without 10k ops never checkpoints. Heavy real-time use can leave hours of unsnapshotted patches if no client emits enough ops to cross the threshold.

---

## Implications for kutup

This integration is **doable but significant**. The cleanest port:

- Bundle OnlyOffice client + x2t in `frontend/public/onlyoffice/` (mirror CryptPad's directory shape).
- Iframe-load the OnlyOffice editor in a sandboxed kutup component (`frontend/src/components/editors/OfficeEditor.tsx`).
- Mirror CryptPad's `rtChannel` / `ooChannel` bridge in TypeScript: capture `saveChanges` postMessages, wrap in our libsodium AEAD envelope, send over the same Go WebSocket relay we use for the Yjs path. The relay does not care about payload shape — just routes opaque ciphertext frames by file_id room.
- Reuse our snapshot model: every N ops (or idle-debounce 30 s), capture `editor.asc_nativeGetFile()`, run x2t to OOXML, encrypt the OOXML, upload as a new file version in S3 (replacing the live blob in S3 versioning). The Postgres delta log captures wrapped OnlyOffice ops.
- Lock state lives in a shared Yjs `Y.Map` per file (or a parallel "locks" frame kind) — same E2EE wrapper.
- License path: relicense the office-edit subdirectory to AGPL, **or** ship OnlyOffice as a separately-installable optional package the user pulls themselves. Consult a lawyer.

The **hardest** parts to get right:
1. Multi-iframe `postMessage` plumbing.
2. x2t boot + memory.
3. Interaction between OnlyOffice's "single docid" expectation and our session model.
4. Handling the `TOO_LARGE` checkpoint case more gracefully than CryptPad.
5. Tracking OnlyOffice upstream so we don't drift.
