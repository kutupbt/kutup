# Spec: Collaborative E2EE File Editing in kutup

**Status:** Approved design (2026-05-04). Ready to drive an implementation plan.
**Author:** Drafted via the superpowers brainstorming flow on 2026-05-04. User approved the architecture and asked to proceed.
**Background research:** [`docs/research/01-cryptpad-collab-stack.md`](../../research/01-cryptpad-collab-stack.md) · [`02-modern-collab-stack-2026.md`](../../research/02-modern-collab-stack-2026.md) · [`03-version-history-design.md`](../../research/03-version-history-design.md) · [`04-office-collab-engines.md`](../../research/04-office-collab-engines.md) · [`05-cryptpad-onlyoffice-integration.md`](../../research/05-cryptpad-onlyoffice-integration.md). Read those before changing this spec.

---

## 1. Context

kutup is a self-hosted, end-to-end-encrypted file storage app (Go/Fiber backend, React/TS frontend, libsodium throughout, SeaweedFS for blobs). Users today can upload, share, and federate encrypted files. They cannot **edit** them in-place: every change requires download, local edit, re-upload.

We want users to click any supported file inside kutup and have a **real-time, multi-user editor** open in place. The server must remain **zero-knowledge** — it stores only ciphertext for every byte that flows through the editing path, exactly as it does for files at rest today. Version history must look and feel like Google Drive's. Office docs (`.docx`/`.xlsx`/`.pptx`) must be supported on equal E2EE footing — no Collabora/WOPI compromise.

This spec describes the architecture, schema, wire format, and build sequencing. It does not prescribe implementation order beyond a coarse phase split — that's the job of the implementation plan.

---

## 2. Goals and non-goals

**In scope (v1.0 ships these):**
- Click a `.txt`/`.md`/code file → live collab editor opens in-place inside kutup.
- Multiple authenticated kutup users editing the same file simultaneously, with text and presence (cursors + names + colors) flowing in real time.
- Server stores ciphertext only; provably zero-knowledge.
- Drive-style version history per file: timeline UI, restore, name-version, keep-forever.
- File on disk (the encrypted S3 blob) always converges to the latest content via periodic snapshots, so download/federation/sharing all keep working unchanged.

**In scope (v1.1 — small follow-ups):**
- Presence polish (color stability, idle detection, awareness throttling).
- Reconnect-from-cold polish.
- Side-by-side version diff in the history panel.

**In scope (v2 — office docs):**
- `.docx`/`.xlsx`/`.pptx`/`.odt`/`.ods`/`.odp` editing using a forked OnlyOffice client + x2t WASM, CryptPad pattern. Same envelope, same transport, same versioning model. The schema and wire format defined here already accommodate this; v2 is about the editor integration itself.

**In scope (v2.1):**
- Offline edit mode (IndexedDB cache, queued updates while disconnected).

**Explicit non-goals (deferred indefinitely or to v3+):**
- Federated **live** editing across kutup instances. (Federation of files-at-rest is unchanged and continues to work.)
- Comments, suggestions, track-changes UX.
- Mobile-optimized editor UI. Desktop-first.
- WebDAV / native filesystem mounting. (See [`docs/research/06-webdav-support.md`](../../research/06-webdav-support.md).)
- Server-side enforcement of editor-level ACLs (e.g. "this user may only edit paragraphs N-M"). E2EE makes this structurally impossible; co-editor trust is symmetric.
- License decision for bundling AGPL OnlyOffice client into MIT kutup — surfaces in v2, deferred until then.

---

## 3. Architecture overview

```
┌──────────────────────────────────────────────────────────────────┐
│              Browser (React + libsodium)                          │
│                                                                    │
│  ┌────────────────────────┐   ┌──────────────────────────────┐  │
│  │ TextCollabEditor       │   │ OfficeCollabEditor (v2)       │  │
│  │   CodeMirror 6         │   │   OnlyOffice iframe + x2t     │  │
│  │   + y-codemirror.next  │   │   iframe (client-only fork)   │  │
│  │   + Yjs                │   │                                │  │
│  │ ↓ Yjs binary updates   │   │ ↓ OnlyOffice OT op JSON       │  │
│  └────────────┬───────────┘   └──────────────┬───────────────┘  │
│               │                               │                    │
│               └────────────┬──────────────────┘                    │
│                            ↓                                        │
│         AEAD-wrap (XChaCha20-Poly1305) + Ed25519 sign              │
│                            ↓                                        │
│              one WebSocket per file (Authorization: Bearer)         │
└────────────────────────────┬───────────────────────────────────────┘
                             ↓
        ┌────────────────────────────────────────────────────────────┐
        │  Go backend (Fiber) — file_collab.Hub  (~300 LOC)          │
        │                                                              │
        │  Per-file room: connections + append-only DB log             │
        │  • Verifies Ed25519 signature using device-key registry      │
        │  • Rejects duplicate (sender, seq) + invalid signatures      │
        │  • Persists frame to file_update_log                         │
        │  • Broadcasts to other peers in the room                     │
        │  • On join: replays log tail from client's last-seen seq    │
        │  • Snapshot frames trigger truncate of older log rows        │
        │  • Never touches plaintext; never instantiates a Y.Doc       │
        └────────────────────────────┬─────────────────────────────────┘
                                     ↓
        ┌────────────────────────────────────────────────────────────┐
        │  Postgres — file_update_log, file_versions, user_devices   │
        │  SeaweedFS S3 — versioned blob per file (snapshots)        │
        └────────────────────────────────────────────────────────────┘
```

**Key principles:**

1. **One file = one room.** No multi-doc-over-one-connection multiplexing in v1; revisit if it bites.
2. **Server is a dumb byte pump.** It does not parse Yjs updates or OnlyOffice ops. It only validates the envelope (header + signature) and persists/broadcasts opaque ciphertext.
3. **Two CRDT stacks (Yjs for text, OnlyOffice OT for office) share one envelope, one transport, one schema.** The `kind` byte in the envelope tells clients which stack to dispatch to.
4. **Reuse of existing kutup primitives:** XChaCha20-Poly1305, Ed25519, `crypto_box_seal`, the per-collection key model, the JWT auth model.
5. **Snapshots are the file.** After every successful snapshot, the encrypted S3 blob reflects the merged state. Download/federation/sharing all keep working without modification.

---

## 4. File model

The existing `files` row stays the canonical object. **No new entity types.** The frontend dispatches on file extension to the right editor; the backend treats every file the same way.

| Extensions | Editor | Sync engine | Phase |
|---|---|---|---|
| `.md`, `.markdown` | CodeMirror 6 + `@codemirror/lang-markdown` (+ optional preview pane) | Yjs `Y.Text` | v1 |
| `.txt` | CodeMirror 6 plain | Yjs `Y.Text` | v1 |
| `.go`, `.js/.ts/.tsx`, `.py`, `.rs`, `.json`, `.yaml`, `.html`, `.css`, `.toml`, `.sh`, `.sql`, `.dockerfile`, `.nix`, … | CodeMirror 6 + per-extension `@codemirror/lang-*` | Yjs `Y.Text` | v1 |
| `.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods`, `.odp` | OnlyOffice client (forked, client-only — CryptPad pattern), bundled at `frontend/public/onlyoffice/`, sandboxed iframe | OnlyOffice native OT ops, wrapped opaquely | v2 |
| `.pdf`, images, video, audio, anything else | View-only / download (existing behavior) | None | unchanged |

**Lifecycle of a single edit session:**

1. User clicks `notes.md` in the kutup drive view.
2. Frontend reads the extension → routes to `TextCollabEditor`.
3. Editor opens a WebSocket to `GET /api/files/:id/collab/ws`.
4. Server replays the latest snapshot blob + the `file_update_log` tail.
5. Client decrypts each frame locally, hydrates the `Y.Text` (or applies OnlyOffice ops), attaches the editor.
6. Local edits → CRDT updates → AEAD-wrapped + Ed25519-signed → sent over WS.
7. Server fans out to other peers, persists to `file_update_log`.
8. Triggers (idle/ceiling/explicit/membership) prompt the client to materialize a snapshot, encrypt, PUT to S3 (creates a new SeaweedFS version), and post a `kind=snapshot` frame. Server records a `file_versions` row and truncates the log up to that seq.
9. When the room empties, server keeps state cold (log + snapshot pointer). No automatic flatten. Next opener resumes seamlessly from the latest snapshot + tail.

---

## 5. Wire envelope (single format for both stacks)

Every frame on the wire — both directions, both stacks — has this layout:

```
struct CollabFrame {
  u8   version;                // currently 1
  u8   kind;                   // 1 = yjs_update
                               // 2 = yjs_awareness     (NOT persisted server-side)
                               // 3 = snapshot_announce
                               // 4 = oo_op             (v2)
                               // 5 = oo_lock           (v2)
                               // 6 = oo_checkpoint_meta(v2)
  u32  doc_key_id;             // increases on key rotation
  u64  sender_device_id;
  u64  sequence;               // server-assigned, monotonic per file
  u8   nonce[24];              // XChaCha20-Poly1305 nonce; fresh per frame
  u32  ciphertext_len;
  u8   ciphertext[ciphertext_len];
                               // AEAD over the editor-specific payload.
                               // AAD = the 30-byte fixed-size header above.
  u8   signature[64];          // Ed25519 over (header || nonce || ciphertext_len
                               //                 || ciphertext)
}
```

**Server's validation responsibilities:**

1. Looks up `sender_device_id` in `user_devices`; rejects if unknown or `is_active=false`.
2. Checks `device.user_id` has access to the collection that owns this file.
3. Verifies the Ed25519 signature against `device.public_signing`.
4. Rejects duplicate `(sender_device_id, sequence_per_device)` tuples (replay).
5. Assigns a server-side `sequence` (per-file monotonic) and persists.
6. Broadcasts to all other peers in the room.

**The server never decrypts `ciphertext` or interprets the payload.**

**Awareness frames (`kind=2`) are broadcast but not persisted.** Cursor positions are ephemeral.

**Snapshot frames (`kind=3`) carry metadata only:** `{ s3_version_id, storage_path, seq_at_snapshot, doc_key_id, size_bytes, label?, keep_forever? }` — already-encrypted JSON inside `ciphertext`. The server reads only the *outer* envelope, but it interprets `kind=3` as "create a `file_versions` row and truncate `file_update_log` up to `seq_at_snapshot`." The actual snapshot blob has already been PUT separately to S3 by the client before sending the snapshot announce frame.

---

## 6. Key model

**Per-file content key** — used for both AEAD and any other file-content encryption — is derived deterministically:

```
content_key = HKDF-SHA256(
  ikm  = collection_master_key,
  salt = "kutup/file-content/v1",
  info = file_id (UUID bytes)
)
```

`collection_master_key` already exists in kutup's data model; recipients of a shared collection already receive it via `crypto_box_seal`. Hence: **no new key wrapping, no new key distribution.** Anyone with collection access can derive the per-file key for any file in that collection.

**Key rotation (`doc_key_id`):** incremented when a member is removed from the collection. The new collection master key + same file id produces a new content key. `doc_key_id` lives in the envelope so peers know which key to use; receivers reject frames whose `doc_key_id` is older than their current. After rotation, all clients are required to re-snapshot under the new epoch within a configurable grace period; old log rows under the old epoch are deleted by a cleanup job once a snapshot under the new epoch exists.

**Per-device signing keys (new — kutup currently has one principal per user):**

- On first WebSocket connect, the browser generates a fresh Ed25519 keypair locally.
- Public key is sent in a registration request, signed by the user's existing master-key-derived signing key (the same one already used elsewhere in kutup) for authenticity.
- Backend stores the row in `user_devices`, returns the numeric `device_id`.
- The private signing key never leaves the browser. Persisted in `sessionStorage` only — meaning **one device row per browser tab session**. Closing the tab clears the key; reopening generates a fresh keypair and a new device row. Sister-tab cleanup (no `BroadcastChannel` sharing in v1) is intentional — see §14 question 3.
- The CLI does the same on first `kutup login` (signing key in the OS keyring + BoltDB session, alongside the existing master key). The CLI persists across runs, so its device row is long-lived.

**Revocation:** `DELETE /api/devices/:id` sets `is_active=false`. The handler also looks up any active WebSocket connections from that device across all rooms and closes them with code 4401. Future reconnect attempts from that device are rejected at upgrade time. Future frames signed by the revoked device key are rejected by the server. This gives integrity revocation (kicked device can't write new content); confidentiality of past content cannot be retroactively protected — that's a known limit of E2EE.

---

## 7. Server schema additions

Three new tables, one new column on `files`. SeaweedFS bucket gets versioning + lifecycle.

```sql
-- One row per collab frame (the delta layer).
CREATE TABLE file_update_log (
  file_id        UUID        NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  seq            BIGINT      NOT NULL,        -- assigned by server, monotonic per file_id
  sender_device  BIGINT      NOT NULL REFERENCES user_devices(id),
  doc_key_id     BIGINT      NOT NULL,
  kind           SMALLINT    NOT NULL,        -- frame.kind (1, 4, 5, 6 — never 2 or 3)
  frame          BYTEA       NOT NULL,        -- entire CollabFrame as received
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (file_id, seq)
);

-- The (file_id, seq) PRIMARY KEY already covers the "replay since seq N" query.

-- One row per snapshot in file history (the version index).
CREATE TABLE file_versions (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  file_id         UUID        NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  s3_version_id  TEXT        NOT NULL,
  storage_path    TEXT        NOT NULL,
  seq_at_snapshot BIGINT      NOT NULL,
  doc_key_id      BIGINT      NOT NULL,
  author_user_id  UUID        NOT NULL REFERENCES users(id),
  size_bytes      BIGINT      NOT NULL,
  label           TEXT,                       -- user-supplied name; nullable
  keep_forever    BOOLEAN     NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX file_versions_timeline ON file_versions (file_id, created_at DESC);

-- Per-device signing keys.
CREATE TABLE user_devices (
  id              BIGSERIAL   PRIMARY KEY,
  user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_signing  BYTEA       NOT NULL,       -- Ed25519 32-byte pubkey
  label           TEXT,                       -- "Firefox on macbook", "kutup CLI", etc.
  is_active       BOOLEAN     NOT NULL DEFAULT true,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at    TIMESTAMPTZ
);

CREATE INDEX user_devices_active ON user_devices (user_id) WHERE is_active;

-- The existing files table tracks the current key epoch.
ALTER TABLE files ADD COLUMN current_doc_key_id BIGINT NOT NULL DEFAULT 1;
```

**SeaweedFS bucket config (one-time setup, in the operator's responsibility — document it in `docs/self-hosting.md`):**

```
aws s3api put-bucket-versioning \
  --bucket kutup-files \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-lifecycle-configuration \
  --bucket kutup-files \
  --lifecycle-configuration file://lifecycle.json
```

```json
// lifecycle.json
{
  "Rules": [{
    "ID": "kutup-version-retention",
    "Status": "Enabled",
    "Filter": { "Prefix": "" },
    "NoncurrentVersionExpiration": {
      "NoncurrentDays": 30,
      "NewerNoncurrentVersions": 50
    }
  }]
}
```

Named/keep-forever versions are protected by a backend cleanup job (see §9).

---

## 8. WebSocket protocol

```
GET /api/files/:fileId/collab/ws
  Authorization: Bearer <jwt>
  Upgrade: websocket
  Sec-WebSocket-Protocol: kutup.collab.v1
```

Server validates the JWT and confirms the user has read access to the collection containing `:fileId`. Read-only collaboration (presence + view) is allowed for users without write access; the server enforces this by rejecting non-awareness frames from such devices.

**On accept:**

1. Server sends `hello`:
   ```
   {"type":"hello",
    "fileId":"…",
    "currentDocKeyId":N,
    "headSeq":M,
    "peers":[{"deviceId":…,"userId":…,"username":…},…]}
   ```
2. Client sends `resume`:
   ```
   {"type":"resume","lastSeenSeq":K}
   ```
   (`K=0` for first join.)
3. Server replays `file_update_log` from `K+1` to current head as a stream of binary frames.
4. Steady state: bidirectional binary `CollabFrame` messages.
5. Server-broadcast control messages for room membership: `peer_joined`, `peer_left`, `device_revoked`.

**Disconnect handling:** client reconnects with its last-seen `seq`; server replays the gap. Clients buffer outgoing frames during disconnect; reconnect flushes them.

**Backpressure:** Go relay maintains a per-connection bounded outbound queue. Slow consumers get disconnected with a `code=1008` reason; their next reconnect re-syncs from the log. No "slow lane" complexity in v1.

---

## 9. Versioning and history

**Snapshot triggers (layered, all client-driven):**

1. **Idle debounce (30 s).** When ≥ 1 update has accumulated since the last snapshot AND no edits have arrived for 30 s, the client materializes a snapshot.
2. **Hard ceiling.** Yjs path: every 200 frames in the log. OnlyOffice path: every 10,000 OnlyOffice ops (mirrors CryptPad's `FORCE_CHECKPOINT_INTERVAL`).
3. **Explicit "Save version" / "Name version"** UI button. Always snapshots; sets `label` + `keep_forever=true`.
4. **Membership change → key epoch bump.** Forces a snapshot under the new `doc_key_id`.

**Election among multiple connected clients:** the client with the lowest `device_id` in the room is the snapshot leader. If they disconnect during a snapshot, the next-lowest takes over after a timeout. Avoids redundant snapshots when many clients are connected.

**Snapshot mechanics (client side):**

1. Encode current state: `Y.encodeStateAsUpdateV2(doc)` (Yjs path) or `editor.asc_nativeGetFile()` → x2t → OOXML (office path, v2).
2. Encrypt with current `content_key` + fresh nonce.
3. PUT to `s3://kutup-files/files/<file_id>/snapshot` (SeaweedFS auto-creates a new noncurrent version).
4. Send `kind=3` snapshot announce frame containing `{ s3_version_id, storage_path, seq_at_snapshot, doc_key_id, size_bytes, label?, keep_forever? }` (encrypted).
5. Server: insert `file_versions` row, delete `file_update_log` rows with `seq <= seq_at_snapshot`, broadcast a `snapshot_committed` event so peers can drop those frames from any local cache.

**Retention** (mirrors Drive's "30 days OR 100 versions, whichever first; named forever"):

- SeaweedFS lifecycle handles S3 noncurrent-version expiry: `NoncurrentDays=30` AND `NewerNoncurrentVersions=50`.
- A backend cleanup job (cron, daily) deletes `file_versions` rows whose corresponding S3 version is gone — but never deletes rows where `keep_forever=true`. For those, the cleanup job ensures the S3 version is **excluded** from lifecycle (using object tagging — SeaweedFS lifecycle filters support tags: tag the kept-forever version with `kutup-keep=true`, scope the lifecycle rule to filter `kutup-keep != true`).
- Default policy: keep last 30 days OR 50 snapshots, whichever yields more. Named/keep-forever forever.

**UI** (right-rail panel, modeled on Drive):

- Timeline grouped per author, time-bucketed (consecutive same-author snapshots within 5 min collapse into one row).
- Row contents: timestamp · author avatar(s) · optional `label` badge · ⋯ menu.
- ⋯ menu actions: **Open** (read-only side-by-side preview), **Restore**, **Name…**, **Keep forever**, **Make a copy** (creates a new file in the same collection from this snapshot).
- Live deltas between snapshots are NOT exposed individually. Internal consistency only.

**Restore:** non-destructive. Client downloads + decrypts the chosen snapshot, posts a fresh snapshot under the current epoch with that content, log truncates. The chosen snapshot stays in history.

---

## 10. New REST endpoints

All endpoints below require Bearer JWT unless noted. Field names follow kutup's existing camelCase convention.

### Device management

```
POST   /api/devices                 Register a device's signing pubkey.
                                    Body: {publicSigning: <base64>, label?: string,
                                           authSig: <base64>}  // signed by master key
                                    Response 201: {deviceId, label, createdAt}

GET    /api/devices                 List the current user's devices.
                                    Response: [{deviceId, label, isActive,
                                                createdAt, lastSeenAt}]

DELETE /api/devices/:id             Revoke a device (mark is_active=false).
                                    Response: 204 No Content
```

### Live edit channel

```
GET    /api/files/:fileId/collab/ws
                                    WebSocket upgrade. See §8.
```

### Version history

```
GET    /api/files/:fileId/versions
                                    List all versions for a file.
                                    Response: [{id, s3VersionId, sizeBytes,
                                                authorUserId, label, keepForever,
                                                createdAt, seqAtSnapshot, docKeyId}]

GET    /api/files/:fileId/versions/:vid/download
                                    Get the encrypted snapshot blob for a version.
                                    Response: encrypted bytes (application/octet-stream)
                                    + headers: x-kutup-doc-key-id, x-kutup-seq

PATCH  /api/files/:fileId/versions/:vid
                                    Set label / keep_forever on a version.
                                    Body: {label?: string, keepForever?: bool}
                                    Response 200: updated version row

                                    (No dedicated /restore endpoint in v1.)
                                    Restore is a pure client-driven flow with no special
                                    server support: client GETs /versions/:vid/download,
                                    decrypts, POSTs a fresh snapshot frame (kind=3) under
                                    the current key epoch with that content. The server
                                    records it as a new file_versions row exactly like any
                                    other snapshot. The frontend UI labels it client-side
                                    (e.g. auto-fills label = "Restored from <date>").
                                    Add a server endpoint if/when audit logging is needed.
```

### Optional helper for WebDAV-future use

```
GET    /api/files/:fileId/collab/active
                                    Cheap "is anyone editing live right now?" check,
                                    used by the future WebDAV daemon to return 423.
                                    Response: {active: bool, peerCount: int}
```

---

## 11. Frontend — extension dispatch

```tsx
// frontend/src/components/editors/dispatch.tsx
const TEXT_EXT = new Set(['md','markdown','txt','go','js','ts','tsx','py','rs',
                          'json','yaml','yml','html','css','toml','sh','sql',
                          'dockerfile','nix']);
const OFFICE_EXT = new Set(['docx','xlsx','pptx','odt','ods','odp']);  // v2

export function chooseEditor(filename: string): EditorComponent | null {
  const ext = filename.split('.').pop()?.toLowerCase() ?? '';
  if (TEXT_EXT.has(ext)) return TextCollabEditor;
  if (OFFICE_EXT.has(ext)) return OfficeCollabEditor;        // v2
  return null;  // fall back to existing preview/download UI
}
```

Files for which `chooseEditor` returns null retain the existing preview/download experience — this feature is purely additive on the frontend.

---

## 12. Crypto contract (concrete)

| Primitive | Algorithm | Library | Rationale |
|---|---|---|---|
| Per-file content key derivation | HKDF-SHA256 | libsodium `crypto_kdf_hkdf_sha256_*` | Deterministic, reuses the existing collection master key |
| AEAD for collab frames + snapshot blobs | XChaCha20-Poly1305 (IETF) | libsodium `crypto_aead_xchacha20poly1305_ietf_*` | Same primitive kutup already uses for streamed file content |
| Frame signature | Ed25519 | libsodium `crypto_sign_*` | Same primitive kutup already uses for the recovery proof |
| Device-key registration signature | Ed25519 over `(deviceId || publicSigning || ts)`, signed by the user's master-derived signing key | libsodium `crypto_sign_*` | Authenticity binding for new device registrations |
| Per-recipient key wrapping (collection sharing — unchanged) | NaCl sealed box | libsodium `crypto_box_seal*` | Existing kutup primitive |

**Nonce strategy:** XChaCha20's 192-bit nonce makes random nonces safe. Generate fresh per frame with `crypto_aead_xchacha20poly1305_ietf_NONCEBYTES` of randomness.

**Wire byte order:** all integers little-endian. Document in code with a struct comment.

---

## 13. Build sequencing

| Phase | Scope | Coarse cost |
|---|---|---|
| **v1.0** | Text/markdown/code path: schema + envelope + Go relay + device-key flow + Yjs/CodeMirror integration + version history backend + version history UI + S3 versioning setup. Ship. | 2–3 weeks of focused work |
| **v1.1** | Awareness polish (color stability, idle, throttling), reconnect resume polish, version diff side-by-side view. | 3–5 days |
| **v2.0** | Office-doc path: bundle CryptPad's OnlyOffice fork + x2t WASM, build the postMessage bridge in TypeScript, wire OnlyOffice's OT ops into the existing envelope (`kind=4`), `oo_lock` (`kind=5`), `oo_checkpoint_meta` (`kind=6`). Handle CryptPad's documented footguns (TOO_LARGE, lock deadlock, x2t failures) better than they did. License decision before merging. | 4–8 weeks |
| **v2.1** | Offline edit mode — IndexedDB cache backed by `y-indexeddb`, queued frames during disconnect, conflict resolution on reconnect. | 1–2 weeks |
| **v3+** | Federated live editing across kutup instances; comments / suggestions; mobile UI; WebDAV (see [`docs/research/06-webdav-support.md`](../../research/06-webdav-support.md)). | TBD |

---

## 14. Open questions (acceptable to defer; flag if they affect v1)

1. **Read-only join for view-only collection members.** v1 plan: server allows the WS upgrade but rejects non-awareness frames. Client UI shows a read-only editor. Confirm this is the desired behavior vs blocking the WS entirely.
2. **WebSocket max message size.** Reasonable cap to prevent log abuse — 1 MiB per frame should be ample for Yjs updates and OnlyOffice ops; office snapshots go via S3 PUT, not WS.
3. **Multi-tab same device.** Two browser tabs on the same machine each register as a separate device today. Could share a device key via `BroadcastChannel` for efficiency; v1 keeps them separate (simplest).
4. **Snapshot leader election under brief disconnects.** Edge cases (everyone disconnects right when the timer fires) may produce duplicate snapshots — both succeed in S3 versioning, the second `file_versions` row is a near-duplicate. Acceptable for v1; we'll cap with a server-side dedup if it bites.
5. **Backpressure for slow consumers** beyond simple disconnect: revisit if real users hit it.
6. **v2 license decision** for bundling AGPL OnlyOffice client into MIT kutup. Realistic options when v2 begins: relicense the office subdirectory to AGPL; ship OnlyOffice as a separately-installed optional package fetched at runtime; relicense the whole project. Lawyer review needed; not a v1 blocker.

---

## 15. Verification

A change is "done" when these all pass.

**Backend builds and tests:**
```
cd backend && go build ./... && go vet ./... && go test ./...
```
New tests required:
- `TestCollabHub_Replay` — populate `file_update_log`, connect, send `resume`, assert the right tail is replayed.
- `TestCollabHub_BadSignature` — send a frame with a flipped signature byte; assert the server disconnects with code 1008.
- `TestCollabHub_RevokedDevice` — revoke the device mid-session; assert the next frame is rejected.
- `TestSnapshot_Truncate` — send a `kind=3` snapshot announce; assert older log rows are deleted and a `file_versions` row is inserted.
- `TestVersionHistory_Retention` — simulate >50 snapshots; assert retention cleanup keeps the right ones (named/keep-forever exempt).

**Frontend builds and type-checks:**
```
cd frontend && pnpm build && pnpm tsc --noEmit
```

**Manual end-to-end (must be checked before declaring v1 done):**
1. Open `notes.md` in two browser tabs as the same user. Edits in tab A appear in tab B in <500 ms. Cursors visible.
2. Open the same file as a different user (collection co-member). Edits flow both directions; presence shows two distinct users.
3. Leave both tabs idle for 31 s. Confirm a snapshot row appears in `file_versions`. Confirm the `file_update_log` is truncated.
4. Click "Save version" + give it a name → confirm `keep_forever=true` row in DB.
5. Restore an older version → confirm content matches and a new snapshot row is created.
6. Disconnect for 30 s, then reconnect. Confirm gap replay and no missing edits.
7. Revoke the second device → confirm subsequent edits from that device are rejected and the device is removed from the peer list.
8. Download `notes.md` via the existing file API. Confirm the bytes are the latest snapshot's plaintext after client decryption.

**Security checks (manual on v1, automated later):**
1. Server logs at `info` level should never contain plaintext content (visual inspection on live edits).
2. Postgres `file_update_log.frame` bytes should not contain the plaintext substring `"hello"` after typing "hello" in the editor (sanity check that AEAD is happening).
3. SeaweedFS object bodies for snapshot versions are not parseable as plaintext markdown.

**Compose validates:**
```
docker compose -f docker-compose.yml config > /dev/null
docker compose -f docker-compose-volume.yml config > /dev/null
```
(Bucket-versioning + lifecycle setup added to `seaweedfs-init` service.)

**Documentation updated** as part of merging v1:
- `docs/architecture.md` — add the collab-edit section.
- `docs/api.md` — add the new endpoints.
- `docs/self-hosting.md` — add the SeaweedFS versioning + lifecycle setup steps.

---

## Critical files (will be created/modified by the implementation plan)

**New backend files:**
- `backend/handlers/collab.go` — WebSocket upgrade + `Hub` (rooms map + per-room goroutine).
- `backend/handlers/devices.go` — register/list/revoke.
- `backend/handlers/file_versions.go` — list/download/label (restore is client-driven, no endpoint).
- `backend/services/collab_envelope.go` — frame parsing, signature validation.
- `backend/db/migrations/012_collab_edit.up.sql` — the four schema changes from §7.

**Modified backend files:**
- `backend/main.go` — register routes.
- `backend/middleware/auth.go` — JWT validation for WebSocket upgrade (use `Sec-WebSocket-Protocol` or query param).

**New frontend files:**
- `frontend/src/components/editors/dispatch.tsx` — extension → editor.
- `frontend/src/components/editors/TextCollabEditor.tsx` — CodeMirror + Yjs.
- `frontend/src/components/editors/OfficeCollabEditor.tsx` — v2 placeholder + iframe boot in v2.
- `frontend/src/collab/envelope.ts` — pack/unpack/sign/verify.
- `frontend/src/collab/transport.ts` — WebSocket client + reconnect.
- `frontend/src/collab/snapshot.ts` — snapshot triggers + S3 PUT.
- `frontend/src/collab/devices.ts` — Ed25519 keypair generation, registration.
- `frontend/src/components/VersionHistory/*` — UI panel.

**New CLI files (v1 scope: snapshot tool only; full WebDAV is later):**
- `cli/cmd/snapshot.go` — manual snapshot trigger for power users.

**Modified frontend files:**
- `frontend/src/pages/Drive.tsx` — wire up `chooseEditor` on file open.
- `frontend/src/store/authSlice.ts` — track current device id.

**Configuration:**
- `seaweedfs-s3.json` — leave unchanged (per-bucket versioning is separate API call).
- `docker-compose.yml` and `docker-compose-volume.yml` — add a one-shot init container that enables versioning on the bucket and applies the lifecycle rule.

---

End of spec.
