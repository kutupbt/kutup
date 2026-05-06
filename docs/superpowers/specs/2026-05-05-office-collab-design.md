# Office Collab Edit (.docx / .xlsx / .pptx) — Design

**Status:** approved 2026-05-05
**Pattern:** CryptPad's OnlyOffice client-only integration. Server stays content-blind.
**Research:** `docs/research/05-cryptpad-onlyoffice-integration.md` is the source of truth for everything implementation-shaped; this spec compresses it into our roadmap.

---

## 1. Goal

Open `.docx`, `.xlsx`, `.pptx` from kutup's Drive in a new browser tab, edit collaboratively in OnlyOffice, persist back to S3 as encrypted OOXML versions. End-to-end encrypted: the relay server never sees plaintext.

---

## 2. Hard decisions (locked)

- **License path: opt-in install script.** kutup itself stays MIT. Operators run `./install-onlyoffice.sh` to fetch AGPL OnlyOffice client JS into `frontend/public/onlyoffice/`. Same model CryptPad uses; AGPL boundary explicit.
- **Versions: v9 only at first.** CryptPad bundles v1 + v2b + v4..v9 to cover legacy-document compatibility. We start with v9; backfill earlier versions only if a real legacy doc breaks. Saves ~80 % of disk.
- **Routing: reuse `/file/:cid/:fid`.** Existing `FileEditorPage` adds `chooseOfficeEditor(name)` between text-collab editor and viewer dispatch. Single file dispatch path.
- **Backend: opaque relay unchanged.** OnlyOffice ops travel as a new `KindOfficeOp` envelope kind; the existing collab WS handler routes by `file_id` and doesn't care about payload shape. Snapshot endpoint reused (`POST /files/:fid/snapshot-blob` + `POST /files/:fid/versions`).

---

## 3. Out of scope

- Federated/cross-server office collab (same gap as Yjs path; tackle together later).
- Comments / track-changes UI (CryptPad disables some via `asc_setRestriction`; we'll match).
- Bundling v1–v8 unless a real legacy doc breaks.
- Live cell-level cursor presence (OnlyOffice ≥ v9 has its own user list; we won't extend).
- Replacing the Yjs-based text collab — `.md/.txt/.code` keep their existing CodeMirror+Yjs path. OnlyOffice is only for OOXML.

---

## 4. Architecture

```
/file/:cid/:fid (FileEditorPage)
  ├ chooseEditor      → text/markdown/code → TextCollabEditor (existing)
  ├ chooseOfficeEditor → docx/xlsx/pptx → OfficeEditor (NEW)
  ├ chooseViewer      → image/pdf/video/audio (existing)
  └ else → unsupported

OfficeEditor.tsx  (kutup React component)
  └ <iframe src="/onlyoffice/inner.html"> — the bridge page (CryptPad-shaped)
      ├ <iframe src="/onlyoffice/dist/v9/web-apps/{type}editor/main/index.html">
      │     # OnlyOffice itself
      └ <iframe src="/onlyoffice/dist/x2t/x2t.html">
            # x2t WASM converter (web worker)

postMessage channel: kutup ↔ inner.html ↔ OnlyOffice
                                       ↘ x2t

Wire format:
  saveChanges (OnlyOffice op)
    → wrap in our existing libsodium AEAD envelope (KindOfficeOp)
    → existing WS relay /api/files/:fileId/collab/ws
    → broadcast (server stays content-blind)
    → on remote: decrypt → ooChannel.send() → OnlyOffice applies
```

The relay is already file-id-room based and signature-validated; **no server-side sync code changes** beyond adding a `KindOfficeOp` constant in `backend/services/envelope` (and for safety, treating it the same as `KindYjsUpdate` for persist + broadcast).

---

## 5. Snapshot / version model

Reuses existing infrastructure end-to-end:

| Trigger | Action |
|---|---|
| Every 10 000 OnlyOffice ops since last checkpoint | `asc_nativeGetFile()` → x2t to OOXML → encrypt with per-file content key → `POST /files/:fid/snapshot-blob` + `POST /files/:fid/versions` |
| Idle 30 s + ≥1 unsynced op | Same. (CryptPad uses op-count only; idle-debounce is our small improvement.) |
| User clicks "Save version" | Same path, with a label and `keep_forever=true`. |

The encrypted OOXML lives in SeaweedFS S3 versioning. The kutup `file_versions` table indexes them. The `file_update_log` Postgres table holds wrapped OnlyOffice ops between checkpoints. Existing 30-day / 50-version retention rules apply unchanged.

---

## 6. Phases

After a deeper read of CryptPad's `inner.js` (3400 LOC, every callback signature mapped), the original 7-phase plan compressed too much into Phase 2. Each major phase below is split into sub-phases that each produce a single browser-testable artifact. Pauses at every "Yes" boundary per the testable-checkpoints rule.

### Reference for everything below

The Explore agent's deep-read of CryptPad lives in this conversation's summary; canonical line numbers come from `cryptpad/www/common/onlyoffice/`. The three-iframe topology is fixed:

```
[1] FileEditorPage (kutup React)
      ↓ src=/onlyoffice/inner.html?type=docx&fileId=…
[2] inner.html (bridge — postMessage protocol)
      ↓ DocsAPI.DocEditor() creates iframe internally
[3] OnlyOffice editor (CryptPad-fork build, AGPL)

Plus a sibling iframe:
[2b] x2t.html (WASM converter, web worker)
```

`connectMockServer({ onMessage, getParticipants, onAuth, getInitialChanges, getImageURL })` is the integration heart; it's a CryptPad-fork patch on top of OnlyOffice — undocumented officially.

### Sub-phases

| # | Phase | Output | Testable? |
|---|---|---|---|
| **1** | License + bundling | `install-onlyoffice.sh` (v9 + x2t + 3 templates from cryptpad@2025.6.0), `frontend/public/onlyoffice/{dist,templates}/`, README opt-in section | Build passes |
| **2a** | Bridge HTML scaffold | `inner.html` skeleton served from `/onlyoffice/inner.html`; nginx + CSP allow the editor's nested iframes (frame-src already set); no JS yet beyond a `postMessage('ready')` heartbeat. Wire FileEditorPage to mount the iframe for `.docx/.xlsx/.pptx` via a new `OfficeEditor.tsx` stub | **Yes** — open a .docx file → blank inner page renders inside the editor route, console shows the ready handshake |
| **2b** | Empty DocsAPI mount | `inner.html` loads `dist/v9/web-apps/apps/api/documents/api.js` and instantiates `DocsAPI.DocEditor` with a stub config (`mode: 'view'`, `documentType: 'word'`, hardcoded URL pointing at one of the templates fetched in phase 1). No `connectMockServer` yet — OnlyOffice will hang waiting for auth, but the editor *chrome* should appear | **Yes** — open .docx → see OnlyOffice's editor UI render |
| **2c** | Stub mockServer | Implement minimum `connectMockServer({ onMessage: noop, getParticipants: returns self + history-keeper, onAuth: noop, getInitialChanges: returns [], getImageURL: noop })`. OnlyOffice's auth handshake completes; an empty editable doc renders | **Yes** — open .docx → OnlyOffice's auth completes, can type into the empty doc (changes don't persist) |
| **2d** | "+ New" entries + real file creation | Drive's "+ New" gains Document / Spreadsheet / Presentation entries. They each create a file in kutup with a placeholder body (the unconverted template binary) then open it. Each opens with the appropriate `documentType` mapped from extension | **Yes** — "+ New → Document" creates Untitled.docx, opens, OnlyOffice editor loads with empty doc |
| **3a** | x2t iframe bootstrap | `x2t.html` page that loads `dist/x2t/x2t.js` and exposes a `postMessage` API: `{type:'convert', input:Uint8Array, from:'docx', to:'bin'}` → returns `{output:Uint8Array, images:{}}`. Mounted as a sibling iframe of the OnlyOffice editor inside `inner.html` | **Yes** — open the editor → x2t iframe loads; manual postMessage from devtools converts a hardcoded test docx blob to bin |
| **3b** | OOXML→bin on first open | When opening an existing `.docx/.xlsx/.pptx` upload: kutup decrypts the blob (existing flow), inner.html receives bytes via postMessage, ships them to x2t iframe (`from:'docx', to:'bin'`), feeds the resulting bin to OnlyOffice via `document.url` blob URL | **Yes** — upload an existing .docx, open it, see its real contents in the editor |
| **4a** | bin→OOXML round-trip | Implement `asc_nativeGetFile()` → x2t iframe (`from:'bin', to:'docx'`) → OOXML bytes. Trigger only on user-initiated Save button (manual). Upload via existing `/files/:fid/snapshot-blob` + `/files/:fid/versions` endpoints | **Yes** — edit a .docx, click Save, reload → see edits |
| **4b** | Auto-checkpoint trigger | Op-count: every 100 ops force a save (CryptPad's `CHECKPOINT_INTERVAL`). Idle: 30s after last op fires save. Both deduped by op count to prevent double-saves | **Yes** — edit a .docx for ~100 keystrokes, see version-history sidebar gain an entry without clicking Save |
| **4c** | Version history compatibility | The history sidebar shows OnlyOffice snapshots alongside Yjs ones; restoring an OnlyOffice version downloads the OOXML, x2t-converts to bin, re-feeds OnlyOffice via destroyEditor + reinit | **Yes** — save a few versions, restore one → editor reloads with that version's content |
| **5a** | Wire saveChanges → relay | Catch `saveChanges` postMessage in inner.html → forward to kutup parent (postMessage) → existing WS path in OfficeEditor.tsx encrypts in our libsodium AEAD envelope (new `KindOfficeOp` constant) → relay broadcasts unchanged. Add `KindOfficeOp` in `backend/services/envelope/` and treat it identically to `KindYjsUpdate` for persist + broadcast | **Yes** — only one tab; verify backend logs show `bcast yjs_update` analog for office ops |
| **5b** | Receive remote ops | When a `KindOfficeOp` frame arrives, kutup decrypts → postMessage to inner.html → `ooChannel.send({type:'saveChanges', changes: [op]})` → OnlyOffice applies the change | **Yes** — two tabs, edits in tab A appear in tab B |
| **5c** | Multi-user (different accounts) | Same path, with a second account in a shared folder. Verify per-user cursors render with the OnlyOffice native cursor list (we already populate `getParticipants` with the right user IDs in 2c) | **Yes** — two accounts, both see each other's edits + cursors |
| **6a** | getLock / releaseLock plumbing | Catch `getLock` and `releaseLock` postMessages, wrap in a new `KindOfficeLock` envelope, broadcast. On receive: `ooChannel.send({type:'getLock', locks: …})` so OnlyOffice greys out the locked range. Lock state in a per-file Y.Map (or a Postgres `office_locks` table; pick simpler) | **Yes** — two tabs editing same .xlsx, click on a cell in tab A → tab B sees it as locked |
| **6b** | Offline lock cleanup | `deleteOfflineLocks()` analog: when a peer disconnects (we know via the Hub's `Leave`), drop their locks from the shared state and broadcast `releaseLock` to remaining peers | **Yes** — close tab A → tab B sees its cell locks released |
| **6c** | Save-lock | Single global save-lock per file (`content.saveLock`) so two tabs don't double-checkpoint. 20-40s timeout if the holder disconnects without releasing | **Yes** — both tabs hit Save simultaneously → only one snapshot lands |
| **7a** | CSS branding hides | Inject the same `injectCSS` rules CryptPad uses (line ~2002-2024 in their inner.js) — hide title-doc-name, file-info, branding logos, etc. Light/dark theme follows kutup's | **Yes** — open an office doc → no OnlyOffice branding visible |
| **7b** | Error / edge cases | TOO_LARGE → "Cannot save — file too large" banner, editor stays read-only (`APP.cantCheckpoint = true` analog). x2t conversion failure → toast + retry button. mediasData cleanup on unmount | **Yes** — manually upload a >10 MB .docx to trip TOO_LARGE; see the banner |
| **7c** | Final regression | All formats: edit, save, reload, share, restore, federation-deferral notice. Build clean, type-check clean. Push. | **Yes** — full sweep |

**Estimated complexity by phase:**
- Phases 1, 2a, 2b, 2c, 2d: small-medium each (each is a couple of careful files)
- Phase 3a, 3b, 4a, 4c: medium (involves x2t WASM behavior + binary handling)
- Phase 5a, 5b: medium (postMessage choreography + envelope)
- **Phase 5c, 6a, 6b: hardest** — multi-user state machines, lock state coordination, OnlyOffice's "single docid" expectations
- Phase 7: small-medium polish

That's 17 sub-phases. Realistic total: **2-3 weeks of careful work** with browser testing at each boundary.

---

## 7. New files (anticipated)

```
install-onlyoffice.sh                         # opt-in, AGPL-fetcher
frontend/public/onlyoffice/                   # populated by the script (gitignored)
  inner.html
  dist/v9/web-apps/...
  dist/x2t/x2t.html, x2t.wasm

frontend/src/components/editors/office/
  OfficeEditor.tsx                            # React wrapper (mounts the iframe)
  bridge.ts                                   # postMessage protocol typings
  rtChannel.ts                                # encrypted op sender (mirrors CryptPad's)
  ooChannel.ts                                # outbound queue → OnlyOffice
  x2t.ts                                      # convert helpers via the x2t iframe
  templates/
    docx-empty.bin
    xlsx-empty.bin
    pptx-empty.bin

frontend/src/components/editors/dispatch.tsx  # extended: chooseOfficeEditor

backend/services/envelope/                    # add KindOfficeOp + KindOfficeLock constants
LICENSES/AGPL-3.0-or-later.txt                # reference (the actual code lives in
                                              # frontend/public/onlyoffice/, gitignored)
```

`frontend/public/onlyoffice/` is gitignored — the AGPL JS doesn't enter our repo. README explains how to populate it.

---

## 8. Risks + mitigations

| Risk | Mitigation |
|---|---|
| OnlyOffice's private-API surface drifts (`asc_nativeGetFile`, `asc_setRestriction`, `sendMessageToOO`) | Pin v9 by SHA-512; document a "we know this is private API" caveat in `OfficeEditor.tsx`. Re-test on every upstream bump. |
| `TOO_LARGE` checkpoint (binary exceeds server quota) | Show "Cannot save — file too large" banner, leave editor read-only; CryptPad's pattern. Capture in phase 7. |
| Image cache leak (`mediasData`) | Explicit cleanup on unmount. Phase 7. |
| Save-lock deadlock if holder disconnects | 30 s timeout (CryptPad uses 20). Phase 6. |
| Multi-iframe `postMessage` plumbing fragile | Lots of unit tests around `bridge.ts` + integration test that walks all four message kinds. Phase 5. |
| OOXML schema drift between OnlyOffice versions | We pin v9; don't try to support documents created in v10+ until we test compat. |
| AGPL "viral" reach into kutup core | Opt-in install script + gitignored public dir keeps the AGPL boundary explicit. Operator opts in. |

---

## 9. Open follow-ups (intentionally deferred)

1. Federated office collab (relay is single-server today).
2. Shared "Comments" channel.
3. v1–v8 backfill if a real legacy doc breaks.
4. Mobile-friendly OnlyOffice (their own concern; we host whatever the bundle ships).

---

## 10. Verification at end of phase 7

1. `pnpm build` clean.
2. `go build ./... && go vet ./...` clean.
3. Manual scenarios:
   - Create new `.docx` from "+ New" → type → close tab → reopen → content persists.
   - Two tabs of the same `.docx` (same user) → typing in one appears in the other.
   - Two users (account A shares folder to B) → both see edits.
   - Spreadsheet — formula `=SUM(A1:A3)` updates live across tabs.
   - Presentation — slide reorder syncs.
   - Save version + restore → restored version replaces live state cleanly.
   - File > 100 MB blocked at the existing preview cap.
4. No CSP errors in console for the new iframe paths.

---

## 11. Status snapshot (2026-05-06): what shipped vs what's deferred

After ~50 commits in one focused session, **single-user E2EE office editing is production-quality.** Real-time multi-tab/multi-user collab (Phases 5/6/7) is **deferred** to a focused next session — the bridge is wired and the WS relay broadcasts correctly, but OnlyOffice v9's spreadsheet doesn't emit content-bearing `saveChanges` over `connectMockServer` for our config.

### Shipped (works end-to-end)

- **Phase 1**: opt-in `install-onlyoffice.sh` (v9 + x2t + CryptPad templates), gitignored AGPL subtree.
- **Phase 2a/b/c/d**: bridge HTML + DocsAPI mount + stub mockServer + "+ New Document/Spreadsheet/Presentation" flow.
- **Phase 3a/b**: x2t WASM bridge iframe; existing OOXML uploads → x2t → OnlyOffice loads them.
- **Phase 4a**: Save button → `asc_nativeGetFile` → x2t → encrypted version uploaded to `/files/:fid/snapshot-blob` + `/files/:fid/versions`.
- **Phase 4c**: open dispatch lists `/files/:fid/versions` and prefers the newest blob over the original.

### Deferred (Phase 5/6/7)

The protocol gap that blocks Phase 5:

> OnlyOffice v9's spreadsheet emits only **empty** `saveChanges` (heartbeats every ~10 s) over the mockServer. Cell commits are visible in the UI but never reach our `fromOO` handler with non-empty `changes`.

Things tried that **did not** fix it:
1. Proper `cpIndex` tracking on outbound + inbound (mirrors CryptPad inner.js:1357 / inner.js:1000).
2. `changesIndex`, `locks: []`, stable `myUniqueOOId` in outbound saveChanges shape.
3. Removing `protect: true` from xlsx permissions; explicit `permissions.edit: true`.
4. `editorConfig.coEditing.mode: 'fast'`.
5. Suppressing empty heartbeat broadcasts.

### What to try next session

Run CryptPad locally and put both integrations side-by-side. Compare every `postMessage` that crosses the editor-iframe boundary for an identical `.xlsx` typing test. Specific entry points worth the deepest read:

- **CryptPad**: `www/common/onlyoffice/inner.js`
  - `handleAuth` (line 1187) — auth response shape and what fields are required.
  - `getInitialChanges` (line 1164) — what initial state the editor expects.
  - `handleNewIds` / `connectState` (line 1097) — when peers are announced.
  - The `setUsers` / `users` field on auth and whether OO needs ≥1 non-history-keeper peer to enable saveChanges emission.
  - `m_bFast` references (lines 1613, 1831) — the gating condition for fast vs. strict coediting.
- **OnlyOffice (un-minified, in `cryptpad/onlyoffice-editor` source repo, NOT the release tarball we install)**:
  - `sdkjs/cell/api.js` — the spreadsheet api class. Trace the path that emits saveChanges to find the gate.
  - `web-apps/apps/api/documents/api.js` — the source of the minified `api.js` we load. The `connectMockServer` patch is here; reading it un-minified will reveal which callbacks gate which feature.
  - `cryptPadMessageToOO` / `cryptPadSendMessageFromOO` — the bridge message dispatch.

A useful diagnostic to add when this work resumes: a `[fromOO]` log on every message OnlyOffice emits (not just our switch), so we can compare the message stream byte-for-byte against CryptPad's.

### Files where Phase 5 lives in our code

- `frontend/public/onlyoffice/inner.html` — bridge page; `fromOO` handler, mockServer callbacks, x2t convert, saveChanges wrap/unwrap.
- `frontend/src/components/editors/office/OfficeEditor.tsx` — React wrapper, WS transport, envelope wrap, ref-exposed `save()`.
- `frontend/src/collab/cryptoFrame.ts` — `encryptOOOp` / `decryptOOOp`.

When the gate is found, the existing wiring should carry remote ops the rest of the way without further surgery.
