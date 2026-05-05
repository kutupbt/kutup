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

Each phase is a separate commit that produces a testable artifact (or, for foundations, a verified build). Per the testable-checkpoints rule, the assistant pauses at each "Yes" boundary and says "you can test …".

| # | Phase | Output | Testable? |
|---|---|---|---|
| **1** | License + bundling | `install-onlyoffice.sh` (kutup-flavored, v9-only fork of CryptPad's), `frontend/public/onlyoffice/dist/v9/`, `frontend/public/onlyoffice/dist/x2t/`, README "Optional: enable OnlyOffice" section, `LICENSES/AGPL-3.0-or-later.txt` reference | Build passes (no UI yet) |
| **2** | Empty editor mount | `OfficeEditor.tsx` + `frontend/public/onlyoffice/inner.html` bridge page; Drive's "+ New" gains "Document (.docx)" / "Spreadsheet (.xlsx)" / "Presentation (.pptx)" entries that create empty files and open them | **Yes** — see OnlyOffice render an empty doc, type locally |
| **3** | x2t bootstrap + load existing docs | x2t iframe + `Q_OO_CONVERT` bridge; uploaded `.docx/.xlsx/.pptx` decrypt → x2t → OnlyOffice loads them | **Yes** — open an uploaded doc, see its real contents |
| **4** | Save / checkpoint | `asc_nativeGetFile` + x2t-to-OOXML + existing snapshot endpoints; integrates with the version-history sidebar we already have | **Yes** — edit, save, reload → changes persist |
| **5** | Real-time collab (the meat) | Wrap `saveChanges` postMessage in `KindOfficeOp`; existing relay routes; remote ops flow back into OnlyOffice via `ooChannel.send` | **Yes** — two tabs, edits sync within a second |
| **6** | Locking | New `KindOfficeLock` frame; OnlyOffice's native cell-range / paragraph lock UI lights up across peers; `deleteOfflineLocks` on disconnect | **Yes** — two tabs, lock prevents conflicts |
| **7** | Polish | Hide branding via CSS, `TOO_LARGE` checkpoint error UX, idle-debounce checkpoint, `mediasData` cleanup, version-history compatibility with the new snapshots | **Yes** — full regression sweep |

Phase-5 is the hardest by far (multi-iframe `postMessage` choreography + OnlyOffice's "single docid" expectation); phase-6 is genuinely tricky lock-state coordination. Phases 1–4 are mostly mechanical.

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
