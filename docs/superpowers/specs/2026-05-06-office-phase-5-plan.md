# Office Phase 5 — Execution plan

**Status:** in-progress 2026-05-06
**Parent spec:** `2026-05-05-office-collab-design.md` §11 ("what to try next session")
**Goal:** unblock real-time multi-tab/multi-user OnlyOffice collab. Phases 5a-c, 6, 7 from the parent spec.

---

## Why this is stuck

Single-user editing works. Two-tab editing doesn't. Symptom from the last session: OnlyOffice v9's spreadsheet emits **only empty `saveChanges` heartbeats** over our `connectMockServer` config — cell commits never reach our `fromOO` handler with non-empty `changes`. WS relay is correct; envelope codec is correct; the gate is somewhere inside OnlyOffice's editor that decides "should I emit content right now."

We don't have to guess the gate. CryptPad ships a working integration against the same OnlyOffice fork, with a clone of its source at `/home/aa/_e/development/cryptpad/`. The plan is **diff-driven** — make ours behaviour-equivalent to CryptPad's at the postMessage layer until saveChanges starts carrying content.

---

## Approach

Three steps, in order. Each one ends at a browser-testable checkpoint.

### Step 1 — Instrument both sides

Add a `[fromOO]` log in `inner.html` that captures **every** postMessage OnlyOffice emits (not just the ones our switch handles), with raw JSON payload. Same in CryptPad's running instance (or its local source — we own it). Any divergence in shape/order becomes diff bait.

We'll need a known-good baseline: clone the CryptPad project's saveChanges trace from a fresh xlsx + a single cell type. Capture in `docs/research/06-cryptpad-postmessage-trace.md` as ground truth.

### Step 2 — Diff against CryptPad's `inner.js`

Reference (full local clone): `/home/aa/_e/development/cryptpad/www/common/onlyoffice/inner.js` (~3400 LOC). Suspect lines from §11 of the parent spec:

- `handleAuth` (line ~1187) — auth response shape, required fields.
- `getInitialChanges` (line ~1164) — initial state expected by editor.
- `handleNewIds` / `connectState` (line ~1097) — when peers are announced.
- `setUsers` / `users` field on auth — does OO need ≥1 non-history-keeper peer to enable saveChanges emission?
- `m_bFast` (lines ~1613, 1831) — fast-vs-strict coediting gate.

For each, diff against our `frontend/public/onlyoffice/inner.html`. Note shape mismatches in this doc as we go.

### Step 3 — Apply the smallest fix that makes saveChanges carry content

Most likely outcomes (rank-ordered by what CryptPad explicitly does that we don't):

1. **Users list shape**: OnlyOffice may require ≥1 peer entry that isn't the history-keeper. Our stub probably returns just `[self]`. CryptPad seeds `[self, history-keeper, …]` and OO treats history-keeper as the persistence layer.
2. **Auth response field**: `view` flag, `denyChat`, `forcesave` config — CryptPad sets them; we may not.
3. **Coediting mode handshake**: `m_bFast` is set off something in the auth response or the participants list, not just `editorConfig.coEditing.mode`.
4. **Initial changes timing**: `getInitialChanges` returns `[]` synchronously vs. async — the order matters for the doc-init state machine.

After the gate flips, verify saveChanges payload reaches our `fromOO` switch with `changes` non-empty.

### Step 4 — Phase 5b: receive remote ops

Wiring is already there in `OfficeEditor.tsx` (KIND.OO_OP frames decrypt → postMessage → `ooChannel.send`). Test: two tabs, edit in A, see in B. If it doesn't apply, the receive-side `ooChannel.send` shape needs the same audit (likely `cpIndex` / `changesIndex` numbering).

### Step 5 — Phase 5c through 7

Once Phase 5a/b is unblocked the rest is mechanical (per parent spec):

- **5c** multi-user (different accounts) — same path, verify cursor list shows both.
- **6a** getLock / releaseLock — wrap in `KindOfficeLock`, broadcast.
- **6b** offline lock cleanup — Hub Leave → drop locks.
- **6c** save-lock — single global, 30 s timeout.
- **7a** CSS branding hides.
- **7b** error / edge cases (TOO_LARGE, x2t failure, mediasData cleanup).
- **7c** final regression sweep + push.

---

## Browser-test checkpoints

After step 3: Two-tab xlsx, type in A → tab A's `[fromOO]` log shows non-empty `changes`. Backend log shows `bcast yjs_update` analog for office ops.

After step 4: Two-tab xlsx, type in A → tab B's cell updates without reload.

After Phase 5c: Two browser profiles (different kutup accounts), shared folder, simultaneous edits, cursors visible to each other.

After Phase 7: parent spec's §10 verification list runs clean.

---

## Files we'll touch

- `frontend/public/onlyoffice/inner.html` — bridge: instrumentation, mockServer callback adjustments, ooChannel send shape.
- `frontend/src/components/editors/office/OfficeEditor.tsx` — only if envelope wrapping needs changes after the diff.
- `backend/services/envelope/` — add `KindOfficeLock` (Phase 6).
- `backend/handlers/collab.go` — broadcast `KindOfficeLock` like `KindOfficeOp` (Phase 6).
- `docs/research/06-cryptpad-postmessage-trace.md` — NEW: captured ground truth.

---

## Risks

- **Patches in OnlyOffice's fork that aren't in our installed bundle.** CryptPad applies its own patches to `api.js` (we have `api-orig.js` and `api.js` side-by-side in the install — the script may have already applied them). Step 2 includes verifying our `api.js` ≡ CryptPad's runtime `api.js`. If they diverge we re-run `install-onlyoffice.sh`.
- **The gate is a multi-step handshake, not one field.** Diagnosis time grows non-linearly. Mitigation: capture FULL sequences at step 1, not just shape snapshots.
- **OnlyOffice version drift.** We pin v9. CryptPad upstream is also v9 in `cryptpad@2025.6.0`. Verified.

---

## Out of scope (still)

Federated office collab; comments/track-changes UI; v1-v8 backfill. Same as parent spec §3.
