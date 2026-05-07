# Office cell-level formatting (fill color) — getLock investigation

**Status:** open. Typing + cross-tab sync work; cell-level formatting
(fill color, applying styles to a selected cell) silently no-ops.
Text-level formatting (bold, font color on selected text inside a cell)
works and syncs.

**Date:** 2026-05-07. Two failed attempts in the same session
(commits not landed; reverted to keep baseline working).

## User-reported symptom

> "i can change tools color on opened dialog color chooser it changes
> the icons color its all good but when i select a cell or cell group
> and click fill color button nothing happens. i can change bold and
> text colors but not just clicking a cell — but selecting a text in
> a cell, in that selected text option fill color is grayed out, also
> this text bold and color synced correctly."

The pattern: cell-as-target operations silently fail; in-cell-text
operations work and sync.

## What OnlyOffice does

When the user clicks a cell-level format (fill, border, etc.), OO emits
`getLock` to the bridge with `obj.block = ['<cell-range>']`. It expects
the bridge to respond with `{type: 'getLock', locks: [...]}` containing
a lock object that grants self the requested range. Without that grant,
OO silently drops the formatting operation.

Typing-in-cell uses a different path that's lenient when the lock list
comes back empty — which is why our current `{locks: []}` stub keeps
text edits working but breaks cell-level formatting.

## CryptPad's reference implementation

`www/common/onlyoffice/inner.js:1251-1330` (`handleLock`):

1. Build lock msg `{time, user: myUniqueOOId, block: obj.block[0]}`.
2. Add to `content.locks[myId][uid]`.
3. Snapshot current state (for diffing).
4. Register `cpNfInner.onPatchSent(callback)` — wait for the netflux
   broadcast of the new content.locks state to be acknowledged.
5. In the callback, send `{type: 'getLock', locks: getLock()}` to OO
   where `getLock()` flattens all current locks across all peers.

Key invariants:
- **Asynchronous response** — answer arrives after the network
  round-trip, not in the same tick as OO's request.
- **Self-lock present in response** — OO must see its own lock
  echoed back to consider the lock granted.
- **`user` field on the lock matches the OO config user.id** —
  CryptPad uses `myUniqueOOId` for both.

## What we tried in this session (both reverted)

### Attempt 1: synchronous self-lock echo

```javascript
case 'getLock':
  var lockUid = 'lk-' + Math.random().toString(36).slice(2, 10)
  selfLocks[lockUid] = { time: Date.now(), user: myUniqueOOId, block: obj.block?.[0] }
  sendToOO({ type: 'getLock', locks: Object.values(selfLocks) })
  break
```

**Result:** All 3 Playwright sync tests fail. Tab A's typing produces
**zero** outbound saveChanges. No JS error, no editor crash, no
`changesError` — just silent breakage of the typing path.

### Attempt 2: deferred response (setTimeout 0)

Same code, wrapped sendToOO in `setTimeout(fn, 0)` to mimic CryptPad's
`onPatchSent` deferral.

**Result:** Identical to attempt 1 — same silent breakage.

## Hypothesis

The blocker is **NOT** sync vs. async response timing — both produced
identical failures. Most likely missing piece:

- **`user.id` config mismatch.** Our editor config hardcodes
  `editorConfig.user.id = '1'`, while we stamp lock `user` as
  `myUniqueOOId` (e.g. `'kutup-abc12345'`). OO may compare incoming
  lock `user` to its own `user.id`; mismatch → "that lock belongs to
  someone else, I still don't have one for myself" → silent no-op.

  CryptPad sets `user.id = myUniqueOOId` so the comparison succeeds.

- **Some other handshake we've never traced** (e.g. `connectState`
  needing to include self in participants before locks are accepted,
  or `authData` carrying a user-id that gets used downstream).

## Recommended next steps

1. **Reproduce minimally outside Playwright.** Open one tab, watch
   DevTools console with the synchronous self-lock echo applied,
   click fill color, see what OO does next (does it emit a follow-up
   message? does it just silently drop?). Live console is much faster
   to iterate on than Playwright.

2. **Try aligning `user.id` to `myUniqueOOId`.** Single-line config
   change with the synchronous self-lock echo from Attempt 1. If this
   fixes it, the rest is plumbing.

3. **If still broken: read OO's compiled source** at
   `frontend/public/onlyoffice/dist/v9/web-apps/apps/spreadsheeteditor/main/app.js`
   for the call site that consumes the `getLock` callback response.
   Search for `"getLock"` or the relevant `_onGetLock` handler. The
   bundle is minified — may need source maps or pretty-printing.

4. **Multi-tab won't work without broadcast.** Even when single-tab
   fill color works, syncing it to peers requires the OO_LOCK frame
   wire (already plumbed in `KIND.OO_LOCK`, `encryptOOLock`,
   collab.go's KindOOLock route — all reverted in 9271c31 but the
   commit body has the design). That's the Phase 6b work.

## Files touched while investigating (all reverted)

- `frontend/public/onlyoffice/inner.html` — getLock + releaseLock +
  unLockDocument handlers, `selfLocks` module state.

## What stays working (current baseline)

- One-way sync A→B
- Two-way concurrent edits in different cells
- **Sequential A→B then B→A** (the user-reported xlsx stall, fixed
  in `e966dac` via the `unLockDocument {isSave}` ack)
- Typing text in cells (single-tab and multi-tab)
- Bold / font color on selected text inside a cell

## What's broken

- Fill color on a selected cell (no in-cell editing)
- Likely: any cell-level formatting that doesn't go through the
  text-edit path — borders, cell merging, conditional formatting, etc.
  Not all verified individually.
