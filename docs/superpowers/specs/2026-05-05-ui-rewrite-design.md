# Drive UI Rewrite — Google-Drive-Style Layout (v1)

**Status:** approved 2026-05-05
**Scope:** Frontend-only redesign of the Drive view. No backend changes.

---

## 1. Goal

Replace the current Drive page with a Google-Drive-style layout matching the Claude Design mockups (`Screenshot From 2026-05-05 13-07-02.png` dark mode + `13-07-10.png` light mode). The current UI is functional but cluttered — files and folders share visual weight, the FAB pattern hides creation, no keyboard shortcuts, files open inside a modal overlay, file types are visually indistinguishable, and `Drive.tsx` has grown to 967 lines.

The redesign delivers a familiar, intuitive interface centered on visual hierarchy (folders as cards, files as a typed table), keyboard-first navigation, and new-tab file editing.

---

## 2. Out of Scope (deferred)

- **Trash sidebar item + soft-delete.** No backend support today; ship together with v2 OnlyOffice integration.
- **Spreadsheet / Document / Presentation / Drawing in "+ New".** Wait for OnlyOffice (deferred per `docs/research/2026-05-04-collab-edit-research.md`).
- **Global cross-collection search.** v1 search filters the **current view only** (folders + files in the current collection). User confirmed 2026-05-05 that this is acceptable for v1 — global search is a v2 follow-up. Implementing it requires either decrypting metadata for every collection on demand (expensive — multiplies the per-collection key derivation across the whole vault) or maintaining a client-side encrypted-metadata index that the search input queries. To revisit when adding more navigation polish.
- **Settings page redesign.** Devices section already redesigned; rest stays.
- **Collection breadcrumb redesign.** The existing `DriveBreadcrumb` is reused as-is.

---

## 3. Sections

### 3.1 Sidebar (256 px wide)

Replaces the current `components/layout/Sidebar.tsx`. Structure top-to-bottom:

| Block | Content |
|---|---|
| **Logo / brand** | `KutupLogo` + "Kutup" wordmark, links to `/drive` |
| **Primary nav** | `My Files` (Home icon), `Shared with me` (Users icon, badge with count) |
| _spacer_ | flex grow |
| **Storage card** | Used / total (`formatBytes`), `Progress` bar, "Recovery phrase backed up?" hint |
| **Footer nav** | Settings, Sign out, theme toggle (Sun/Moon), user chip (avatar circle + email) |

Active item: `bg-primary/10 text-primary` (matches mockup). Inactive: `text-muted-foreground hover:bg-accent`. Implements via `react-router-dom` `NavLink`. Pattern follows `agsea-core/src/web/src/components/layout/Sidebar.tsx`.

### 3.2 Top bar

Replaces the current ad-hoc top buttons / FAB. Three-region flex layout:

- **Left:** breadcrumb (existing `DriveBreadcrumb`).
- **Center:** search input — `Search in Kutup...`, filters folders+files in the current view by their decrypted name (case-insensitive substring). Pressing `/` focuses, `Esc` clears.
- **Right:** primary action cluster:
  - **Upload** — primary button (`Upload` icon + "Upload"). Triggers existing file picker / `uploadFiles()`.
  - **+ New** — `DropdownMenu`. v1 entries: `Folder`, `Note (.md)`. Hidden when current folder is read-only (no `canUpload`).
  - **?** — icon button. Opens `ShortcutsDialog`.

### 3.3 Main content area

Two stacked sections inside the scroll container:

**FOLDERS** section header `FOLDERS [count]` then a 5-up grid of color-coded `FolderCard`s. Card content: tinted folder icon (color from `col.color`), folder name, "X items · MMM D" hint, optional shared-with icon, three-dot context-menu trigger. Drag-over highlights for upload-into-folder. Click → `enterFolder`. Right-click → folder context menu.

**FILES** section header `FILES [count]` then a typed table with columns: ☐ checkbox · Name (icon + filename) · Modified · Size · ⋮ menu. Sort by Name / Modified / Size (ascending/descending) via clickable column headers — also reachable via the empty-space context menu's "Sort by" submenu. Click on a row → opens file in **new tab** (see §3.6). Right-click → file context menu.

`FileIcon` component maps extensions to a Lucide icon + tinted-bg square (mirroring the mockup):

| Extension(s) | Icon | Color |
|---|---|---|
| `.xlsx`, `.csv` | `FileSpreadsheet` | green |
| `.docx` | `FileText` | blue |
| `.pptx` | `Presentation` | orange |
| `.pdf` | `FileText` | red |
| `.png`, `.jpg`, `.gif`, `.webp`, `.svg` | `Image` | blue |
| `.txt`, `.md` | `FileText` | gray |
| `.mp3`, `.wav`, `.flac` | `Music` | pink |
| `.mp4`, `.mov`, `.webm` | `Video` | purple |
| `.zip`, `.tar`, `.gz` | `Archive` | amber |
| _default_ | `File` | gray |

Empty states: "No folders yet — right-click anywhere to create one" and "No files — drag here or click Upload."

### 3.4 Context menus (right-click)

Three menus, all powered by Radix `ContextMenu` (added as a new shadcn primitive `components/ui/context-menu.tsx`; install `@radix-ui/react-context-menu`).

**Folder card** → Open · Rename · Share · Change color (▸ palette submenu using existing `FolderIcon` colors) · Delete.

**File row** → Open in new tab · Download · Rename _(deferred — no backend rename API for files yet; hidden if not implemented at impl-time)_ · Share _(same caveat — file-level share doesn't exist; use folder share)_ · Delete.

**Empty space** (the main scroll container, _not_ on folder/file items) → 📁 New folder · 📝 New note (.md) · ⬆ Upload files · ─── · Sort by ▸ (Name / Modified / Size) · Refresh.

The "+ New" dropdown menu and the empty-space menu share the same item set — the dropdown reuses the menu component for DRY.

### 3.5 Keyboard shortcuts

Global hook `useKeyboardShortcuts` mounted at Drive page level. Suppressed when typing in `<input>` / `<textarea>` / `[contenteditable]`.

| Key | Action |
|---|---|
| `U` | Upload — same as Upload button |
| `N` | Open "+ New" dropdown |
| `Esc` | Close panel / clear search |
| `⌘A` / `Ctrl+A` | Select all visible files |
| `/` | Focus search input |
| `Del` | Delete selection (with confirm dialog) — Trash deferred, so this is a hard delete in v1 |
| `?` (Shift+/) | Toggle ShortcutsDialog |

`ShortcutsDialog` is a small `Dialog` listing the same table — opened via `?` button or `?` key.

### 3.6 New-tab file routing + cross-tab session sync

**Routing.** New protected route `/file/:cid/:fid` (cid = collection id, fid = file id). Mounts a full-height page that:

1. On mount, fetches the file metadata + encrypted file key from the backend, decrypts using the parent collection key (which it derives from `masterKey`).
2. Mounts the appropriate editor from `chooseEditor(filename)` at full height (replaces the existing in-page modal overlay).
3. Sets `document.title` to the filename.
4. On unmount: existing editor cleanup (`y-websocket` provider close, etc.).

The `/drive` page opens files via `window.open('/file/:cid/:fid', '_blank')`. The current modal overlay (`editorOpen` state in Drive.tsx) is removed.

**Cross-tab session sync.** New tabs are spawned via `window.open` and each tab gets its own `sessionStorage` (per-tab by design). The new tab needs `masterKey`, `privateKey`, `accessToken`, identity fields — all sensitive material currently kept in Redux/sessionStorage of the originating tab.

Solution: a `BroadcastChannel('kutup-session')` handshake. New `frontend/src/lib/sessionSync.ts`:

- **Sender** (any logged-in tab): on Redux `setAuth` and on every successful `accessToken` refresh, broadcasts `{ type: 'session-share', payload: { ...sessionFields } }`. Also listens for `request-session` and replies with the latest payload.
- **Receiver** (a fresh tab boot): if `sessionStorage` has no session AND we're on a route that requires auth, post `{ type: 'request-session' }` and wait up to 500 ms. If a `session-share` arrives, dispatch `setAuth` to hydrate Redux + sessionStorage. If timeout → redirect to `/login?next=<original-url>`. After login, redirect to `next`.

Security: BroadcastChannel is same-origin only, so the master key never leaves the user's browser. The 500 ms timeout prevents the new tab from hanging forever if the originating tab was closed.

**`/login?next=...` support.** `Login.tsx` already exists; add support for the `next` query param so that a fresh-tab fallback returns the user to the file editor after login.

---

## 4. Component tree (target)

```
Drive.tsx (~150 lines orchestrator; data loading, dialog state, intent dispatch)
├─ DriveSidebar.tsx                 (replaces components/layout/Sidebar.tsx)
├─ DriveTopBar.tsx
│  ├─ DriveSearchInput.tsx
│  ├─ NewMenu.tsx                   (also reused by EmptySpaceContextMenu)
│  └─ ShortcutsDialog.tsx
├─ DriveContent.tsx
│  ├─ FoldersGrid.tsx
│  │  └─ FolderCard.tsx             (with right-click ContextMenu)
│  └─ FilesTable.tsx                (with right-click ContextMenu, sortable headers)
│     └─ FileIcon.tsx
└─ EmptySpaceContextMenu.tsx        (wraps DriveContent)

frontend/src/lib/sessionSync.ts     (BroadcastChannel handshake)
frontend/src/hooks/useKeyboardShortcuts.ts
frontend/src/pages/FileEditorPage.tsx (mounted at /file/:cid/:fid)
frontend/src/components/ui/context-menu.tsx (new shadcn primitive)
```

`Drive.tsx` keeps the data layer (`loadCollections`, `loadFiles`, `uploadFiles`, all CRUD handlers), passes them down to the new components. No business logic moves into the new components — they're presentational + event-emitting.

---

## 5. Implementation phases

Each phase is a separate commit and ends with either a testable artifact or pure scaffolding.

| # | Phase | Testable? |
|---|---|---|
| 1 | Foundations: `@radix-ui/react-context-menu` install, `ui/context-menu.tsx`, `FileIcon`, `useKeyboardShortcuts`, `sessionSync.ts`, `ShortcutsDialog` | No |
| 2 | New `DriveSidebar` replaces old Sidebar | **Yes** — sidebar layout |
| 3 | New `DriveTopBar` (search, Upload, "+ New" with Folder/Note.md, ?) | **Yes** — create folder + create new note via "+ New" |
| 4 | `FoldersGrid` + `FilesTable` with `FileIcon` + section headers + sort | **Yes** — visual redesign of main area |
| 5 | Right-click context menus (folder, file, empty space) | **Yes** — right-click everywhere |
| 6 | Keyboard shortcuts wired (U/N/Esc/⌘A//Del/?) | **Yes** — all shortcuts |
| 7 | `/file/:cid/:fid` route + new-tab opening + `BroadcastChannel` session sync + `?next=` login redirect | **Yes** — files open in new tab; close primary tab → editor still works |
| 8 | Final `Drive.tsx` cleanup (remove dead code: modal overlay, FAB) — by this point the file should already be ~150 lines from incremental moves | No |

After every testable phase, the assistant says **"You can test this feature: <description>"** and pauses for the user to verify in the browser before continuing.

---

## 6. Risks & mitigations

| Risk | Mitigation |
|---|---|
| BroadcastChannel handshake races on slow systems → false-positive login redirect | 500 ms timeout is generous; same-origin BroadcastChannel typically resolves <50 ms |
| `?next=` open-redirect vector | Validate `next` is a same-origin pathname starting with `/`; reject anything else |
| `window.open` blocked by popup blockers when not initiated by user gesture | All new-tab opens are inside click handlers — user gesture always present |
| File-level rename/share don't exist server-side → menu items are dead | Hide those items in v1 menus (note in §3.4) |
| Drive.tsx refactor breaks an existing flow | Each phase keeps the data layer in Drive.tsx and only swaps the view layer; full e2e regression-test at the end of phase 7 |
| Trash key (Del) without trash backend = irreversible | Show confirm dialog, identical to current delete; mention "(no trash yet)" in `ShortcutsDialog` |

---

## 7. Verification (end of phase 7)

1. `pnpm build` and `pnpm tsc --noEmit` clean.
2. Manual walk in `https://localhost:38443`:
   - Sidebar nav: My Files, Shared with me, Settings, Sign out, theme toggle, storage bar.
   - Top bar: search filters, Upload, + New → Folder + Note.md, ? opens shortcuts.
   - Main: folders as color cards, files as typed table, sort by all 3 columns.
   - Right-click on folder, file, empty space — all three menus.
   - Keyboard: U N / Esc Del ⌘A ?.
   - Click `test.md` → opens in **new tab**, can edit, Y.Text sync still works (open same file from a 3rd tab to verify multi-user).
   - Close the originating Drive tab → editor tab still works (session was already shared on its boot).
   - Open editor URL directly without a logged-in session → redirected to `/login?next=...`, after login lands back on the editor.
3. No regressions in: federated shares, public links, batch delete, drag-and-drop upload, color folders, share dialog, recovery phrase flow.
