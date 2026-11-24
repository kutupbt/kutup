# Drive: Proton Drive parity

**Status:** the gap list, 2026-11-18. Proton Drive's web client is the
reference for Kutup Drive, as Proton Mail is for Mail
([`mail-parity.md`](mail-parity.md)). This lists its features, where Kutup
Drive stands, and the order to close the gaps. Each slice gets its own plan
before it is built; keep this list current as they land. Photos, which Proton
keeps inside Drive, has its own list: [`photos-parity.md`](photos-parity.md).

Read from `WebClients` (2026-11-18): `applications/drive/src/app` (the
SDK-based `sections/`, `modals/`, `modules/` and the `legacy/` tree), the
shared `packages/drive` and `packages/drive-store`, the file previews in
`packages/components/containers/filePreview`, and Drive's settings in
`packages/components/containers/drive/settings`. Paths in the Proton column
are under `applications/drive/src/app/` unless they start with `packages/`.

Kutup read from the code on `wipe/api-pass` (eb93ce2d), not from the plans:
`frontend/apps/drive`, `frontend/packages/{drive-core,drive-ui,files,editors}`,
the handlers in `crates/kutup-server` and the `kutup` CLI. Kutup paths are
under `frontend/apps/drive/src/features/` unless said otherwise.

**Key:** ✅ works end to end in the website · 🟡 partial (what is missing is
said) · ❌ missing · ➖ not for Kutup, or comes with another app. **Schema**
marks a gap whose fix changes the database (a column, a table, a CHECK
list); **format** marks one that changes an encrypted record but no table.
Both are cheapest before the wipe.

## Browsing and listing

| Feature | Proton | Kutup |
|---|---|---|
| List and grid, virtualised | `statelessComponents/DriveExplorer/DriveExplorer.tsx` | ✅ `explorer/Explorer.tsx`; default view in Settings (per browser; Proton keeps `Layout` in synced user settings) |
| Sort | `modules/sorting/` (name, modified, size) | ✅ name, modified, size, type, folders first (`explorer/sort.ts`); per browser, not synced |
| Type filter | (none) | ✅ Kutup's: show only folders, documents, images… |
| Columns: name, modified, size, location, sharing | `sections/commonDriveExplorerCells/` | 🟡 name, modified, size, shared mark; location only in search results |
| Breadcrumbs, drop on a crumb to move | `sections/folders/FolderViewBreadcrumbs/` | ✅ |
| Folder tree in the sidebar | `sections/sidebar/DriveSidebarFolders/` | ❌ My files, Shared with me, Shared by me, Trash, Settings |
| Multi-select: Ctrl, Shift, arrows, marquee | `useArrowKeyNavigation.ts`, `modules/selection/` | ✅ plus marquee (`explorer/useMarquee.ts`), Home/End, Escape |
| Drag to move between folders | `modules/selection/useDriveDragMove.ts` | ✅ (`explorer/dragItems.ts`, `drive/useMove.ts`) |
| Context menu and toolbar | `sections/folders/menus/FolderItemContextMenu.tsx`, `FolderToolbar.tsx` | ✅ `explorer/ExplorerContextMenu.tsx`, `explorer/Toolbar.tsx` |
| New folder, rename, move, copy | `packages/drive/modals/{createFolderModal,moveItemsModal,copyItemsModal}/`, `modals/RenameModal/` | ✅ copy also across owners and servers (`drive/copy.ts`) |
| New document, sheet | `sections/folders/buttons/CreateNewDocumentButton.tsx`, `CreateNewSheetButton.tsx` | ✅ note, document, spreadsheet, presentation, whiteboard, map, password vault (`create/NewMenu.tsx`) |
| Create a blank file of any name | `modals/CreateFileModal/CreateFileModalView.tsx` | ❌ |
| Details: size, type, dates, created by, last uploaded by (signature check), downloads of a shared item | `modals/DetailsModal/FileDetailsModalView.tsx`, `FilesDetailsModal/` | 🟡 a file's or folder's menu → Details (`details/DetailsDialog.tsx`), in folders and search results: name, location, created by, last uploaded by, uploaded, modified, type and media type, size (stored, encrypted) and original size, versions, sharing (owner: people and public links), your access to someone else's folder; the signature on the current content checked against the identity pins (only its manifest is read), as Proton's banner; advanced: exact bytes, the upload's SHA-256 while it still describes the content, the id. Several items: their number and the files' size. No download count (gap 15); notes show no original size (their metadata keeps the upload's) and no signature banner (their saved state is checked as the editor opens it) |
| Signature mark on items | `statelessComponents/SignatureIcon.tsx` | 🟡 warnings, not a mark per item |
| Folder colours | (none) | ✅ Kutup's (`dialogs/ColorDialog.tsx`, also `kutup color`) |
| Keyboard shortcuts | arrows and selection only | ✅ arrows, Enter, Space for Quick look, Escape |
| Recent, Starred | (none) | ❌ neither has them; Starred would be **format** (an account record, as Photos' favourites) |
| AI assistant (Lumo) | `lumo/` | ➖ |
| Onboarding, app download prompts | `modals/DriveOnboardingModal/` | ❌ |

## Upload and download

| Feature | Proton | Kutup |
|---|---|---|
| Upload files and folders, drop anywhere | `packages/drive/modules/upload/UploadManager.ts`, `utils/processDroppedItems.ts` | ✅ files, folders (`uploads/folderUpload.ts`), drops on the folder and on crumbs |
| Name conflicts: replace, keep both, skip, for all | `packages/drive/modules/upload/orchestration/ConflictManager.ts`, `modals/UploadConflictModal/` | ✅ `drive-ui/NameConflictDialog.tsx`; Replace makes a new version |
| Transfer manager with cancel, retry | `sections/transferManager/TransferManager.tsx` | ✅ `drive-ui/UploadPanel.tsx`: cancel one or all |
| Resume uploads after a reload or crash | (none: no resumable uploads across sessions) | ✅ tus, `drive-ui/InterruptedUploads.tsx` |
| Pause and resume by hand | (server-driven pause only) | ❌ neither |
| Empty-file confirmation | `sections/transferManager/connectedComponents/EmptyFileConfirmModal.tsx` | ❌ |
| Download progress in the transfer manager | `modules/download/DownloadManager.ts` | 🟡 ZIP progress in a toast; single files stream without a list |
| Folders and selections as ZIP | `modules/download/ArchiveStreamGenerator.ts` | 🟡 ZIP over 1 GB only in Chrome or Edge (`files/src/zipDownload.ts`) |
| Large files in every browser | `modules/fileSaver/fileSaver.ts` (memory, OPFS or a service worker stream) | 🟡 File System Access in Chrome and Edge; Firefox and Safari buffer in memory and refuse large files (`drive.fileTooLargeForBrowser`). A service worker stream would close it |
| Signature or integrity problem on download: cancel or continue | `modals/SignatureIssueModal/SignatureIssueModal.tsx` | ✅ blocks are verified against the signed manifest; a bad block stops the download |
| Malware scan on download | `modules/download/malwareDetection/malwareDetection.ts` | ❌ (it would send file hashes to a service: decide first) |
| Import from Google Drive (Easy Switch) | `sections/sidebar/EasySwitchSidebarSection.tsx` | ❌ |
| Limits as site settings | plan-driven | ✅ upload and stream limits come from the server (`files/src/stream/limits.ts`) |

## Sharing and links

| Feature | Proton | Kutup |
|---|---|---|
| Share a folder with people: viewer or editor | `packages/drive/modals/sharingModal/internal/SharingModalView.tsx`, `DirectSharing/` | ✅ `dialogs/ShareDialog.tsx`, `dialogs/AccessList.tsx`: view, add and edit, delete own files, an upload limit; people on other servers by invite link |
| Share one file: viewer or editor, editors may share | `SharingSettingsModal.tsx`, `useEditorsManageAccess.tsx` | ✅ `drive-ui/FileShareDialog.tsx`, incl. "editors can share" |
| Change a role, remove someone (folder moves to a new key) | `DirectSharing/DirectSharingMemberMenu.tsx` | ✅ |
| Invitation message, name in the mail | `DirectSharing/DirectSharingInviteMessage.tsx` | ❌ no message, no notice: a share appears silently (Mail could send it; or a web push) |
| Accept or decline an invitation | `sections/sharedWith/buttons/AcceptButton.tsx`, `DeclineButton.tsx` | 🟡 other servers through an invite link (`shared/AcceptInviteDialog.tsx`); on this server shares appear at once with Leave, no decline step (**schema**: an accepted state on `drive_collection_shares`, `drive_file_shares`) |
| Invite people without an account by email | `nonProtonInvitations` in the sharing modal | ❌ (public links instead; a signup-bound invite needs **schema**) |
| Shared with me, Shared by me, stop sharing | `sections/sharedWith/SharedWithMeView.tsx`, `sections/sharedby/SharedByMeView.tsx` | ✅ `shared/SharedPage.tsx`, `shared/SharedByMePage.tsx` |
| Public link to a folder | `PublicSharing/PublicSharing.tsx` | 🟡 files directly in the folder only, not subfolders (`public/PublicSharePage.tsx`); several links; report link; admin block and site/account switch |
| Public link to a file | same | ✅ in the file's share dialog; documents open read-only in Office (`editors/PublicFileRoute.tsx`) |
| Link password | `PublicLinkSettingsModal.tsx`, `publicPage/PublicPagePassword.tsx` | ✅ link settings dialog and password page ([`drive-link-password.md`](drive-link-password.md)); CLI flags on the roadmap |
| Link expiry | `PublicLinkSettingsModal.tsx` | ✅ the link settings dialog (end of a chosen day, at most the site's `drive.public_link_max_expiry_days` ahead) |
| Link with edit rights, uploads through a link | `PublicRoleDropdownMenu.tsx`, `publicPage/PublicFolderView.tsx` (anonymous signatures) | ❌ (**schema**: a role on the link, owner-charged anonymous uploads) |
| Save a public link to your own Drive (bookmark) | `sections/publicPage/BookmarkButton.tsx`, `sharedWith/buttons/OpenBookmarkButton.tsx` | ❌ (**schema** or an account record: the link key must be kept sealed) |
| Pick a file to share from a dialog | `modals/SelectLinkToShareModal/` | ❌ |
| Download count for links | details modal | ❌ (**schema**: a counter) |
| Report a link | `modals/ReportAbuseModal/` | ✅ `drive-ui/ReportLinkDialog.tsx` |
| Copying from and to other servers | (none) | ✅ Kutup's federation |

## Versions

| Feature | Proton | Kutup |
|---|---|---|
| Version list for any file: preview, restore, download, delete, details | `modals/RevisionsModal/RevisionsModalView.tsx`, `revisions/ContextMenuButtons/` | ✅ Drive → a file's menu → Version history (`features/versions/VersionHistoryDialog.tsx`, `editors/src/history.ts`): current version, then earlier ones by day, week, month and year (Proton's grouping), with who saved each and its size; preview in Quick Look, download, restore (sealed again as the newest version, the rest kept), keep forever, delete (the owner, or whoever saved it), and the owner's retention with a link to change it. Notes, code files and place lists list their saved states and are restored in their editor (`VersionHistoryPanel.tsx`), which merges into the live document. No details dialog per version |
| Retention setting | `packages/components/containers/drive/settings/RetentionDaysSection.tsx` | ✅ Drive → Settings: 1 week to 10 years (`settings/DriveSettingsPage.tsx`, `version_retention.rs`); Proton also offers "don't keep" |

## Trash

| Feature | Proton | Kutup |
|---|---|---|
| Restore, delete forever, empty | `sections/trash/TrashView/TrashView.tsx` | ✅ `trash/TrashPage.tsx`; Undo after Move to trash |
| Automatic purge | (none: items stay until deleted) | 🟡 the server sweeps after `trash_retention_days` from the environment (`jobs.rs`); not an admin setting yet (roadmap, "trash-retention settings"), and items do not say when they go |

## Search

| Feature | Proton | Kutup |
|---|---|---|
| Name search on the device | `modules/search/internal/` (SharedWorker, WASM, encrypted IndexedDB index, 50,000 entries, opt in) | 🟡 names decrypted in the browser and matched there (`search/SearchPage.tsx`, `editors/src/search.ts`), accents and Turkish i folded; rebuilt per visit, no stored index |
| Filters: type, date, shared, author | index entry fields (no filter UI) | ✅ the toolbar's type, and on the results: modified (today, 7 days, 30 days, 12 months), location (My files, Shared with me), created by (me, others), shared by me; kept in the URL (`search/FilterBar.tsx`, `search/filters.ts`) |
| Content search | (none) | ❌ neither |

## Previews and players

| Feature | Proton | Kutup |
|---|---|---|
| Preview with previous and next | `modals/preview/Preview.tsx` | ✅ Quick look on Space (`quicklook/QuickLook.tsx`), ← and → |
| Images, HEIC, RAW, SVG | `filePreview/ImagePreview.tsx`, `packages/raw-images` | 🟡 images and SVG; RAW as its large thumbnail; HEIC only where the browser draws it (Safari), elsewhere "cannot be shown" although Photos converts it (libheif); no zoom |
| Video and audio, streamed | `VideoStreamingPreview.tsx`, `modals/preview/mseStreaming.ts` | ✅ ranged playback (`drive-core/playback.ts`), a cap on streams per tab |
| PDF | `filePreview` | ✅ |
| Text and code, edit and save from the preview | `TextPreview.tsx` | ✅ preview; editing in the note and code editor |
| Word, Excel previews | `SandboxedPreview.tsx`, `ExcelPreview.tsx` | ✅ opened in Office (ONLYOFFICE in the browser); the preview shows the large thumbnail |
| Comic books, STL, DOOM WADs | `ComicBookPreview.tsx`, `3DPreview/STLPreview.tsx`, `IWADPreview.tsx` | ➖ |
| Thumbnails: image, SVG, HEIC, RAW, video, CBZ | `packages/drive/modules/thumbnails/generator/handlers/` | ✅ plus PDF, Office, text pages and audio waveforms (`files/src/mediaPreview`) |
| Encrypted thumbnail cache | `thumbnails/encryptedThumbnailCache/` | ✅ `files/src/mediaCache` |

## Offline and sync

| Feature | Proton | Kutup |
|---|---|---|
| Live updates when others change a folder | `packages/drive/modules/busDriver/internal/BusDriver.ts`, `sections/folders/subscribeToFolderEvents.ts` | ❌ lists refresh on navigation (30 s stale time, no refetch on focus). The server's change feed (`change_feed.rs`) serves Mail only so far; Drive tables would need its trigger and tombstones (**schema**) |
| Offline files | (none) | ❌ neither; the browser-storage plan ([`../research/16-browser-storage-architecture.md`](../research/16-browser-storage-architecture.md)) |
| Diagnostics, system log export | `legacy/components/drawer/DriveQuickSettings.tsx`, `modals/DiagnosticsModal/` | ❌ |

## Devices and computers

| Feature | Proton | Kutup |
|---|---|---|
| Computers: synced folders of desktop clients, rename, remove | `sections/devices/DevicesView.tsx`, `modals/RenameDeviceModal/`, `RemoveDeviceModal/` | ❌ `kutup sync` syncs any folder, but the website does not know which folders a computer syncs (**schema**: a sync-root table or a `kind` on `drive_collections`, whose CHECK allows `folder`, `album`) |
| Device list of the account | (account app) | ✅ Account app and `kutup devices` (Chat, editors, CLI) |

## Settings

| Feature | Proton | Kutup |
|---|---|---|
| Version retention | `RetentionDaysSection.tsx` | ✅ |
| Layout and sort synced across devices | `packages/shared/lib/interfaces/drive/userSettings.ts` | 🟡 per browser (`explorer/prefs.ts`); `account_ui_preferences` exists for synced ones |
| Storage meter | `legacy/components/layout/sidebar/SidebarStorageUpsell.tsx` | ✅ `drive-ui/StorageMeter.tsx`; usage by app in Account |
| Key recovery, locked volumes | `legacy/components/modals/FilesRecoveryModal/`, `ResolveLockedVolumes/` | ➖ Kutup's account keys and recovery phrase cover it |

## Desktop and mobile clients

| Feature | Proton | Kutup |
|---|---|---|
| Desktop sync app (Windows, macOS) | `utils/appPlatforms.tsx`, `modals/DownloadAppModal/` | 🟡 the `kutup` CLI (Linux, macOS, Windows): `upload`, `download`, `sync --watch` with three-way merge, `share`, `versions`, `trash`; no tray app, no placeholders |
| Mobile apps (iOS, Android) with photo backup | onboarding `MobileAppStep.tsx` | ❌ deferred; one app per product ([`../mobile-build.md`](../mobile-build.md)) |
| Mobile web | responsive | 🟡 responsive shell; the mobile selection mode is on the roadmap |

## Gaps in priority order

What people hit first, with whether the fix needs the server or the schema:

1. ~~**Link password and expiry in the dialogs**~~ — built once for Drive,
   Office and Photos links ([`drive-link-password.md`](drive-link-password.md)).
2. **Public folder links with subfolders:** server (walk the tree under the
   link, keys of subfolders sealed to the link) and probably **schema**
   (link keys per subfolder, or a link-to-epoch table).
3. ~~**Version history for every file**~~ in Drive (open, restore,
   download, delete one): built (`features/versions/VersionHistoryDialog.tsx`).
4. **Large downloads in Firefox and Safari:** a service worker stream, as
   Proton's. Client only.
5. ~~**Details dialog**~~ (size, type, dates, uploader, signer, location,
   shares): built (`features/details/DetailsDialog.tsx`).
6. **Live updates** while a folder is open: **schema** (Drive tables into
   the change feed: triggers, tombstones) and a client subscription.
7. **Invitations: a notice when something is shared, accept or decline:**
   **schema** (an accepted state on the share tables) plus a notice (web
   push or mail).
8. ~~**Search filters**~~ (type, date, location, creator, shared): built
   (`features/search/FilterBar.tsx`). Still open: a stored encrypted index
   for large Drives (client only).
9. **Folder tree in the sidebar:** client only.
10. **Bookmarks** (save a public link to Shared with me): an account record
    (**format**), or a table if the server must list them (**schema**).
11. **Editable links and uploads through a link:** **schema** (link role,
    anonymous uploads charged to the owner, limits as site settings) and a
    server upload path for links.
12. **Computers section** for `kutup sync` roots: **schema** (sync roots per
    device, or a collection kind; the `drive_collections` kind CHECK).
13. **Trash retention as an admin setting** and "deleted in N days" on
    items: site setting, no schema.
14. **Synced layout and sort:** `account_ui_preferences`, no schema.
15. **Download count for links:** **schema** (a counter column).
16. Invite people without an account, Google import, malware scan, a
    desktop sync app, native apps: later, each with its own plan.

**Schema before the wipe:** items 1, 2, 6, 7, 11, 12, 15 (and 10 if the
server lists bookmarks). Items 1, 2 and 11 all touch `drive_public_shares`:
design them together so the table changes once.
