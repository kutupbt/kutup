# Drive screens over a `DriveSource` — plan

**Status:** PR 1 converted (2026-11-26): the Drive screens in
`apps/drive/src/features` read their data only through `@kutup/drive-source`
(a lint rule keeps them off drive-core); Kutup's implementation is in
`apps/drive/src/source`. Nothing changes for Kutup's users. Left for PR 2:
the app shell (`App.tsx`, `app/`: session, people, the boot), which is
`SessionSource`'s, and Kutup's public link pages (`apps/drive/src/public`,
outside the screens). The Kutup Home drive (`kutup-home-drive`,
plain files in plain folders, no end-to-end encryption) is the second
implementation this enables; its server is built and waiting for the screens.

**Rule for every PR of this series:** Kutup looks and behaves exactly as
before, Kutup's build never contains a plain implementation, and no PR
contains anything that only the home drive needs.

## The series

1. **`DriveSource` with Kutup's encrypted implementation.** The screens in
   `apps/drive/src/features/` read their data only through
   `@kutup/drive-source`; Kutup's implementation lives in `drive-core`.
2. **The screens move** into a shared package (`@kutup/drive-screens`, name to
   agree), together with a `SessionSource` (who is signed in, preferences,
   sign-out, feedback, the app list, the account header state; Kutup's
   hand-over between apps, `fork` and `childBoot`, stays in Kutup's).
3. **`CollabCrypto` and `DocumentStore`** in the editors (frames, the sender
   check and devices; loading and saving a document, versions, thumbnails).
4. **A PMTiles provider type** in `@kutup/map` and its config.

## This PR: the interface

`packages/drive-source/src/source.ts`. Decided in review:

- **Views, not drive-core's types.** The screens get `FolderView` and
  `FileView`. Kutup's `Folder` and `DriveFile` keep all their fields and
  satisfy the views; Kutup's implementation receives its own objects back and
  narrows them. `FileView` carries the current **revision id** (the base a
  version save or an editor's save names, shown in the details panel).
- **A file's kind is not the source's.** Both apps derive it the same way
  from name and type (`drive-core/kinds`, `editorKind`), so "open in Office"
  is decided alike.
- **Hooks on the source** (`useFolders`, `useFolderFiles`, `useTrash`,
  `useSharedWithMe`, `useSharedByMe`). **Kutup's implementation keeps
  drive-core's query keys exactly**: the editors, Calendar's attachments and
  the upload commit invalidate Drive's lists by those keys.
- **Capabilities instead of branches**, one per Kutup feature another source
  may not have: identity pins, federation, leaving remote shares, invites,
  roles, "editors can share", file links, link passwords, upload links, folder
  colours, thumbnails made by the source.
- **Sharing** is a small common core (shares with people and groups, links)
  with Kutup's extras as optional, flagged operations.
- **Operations** the screens use, all on the interface: folder move and copy
  (Kutup's recursive `copy.ts` and `move.ts` move into its implementation),
  folder colour, empty trash, the shared lists, search (Kutup searches in the
  browser over its decrypted index; another source on its server), the names
  in a folder for the conflict dialog, a new version from a base revision
  (`replaceContent`), downloads by the source's own rules (Kutup's large-file
  handling, File System Access) and a folder as a ZIP, reading for viewers,
  previews, versions.
- **Uploads** report changes (`subscribe`), not only a polled state.
- **Thumbnails:** the screens never draw one. With `serverThumbnails`, the
  source makes them: Kutup's upload engine draws and seals them in the browser
  after an upload (`thumbnailQueue`) inside its implementation; a server source
  makes them on the server. The screens only call `preview`.

**Packaging for the other app** (agreed): the home drive includes Kutup as a
git submodule pinned to a commit, in one pnpm workspace with
`frontend/packages/*`. Kutup's packages stay private and unpublished, and
Kutup promises **no API stability**: the home repository fixes its side when
it moves the pin. Kutup's CI never builds the home edition.

## Where the screens touch encryption today

Measured at `622a2eb8` (`apps/drive/src`, 7,232 lines). These move behind the
interface, into Kutup's implementation in `drive-core`:

| Screen code | What it does with keys or sealed data | Goes to |
|---|---|---|
| `features/uploads/upload.ts` | seals a new file: file key, envelope under the folder key, content hash, metadata, commit | `UploadEngine.upload` |
| `features/uploads/replace.ts` | replaces content: re-keys below the folder epoch, keeps original/state revisions | `UploadEngine.upload` with `version` |
| `features/uploads/folderUpload.ts`, `useUploadActions.ts` | folder uploads, pending uploads, names under the folder key | `UploadEngine` |
| `features/drive/copy.ts` | re-seals a file (and embedded assets) under the target folder | `copyFile` |
| `features/drive/move.ts`, `useMove.ts` | re-keys on move, name conflicts | `moveFile` |
| `features/thumbnails/FileThumbnail.tsx`, `schedule.ts` | opens sealed thumbnails, draws and seals missing ones | `preview` (and Kutup's drawing stays inside its implementation) |
| `features/folder/FolderPage.tsx` | folder key for listings, downloads, public links | the hooks, `download` |
| `features/details/DetailsDialog.tsx`, `versions/VersionHistoryDialog.tsx` | content commitments, signers, revision authors | `versions`, plus Kutup-only details behind `identityPins` |
| `features/quicklook/QuickLook.tsx`, `public/*` | content keys for viewing and playback | `download`, `preview` |
| `features/shared/SharedPage.tsx`, `dialogs/AccessList.tsx`, `ShareDialog.tsx` | remote shares, identity pins, access | sharing (in this PR's next step), `federation` and `identityPins` capabilities |
| `features/search/*` | the encrypted search index | a `search` operation (next step) |

Steps inside PR 1, each keeping Kutup's unit tests green; the Drive browser
suite runs on Kutup's even-numbered nights, so the steps are batched for one
night to cover several:

1. **Kutup's implementation** (`apps/drive/src/source/kutupSource.ts`):
   drive-core's own hooks, unchanged, with a unit test that they are drive-core's
   (so every query key and invalidation stays). It lives in the app, not in
   `drive-core`: the upload, copy and move code it will need is in the app
   today, and after PR 2 the app is exactly "Kutup's screens + Kutup's source".
   **Done** for the lists (folders, a folder's files, trash) and the folder,
   file and trash changes; the trash page reads through it.
2. **Lists and simple changes**: the explorer, folder page, shared pages and
   dialogs read through `useDriveSource()`. **Done.**
3. **Content**: uploads, replace, copy, move, downloads, quick look, versions,
   thumbnails, details. **Done** (3a–3e).
4. **Sharing and search**, then the remaining direct imports removed (a lint
   rule keeps `apps/drive/src/features` off drive-core's internals). **Done**
   (4a–4f): the sharing dialogs as slots, search over the source's index, the
   shared pages, the folder picker; the pure helpers both apps decide alike
   (`kinds`, `editorKind`, `names`, `documents`, `tree`, the restore errors)
   live in `@kutup/drive-source`, re-exported by drive-core.

**Sharing (decided on #458, 2026-11-26).** The source *supplies* the sharing
dialogs as components; the common core is data. Kutup's share dialogs stay
exactly as they are and where their security reviews left them: identity pins,
the key-rotation review and federation live inside them, and they keep reading
drive-core and the pins themselves. The slots are narrow (the screens pass only
what they show):

| Slot | Props | Kutup supplies |
|---|---|---|
| `ShareDialog` | `{ target: ItemRef \| null, open, onOpenChange }` | `ShareDialog` (with `AccessList`) for a folder, `FileShareDialog` for a file (as its owner, or as an editor of a file shared with them), and the federated invite shown after |
| `usePublicLink()` → `{ create(target), dialog }` | none: the screen calls `create` from the menu item and renders `dialog` | the public link made with `useCreatePublicLink` on that click and shown once |
| `AcceptInviteDialog` | `{ open, onOpenChange }` (capability `invites`; null without) | `AcceptInviteDialog` |
| `DetailsBanner` | `{ folder, file }` (null for none) | the content signature check |

The shared lists and the details use only the common data (shares, people,
rights, links, capability flags) and `mayShare` / `mayLink`; no Kutup-only
field reaches them: an identity or federation state stays behind its
capability and in the slot components. The home edition supplies simpler
dialogs of its own.

A public link is the one sharing action that writes on the server as it
starts, so it is not a dialog slot. The first conversion made it one, and it
made its link in an effect when it opened; the screen passes a new target on
every render, so each render made another link (Drive suite, 226 and 228, on
`fea6dfe`). The link is made on the person's click again, as on master, and
nothing on the source's path writes in an effect.

**How the interface grows.** `source.ts` holds what is implemented and used,
nothing more (no stubs); each step adds its part. The whole target, as
reviewed, is `packages/drive-source/src/source.ts` at `afbd1d9`. Two
refinements made while implementing:

- **The views use Kutup's own field names** (`source`, `collectionId`,
  `content.revisionId`, `MediaMetadataV1`'s names), so Kutup's `Folder`,
  `DriveFile` and `TrashEntry` *are* the views: nothing is copied, the screens'
  memoisation sees the same objects, and Kutup's source is drive-core's hooks.
  The folder list is a `FolderTree` (drive-core's `FolderIndex` shape: root,
  children, shared with me).
- **Changes are mutation hooks**, as in drive-core (`useRenameFile()` with
  `mutate`, `isPending`, `error`), not bare promises: the screens keep their
  pending and error states, and Kutup's invalidation stays drive-core's.
- **`kinds.ts` and the restore errors** moved into `@kutup/drive-source`
  (drive-core re-exports them unchanged), so every source decides a file's kind
  and reports a cancelled restore the same way, without a package cycle.

## Review

Questions 1–4 of the first draft were answered on #458 (2026-11-26); the
answers are folded in above.
