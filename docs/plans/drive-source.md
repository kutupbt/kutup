# Drive screens over a `DriveSource` — plan

**Status:** draft for review (PR 1 of 4). Nothing changes for Kutup's users;
nothing uses the new package yet. The Kutup Home drive (`kutup-home-drive`,
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

## This PR (draft): the interface

`packages/drive-source/src/source.ts` has the proposal. Its key decision:

- **The screens work with views, not with drive-core's types.** `Folder` and
  `DriveFile` carry keys, epochs, sealed metadata, envelopes and revisions,
  which a plain source does not have. The screens get `FolderView` and
  `FileView` (id, name, size, kind, rights, times, media details, origin).
  Kutup's `Folder` and `DriveFile` keep everything they have and satisfy the
  views; Kutup's implementation receives its own objects back and narrows
  them, so nothing is looked up twice.
- **Operations by view**, each invalidating what it changed, as drive-core's
  mutations do today.
- **Capabilities** instead of branches on the source: identity pins,
  federation, folder colours, upload links, server-made thumbnails.
- **`UploadEngine`** wraps `streamUpload`, `uploadFolder` and `pendingUploads`
  for Kutup; the screens see an `UploadHandle` (progress, pause, resume,
  cancel, done) and the uploads that come back after a reload.

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

Steps inside PR 1, each with Kutup's unit tests and the Drive browser suite
green: (a) this interface; (b) Kutup's implementation in `drive-core`,
wrapping today's code without changing it; (c) the screens switched to
`useDriveSource()`, one feature folder at a time; (d) the moved code deleted
from `apps/drive`.

## Questions for review

1. **Views over drive-core's types** (above): agreed, or should the screens
   keep `Folder`/`DriveFile` with the encrypted fields optional?
2. **Hooks on the source** (`useFolders`, `useFolderFiles`, `useTrash`) rather
   than plain async functions the screens wrap in React Query themselves:
   the source then owns its query keys and invalidation, as drive-core does now.
3. **Sharing and search** are not in this draft yet: the access list and the
   share dialog differ the most (federation, identity pins, invites). Proposal:
   a `sharing` part with a small common core (people and groups, rights,
   links) and Kutup's extras behind `federation` and `identityPins`.
4. **Packaging for the other app:** the home drive includes Kutup as a git
   submodule pinned to a commit, in one pnpm workspace with
   `frontend/packages/*`, mirroring the root `pnpm.overrides` and
   `patchedDependencies` (with a check that fails when they drift). Kutup
   publishes nothing and changes nothing for it. Is that acceptable, or do you
   prefer published packages?
