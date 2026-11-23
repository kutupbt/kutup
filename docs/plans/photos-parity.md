# Photos: Ente Photos parity

**Status:** the gap list, 2026-11-18. Ente Photos is the reference for
what an end-to-end encrypted photo library does (as decided for Photos in
[`photos.md`](photos.md) and the roadmap); Proton Drive's Photos section is
the second reference, where it differs. This lists their features, where
Kutup Photos stands, and the order to close the gaps. Each slice gets its own
plan before it is built; keep this list current as they land.

Read from `kutup-references/ente` (2026-11-18): the web app in
`web/apps/photos`, its packages `web/packages/{new/photos,gallery,media}`,
the public album site `web/apps/albums`, the desktop app `desktop/` and the
mobile app `mobile/apps/photos` (for the clients section only). Proton from
`WebClients/applications/drive/src/app/photos`. Paths in the Ente column are
under `web/` unless they start with `desktop/` or `mobile/`; Proton paths
are under `applications/drive/src/app/photos/`.

Kutup read from the code on `wipe/api-pass` (eb93ce2d), not from the plans:
`frontend/apps/photos`, the Drive packages it uses
(`frontend/packages/{drive-core,files,drive-ui}`), `crates/kutup-server`
and `crates/kutup-cli`. Kutup's photos are Drive files (photos.md, "Photos
are Drive files"): the library is the upload folder plus the folders you add,
so trash, sharing of single photos and storage are Drive's.

**Key:** ✅ works end to end in the website · 🟡 partial (what is missing is
said) · ❌ missing · ➖ not for Kutup, or comes with another app. **Schema**
marks a gap whose fix changes the database (a column, a table, a CHECK
list); **format** marks one that changes an encrypted record's contents but
no table. Both are cheapest before the wipe.

## Timeline

| Feature | Ente (Proton) | Kutup |
|---|---|---|
| Date-grouped grid, virtualised | `apps/photos/src/components/FileList.tsx` | ✅ days under months, virtualised (`timeline/PhotoGrid.tsx`) |
| Fast scroll bar with month labels | none in Ente web; Proton `PhotosWithAlbums/FastScrollBar.tsx` | ✅ `timeline/Scrubber.tsx`, "Jump to a month" |
| Grid size / zoom levels | automatic columns (`new/photos/components/utils/thumbnail-grid-layout.ts`); pinch zoom on mobile | 🟡 automatic columns from the width, smaller tiles on narrow screens; no zoom control |
| Select, select a day, Shift range | `FileList.tsx` (`handleRangeSelect`) | ✅ tile check, "Select all of {day}", Shift-click |
| Right-click menu on a photo | `apps/photos/src/components/FileContextMenu.tsx` | ❌ actions only in the selection bar |
| Favourites | special collection (`media/collection.ts`), shareable | ✅ account-private marks (`library/marks.ts`, the photos-library record), also for photos shared with you; not shareable as an album |
| Archive | `Sidebar.tsx` shortcut | ✅ Archive page; archived photos leave the timeline and Places |
| Hidden, behind re-authentication | `Sidebar.tsx`; hidden view asks to re-authenticate | 🟡 Hidden page; no lock on it (photos.md open question: "not in these slices") |
| Type filters (videos, live photos, screenshots, RAW, selfies, panoramas…) | Ente: fileType search; Proton `PhotosWithAlbums/components/Tags.tsx` (`PhotoTag`) | ❌ no filter; the media record has no tag field (**format**: a `tags` list in `MediaMetadataV1`, set on upload like Proton's) |
| Duplicates finder | `apps/photos/src/pages/duplicates.tsx`, `services/dedup.ts` | ❌ upload skips exact duplicates (below), nothing finds those already there |
| Large files, "free up space" | `apps/photos/src/pages/large-files.tsx` | ❌ (Account's storage page shows usage by app) |
| Memories, "on this day" | mobile only (`mobile/apps/photos/lib/services/smart_memories_service.dart`) | ❌ |
| Empty state with upload | `components/gallery/GalleryEmptyState.tsx` | ✅ upload, drop, "Choose folders" |

## Upload and download

| Feature | Ente (Proton) | Kutup |
|---|---|---|
| Drop anywhere, upload files | `gallery/components/FullScreenDropZone.tsx`, `apps/photos/src/components/Upload.tsx` | ✅ files and drops; non-media left out with a note |
| Upload a folder, folder → album mapping | `CollectionMappingChoice.tsx` | 🟡 a folder can be uploaded in Drive and added to the library in Settings; no folder upload in Photos, no "one album per folder" |
| Upload straight into an album | `CollectionSelector.tsx` | ❌ upload goes to the upload folder; add to an album after |
| Skip duplicates on upload | `gallery/services/upload/upload-service.ts` (`areFilesSame`) | ✅ name + SHA-256 against the library (`upload/useUploadPhotos.ts`); Ente adds the existing file to the target album instead |
| Live photos (still + video pair) | `media/live-photo.ts` | ✅ paired on upload (`liveOf`), played in the viewer |
| HEIC, RAW, video thumbnails | `media/formats.ts`, `heic-convert.ts`, `gallery/services/ffmpeg/` | ✅ HEIC (libheif), RAW previews, video frames (`files/src/mediaPreview`, `files/src/media/raw.ts`) |
| Background read of older photos' details | (on upload only) | ✅ `library/catchUp.ts` fills date, place, hash, thumbnails for files uploaded elsewhere |
| Resumable uploads after a reload | upload progress UI | ✅ Drive's tus uploads, `InterruptedUploads` |
| Google Takeout import (sidecar JSON dates, places) | `TakeoutOptions.tsx`, `gallery/services/upload/metadata-json.ts` | ❌ |
| Download one, a selection, an album as ZIP | `apps/photos/src/services/save.ts`, `gallery/services/save-core.ts` | 🟡 one or a selection as ZIP; large ZIPs need Chrome or Edge (File System Access); no "download album" button; live photos not split |
| Export to a folder, continuous | `desktop/src/main/services/fs.ts`, `apps/photos/src/services/export.ts` | 🟡 `kutup download` / `kutup sync` of the upload folder (no album structure, no metadata sidecars) |
| Watch folders | `desktop/src/main/services/watch.ts` | 🟡 `kutup sync --watch` into the upload folder; the CLI writes no media details (Photos fills them later, `catchUp.ts`) |

## Albums

| Feature | Ente (Proton) | Kutup |
|---|---|---|
| Create, rename, delete (photos stay) | `Collections/EditAlbumDetailsDialog.tsx`, `CollectionHeader.tsx` | ✅ (`albums/albums.ts`); Proton's "Save photos and remove" for others' photos is moot: they stay in their owners' storage |
| Add to album, remove from album | `SelectedFileOptions.tsx` | ✅ own photos only (others' are theirs to share) |
| Album description | `EditAlbumDetailsDialog.tsx` | ❌ (**format**: the album's sealed record) |
| Cover photo | `PickCoverPhotoDialog.tsx`; Proton `toolbar/PhotosMakeCoverButton.tsx` | ❌ (**format**) |
| Album sort (name, created, updated) and photo order in an album | `CollectionsSortOptions.tsx`, `CollectionHeader.tsx` | ❌ albums by last change only, photos newest first |
| Album list filters (shared, received, links, pinned, archived, hidden) | `Collections/AllAlbums.tsx`; Proton `Tags.tsx` (All, Mine, Shared, Shared with me) | ❌ one list; shared albums say who shared them |
| Pin, archive, hide an album | `CollectionHeader.tsx` | ❌ (**format**: the account's library record) |
| Album layouts (grouped, masonry, trip) | `layout` in `media/collection.ts`, `apps/albums/.../TripLayout/` | ❌ |
| Album map | `Collections/CollectionMapDialog.tsx` | ❌ (Places covers the whole library) |
| Share with people: view, add photos | `Collections/CollectionShare.tsx` (viewer, collaborator, admin) | 🟡 Can view / Can add photos on this server; other servers view only; no admin role (**schema** for an admin role: `drive_collection_shares` has only `can_upload`, `can_delete`) |
| Album invitations with Join or Decline, unverified-sender warning | Proton `PhotosWithAlbums/AlbumsInvitations.tsx` | 🟡 other servers through an invite link (`AcceptAlbumInviteDialog.tsx`); on this server the album appears at once |
| Leave a shared album | `CollectionHeader.tsx` | ✅ your photos leave with you |
| Save a shared photo into your own library | Proton `toolbar/PhotosSavePhotoButton.tsx` | ❌ |
| Public album link | `CollectionShare.tsx`, `apps/albums/src/public-album/page/PublicAlbumPage.tsx` | ✅ key in the link, several links, remove; report link; admin block |
| Link password | `access/components/PasswordUnlockScreen.tsx` | ✅ album link settings and the password page ([`drive-link-password.md`](drive-link-password.md)) |
| Link expiry | `CollectionShare.tsx` | ✅ album link settings ([`drive-link-password.md`](drive-link-password.md)) |
| Link: downloads off, device limit | `CollectionShare.tsx` | ❌ (**schema**: no columns) |
| Collect link (anyone uploads, with a name) | `upload/components/UploaderNameInput.tsx` | ❌ (**schema**: no upload permission on a link, anonymous uploads need an owner-quota rule) |
| Join album from a public link | `access/hooks/use-join-album.ts` | ❌ |
| Comments and likes | `gallery/components/viewer/CommentsSidebar.tsx`, `LikesSidebar.tsx`, `new/photos/services/comment.ts` | ❌ (**schema**: new tables, or Chat) |
| Per-photo links, several photos in one link | Proton `toolbar/PhotosShareLinkButton.tsx`, `PhotosShareMultipleLinkButton.tsx` | 🟡 Share on one photo opens Drive's file sharing (people, file links); several photos need an album |
| Cast to a TV, embed | `AlbumCastDialog.tsx`, `apps/embed/` | ➖ |
| Custom domain for links | `Sidebar.tsx` `DomainSettings` | ➖ the server's own domain |

## People, places and search

| Feature | Ente (Proton) | Kutup |
|---|---|---|
| Face grouping, naming, merging, ignoring people | `new/photos/services/ml/{face,cluster,people}.ts`, `Collections/AllPeople.tsx`, `gallery/PeopleHeader.tsx` | ❌ slice 6 in [`photos.md`](photos.md), deferred until after the native apps. Tags sealed under the file key fit `drive_file_assets`; people as an account record scope: no schema expected |
| CLIP search ("magic search") | `new/photos/services/ml/clip.ts`, `sidebar/MLSettings.tsx` | ❌ slice 6 |
| Search bar: name, caption, camera, date, album, file type, place | `apps/photos/src/components/SearchBar.tsx`, `new/photos/services/search/` | ❌ no search in Photos (Drive's search matches names only); the details are all on the device already |
| Places map of the library | Ente web: maps in the info panel and album map only; mobile `ui/map` | ✅ `places/PlacesPage.tsx`: clustered map, photos in view; maps opt in |
| Location tags with a radius | `new/photos/services/user-entity/index.ts` (made on mobile) | ❌ |
| Similar images, OCR | mobile `services/machine_learning/` | ❌ slice 6 |

## Viewer and editing

| Feature | Ente (Proton) | Kutup |
|---|---|---|
| Viewer: previous, next, keyboard, download, favourite | `gallery/components/viewer/FileViewer.tsx` (PhotoSwipe) | ✅ `viewer/PhotoViewer.tsx`: ← →, Esc, `i` for details |
| Zoom, pinch, pan, full screen | `photoswipe.ts` | ❌ |
| Trash, archive, add to album from the viewer | `FileViewer.tsx` | ❌ only from the selection bar |
| Copy as PNG, shortcuts help | `FileViewer.tsx` | ❌ |
| Live photo playback | `FileViewer.tsx` | ✅ |
| Video: streaming playback | `gallery/utils/hls.ts` (HLS streams made by desktop or mobile) | 🟡 Drive's range playback of the original (`drive-core/playback.ts`), a size cap per tab; no transcoded stream (**schema** if it becomes a thumbnail variant: the `drive_file_thumbnails` CHECK allows `sm`, `lg` only) |
| Info panel: date, place on a map, camera, size, length, caption, folder | `gallery/components/FileInfo.tsx` | ✅ `viewer/InfoPanel.tsx` |
| Full EXIF view, rename from the info panel, "added by" | `FileInfoComponents.tsx` | 🟡 "added by" in albums; no EXIF list, rename in Drive |
| Edit date, place, caption | `FileDateTimePicker.tsx`, `EditLocationDialog.tsx` | ✅ one photo (`viewer/EditDetailsDialog.tsx`), place picked on the map |
| Fix dates or places of many photos | `apps/photos/src/components/FixCreationTime.tsx`, selection → `EditLocationDialog` | ❌ |
| Image editor: crop, rotate, flip, adjustments, saved as a copy | `new/photos/components/ImageEditorOverlay.tsx` | ❌ |
| Slideshow | Cast only on web; mobile `ui/viewer/album_slideshow` | ❌ |

## Trash

| Feature | Ente (Proton) | Kutup |
|---|---|---|
| Restore, delete forever | `new/photos/services/trash.ts`, `SelectedFileOptions.tsx` | ✅ photos-only view of Drive's trash (`trash/TrashPage.tsx`) |
| Empty trash | `CollectionHeader.tsx` | 🟡 in Drive's trash (linked); not in Photos |
| Auto-delete after 30 days, shown per item | `deleteBy` per item | 🟡 the server's trash sweeper (`jobs.rs`, `trash_retention_days` from the environment); not an admin setting, and no "deleted in N days" on items |

## Settings

| Feature | Ente (Proton) | Kutup |
|---|---|---|
| Where uploads go, which folders are the library | (albums) | ✅ `settings/SettingsPage.tsx`: upload folder, library folders incl. shared ones |
| Map on or off | `Sidebar.tsx` `MapSettings` | ✅ the account's maps preference |
| ML on or off | `sidebar/MLSettings.tsx` | ❌ with slice 6 |
| App lock | `sidebar/AppLockSettings.tsx` | ❌ (a Hidden lock above) |
| Language, theme, account, storage, family plan | `Sidebar.tsx`, `FamilyManagement.tsx` | ✅ in the Account app; family plans ➖ (organizations instead) |
| Legacy, emergency contacts | `apps/legacy/` | ❌ an account feature, not Photos' |

## Desktop and mobile clients

| Feature | Ente | Kutup |
|---|---|---|
| Desktop app: watch folders, export, ZIP and Takeout reading, native ML, ffmpeg | `desktop/src/main/services/{watch,fs,zip,ml-native,ffmpeg}.ts` | 🟡 the `kutup` CLI: `upload`, `download`, `sync --watch`; no media details, no albums, no ML |
| Mobile background backup by folder | `mobile/apps/photos/lib/services/sync/local_sync_service.dart` | ❌ native apps deferred ([`../mobile-build.md`](../mobile-build.md)); the mobile website uploads by hand |
| Free up space on the phone | `mobile/.../ui/tools/free_space_page.dart` | ➖ with the native app |
| Widgets, memories, collages, video editor | `mobile/.../services/home_widget_service.dart`, `ui/tools/` | ➖ with the native app |

## Gaps in priority order

What people hit first, with whether the fix needs the server or the schema:

1. **Search in Photos** (date, place, caption, camera, name, album, type):
   client only; every detail is already decrypted on the device. No server.
2. **Viewer zoom and full screen**, and the viewer's own actions (trash,
   archive, add to album, hide): client only.
3. **Downloads off for album links:** **schema** (`drive_public_shares`: an
   `allow_download` flag) and the public page. Password and expiry are built
   ([`drive-link-password.md`](drive-link-password.md)).
4. **Type filters (videos, live, screenshots, RAW, panoramas, selfies):**
   **format**: a `tags` list in the sealed media record, set on upload and by
   `catchUp.ts`. Before the wipe so every photo carries it.
5. **Upload into an album, folder upload with one album per folder:** client
   only (albums already hold any of your files).
6. **Album cover, description, photo order, sort of the album list:**
   **format** (the album's sealed name record); no table.
7. **Fix dates and places of many photos at once:** client only (the edit
   exists for one).
8. **Collect links** (anyone with the link adds photos): **schema** (an
   upload permission on links; anonymous uploads charged to the owner, with
   limits as site settings) and a public upload path on the server.
9. **Duplicates finder, large files:** client only (hashes are in the
   media record).
10. **Hidden lock** (account PIN, as Pass's): client plus the account's PIN;
    no schema.
11. **Album roles** (admin who can share and remove) and **album
    invitations** with Join or Decline on this server: **schema**
    (`drive_collection_shares` gains a role and an accepted state).
12. **Image editor** saving a copy: client only.
13. **Takeout import:** client only (sidecar JSON read on the device).
14. **Comments and likes on albums:** **schema** (new tables) or built on
    Chat groups; decide which first.
15. **Faces, people, CLIP search** (slice 6): new asset kinds sealed under
    file keys and an account record scope; expected no schema, but check the
    asset id rules and the thumbnail variant CHECK before the wipe.
16. **Transcoded video streams:** **schema** if stored as a thumbnail
    variant (`drive_file_thumbnails` CHECK).
17. Memories, mobile backup, slideshow, map per album: after the native
    apps.

**Schema before the wipe:** items 3, 8, 11, 16 (and 14 if comments get
their own tables); **format before the wipe:** items 4 and 6.
