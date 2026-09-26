# Photos

**Status:** slice 1 implemented 2026-09-26 (details below, under "Slice 1
done"). Plan written 2026-09-26. Branch `feat/frontend-rewrite`. The product
owner asked for it after Maps: "continue with photos". The roadmap's
decisions stand (docs/roadmap.md, "Photos (like Ente Photos)"):
- photos are Drive files in folders you choose;
- albums are views;
- one storage quota for Drive and Photos;
- the Places map lives in Photos.

The product owner also asked for Ente's map of where photos were taken to be
studied closely (see "Places").

References: Ente (`kutup-references/ente`: `web/`, the mobile app's map in
`mobile/apps/photos/lib/ui/map`, its Rust clusterer in
`rust/crates/location/src/cluster.rs`) and Proton Drive's Photos
(`kutup-references/WebClients/applications/drive/src/app/photos`).

## What people get

`photos.<domain>`, a fifth web app:
- **Timeline:** everything, newest first, by day under month headings, with a
  scrubber to jump by year and month.
- **Viewer:** full screen, with an info panel showing when, where (a small
  map), camera, size and folder.
- **Places:** a map of where photos were taken.
- **Library tools:** favourites, archive, hidden, trash; upload by drag and
  drop, with duplicates skipped.
- **Later slices:** albums, then shared and public albums, then search on the
  device.

## How it is built

### Photos are Drive files

- **Uploads** go to one folder, "Photos" in My files by default; Settings
  can choose another.
- **Library folders:** the timeline shows that folder and any others you add,
  each with its subfolders. Folders shared with you count too.
- **Drive rules apply to every photo:** its key, thumbnails, versions, trash,
  quota and sharing. A photo moved in Drive stays in the timeline if its new
  folder is in the library.

The library settings live on the server as folder ids (`photos_preferences`:
upload folder and library folders), as Maps keeps its save folder. The
server already knows the folders exist; it learns only which ones Photos
shows.

### Photo metadata, encrypted with the photo

The timeline and Places need, for each photo:
- when it was taken;
- where;
- its size;
- for videos, its length;
- a hash to find duplicates.

Proton keeps the capture time in plaintext so its server can sort the
timeline. Kutup does not: everything goes into the file's existing metadata
envelope, under the file key, and the browser sorts.

`FileMetadataV1` gains an optional `media` object:

| Field | Meaning |
|---|---|
| `takenAt` | when it was taken, UTC milliseconds |
| `takenOffset` | the local time zone there, in minutes, so the time is shown as it was on the camera |
| `takenFrom` | where the date came from: `exif`, `video`, `filename` or `file` (the file's own date) |
| `lat`, `lon` | where, when known; (0, 0) counts as unknown, as in Ente |
| `width`, `height` | after rotation |
| `durationMs` | videos |
| `camera` | make and model, up to 100 characters |
| `hash` | SHA-256 of the content, base64 |
| `caption` | the owner's text, up to 2,000 characters |

- **One canonical format, in Rust.** The format moves into `kutup-crypto` (a
  `file_metadata` module: encode, strict decode, limits), used by the CLI
  and through WASM by the browser. Today the browser and the CLI each hold a
  copy, and both reject unknown fields. Vectors are checked in, as for every
  format.
- **Changes are metadata revisions.** A rename keeps `media`. Edits (fixing a
  date or a place, a caption) are new metadata revisions, as a rename is.
- **Who sees it:** anyone who can open the photo, as in Proton (its
  encrypted XAttr) and Ente (its public magic metadata). A shared photo shows
  its date and place to the people it is shared with. The viewer says so
  beside the place.

### Reading it, on the device

The same code serves Drive and Photos uploads (`@kutup/files`), in the
bounded preview worker that already makes thumbnails.
- **Images:** `exifreader` (MPL-2.0), as Ente and Proton use it.
  - **Date order:** DateTimeOriginal, then DateTimeDigitized, then
    DateTime, from XMP, IPTC or EXIF, with sub-seconds and offsets.
  - **Other fields:** GPS, dimensions swapped for rotated orientations,
    make and model.
  - **Rejected dates:** zero and the year-4501 placeholder.
- **Videos:** a small bounded MP4/QuickTime box reader for:
  - the creation time (`mvhd`, or Apple's `com.apple.quicktime.creationdate`);
  - the place (ISO 6709 `©xyz` or Apple's location key);
  - size and length.
  Proton reads `mvhd` the same way. No ffmpeg.
- **Fallbacks:** a date in the file name (Ente's patterns:
  `IMG-20171218-WA0028`, `Screenshot_…`, `20240101_120000`), then the
  file's own date.
- **The hash** is taken on the device from the plaintext (through WASM,
  streamed), before upload, because the metadata is sealed first.

Photos already in Drive have no `media`. Photos fills it in the background:
- **Where it can:** for a file you may rename, it downloads, reads and writes
  a new revision. It works a few files at a time and resumes after a reload,
  as the thumbnail backfill does.
- **Where it can't:** for one you may only view, it reads the data on the
  device and keeps it in memory.

Until then, a photo sorts by when it was uploaded.

### Timeline

- **Loading:** the browser lists the library folders' files (the cached
  folder queries Drive uses) and opens their metadata. It keeps images and
  videos, sorted by `takenAt`.
- **Layout:** grouped by day under month headings, as in Ente. Rows are
  virtualized, drawing only rows near the screen. The scrubber jumps by
  month, as in Proton.
- **Thumbnails:** Drive's small thumbnail (512 px). Missing ones are made by
  the existing backfill. Loading goes nearest to the screen first; rows
  scrolled away stop loading, as in Proton.
- **Selection:**
  - click, shift-click for a range, or a day's checkbox for the whole day;
  - actions: download, move to trash, favourite, share (a single photo, with
    Drive's file sharing).
- **Large libraries:** in-memory for the first slice.
  - **To measure:** 10,000 photos (opening 10,000 metadata envelopes).
  - **If too slow:** a local cache of dates, places and thumbnails, encrypted
    at rest under a key the browser cannot export. Unlike Ente's, whose
    thumbnail cache is plaintext.

### Viewer

- **Images:** the original when the browser can draw it and it is under
  50 MB; otherwise the large thumbnail (1920 px).
- **Videos:** played as Drive plays them today, downloaded and decrypted
  first.
- **Info panel:** date and time with the time zone, the place on a small map,
  camera, dimensions, size, folder (opens it in Drive), and caption.
  - **Editable by those who may rename the photo:** date, place, caption.
  - **Photos you can only view:** shown, not editable.

### Upload and duplicates

- Uploads go to the upload folder: drag and drop anywhere, or the Upload
  button.
- **Duplicates:** before a file uploads, its hash and name are looked up in
  the library on the device. A file with the same name and hash is skipped
  and reported as already in the library; the same content under another
  name is uploaded. This is Ente's rule.
- The server never sees a hash. Proton sends name and content hashes, keyed
  per folder, to its server; Kutup does not.

### Favourites, archive, hidden

These are yours, not the photo's: a favourite from a shared folder is
private to you. They are kept in one encrypted **library record** per
account:
- **Key:** a random library key, sealed with the account key (new account
  envelope purpose).
- **Record:** file id sets for favourites, archived and hidden, sealed under
  that key (new Drive envelope purpose), with a revision.
- **Two devices changing it at once:** the second write is refused, and that
  device merges and writes again.
- **What the server learns:** only that a record exists and its size. Ente's
  favourites are a collection its server can see.

**Where each shows:**
- **Archived:** leaves the timeline and Places, and appears in albums and
  search.
- **Hidden:** leaves everything except its own page.

A lock on Hidden (asking again for the password) is a later choice.

### Places (studied from Ente, as asked)

**Ente's two versions:**
- **Web** (`CollectionMapDialog.tsx`):
  - a Leaflet map with `supercluster` (80 px radius);
  - each marker is the newest photo in its group, with a count;
  - clicking a group zooms to where it splits;
  - a side panel lists every photo inside the current view, newest first,
    by day, and updates as the map moves;
  - thumbnails load for what is on screen plus a 15% margin, and the next
    zoom level.
- **Mobile** (`map_screen.dart`, clustering in Rust):
  - groups by distance on screen (a grid of cells the marker's size, points
    joining the nearest group within that distance);
  - a tapped group zooms to fit its photos;
  - a pull-up gallery shows the photos in view;
  - the map opens where the most recent photos are: among the 10 newest
    photos with a place, it takes the biggest group within 50 km and centres
    on its middle photo;
  - it works across the date line.

**Kutup's Places does the same:**
- **Map:** the shared map component (MapLibre, the provider the admin chose,
  through the relay if set) with photo markers. Maps off for this person:
  the usual "maps are off" state, with a link to turn them on.
- **Clustering:** Ente's screen-space grid, in TypeScript, on the device.
  Pure functions with tests (date line included), run on each move, for
  photos near the view.
- **Markers:** the newest photo in each group, with a count. Clicking one
  zooms to fit it; a single photo opens the viewer.
- **Panel:** the photos in view (a bottom sheet on phones), newest first, by
  day, updating as the map moves.
- **Opening position:** Ente's rule (the biggest recent group); otherwise
  the whole library fitted.
- **Which photos:** those with a place, minus archived and hidden. A photo's
  place comes only from its encrypted metadata; tiles are the only thing
  fetched, as for every map.

### HEIC, RAW, live photos, video (slice 3)

- **HEIC** (iPhone photos): Safari draws them; other browsers need libheif
  in WASM (LGPL-3.0, compatible with Kutup's AGPL-3.0), in the preview
  worker, for thumbnails and the viewer. Ente does the same.
- **RAW:** the JPEG preview cameras embed, for the thumbnail and viewer; the
  original downloads.
- **Live photos:** the still and the video stay two Drive files. The video's
  `media` names its still. The timeline shows one tile with a "Live" badge,
  and the viewer plays the video on hover or press.
  - Proton links related photos the same way.
  - Ente zips the two into one file; that would hide them from Drive.
  - Pairing on web upload uses Ente's rules: the same base name, one image
    and one video, taken within a day. The native apps will pair from the
    phone's own records.
- **Video streaming:** Drive's secretstream format is sequential, so a video
  can play while it downloads but cannot jump ahead without decrypting what
  comes before. Seeking needs a format with independently sealed chunks,
  which is a new file suite. That is recorded as its own decision, not done
  here.

### Albums (slices 4 and 5)

- **An album is a new kind of Drive collection** (kind `album`), hidden from
  Drive's folder tree. It holds references, not files:
  - `album_items(album, file, file key sealed under the album key, added by,
    added at)`, with a new Drive envelope purpose;
  - a photo in five albums is one file, counted once.
- **Access:** the server lets anyone with access to the album download the
  photo and its thumbnails.
- **Reused from folders:** keys, epochs, members, sharing across servers,
  public links and revocation all come from collections, so shared albums
  get them without a second system.
- **Collaborative albums:** members allowed to add put in their own photos,
  which stay in their storage (Proton and Ente do the same).
- **"Save to my library"** copies a photo from someone else's album into your
  upload folder.

### Search on the device (slice 6)

Faces, objects and text, found by models running in the browser (Ente's
approach). The index stays on the device, encrypted. The design comes in its
own plan.

## Slices

1. **Foundation and timeline:**
   - the `photos.` origin, `web-photos` sessions, the app switcher and the
     account's apps page;
   - `media` metadata (Rust format, vectors, WASM, CLI keeping it on
     rename), read on upload in Drive and Photos;
   - library settings;
   - the timeline, viewer and info panel;
   - upload with duplicates skipped;
   - the metadata backfill.
2. **Library tools:**
   - favourites, archive and hidden (the library record);
   - Places;
   - editing date, place and caption;
   - the trash view (Drive's trash, photos only).
3. **Formats:** HEIC, RAW, live photos, and video details.
4. **Private albums.**
5. **Shared albums:** people here and on other servers, collaborative albums,
   public album links.
6. **Search on the device.**

## Slice 1 done (2026-09-26)

- **The format:** `FileMetadataV1` with `media` is the Rust format
  (`kutup-crypto` `file_metadata`, vector `fileMetadata`), used by the
  browser through WASM and by the CLI. Rename, re-key, re-seal for sharing
  and copy keep `media`. The hash is SHA-256 (the crate's own).
- **Reading on upload:** `@kutup/files/media` (ExifReader; a bounded
  MP4/QuickTime reader for `mvhd`, `tkhd`, Apple's keys, `©xyz` and 3GPP
  `loci`; dates in names). Tested on real JPEG, MP4 and MOV files. Every
  Drive upload of a photo or video seals it too.
- **The app:** `photos.` (`KUTUP_PHOTOS_URL`, dev port 5178, `web-photos`
  sessions, migration 066); in the app switcher and on the account's apps
  page.
  - The timeline: virtualized, by day under month headings, with a month
    scrubber.
  - Selection: click, shift-click, a whole day; download (one file, or a
    ZIP), share one, move to trash.
  - Drag and drop anywhere to upload.
  - The viewer: the original when the browser can draw it (the large
    thumbnail otherwise); arrows, swipes and keys; a details panel with a
    small map.
  - Settings: the upload folder, and library folders (yours or shared with
    you).
- **Catch-up:** photos without details or a thumbnail get both from one
  download, one at a time, those on screen first. They are written back
  where this account may, and kept for the tab otherwise.
- **Shared with Drive:** the thumbnail store and queue (`drive-core`), photo
  and video thumbnails (`@kutup/files/thumbnails`), the upload queue and
  panel and the storage meter (`drive-ui`).
- **Also fixed:** Drive's retry after a folder moved to a new key mid-upload
  read the folder index by the wrong cache key and always failed.
- **Not yet:** folders shared from other servers in the library (their ids
  are not local folders); a thumbnail for a HEIC photo in browsers that
  cannot decode it (slice 3).

## Open questions

Each has a proposed answer, used unless the product owner decides otherwise:
- **Folders shared with you in the library?** Yes, any folder you can open.
  Photos you can only view get no metadata written.
- **Lock on Hidden?** Not in these slices.
- **Library cache on the device?** Only if 10,000 photos measure slow.
