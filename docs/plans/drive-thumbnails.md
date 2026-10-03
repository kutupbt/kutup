# Drive thumbnails — design

**Status:** agreed 2026-09-24, branch `feat/frontend-rewrite`. Phases A
(format, server), B (images, notes/code, whiteboards; display, editor
redraws, backfill, Quick Look), C (video frames; PDF first pages through
PDF.js 6.3.289, pinned, no scripting or XFA, worker-parsed) and D (office)
are implemented.

Office thumbnails (D) are drawn on Save from the document as OnlyOffice lays
it out, inside the office sandbox: the bridge installs the CryptPad build's
`APP.printPdf` hook for one request, calls `asc_Print`, and x2t turns the
print buffer plus the document and its fonts (from the sandbox's own font
folder) into a PDF; Drive draws page one with PDF.js. Spreadsheets print
page one only, with gridlines (set in that print request's page options,
never in the document), and show the grid's top-left corner at a readable
zoom in the card's 4:3 shape. Office files cannot be
backfilled (drawing needs a running editor): a document gets its thumbnail
at its first save.

Generation reuses the shared preview worker Chat already used
(`packages/files/src/mediaPreview`: safety classification, header-bounded
decoding, re-encoding that strips metadata, byte/pixel/time budgets, never
SVG), extended with a text-page renderer and a JPEG fallback for browsers
that cannot encode WebP. Chat keeps its own transport on purpose: its
preview is sealed inside the (immutable) message, as in the Chat media plan;
Drive files change, so their previews live in a replaceable slot.
**Scope:** encrypted previews for the Drive grid and Quick Look.
Pre-tag: formats and schema change directly; no compatibility shims.

## Goal and constraint

Google Drive draws a picture of every file because its servers can read them.
Kutup's cannot: every preview has to be made by a client that holds the
file's key, encrypted like the file, and decrypted by the client that shows
it. This is Proton Drive's model (client-made thumbnails, encrypted with the
file's key, stored beside it); the sizes below follow theirs
(`kutup-references/WebClients/packages/shared/lib/drive/constants.ts`:
512 px ≤ 60 kB, HD 1920 px ≤ 1 MB).

Non-goals for this change: server-side rendering of anything, previews in
federated shares, previews on public links (both listed under "Later").

## Two variants

| Variant | Id | Longest side | Plaintext cap | Used by |
|---|---|---|---|---|
| Small | `sm` | 512 px | 64 KiB | grid cards, search results |
| Large | `lg` | 1920 px | 1 MiB | Quick Look for kinds without a viewer (office, whiteboard) and for images too large to open whole |

`lg` is made only where it pays: whiteboards, office documents, PDFs, place
lists, and images larger than 20 MiB. Everything else gets `sm` only.

## Format (kutup-crypto)

A thumbnail is a `DriveEnvelopeV1` — the existing purpose-bound AEAD
envelope; no new construction.

- New purpose `DriveEnvelopePurpose::Thumbnail = 7`.
- Root key: the **file key** (not the collection key). Whoever can open the
  file can open its preview; nobody else can, including other members of a
  shared folder who lack the file (there are none today, but the binding is
  the right one) and the server.
- Context:
  - `object_id` = file id
  - `parent_id` = first 16 bytes of `SHA-256("kutup/drive/thumbnail/v1" ‖ variant)`
    (the whiteboard-asset pattern: a derived id instead of a second UUID), so
    an `sm` envelope never opens as `lg`
  - `epoch` = the file row's key epoch (as the file blob)
  - `revision` = 1 (see "Freshness")
- Plaintext limits enforced by the purpose: `sm` ≤ 64 KiB, `lg` ≤ 1 MiB
  (including the container below).

Plaintext is a small container, not a bare image, so it can carry
dimensions and hide the image's exact size:

```
magic    "KTH1"            4 bytes
format   u8                1 = JPEG, 2 = WebP, 3 = PNG (nothing else; never SVG)
width    u16 BE            pixels
height   u16 BE            pixels
length   u32 BE            image byte count
image    [length]
padding  zeros to the next 4 KiB boundary (sm) / 16 KiB (lg)
```

The width and height let the grid reserve the right aspect before the image
decodes. Padding means the server sees one of a few bucket sizes instead of
an exact byte count that correlates with content. Decoders check the magic,
the format byte, that the image's own leading bytes match the declared
format, that the padding is all zero, and the dimensions against the variant
limit.

Deliverables: Rust (`drive_envelope.rs` purpose and context constructor,
`thumbnail.rs` container encode/decode), WASM exports
`sealThumbnail`/`openThumbnail`, TS wrapper in `@kutup/crypto/thumbnail`,
vectors in `crates/kutup-crypto/tests/vectors` for both variants (plus
rejected cases: wrong variant, wrong file, bad padding, SVG), and the
`docs/v1-format-inventory.md` entry.

## Server

Table (migration `045_file_thumbnails`):

```sql
CREATE TABLE file_thumbnails (
  file_id          UUID        NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  variant          TEXT        NOT NULL CHECK (variant IN ('sm', 'lg')),
  size_bytes       BIGINT      NOT NULL CHECK (size_bytes > 0),
  -- The content it was drawn from: a file_versions id, or NULL for the
  -- original upload. Lets clients see a thumbnail has gone stale.
  source_version   UUID        REFERENCES file_versions(id) ON DELETE SET NULL,
  uploader_user_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (file_id, variant)
);
```

Objects at `files/{fileId}/thumbnails/{variant}`, so the existing
`files/{fileId}/` prefix wipe on purge removes them.

Endpoints:

- `PUT /api/files/{fileId}/thumbnails/{variant}?source={versionId|original}`
  — raw body (the envelope),
  size-checked against the variant cap before reading further; the server
  validates the envelope header (`drive_envelope::validate`: purpose 7, file
  id, variant id, epoch = the file's) without decrypting. Replaces any
  previous one. Permission: the same as saving a version of the file
  (`can_access_file`) — anyone who can change the content can change its
  picture. Quota: a transaction like `file_assets`, charging the uploader and
  releasing the previous object's bytes.
- `GET /api/files/{fileId}/thumbnails/{variant}` — the envelope, `404` when
  there is none. `Cache-Control: private, max-age=31536000, immutable`, with
  the URL carrying `?v={updatedAt}`: the browser cache holds ciphertext only.
- `DELETE /api/files/{fileId}/thumbnails` — both variants; used when a file's
  content changes into something that has no preview.
- File listings (`/collections/{id}/files`, search's per-folder lists) gain
  `thumbnails: { sm?: string, lg?: string }` — the `updatedAt` of each that
  exists — and `thumbnailStale: boolean` (its `source_version` is not the
  file's latest version), so a folder view makes no requests for files
  without one and knows which to redraw. The server can only claim
  staleness; the worst it can do with that is make a client redraw.

Quota: `file_thumbnails` joins `files`, `file_versions` and `file_assets` in
every usage sum (the four call sites: `chat_media.rs`, `admin.rs`, and the two
in `jobs.rs` reconciliation/purge release). A test asserts the usage sum
matches the rows after upload, replace and purge.

## Making them (frontend)

Generation runs in a dedicated worker (`OffscreenCanvas`), one job at a
time, so a folder upload never janks the page. The encoder prefers WebP and
falls back to JPEG where the browser cannot encode WebP; quality steps down
(0.8 → 0.3) until the result fits the cap, the way Proton's
`THUMBNAIL_QUALITIES` does.

| Kind | Source | When |
|---|---|---|
| Image | `createImageBitmap` (EXIF orientation honoured); skipped above 50 MP or 100 MiB; HEIC only where the browser decodes it | upload |
| Whiteboard | Excalidraw `exportToBlob` of the scene, light theme, padded | every save (Save / Ctrl+S) |
| Note / text / code | the start of the file drawn on a white page — a paper look, the same in both themes, like Google's document cards. Code files as written, in monospace, coloured by their extension; notes laid out as their Markdown reads: headings, fenced code in a shaded monospace box coloured by its language (a small tokenizer, `codeTokens.ts`, keeps highlight.js out of the worker), bullets and numbers, task checkboxes (ticked when done), quotes beside a bar, tables in columns, rules; inline marks and link targets left out (`textPage.ts`) | upload; text editor snapshot, at most once a minute |
| Video | a `<video>` frame at 10% (max 5 s in) | upload |
| PDF | first page via PDF.js, loaded only when needed | upload (phase C) |
| Office | first page rendered by OnlyOffice's own canvas on save, inside the sandbox, returned over the bridge | editor save (phase D) |
| Place list (`.kutupmap`) | a hidden 960×720 map in the Maps app, fitted to the list's places, with its pins (in the list's colour) and the map data's credit drawn on (`@kutup/map/preview`) | Maps: two seconds after each change of your own; each saved version; opening a list whose picture is missing or behind its places |

Uploads already hold the plaintext `File`, so thumbnails cost no extra
download there. Copies go through the upload path and get them for free.

**When a file changes.** A thumbnail is redrawn whenever a new version is
saved, by the browser that saved it, from the content it already holds:

- Office documents and whiteboards save when someone presses Save or
  Ctrl+S (decided 2026-09-24: no autosave for these). Each such save redraws
  `sm` and `lg`.
- Notes and code keep their autosave (30 s idle or 200 changes); their
  thumbnail is redrawn at most once a minute, and always on Save / Save
  version and when the editor closes with a newer snapshot than the last
  thumbnail.
- Place lists save live like notes, but their picture follows every change:
  Maps redraws it two seconds after a change of your own (a burst draws
  once; other people's changes are drawn by their browsers), filed under the
  latest saved version, and again from each saved version. A list emptied
  of places has its picture removed. A list opened in Maps gets a new
  picture, by someone who may manage it, when it has none, a stale one, or
  changes in the relay's log past its latest version (editors who left
  before it was saved again); it is drawn once the relay has replayed them
  (the session's `onReplayed`), so it holds every place. The picture
  loads tiles exactly as the open list does (the person's provider, through
  the relay when that is on), so drawing it reveals nothing opening the list
  did not; Drive never draws one itself (it has no map, and a backfill would
  fetch tiles for lists nobody opened). With maps off, no picture is drawn.
- Restoring a version saves a version, so it redraws too.
- With several people editing, whoever saves redraws; they hold the same
  content.

Anything that changes a file without an editor (a CLI upload, a save cut
off before its thumbnail went up) leaves the thumbnail marked stale in the
listing: the grid keeps showing the old picture and the backfill queue
redraws it for someone who may write to the file.

**Older files and stale ones (backfill).** When the grid shows a file that
could have a thumbnail but has none or a stale one, and the viewer may write
to it, the file joins a
low-priority background queue: download, decrypt, generate, upload.
Only kinds that are cheap to render (images ≤ 20 MiB, notes, code,
whiteboards), one at a time, only while the tab is visible, skipped under
`navigator.connection.saveData`, and each file tried at most once per
session. Readers of shared folders never backfill (they could, but it would
charge their quota for the owner's files).

## Showing them

- **Grid:** the preview area shows the `sm` thumbnail (`object-cover`,
  top-aligned for documents so the start of the page shows; photos and maps
  fill the frame); the kind icon
  stays as the header icon and as the fallback. Thumbnails are fetched only
  when the card scrolls into view (`IntersectionObserver`), decrypted with
  WASM, and turned into `blob:` URLs that are revoked when the card leaves the
  page. Decrypted pixels are never persisted.
- **List view:** unchanged (icons), as in Google Drive.
- **Quick Look:** kinds without a viewer show `lg` with "Open in editor";
  images above 20 MiB show `lg` first with "Show full size".
- **Setting:** "Show previews" in the view menu (the Toolbar), on by
  default, per browser. Off means no thumbnail is fetched or shown, for
  people who do not want document contents readable at a glance.
- Images come only from our decoder's accepted formats, through `blob:`
  URLs into `<img>` (never SVG, never HTML); the Drive CSP already allows
  `img-src blob:`.

## Security notes (to add to `drive-security-threat-model.md`)

- **Who can make a thumbnail:** anyone who can change the file, since they
  hold the file key and could change the content itself. A collaborator can
  set a misleading picture exactly as they could write misleading content.
- **Freshness:** the server cannot forge or move a thumbnail (file id,
  variant and epoch are authenticated), but it can serve an older one of the
  same file — the same rollback limit file content has in V1 (there is no
  signed file revision chain yet). Revision is therefore fixed at 1 rather
  than pretending to protect freshness; a signed revision chain would bind
  both together later.
- **Metadata:** the server learns that a file has a preview, its padded
  size bucket and when it changed. Dimensions and image bytes stay hidden.
- **Parsing:** the container parser is bounded and strict and is fuzzed with
  the other V1 structures; image decoding is the browser's.

## Phases

- **A — format and storage:** crypto (Rust, WASM, TS, vectors), migration,
  endpoints, quota sums and their test, listing field, docs.
- **B — images, whiteboards, notes/code:** worker, upload and editor hooks,
  grid display, Quick Look `lg`, "Show previews", backfill.
- **C — video and PDF.**
- **D — office documents** (through the OnlyOffice bridge).

Each phase lands with its tests and a browser check; A is useful only with B,
so they ship together.

## Later

- **Public links:** thumbnails need the link-scoped read path (the link's
  key opens the file key); do it with the "public links serve the latest
  version" fix.
- **Federated shares:** the federation file API would carry thumbnails like
  content.
- **CLI:** `kutup upload` could make image thumbnails (the `image` crate) so
  files uploaded from the command line are not left to backfill.
- **Move:** when file content stops being bound to its collection (the move
  design), thumbnails follow the same binding; they already avoid the
  collection id.

## Compared with Proton Drive

Same model — made in the browser, encrypted with the file's key, the same
size targets, quality stepped down to fit, ciphertext-only caching. The
differences (from `kutup-references/WebClients/packages/drive-store/store`):

- Proton encrypts thumbnails with the revision's content session key and
  **signs** them with the uploader's address key, and their block hashes are
  part of the revision's **signed manifest**: a thumbnail is authenticated as
  belonging to one immutable revision, by a known author. Kutup has no signed
  file revisions yet, so a thumbnail is a replaceable per-file slot and the
  server could serve an older one (see Security notes).
- Proton makes them at upload only; Kutup documents change after upload, so
  they are redrawn on every save, and stale ones are backfilled.
- Proton covers images (with HEIC and RAW converters), video and SVG; Kutup
  adds notes, code, whiteboards, PDFs and office documents. HEIC is worth
  borrowing: a decoder library, loaded only for HEIC files (phase B).
- Kutup pads thumbnails to size buckets; Proton's sizes are exact.

The follow-up this points to: **signed file revisions** (content, metadata
and thumbnails in one signed record per save), which closes the rollback
limit for files and thumbnails together. It belongs with the file-format
rework Move needs, not in this change.

## Decisions (2026-09-24)

1. Thumbnails count against the quota of whoever uploaded them, as
   whiteboard assets do (≤ ~1.1 MiB per file, usually ≤ 64 KiB).
2. Readers of shared folders do not backfill.
3. "Show previews" is on by default.
4. Office documents and whiteboards redraw on explicit save only.
