# Unique names in a folder, and files not uploaded twice

**Status:** done (October 2026): server, web (Drive, Photos, Office,
Maps), CLI and its sync engine. Since the clean-slate release every item
has a name hash, as in Proton Drive: no write without one, nothing filled
in later. Tests: `unique_names_live` (server),
browser spec 50, `scripts/verify-cli.sh`, unit tests beside the code. Follows Proton Drive's name and
content hashes (read in `kutup-references/WebClients`, `drive-store`), with
SHA-256 for both: measured here, Kutup's Rust/WASM SHA-256 runs at about
540 MB/s in the browser (10 GB in under 20 s), faster than encryption, the
disk or the network, and natively SHA-256 is as fast as SHA-1.

## What it does

- **A name is unique in its folder**, among the folder's files and its
  subfolders together, as on a disk or in a ZIP. Names compare without
  letter case or Unicode composition: `Report.pdf` and `report.PDF` are the
  same name. The server enforces it without reading a name.
- **An upload that would put an identical file under a name already there
  is not sent** ("Already in this folder"). Same name, different content
  (or a folder of that name): the person chooses **Replace** (the upload
  becomes a new version of the file there, as Proton's revisions, so the
  old content stays in its versions; resumable at any size over tus, with
  the new size, SHA-256 and content hash landing together with it),
  **Keep both** (the first free `name (n)`, asked of the server ten at a
  time, as Proton's `findAvailableName`) or **Skip**, with "apply to all" for
  the rest of the batch. A dropped folder goes into the folder of its name
  already there, so dropping it again uploads only what is new or changed;
  the file a reload interrupted goes on (resumable uploads).
- Photos, a new document (Office, Drive's New menu) and a new place list
  never replace anything: a taken name becomes the next free one without a
  question (cameras reuse names; the same photo is skipped by the
  library's own check, which ignores the ` (2)`).
- A rename onto a taken name is refused (the dialog says so before it is
  sent). A move into a folder where the name is taken leaves the item
  where it is, as before. A copy takes the next free name. A restore into
  a taken name is refused (`409 name_taken`), and the client restores it
  under a new name in the same request (the next free `name (n)`, sealed
  at the next revision); a folder that comes back at the top level is
  named there (`409 nameNeeded` until it is).
- Versions do not change a file's name. Saving one clears the content hash
  (the upload is no longer what the file holds) until the client records
  the new one, so a clash with an edited document asks.
- Someone who edits a file shared by itself, without its folder's key,
  cannot hash the name in that folder: a rename then stores a random hash.
  The name stays unique for everyone else, but its owner may see two items
  of the same name in the folder (as in Proton, where a hash is only as
  good as the client that wrote it).

## The hashes (`crates/kutup-crypto/src/drive_names.rs`)

- **Folder hash key**: `HKDF-SHA256(first folder key, salt = folder id,
  info = "kutup/drive/folder-hash-key/v1")`. The first (epoch 1) key is
  reached by every member through the folder's key chain, so the hash key
  stays the same through every rotation and nothing is rehashed. An
  account's top-level folders, with no folder above them, use one key from
  the account master key (`"kutup/drive/top-level-names/v1"`). Like
  Proton's per-folder hash key, someone removed from a folder can still
  compute it, but the server no longer shows them the folder.
- **Name hash**: `HMAC-SHA256(hash key, "name" ‖ 0 ‖ canonical name)`;
  canonical name = NFC, Unicode default (locale-independent) lowercase,
  NFC. Turkish dotted capital `İ` lowercases to `i` + combining dot, so
  `İstanbul` and `istanbul` stay different; `ISTANBUL` and `istanbul` do
  not.
- **Content hash**: `HMAC-SHA256(hash key, "content" ‖ 0 ‖ SHA-256 of the
  plaintext)`. A plain content hash would let the server confirm someone
  holds a known file; keyed by the folder, it only tells members' clients
  that two files in that folder are the same.

Rust owns the format (vectors in `crypto.json` → `driveNames`); the browser
calls it through WASM, so browser, CLI and server never fold a name
differently. The plaintext's SHA-256 travels inside the file's encrypted
metadata (`sha256`, `crypto.json` → `fileMetadata`), so a move recomputes the
content hash under the destination's key without reading the file.

### Against Proton Drive

Same: a name hash on create file, create folder, rename and move (a move
recomputes it, a revision keeps it); `HMAC-SHA256` under a per-folder key; a
clash refuses the write and names what holds it; a free name is found by
asking which of up to ten candidate hashes are free; the content hash is
recomputed on move. Different on purpose: names fold case and Unicode
composition (Proton hashes the raw UTF-8, so `a.txt` and `A.txt` may sit
side by side there; on disks most people use they cannot); the hash key is
derived from the folder's first key instead of a random key sealed to it
(nothing more to store or share); and the content fingerprint is SHA-256,
not SHA-1.

## Server

- `files.name_hash`, `files.content_hash`, `collections.name_hash`
  (lowercase hex; required for files, uploads and folders, not albums).
  Unique indexes per folder
  (`collection_id` for files, `parent_collection_id` for folders, the owner
  for top-level folders) among items not in the trash, and every write
  checks files and folders together in one transaction, so a file and a
  folder cannot share a name either.
- Every write that sets a name or a folder carries the name hash (a
  missing one is `400`): create folder, rename folder, move folder, upload (tus at create and again when
  it finishes, multipart before anything is stored), rename file, move
  file, and uploads arriving from another server. A clash is
  `409 name_taken` with what holds the name (file or folder, its id, its
  content hash); signed federation errors carry the same body. Restore
  refuses a name taken where the item lands, and takes a new name (its
  hash and envelope) in the same request.
- A file's metadata update without a hash keeps the stored one (Photos
  updating a photo's details renames nothing).
- `PUT /api/files/:id/content-hash` records a file's content hash after
  its upload (it is known only once the whole file has been read).
- The folder listing returns each item's name hash and content hash, so the
  client compares against what it already decrypted.
- Free names: `POST /api/collections/:id/available-hashes` (and
  `POST /api/drive/top-level-available-hashes`) answers which of up to ten
  hashes no item there holds, for someone who can write the folder, rate
  limited.

## Clients

- **Web** (`frontend/packages/drive-core/src/names.ts`): the folder hash
  key per folder (cached), the name hash on every write, the content hash
  computed while the upload encrypts (every pass reads the file from its
  start, a resumed one too) and recorded at the end. Before an upload
  (`planUpload`), a clash with a name in the listing: same size and a known
  content hash → hash the local file and compare; identical → skipped;
  otherwise the choice above (`NameConflictDialog`, one question at a time,
  answered for the batch when "apply to all" is ticked). A name taken
  meanwhile (the server's 409) is looked at again once. Names are compared
  on the device with the same folding as Rust (a unit test checks the two
  agree); the hashes always come from Rust through WASM.
- **CLI and its sync engine**: the same hashes from `kutup-crypto`
  (`crates/kutup-cli/src/names.rs`). `kutup upload` skips the same file
  ("Already there"), stops on a different one unless `--keep-both`, and
  goes into a folder of the same name when uploading a directory again.
  `mkdir`, `mv` (rename and move) send hashes. A sync push of an edited
  file uploads it as a new version, as the web's Replace does; when both
  sides changed, the local copy takes a free conflict name found with
  `available-hashes`.

## Left for later

- Content hashes in folders on other servers: their listings and uploads
  carry none yet, so a clash there always asks. Names are kept unique there
  (the upload carries its name hash).
- Replace into a folder on another server: versions go there by
  multipart, so at most 2 GiB.
- Uploads into folders on other servers whose server predates this: the
  server cannot enforce what it is not sent.
- A server-side lookup by content hash across a whole library (Proton
  Photos): only worth it where the client does not hold the listing
  (Phase 4 of the browser-storage plan).
