# Unique names in a folder, and files not uploaded twice

**Status:** done (October 2026): server, web (Drive, Photos, Office,
Maps), CLI and its sync engine. Tests: `unique_names_live` (server),
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
  (or a folder of that name): the person chooses **Replace** (the file
  there goes to the trash, where it can be restored; the new one is
  uploaded first, without a name hash, and takes the name once the old one
  is gone), **Keep both** (`name (2)`) or **Skip**, with "apply to all" for
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
  a taken name keeps both: the restored item comes back without its hash
  and the owner's client names it `name (2)`.
- Versions do not change a file's name. Saving one clears the content hash
  (the upload is no longer what the file holds), so a clash with an edited
  document asks.

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
differently.

## Server

- `files.name_hash`, `files.content_hash`, `collections.name_hash`
  (lowercase hex, nullable until filled in). Unique indexes per folder
  (`collection_id` for files, `parent_collection_id` for folders, the owner
  for top-level folders) among items not in the trash, and every write
  checks files and folders together in one transaction, so a file and a
  folder cannot share a name either.
- Every write that sets a name or a folder carries the name hash: create
  folder, rename folder, move folder, upload (tus at create and again when
  it finishes, multipart before anything is stored), rename file, move
  file, and uploads arriving from another server. A clash is
  `409 name_taken` with what holds the name (file or folder, its id, its
  content hash); signed federation errors carry the same body. Restore
  clears a hash that is taken where the item lands (or that belonged to
  another place: a folder brought back at the top level).
- A rename without a hash keeps a file's stored one when absent (Photos
  updating a photo's details renames nothing) and clears it when `null` (a
  file shared by itself renamed by an editor who has no folder key); a
  folder renamed without one has it cleared. Cleared hashes are filled in
  again by the owner.
- `PUT /api/files/:id/content-hash` records a file's content hash after
  its upload (it is known only once the whole file has been read).
- The folder listing returns each item's name hash and content hash, so the
  client compares against what it already decrypted.
- Filling in: `POST /api/collections/:id/name-hashes` (and
  `POST /api/drive/top-level-name-hashes`) sets the hashes of items that
  have none yet, in the order given, by someone who can write the folder,
  and reports the ones whose name another item holds.

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
  agree); the hashes always come from Rust through WASM. Existing items
  without hashes are filled in, in the background, when the folder's owner
  opens it (and the top level when the folder list loads); of two that
  share a name, the later is renamed `name (2)`, `name (3)`…
- **CLI and its sync engine**: the same hashes from `kutup-crypto`
  (`crates/kutup-cli/src/names.rs`). `kutup upload` skips the same file
  ("Already there"), stops on a different one unless `--keep-both`, and
  goes into a folder of the same name when uploading a directory again.
  `mkdir`, `mv` (rename and move) send hashes. A sync push of an edited
  file uploads without a hash, trashes the old file, then claims the name
  (`name-hashes`), as the web's Replace does.
- A file uploaded before this has no content hash: a clash with it always
  asks, never skips silently.

## Left for later

- Content hashes in folders on other servers: their listings and uploads
  carry none yet, so a clash there always asks. Names are kept unique there
  (the upload carries its name hash).
- A moved file loses its content hash (keyed to the folder it left; the
  plaintext's SHA-256 is not kept with the file).
- Replace from the CLI.
- Uploads into folders on other servers whose server predates this: the
  server cannot enforce what it is not sent.
- A server-side lookup by content hash across a whole library (Proton
  Photos): only worth it where the client does not hold the listing
  (Phase 4 of the browser-storage plan).
