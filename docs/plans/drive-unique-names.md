# Unique names in a folder, and files not uploaded twice

**Status:** in progress (October 2026). Follows Proton Drive's name and
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
  is not sent.** Same name, different content: the person chooses
  **Replace** (a new version of that file), **Keep both** (`name (2)`) or
  **Skip**, with "apply to all". Dropping a folder again therefore uploads
  only what is new or changed, and the file a reload interrupted goes on
  (resumable uploads).
- Rename, move, copy and restore follow the same rule: a rename onto a
  taken name is refused; a move or copy into a clash asks as an upload
  does; a restore into a clash keeps both.

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
  folder, rename folder, move folder, upload (tus and multipart), rename
  file, move file, restore, and uploads arriving from another server. A
  clash is `409 name_taken` with what holds the name (file or folder, its
  id, its content hash).
- `PUT /api/files/:id/content-hash` records a file's content hash after
  its upload (it is known only once the whole file has been read).
- The folder listing returns each item's name hash and content hash, so the
  client compares against what it already decrypted.
- Filling in: `POST /api/collections/:id/name-hashes` sets the hashes of
  items that have none yet, by someone who can manage the folder.

## Clients

- **Web**: the folder hash key per folder (cached), the name hash on every
  write, the content hash computed while the upload encrypts (the bytes are
  read anyway) and recorded at the end. Before an upload, a clash with a
  name in the listing: same size → hash the local file and compare content
  hashes; identical → skipped ("already there"); otherwise the choice
  above. Existing items without hashes are filled in when someone who can
  manage the folder opens it; two that turn out to share a name have the
  later ones renamed `name (2)`, `name (3)`…
- **CLI and its sync engine**: the same hashes from `kutup-crypto`.
- A file uploaded before this has no content hash: a clash with it always
  asks, never skips silently.

## Left for later

- Uploads into folders on other servers whose server predates this: the
  server cannot enforce what it is not sent.
- A server-side lookup by content hash across a whole library (Proton
  Photos): only worth it where the client does not hold the listing
  (Phase 4 of the browser-storage plan).
