# Drive move — design

**Status:** implemented 2026-09-24, branch `feat/frontend-rewrite` (crypto,
WASM, server migration `049_drive_move`, web app, CLI; live test
`drive_move_live`, vector `fileKeyring`). Pre-tag: the Drive content,
envelope and collaboration formats changed directly (`KUTPDB2`, `KUTPCF2`,
purpose 10); files stored before this change must be uploaded again.

## Why

Drive can copy but not move. A folder move needs only a server endpoint, but a
file move is impossible without re-encrypting: everything sealed under a
file's key also names its folder (the content header, the metadata envelope,
whiteboard assets) or is sealed under the folder's key outright (collaboration
frames), and all of it carries the *folder's* key epoch, whose older keys sit
under the folder's own history.

## References

- **Proton Drive:** every node has its own key; content, revisions and
  thumbnails hang off it. Only three things depend on the parent: the node
  passphrase (encrypted to the parent key), the name (encrypted to the parent
  key) and the name hash (keyed by the parent's hash key). A move re-wraps
  those three and touches nothing else — not the node key, not the content,
  not a moved folder's subtree. Moves stay inside one volume; across volumes
  it is a copy. No re-keying: whoever held the old parent keeps what they had.
- **CryptPad:** a pad's key is its link and has nothing to do with folders.
  A move edits the encrypted folder object; between drives it copies the
  reference and deletes it from the source. Nothing is re-encrypted; nested
  shared folders are forbidden.

Kutup follows Proton.

## Model

### What a file's key covers

A file has a random **file key**. Everything else about the file is sealed
under it and bound to the file alone:

| object | bound to |
|---|---|
| content blob (header `KUTPDB2`) | file id, key generation |
| metadata envelope (`FileMetadata`) | file id, key generation, metadata revision |
| versions, thumbnails | file id, key generation |
| whiteboard assets (`WhiteboardAsset`) | file id, key generation, asset id |
| collaboration frames (`KUTPCF2`) | file id, key generation, document key id |

Only the **file-key wrap** names the folder: `FileKey` sealed under the folder
key, with epoch = the folder epoch it is sealed at, revision = the file's key
generation, object = file, parent = folder. Moving a file re-seals this one
envelope for the destination.

### Key generations

The share-revocation work (docs/plans/drive-share-revocation.md) re-keys a
file before anything new is written to it once its folder has rotated past it,
so a removed member cannot read later edits. A file therefore has keys
`F1 … Fg`, `g = files.key_generation`. Each generation `g > 1` stores the
previous key sealed under its own (`PreviousFileKey = 10`: epoch = `g`,
revision 1, object = parent = file). Whoever holds `Fg` walks down to every
older key, whichever folder the file is in. Every stored object records the
generation it was sealed at.

`files.key_epoch` keeps its meaning: the folder epoch the current wrap is
sealed at. A file is *behind* its folder when it is lower than the folder's
epoch; such a file is re-keyed (new generation, wrapped at the current epoch)
before it is written to — or moved.

The file-key chain carries no signatures: the server cannot produce a valid
envelope under a key it does not hold, and each envelope is bound to its file
and generation, so the chain can be withheld but not forged or reordered.

### Moving a file

`POST /api/files/{id}/move` — `{ fromCollectionId, toCollectionId,
toKeyEpoch, fileKeyEnvelope }`.

- The caller can write both folders; both have the same owner (quota stays
  with them); neither is federated.
- The file is not behind its source folder (`409 file needs a re-key`; the
  client re-keys it in its folder and retries).
- `toKeyEpoch` is the destination's current epoch (`409 folder key changed`).
- The envelope is the file's current key sealed under the destination key at
  `toKeyEpoch` with the file's generation.

The server updates the folder, the wrap and `key_epoch` in one transaction
and closes the file's collaboration room; nothing else changes.

### Moving a folder

A folder's key is sealed to its owner, not to its parent, so a folder move
changes nothing encrypted. `POST /api/collections/{id}/move` — `{
parentCollectionId: string | null }`: owner only, destination owned by the
same user and live, not the folder itself or anything under it (checked in
the transaction, under a lock on the owner's folders).

### Across owners and servers

Not a move: the UI offers Copy to… (as Proton copies across volumes).

### Names

As in Proton Drive, a move never renames or overwrites: an item whose name is
already used in the destination stays where it is and the user is told.

## UI

- Web: Move to… in the item, selection and right-click menus (the folder
  picker of Copy to…, with each unavailable folder disabled and the reason as
  its tooltip), drag and drop onto folders and onto the folders in the path,
  and an undo in the toast that moves everything back.
- CLI: `kutup mv <file> --to <folder> [new-name]`,
  `kutup mv --folder <id> --to <folder>`, `kutup mv --folder <id> --root`.
