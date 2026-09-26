# Drive: sharing a single file

**Status:** proposed 2026-09-26 (product owner asked for it: "share just a
file like CryptPad and Proton Drive"). Branch `feat/frontend-rewrite`.

## Why

Drive shares folders only: the owner seals the folder key to each person
(`NamedShareEnvelopeV1`, bound to collection id and folder epoch) and every
file in the folder opens with it. To share one note, map or document today,
it needs a folder of its own. Proton Drive and CryptPad share single files:

- **Proton Drive:** every node (file or folder) has its own key; sharing a
  file makes a share rooted at that node, and only its members reach it.
- **CryptPad:** every document has its own keys (in its link); it is shared
  by giving someone those keys, by link or to a contact.

Since Move (docs/plans/drive-move.md) Kutup is built like Proton underneath:
a file's content, name and metadata, versions, thumbnails, whiteboard
assets and collaboration frames are all under the file's own key and bound
to the file, not the folder. Only the wrap of the file's current key under
the folder key names the folder. So a person can be given one file's key.

## Design

### Keys

- **`FileShareEnvelopeV1`** (new format next to `NamedShareEnvelopeV1`,
  its own magic and HPKE info): the file's current key, HPKE-sealed to the
  recipient's Drive key and signed with the owner's Drive signing key; bound
  to the file id, the file key generation, both accounts and both
  incarnations. Canonical vector; Rust, WASM and TS like the folder one.
- The recipient opens it, then everything else as today: the name and
  metadata, and older generations through the file's key history
  (`file_keyring::key_at`). No folder key is ever given.
- Only the owner (the owner of the file's folder) shares a file; a
  recipient checks that the envelope is signed by the owner.

### Access

| | View | Edit |
|---|---|---|
| Open, download, versions, thumbnails | ✓ | ✓ |
| Edit together live, save versions, thumbnails | | ✓ |
| Rename, move, delete, share | owner only | owner only |

What an editor stores counts against the editor's own storage, as uploads
into shared folders do today.

### Removing someone

As for folders, removing someone moves the file to a new key: one request
from the owner, all or nothing — a new generation (the file key re-wrapped
under the folder, the metadata under the new key, the previous key sealed
under the new one) and new envelopes for everyone who stays. Live editing
sessions are closed and reopen on the new key. The removed person keeps
what they already had, never anything newer.

### When the folder's key changes

When someone is removed from the *folder*, files move to a new generation
lazily, when first written. If that write is by the owner, the owner's app
re-seals the file's single-file shares in the same step. If it is by
another folder member, they cannot sign for the owner: the file's shares
wait at the old generation (recipients see "Waiting for the owner to
update access"; they can still open what they had), and the owner's app
re-seals them the next time Drive is open there, as it does for profile
keys. A file moved out of its owner's folders loses its single-file
shares.

### Server

- `file_shares` (file, sharer, recipient, envelope, key generation,
  can_edit): the same authorization helpers (`can_access_file`,
  `can_write_file`, the collaboration socket's `file_access`, content
  download) also accept a file share; everything else stays folder-only.
- Endpoints: share a file, list who has a file, remove (the rotation
  above), and "files shared with me" (the file record, the envelope and the
  owner's identity keys). A file in the trash is not reachable through its
  shares; deleting it removes them.

### Web

- "Share" on files as on folders; the same dialog with "Can view / Can
  edit" and the access list with remove.
- "Shared with me" lists files as well as folders; they open in the same
  viewers and editors (notes, office documents, whiteboards, and maps).
- A shared file shows a "Shared" mark for its owner.

## Slices

1. **Local single-file sharing:** the envelope, `file_shares`, access
   checks, share / access / remove, "Shared with me", opening and live
   editing a shared file; the folder-rotation re-seal.
2. **Across servers:** a file invite (capability for one file), read and
   write through the recipient's server, like folder federation.
3. **Public link to a single file:** `public_shares` already reserves
   `share_type` for it; a link key sealing the file key.

## Open questions

- Should editors be able to rename a shared file (Google Drive allows it)?
  Proposed: not in slice 1.
