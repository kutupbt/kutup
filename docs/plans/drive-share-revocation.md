# Drive share revocation and folder-key rotation — design

**Status:** implemented 2026-09-24, branch `feat/frontend-rewrite` (server,
web app, CLI; live tests `share_revocation_live`, the federated phase of
`chat_federation_live`). Pre-tag:
schema, API and the Drive crypto formats change directly (new envelope
purposes; no existing purpose changes meaning).

## Why

An owner can share a folder with people on this server, with people on
other servers and through public links, and can do none of the following:
see who has access, remove someone, or delete a link. Deleting the database
row alone would stop the server from serving the folder but not make anyone
forget the folder key they already hold, and the server is not trusted with
confidentiality. `docs/draft/v1/security-review-follow-ups.md` sets the bar:
removal rotates to a new collection-key epoch before future content is
written and redistributes it only to the remaining members; what the removed
party could already read cannot be made secret again.

## References

- **Keybase KBFS:** per-folder key *generations*; removing a device or member
  adds a generation, new writes use it, old data stays under older
  generations and remaining members can still derive them (lazy rotation).
- **Tresorit, Proton Drive:** no bulk re-encryption on member removal.
  Proton keeps a link's key sealed to its owner, so the owner can list links
  and copy them again.
- **CryptPad:** a password change re-encrypts the whole document. That is
  workable for one pad but not for a folder of large files.

Kutup follows KBFS: lazy rotation, a keyring, and files re-keyed when next
written.

## Model

### Epochs and the keyring

A folder has keys `K1 … Kn`, one per epoch, with `n = collections.key_epoch`.
Each epoch `e > 1` stores, beside its signed `CollectionEpochStatementV1`
(already hash-chained to `e − 1` and committing to `Ke`), a **previous-key
envelope**: `K(e−1)` sealed under `Ke` (new `DriveEnvelopePurpose`
`PreviousCollectionKey = 8`; object = collection, parent = owner, epoch =
`e`). Anyone holding `Kn` walks down the chain to any older key. Each key
recovered is checked against its epoch's statement commitment, and each
statement's `previous_statement_hash` against its predecessor's hash, so a
server cannot splice keys or statements.

A removed member keeps `K1 … Kn` and never learns `K(n+1)`.

`GET /api/collections/{id}/epochs` returns the chain (statements plus
previous-key envelopes) to the owner and members. Public links and federated
peers get the same list through their own endpoints. Clients fetch it only
when they meet an object older than the current epoch, and cache it per
folder.

### Rotation is part of every removal

`POST /api/collections/{id}/rotate` is one owner request, applied in one
transaction or not at all. It carries:

- the new epoch statement (verified with `verify_binding` against the
  current statement hash, by the owner's authority);
- the owner key envelope and name envelope at the new epoch, and the
  previous-key envelope;
- what is being removed: local shares, public links, federated shares;
- a new envelope for **every** member that stays: a named share for each
  local and federated recipient, and a public-link envelope for each link.

If the membership the client saw is not the membership now (someone was
added or removed meanwhile), the request is refused with `409`; the client
reloads and tries again. Removing access *is* this request: there is no
bare delete.

Uploads already refuse a stale epoch (`409 folder key changed`); clients
reload the folder and retry.

### Files are re-keyed before they are written again

A file keeps the key it was uploaded with. Readers open it through the folder
key of the epoch its wrap is sealed at. Everything written *after* a rotation
must not be readable with an old key, so an editor who opens a file whose key
is wrapped at an older epoch than the folder's re-keys it first:

`POST /api/files/{id}/rekey` carries a new random file key of the next
*generation*, wrapped at the current epoch, the metadata re-sealed under it,
and the key it leaves sealed under it (`PreviousFileKey = 10`). The server
stores that record in `file_key_history` and moves the file on
(compare-and-swap on the generation: `409` if another editor got there first;
that editor's key is then used). The collaboration log is kept: frames carry
their key generation, and clients open older ones through the file's key
chain. The relay accepts new frames only at the file's current generation.

*Superseded detail (2026-09-24):* the first version of this design kept each
left-behind file key sealed under the folder key of its epoch and sealed
content to the folder too. docs/plans/drive-move.md replaced that with the
file's own key chain, so a file's history moves with it between folders.

Everything already stored keeps the generation it was sealed under, and
clients open it with that generation's key. `files.original_key_generation`,
`file_versions.key_generation`, `file_assets.key_generation` and
`file_thumbnails.key_generation` record it. New versions, assets, thumbnails
and collaboration frames must use the file's current generation.

Only the owner and editors re-key. A viewer never writes, so a viewer never
needs to. A file is also re-keyed before it moves out of a rotated folder.

### Public links

A link's key now also goes to the owner: `PublicLinkKey = 9`, sealed under
the owner's master key, with object = link id and parent = owner. This lets
the owner list links, copy them again, and re-wrap each link at the new
epoch when rotating, so a kept link keeps working. Deleting a link rotates.
Links made before this change have no owner copy; rotation deletes them.

### Federated recipients

The owner re-seals the named share for each remaining federated recipient,
using the recipient key its client pinned when sharing, looked up again
through the signed transport. The recipient's server stores a snapshot of
the share at accept time. When the owner's listing shows a newer epoch, the
recipient's client calls `POST /api/drive/federation/shares/{id}/refresh`.
Its server fetches the invite again and accepts the new statement only if
it chains from the snapshot's statement hash. A revoked federated share
fails with `403` or `404` from then on.

## Accounting, safety, failure

- The owner-only rotate endpoint also bumps `name_revision` and re-checks
  the owner's authority key.
- Crash safety: the client builds everything, then sends one request. The
  server applies all or nothing.
- The relay drops sockets whose access is gone within 15 s (already in
  place). A re-key changes the file's epoch, so frames at the old epoch are
  refused; clients reconnect with the new key.

## Not covered

What a removed member could already read (old keys, old ciphertext) stays
readable to them. This cannot be undone and the UI says so.
