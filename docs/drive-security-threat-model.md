# Drive V1 security threat model

**Status:** normative for the pre-tag Drive cutover

## Assets and trust boundaries

- The account master key, account authority private key, Drive private keys,
  collection keys, file keys and plaintext exist only in clients.
- The server stores ciphertext, suite identifiers, object relationships,
  sizes, timing, access-control rows and opaque signed state.
- `AccountManifestV1` binds the account authority, account-scoped Drive keys
  and complete active device set. A face-to-face QR pins the authority and
  incarnation, not a particular device version.
- Collection owners sign the monotonic collection-key epoch. The server may
  relay or withhold it but cannot select a different current key.
- Federation authenticates servers and transport separately from the
  recipient account identity and share envelope.

## Threats and required results

| Threat | Required control and result |
|---|---|
| Server substitutes a share recipient key | Recipient key must be in the pinned or explicitly TOFU-accepted account manifest. A mismatch blocks sharing. |
| Server moves ciphertext between objects or revisions | Suite, purpose, canonical identifiers, epoch and revision are authenticated as AAD. Decryption fails without returning partial plaintext. |
| Server rolls back a collection after a member was removed | Owner-signed epoch chain and durable client pin reject rollback. Clients never write under an unverified pending epoch. |
| Removed member reads new content | Removal completes only after a new random collection key is distributed to remaining accounts and the signed epoch is committed. Previously learned plaintext/ciphertext cannot be revoked. |
| Offline writer uses a stale key | Upload and collaborative mutation carry the exact epoch; server and clients reject stale writes. There is no automatic legacy-key retry. |
| Named share is forged or redirected | HPKE ciphertext is signed by the sender's manifest-bound Drive signer and binds exact canonical sender, recipient, collection, epoch and suite. |
| Federation peer or network is unavailable | Retain established pins and readable cached data; block state-changing operations that require fresh identity/epoch evidence. |
| Account address is wiped and reused | Wipe terminates the old incarnation. Peers show a red identity reset and shares/groups do not transfer without explicit reauthorization. |
| Compromised client retains secrets | Device removal stops future authenticated service access and rotates affected future-access keys. It cannot remotely erase copied master keys or old plaintext. |
| Malformed or oversized ciphertext | Bounded strict parsers reject before allocation/decryption; fuzzing covers every public V1 structure. |
| Crash during epoch/share mutation | Manifest, epoch, member wraps, current state and audit event commit atomically; restart resumes an idempotent operation or retains the prior epoch. |

## Thumbnails

Previews are made by clients and sealed under the file key
(`docs/plans/drive-thumbnails.md`), so the server never sees one.

- **Who can set one:** anyone who can change the file (the owner or a
  recipient whose share lets them edit; not a viewer). They hold the file key
  and could change the content itself, so a misleading picture is no new
  power.
- **Relocation:** the envelope binds file, variant and epoch; the server
  cannot move a thumbnail to another file or variant.
- **Freshness:** the server can serve an older thumbnail of the same file —
  the same rollback limit file content has in V1, which has no signed file
  revision chain. Signed revisions covering content and thumbnails together
  are the intended fix.
- **Parsing:** the `KTH1` container parser is bounded and strict; images are
  decoded only by the browser, from JPEG/WebP/PNG, never SVG.
- **Drawing someone else's file:** backfill means a folder owner's browser
  can decode a file a collaborator uploaded into it. Images go through the
  bounded preview worker; PDFs through pinned PDF.js in its worker with no
  scripting, no XFA and no external fetches (64 MiB cap, 16 MP images);
  videos through the browser's own decoder, one frame under a deadline.
  This is the same exposure as opening the file, done without the click.

## Write rights and accounting

The server cannot read files, but it decides who may change them and who
pays for what is stored. These rules hold on every write path — upload, tus,
versions, assets, thumbnails, the collab relay and federation — through one
shared module (`crates/kutup-server/src/drive_writes.rs`).

| Threat | Control |
|---|---|
| A view-only recipient changes a file | Changing content or anything derived from it (versions and their names, assets, thumbnails, the note seed, collab edits) needs the owner or a share with `canUpload`. The relay forwards only a viewer's presence frames, re-checks rights per edit frame, and closes sockets whose session or access has gone (checked every 15 s). Clients open editors read-only for viewers. |
| Quota bypass through a second path | Every writer checks one headroom: quota − stored − the full length of the user's open tus uploads; tus finalize checks again. Recipients' writes also count against the share's upload limit. Sizes are always measured, never claimed. |
| Paying once, releasing twice | A purge locks the file row, re-checks it is still in the trash (a racing restore wins), and releases only what it deleted. Retention releases a version only if it removed the row. Reconcile corrects each user under their row lock. |
| A client-chosen id overwrites stored bytes | A new file id is claimed under a lock and refused (`409`) if a stored file or open upload holds it, before anything is written; a failed attempt deletes only its own object. Content-addressed assets are immutable once stored. Chat backup media attempts use keys of their own. |
| A federated peer deletes or fills the owner's Drive | A peer deletes only files its share uploaded, into the owner's trash; its uploads must fit the owner's quota and the share's limit, measured from the files it made. |
| Deleting an account deletes others' data or leaks bytes | Account deletion purges the account's own Drive (objects included, open uploads aborted) and hands what it added to other people's folders to each folder's owner, charges included. |
| Resource exhaustion | Request bodies are capped per route (4 MiB default); collab messages at one frame, with a per-connection rate; office edit frames kept a day; user lookup by email rate-limited. |

Not yet covered: revoking a user share, a public link or an outgoing
federated share (no endpoint; `docs/roadmap.md`), and key rotation on
member removal.

## Metadata not hidden in V1

Servers see accounts, collection/file relationships, ciphertext lengths,
access timing, storage size, federation domains and share membership, and
for thumbnails whether one exists, its padded size bucket and when it
changed. V1 does
not claim traffic-shape protection, ORAM, anonymous Drive sharing or
subscriber privacy from a user's own homeserver. The advanced fixed-cell
transport profile remains post-V1 work.

## Failure classes

Network unavailability may warn while retaining the last valid pin. Invalid
signature, account-authority replacement, manifest rollback/equivocation,
share substitution, epoch rollback or unknown suite blocks new writes and
shares durably. Recovery requires explicit identity acceptance or a valid
successor signed under the already pinned authority; a server assertion alone
never clears a cryptographic failure.
