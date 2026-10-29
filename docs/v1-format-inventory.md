# V1 cryptographic format inventory

**Status:** normative pre-tag cutover inventory

This inventory names every persistent or federated ciphertext family that the
V1 cutover must replace or freeze. Kutup is preproduction, so legacy rows,
development object storage and browser databases are recreated rather than
dual-written. This destructive rule expires at the first stable `v*` tag.

| Purpose | Pre-V1 shape | V1 owner and format |
|---|---|---|
| Master-key password wrap | XSalsa20 secretbox plus separate nonce; implicit Argon parameters | **Implemented:** OPAQUE for the password (its Argon2id in the OPAQUE key-stretching function), and the suite-bearing `AccountEnvelopeV1` (suite 2, bound to the account's key binding, XChaCha) for the wrap |
| Master-key recovery wrap | XSalsa20 secretbox under random recovery entropy | **Implemented:** `AccountEnvelopeV1` (suite 2) with recovery purpose, the account's key binding as context, and XChaCha |
| Account sharing private key | XSalsa20 secretbox; public X25519 key stored separately | **Implemented:** account-scoped Drive keys in `AccountManifestV1`; private material wrapped by the Drive-private-key purpose of `AccountEnvelopeV1` |
| Collection name/key | Separate ciphertext/nonce columns with implicit secretbox | **Implemented end to end:** client-generated collection UUID, `DriveEnvelopeV1` owner-key/name records (names padded to 256-byte buckets), immutable `CollectionEpochStatementV1` history and exact revision/epoch binding |
| File metadata/key | Separate ciphertext/nonce columns with implicit secretbox | **Implemented end to end:** client-generated file UUID; the file key's wrap is bound to file, folder, the folder epoch it is sealed at and the key's generation, and the metadata (padded to 256-byte buckets, with the content SHA-256) to the file alone (generation and revision), across multipart, tus, trash, public-link and signed-federation paths (docs/plans/drive-move.md) |
| File blob and version snapshot | Raw secretstream header/chunks, or nonce-prefixed snapshot AEAD | **Implemented end to end:** one `DriveObjectSuiteId` file-blob format for originals and text/office/whiteboard snapshots, with 5 MiB secretstream framing bound to the file and its key generation, never the folder |
| Profile key for a share partner | — (new) | **Implemented end to end:** `ProfileKeyEnvelopeV1` (`KUTPPK1`), the same HPKE suite and Drive keys as a named share, bound to both accounts and incarnations, not to a folder |
| Single-file share | — (new) | **Implemented (local):** `FileShareEnvelopeV1` (`KUTPFS1`), the named-share layout bound to a file and its key generation instead of a folder and epoch (docs/plans/drive-file-sharing.md) |
| Local/federated named share | Anonymous `crypto_box_seal` bytes | **Implemented end to end:** one `NamedShareEnvelopeV1` format for local and signed-federation routes, X25519 HPKE plus account-manifest-bound Ed25519 sender signature |
| Public-link collection wrap | Secretbox under link key plus separate nonce | **Implemented end to end:** public-link purpose `DriveEnvelopeV1` bound to collection, owner and epoch; the independent link capability remains only in the URL fragment |
| Collaborative frame | XChaCha frame with `doc_key_id`, device and sequence | **Implemented end to end:** canonical Rust `CollabFrameSuiteId = 1`, 80-byte authenticated context header, XChaCha key derived from the file key and Ed25519 signature; browser uses the Rust parser/KDF/AEAD through WASM |
| Whiteboard asset | XChaCha with asset AAD | **Implemented end to end:** `DriveEnvelopeV1` whiteboard-asset purpose under the file key, bound to file, key generation and asset ID across browser, CLI and server ingestion |
| File thumbnail | — (new) | **Implemented end to end:** `DriveEnvelopeV1` purpose 7 under the file key, bound to file, variant and key generation; padded `KTH1` container |
| Public link to one file | — (new) | **Implemented end to end:** `DriveEnvelopeV1` purpose 11 (`PublicLinkFileKey`): a file key of one generation under a link key, object = file, parent = owner, epoch = generation (docs/plans/drive-file-sharing.md, slice 3) |
| File key history | — (new) | **Implemented end to end:** `DriveEnvelopeV1` purpose 10 seals generation *g − 1*'s file key under generation *g*'s; `file_keyring::key_at` walks the chain, so a file's history travels with it between folders (docs/plans/drive-move.md) |
| Folder key history | — (new) | **Implemented end to end:** `DriveEnvelopeV1` purpose 8 seals epoch *e − 1*'s key under epoch *e*'s; `collection_keyring::unlock` verifies the whole owner-signed statement chain and every key commitment (docs/plans/drive-share-revocation.md) |
| Public-link owner copy | — (new) | **Implemented end to end:** `DriveEnvelopeV1` purpose 9 seals a link's key under the owner's master key (object = link id), so links can be listed, copied and re-wrapped on rotation |
| Encrypted profile | AES-256-GCM nonce/ciphertext | **Implemented end to end:** `ProfileSuiteId = 1` plus account/revision/device/purpose-bound XChaCha `ProfileEnvelopeV1`; suite code accompanies every E2EE profile-key capability; the owner's own copy of the profile key is wrapped under a key from the master key and the key binding (`kutup/chat-profile/wrap/v2`) |
| Identity pins | — (new) | **Implemented end to end:** `KUTIP3` suite 3, the account's synced pin list sealed under a master-key-derived key, bound to the account's key binding and the list's revision; pins are keyed by account (server and account id), with addresses kept only as labels. Earlier suites are not read. Vector: `identity-pins-v3.json` |
| Contacts | — (new) | **Implemented end to end:** summaries signed by the account authority under `kutup/contact-summary/v2` and cards sealed as `KUTCC2` suite 2, both bound to the account's key binding (cards also to the contact UID). Vector: `contact-card-v2.json` |
| Mail folder, label and filter names | — (new) | **Implemented end to end:** `KUTMN2` suite 2, sealed under a master-key-derived key, bound to the account's key binding, the kind and the id. Vector: `mail-names-v2.json` |
| Direct Chat | `DirectChatSuiteId = 1`, libsignal bytes | Unchanged pinned libsignal suite |
| MLS group | MLS `0x0002`, P-256 control and delivery keys | MLS `0x0003`, X25519/ChaCha/Ed25519 throughout Kutup-owned bindings |
| Account device directory | Chat-only `DeviceManifest` plus global transparency proofs | One account-signed `AccountManifestV1` with complete device set, previous hash, history and durable peer pin |
| Chat history backup | Absent; a new browser device starts with an empty local database | **Implemented:** always-on account-local E2EE backup using a master-key-wrapped Chat root, independently derived segment/base/manifest/media keys, signed hash-chained manifests, and server-side base-plus-tail restore; device-to-device transfer is not supported (current contract: [`chat-backup.md`](chat-backup.md)) |
| Broadcast post and grants | Absent | Typed broadcast policy, epoch, account/device grant, history grant and post structures |

`AccountEnvelopeV1` is encoded as magic `KUTPAE2\0`, big-endian suite ID
(2; suite 1 is retired and not read), purpose byte, zero reserved byte, the
big-endian u32 master-key generation (never 0: the generation of the master
key a password or recovery wrap holds, or of the one that sealed any other
secret; docs/plans/w6-key-hierarchy.md §2), big-endian context length, the context (the account's key binding, a UUID v4,
never an email, username or address: docs/plans/account-identity.md), the
object id's length byte and the object id where the purpose has one secret
per object, an 8-byte big-endian revision for a mutable purpose, 24-byte
nonce, big-endian ciphertext length, and XChaCha20-Poly1305 ciphertext/tag.
The bytes preceding the ciphertext are the complete AAD, and the AEAD key is
derived per envelope with HKDF-SHA256 over the purpose, the binding and the
object. Each purpose has one policy (`AccountEnvelopePurpose::policy`),
checked on seal, open and by the server: whether it names an object (and its
length), how its plaintext's length shows (`Exact` for keys; `Fixed` or
`Bucket` padding, `0x80` then zeros, applied once by the envelope and checked
canonically on open) and whether it carries a revision:

| Purpose | Object | Length | Revision |
|---|---|---|---|
| PasswordMasterKey, RecoveryMasterKey, DriveHpkePrivateKey, ChatBackupRoot | none | exactly 32 bytes | no |
| MailAddressPrivateKey | none | padded to a multiple of 256 bytes | no |
| PassVaultSecret | the vault's file id (16 bytes) | padded to one length (`pass_vault::MAX_PAYLOAD_LEN` + 1 = 3121 bytes) | yes |

Every server write path checks an envelope with
`account_envelope::validate_for(purpose, binding, object)` before storing it,
and so rejects noncanonical base64, unknown or retired suites and purposes,
noncanonical context, the wrong purpose, binding or object, a missing or
extra object or revision, a length its policy never gives, and trailing data.
`account-envelope-v2.json` holds one envelope per purpose and, for each, the
envelopes that must be refused, read by the Rust and the WASM tests.

Contact cards (`KUTCC2`), mail names (`KUTMN2`) and identity pin lists
(`KUTIP3`) carry their revision in clear after the suite, covered by the AAD
(docs/plans/sealed-revisions.md); cards and names are padded to a multiple of
256 bytes.

The account's own at-rest formats bind the key binding, never a name, and a
format that bound a name was replaced by a new version with no reader for the
old one (the private beta was reset): identity pins `KUTIP1` → `KUTIP2` →
`KUTIP3` (suite 3, the key binding),
contact summaries `kutup/contact-summary/v1` → `/v2` and cards `KUTCC1` →
`KUTCC2`, mail names `KUTMN1` → `KUTMN2`, and Chat's wrapped profile key
`kutup/chat-profile/wrap/v1` → `-v2`. Each vector file lists the values that
must be refused: another key binding, the address in place of the binding, a
changed header, nonce or ciphertext, and the old address-bound value.
Statements to other people keep naming the address, because the address is
what they are about: the Drive key binding, named shares and profile key
shares, MLS credentials, the mail key's own address and the peer-facing
profile envelopes. Safety numbers (V2) name only the two authority keys.

`DriveEnvelopeV1` is encoded as magic `KUTPDE1\0`, big-endian suite ID,
purpose, zero reserved byte, epoch, revision, 16-byte object UUID, 16-byte
parent UUID, 24-byte nonce, exact ciphertext length, and XChaCha20-Poly1305
ciphertext/tag. The fixed header is AAD. Its stable scope also feeds
HKDF-SHA256, so raw master/collection/file/link roots are never AEAD keys and
each purpose, object, parent, epoch and revision has a distinct derived key.

A file blob is `[DriveFileBlobHeaderV1][secretstream header][frames]`.
The 32-byte Drive header is magic `KUTPDB2\0`, big-endian
`DriveObjectSuiteId`, file-blob purpose, zero reserved byte, the non-zero
generation of the file key that sealed it, and the file UUID. It names no
folder, so a file moves without re-encryption (docs/plans/drive-move.md; the
48-byte `KUTPDB1` layout, which also named the folder, was replaced before the
first tag). HKDF-SHA256 derives a purpose key from the random file key using
the fixed header as info. The same header is associated data for every 5 MiB
secretstream frame. Every blob, including an empty file, contains an
authenticated `TAG_FINAL` frame; truncation, trailing frames and
file/generation relocation fail closed. Multipart, tus, snapshot and
signed-federation ingestion validate the exact public header before storage.

A file's key is wrapped under its folder's key as a purpose-3 envelope: object
= file, parent = folder, epoch = the folder epoch it is sealed at, revision =
the file key's generation. It is the only file object that names the folder;
moving a file re-seals it alone. The metadata (purpose 4) is sealed under the
file key with object = parent = file, epoch = key generation and revision =
metadata revision. Its plaintext is `FileMetadataV1` (`kutup-crypto`
`file_metadata`, vector `fileMetadata`): canonical JSON `{ name, mimeType,
size, media? }`, decoded strictly (unknown fields and out-of-range values
refused) by the browser (WASM) and the CLI alike. `media` holds a photo's or
video's details (docs/plans/photos.md): when it was taken (UTC ms, the time
zone in minutes, and where the date came from), place, size on screen,
length, camera, a SHA-256 content hash, a caption and, for a live photo's
video, `liveOf` (its still's file id).

An album item is a photo's file key sealed under the album key as Drive
envelope purpose 12 (`AlbumFileKey`): object = file, parent = album, epoch =
the album's key epoch, revision = the file key's generation.

The Photos library record (`kutup-crypto` `photos_library`, vector
`photosLibrary`) is one account-private XChaCha20-Poly1305 envelope under an
HKDF subkey of the master key (as the Chat attachment ledger's). A 112-byte
header (magic `KUTPPL1`, suite, purpose, account incarnation, revision, the
previous envelope's SHA-256, nonce, length) is the AAD and the per-envelope
key's input; the server checks it for compare-and-swap. The plaintext is
canonical JSON `{ favourites, archived, hidden }`, each a sorted set of file
UUIDs, at most 100,000 in all.

`CollectionEpochStatementV1` is a fixed-width account-authority-signed record
over suite, collection UUID, owner UUID, non-zero epoch, exact previous-record
hash, collection-key commitment and authority-key ID. Epoch 1 has an all-zero
previous hash; later epochs require an exact predecessor. Its record hash
covers the original signed statement unchanged. The server verifies identity,
signature and continuity; a client also verifies the key commitment before it
uses a collection key.

Rotating a folder (on every removal of access) appends epoch *e*: a new random
key, its statement chained to *e − 1*, and a purpose-8 envelope sealing the key
of *e − 1* under the key of *e* (object = collection, parent = owner, epoch =
*e*). `collection_keyring::unlock(current key, collection, owner, authority,
history)` requires the complete history from epoch 1, checks every statement's
authority, binding and predecessor hash, opens each older key from the next
and checks it against its statement's commitment; the current key must match
the last. A key of an earlier epoch therefore unlocks nothing. Keyless parties
(a federated recipient's server) use `verify_history` to check that a new
epoch descends from the one they pinned. Vector: `collectionKeyring`.

A file whose key is wrapped at an older folder epoch is re-keyed before new
content is written to it or it moves: a new random key of the next
generation, wrapped at the folder's current epoch, with the metadata re-sealed
under it and the key it leaves sealed under it as a purpose-10 envelope
(object = parent = file, epoch = the new generation). Everything already
stored records the generation it was sealed under and opens through
`file_keyring::key_at`, whichever folder the file is in. The chain carries no
signature: an envelope under a key the server does not hold cannot be forged,
and each is bound to its file and generation. Vector: `fileKeyring`.

`NamedShareEnvelopeV1` uses the fixed RFC 9180 HPKE suite X-Wing (X25519 +
ML-KEM-768, KEM 0x647a)/HKDF-SHA256/ChaCha20-Poly1305 (named-share suite 2). Its AAD and Ed25519 signature
bind the collection UUID, epoch, canonical sender and recipient accounts, and
both account incarnation IDs. The sender key is the manifest-bound Drive share
signer; the recipient key is the manifest-bound Drive HPKE key. V1 intentionally
provides no anonymous Drive sharing.

`FileShareEnvelopeV1` (magic `KUTPFS1\0`, HPKE info
`kutup/drive/file-share-hpke/v1\0`) is the same layout and suite as
`NamedShareEnvelopeV1`, generated by the same macro, with the collection UUID
and epoch replaced by the file UUID and the file key's generation. It carries
one file's current key to someone the file is shared with by itself. Older
generations open through the file's key history. Tests in `named_share.rs`
and `scripts/test-crypto-wasm.mjs` (randomized HPKE, like the named share: no
fixed vector).

`ProfileKeyEnvelopeV1` (magic `KUTPPK1\0`, HPKE info
`kutup/drive/profile-key-hpke/v1\0`) carries a 32-byte profile key between
two people who share a folder (docs/plans/unified-profile.md). The same suite
and keys as a named share; the AAD and signature bind the magic, suite, both
incarnation IDs and both canonical accounts, but no folder: one key serves
every share between the pair. Tests in `profile_key_share.rs` (no vector: the
format has one producer and one consumer, both in this crate and its WASM).

`CollabFrameSuiteId = 1` uses magic `KUTPCF3\0` and a fixed 88-byte
big-endian header containing suite, kind, file-key generation, document-key
generation, file UUID, the sender's device id (its entry in its account's
manifest), the manifest sequence it sealed under, sequence, nonce and exact
ciphertext length. The header is AEAD associated data. HKDF-SHA256 derives from the file
key a distinct XChaCha20-Poly1305 key bound to the same suite, kind, key
generation, document generation and file UUID (the 96-byte `KUTPCF1` layout,
under the folder key, was replaced before the first tag). Ed25519 signs a
domain (`kutup/collab/frame/v3\0`), the sender account, the header and the
ciphertext; the trailing signature is not self-covered. The account travels
beside the frame (`envelope::deliver`). The server accepts only the exact
current file/key-generation/document binding and a sender device that its
account's manifest lists with the signing key (docs/plans/one-device-list.md).

Whiteboard assets use `DriveEnvelopeV1` purpose 6 under the **file key**. The
object UUID is the file UUID; the parent binding is a fixed-label
(`whiteboard-asset/v2`) SHA-256 commitment to the canonical asset ID. The
epoch slot carries the file key's generation; revision is 1. Plaintext is limited to 25 MiB and the server
validates the complete public envelope before quota or object-storage mutation.

Thumbnails use `DriveEnvelopeV1` purpose 7 with the **file key** as root key.
The object UUID is the file UUID; the parent binding is a fixed-label
SHA-256 commitment to the variant id (`sm` or `lg`), so one variant never
opens as the other. The epoch slot carries the file key's generation; revision is fixed at 1
because V1 has no signed file revision chain to make freshness meaningful.
The plaintext is a `KTH1` container: magic, format (1 JPEG, 2 WebP, 3 PNG —
never SVG), u16 width and height (≤ 512 or ≤ 1920), u32 image length, the
image, then zero padding to whole 4 KiB (`sm`, cap 64 KiB) or 16 KiB (`lg`,
cap 1 MiB) blocks. Decoding rejects any other magic, format, size, a leading
image signature that does not match the declared format, or non-zero
padding. The generic `sealDriveEnvelope`/`openDriveEnvelope` WASM exports
refuse purposes 6 and 7; each has its typed export. Vector:
`crypto.json` → `thumbnail`. Design: `docs/plans/drive-thumbnails.md`.

`ProfileEnvelopeV1` uses magic `KUTPPE1\0`, `ProfileSuiteId`, a closed purpose
(display name, avatar or wrapped profile key), revision, source device,
profile-key-derived version, canonical federated account, 24-byte nonce and
exact ciphertext length. The complete variable-length header is AAD. A
purpose-specific HKDF-SHA256 subkey binds the same context before
XChaCha20-Poly1305. Name padding remains the fixed 53/257-byte Signal-style
buckets; avatars are limited to 512 KiB. The profile suite code travels beside
the profile key inside encrypted Direct Chat content, and unknown codes do not
authorize a profile fetch.

Chat backup uses `ChatBackupRootV1`, wrapped with the Chat-backup purpose of
`AccountEnvelopeV1`. Fixed HKDF-SHA256 labels derive independent message,
media-ID, media-encryption, manifest-signing and segment keys. Typed headers
bind every XChaCha20-Poly1305/secretstream object to its suite, account,
incarnation, protection domain, generation and object purpose. Signed,
hash-chained manifests select one encrypted base plus an ordered event tail;
the homeserver stores and quotas opaque objects but cannot inspect Chat
content. Backup media uses independently derived opaque IDs and outer keys.

Every V1 structure has a numeric typed suite, a fixed domain separator,
canonical big-endian length-prefixed signing/AAD encoding, deterministic test
vectors, strict byte limits and an explicit unknown-suite error. JSON is a
transport representation only and is never the signed encoding.

After V1, an old suite may remain readable while migration is active, but new
writes use exactly one locally allowed suite. Federation advertises supported
suites and returns `NoCommonSuite`; it never silently retries a legacy format.
