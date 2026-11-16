# V1 cryptographic format inventory

**Status:** normative pre-tag cutover inventory

This inventory names every persistent or federated ciphertext family that the
V1 cutover must replace or freeze. Kutup is preproduction, so legacy rows,
development object storage and browser databases are recreated rather than
dual-written. This destructive rule expires at the first stable `v*` tag.

| Purpose | Pre-V1 shape | V1 owner and format |
|---|---|---|
| Master-key password wrap | XSalsa20 secretbox plus separate nonce; implicit Argon parameters | **Implemented:** OPAQUE for the password (its Argon2id in the OPAQUE key-stretching function), and the suite-bearing `AccountRecordV1` (suite 2, bound to the account's key binding, XChaCha) for the wrap |
| Master-key recovery wrap | XSalsa20 secretbox under random recovery entropy | **Implemented:** `AccountRecordV1` (suite 2) with recovery purpose, the account's key binding as context, and XChaCha |
| Account sharing private key | XSalsa20 secretbox; public X25519 key stored separately | **Implemented:** account-scoped Drive keys in `AccountManifestV1`; private material wrapped by the Drive-private-key purpose of `AccountRecordV1` |
| Collection name/key | Separate ciphertext/nonce columns with implicit secretbox | **Implemented end to end:** client-generated collection UUID, `DriveEnvelopeV1` owner-key/name records (names padded to 256-byte buckets), immutable `CollectionEpochStatementV1` history and exact revision/epoch binding. The owner key (purpose 1) is sealed under the owner's Drive root (account-record purpose 23), not the master key, with the root's generation in the revision slot (docs/plans/identity-rotation.md §3). Vector: `crypto.json` → `driveOwnerKeys` |
| File metadata/key | Separate ciphertext/nonce columns with implicit secretbox | **Implemented end to end:** client-generated file UUID; the file key's wrap is bound to file, folder, the folder epoch it is sealed at and the key's generation, and the metadata (padded to 256-byte buckets, with the content SHA-256) to the file alone (generation and revision), across multipart, tus, trash, public-link and signed-federation paths (docs/plans/drive-move.md) |
| File blob and version snapshot | Raw secretstream header/chunks, or nonce-prefixed snapshot AEAD | **Implemented end to end:** one block-format file blob (Drive object suite 2, `KUTPDB3`) for originals and text/office/whiteboard snapshots: 4 MiB AEAD blocks bound to the file, its key generation and the revision, never the folder, with a signed manifest of block hashes (docs/plans/drive-block-format.md) |
| Profile key for a share partner | — (new) | **Implemented end to end:** `ProfileKeyEnvelopeV1` (`KUTPPK1`), the same HPKE suite and Drive keys as a named share, bound to both accounts and incarnations, not to a folder |
| Single-file share | — (new) | **Implemented (local):** `FileShareEnvelopeV1` (`KUTPFS1`), the named-share layout bound to a file and its key generation instead of a folder and epoch (docs/plans/drive-file-sharing.md) |
| Local/federated named share | Anonymous `crypto_box_seal` bytes | **Implemented end to end:** one `NamedShareEnvelopeV1` format for local and signed-federation routes, X25519 HPKE plus account-manifest-bound Ed25519 sender signature |
| Public-link collection wrap | Secretbox under link key plus separate nonce | **Implemented end to end:** public-link purpose `DriveEnvelopeV1` bound to collection, owner and epoch; the independent link capability remains only in the URL fragment |
| Collaborative frame | XChaCha frame with `doc_key_id`, device and sequence | **Implemented end to end:** canonical Rust `CollabFrameSuiteId = 1`, 80-byte authenticated context header, XChaCha key derived from the file key and Ed25519 signature; browser uses the Rust parser/KDF/AEAD through WASM |
| Whiteboard asset | XChaCha with asset AAD | **Implemented end to end:** `DriveEnvelopeV1` whiteboard-asset purpose under the file key, bound to file, key generation and asset ID across browser, CLI and server ingestion |
| File thumbnail | — (new) | **Implemented end to end:** `DriveEnvelopeV1` purpose 7 under the file key, bound to file, variant, the content revision it shows and key generation; padded `KTH1` container |
| Public link to one file | — (new) | **Implemented end to end:** `DriveEnvelopeV1` purpose 11 (`PublicLinkFileKey`): a file key of one generation under a link key, object = file, parent = owner, epoch = generation (docs/plans/drive-file-sharing.md, slice 3) |
| File key history | — (new) | **Implemented end to end:** `DriveEnvelopeV1` purpose 10 seals generation *g − 1*'s file key under generation *g*'s; `file_keyring::key_at` walks the chain, so a file's history travels with it between folders (docs/plans/drive-move.md) |
| Folder key history | — (new) | **Implemented end to end:** `DriveEnvelopeV1` purpose 8 seals epoch *e − 1*'s key under epoch *e*'s; `collection_keyring::unlock` verifies the whole owner-signed statement chain and every key commitment (docs/plans/drive-share-revocation.md) |
| Public-link owner copy | — (new) | **Implemented end to end:** `DriveEnvelopeV1` purpose 9 seals a link's key under the owner's Drive root (object = link id, parent = owner, epoch 1, revision = the Drive root's generation), so links can be listed, copied and re-wrapped on rotation, and a new master key moves none of them. Vector: `crypto.json` → `driveOwnerKeys` |
| Encrypted profile | AES-256-GCM nonce/ciphertext | **Implemented end to end:** `ProfileSuiteId = 1` plus account/revision/device/purpose-bound XChaCha `ProfileEnvelopeV1`; suite code accompanies every E2EE profile-key capability; the owner's own copy of the profile key is an account record (`KUTPAR1`, purpose `ChatProfileKeyWrap`) bound to the key binding, the profile version and the revision |
| Identity pins | — (new) | **Implemented end to end:** the account's synced pin list, an `AccountRecordV1` (purpose `IdentityPins`, one per account) under the master key, bound to the account's key binding and the list's revision; pins are keyed by account (server and account id), with addresses kept only as labels. Vector: `identity-pins-v4.json` |
| Contacts | — (new) | **Implemented end to end:** summaries signed by the account authority under `kutup/contact-summary/v2`, and cards as `AccountRecordV1` (purpose `ContactCard`, object the SHA-256 of the UID, which the server checks against the summary), both bound to the account's key binding. Vector: `contact-card-v3.json` |
| Mail folder, label and filter names | — (new) | **Implemented end to end:** `AccountRecordV1` (purpose `MailName`, object the kind and the id) under the master key, bound to the account's key binding. Vector: `mail-names-v3.json` |
| Direct Chat | `DirectChatSuiteId = 1`, libsignal bytes | Unchanged pinned libsignal suite |
| MLS group | MLS `0x0002`, P-256 control and delivery keys | MLS `0x0003`, X25519/ChaCha/Ed25519 throughout Kutup-owned bindings |
| Account device directory | Chat-only `DeviceManifest` plus global transparency proofs | One account-signed `AccountManifestV1` with complete device set, previous hash, history and durable peer pin |
| Chat history backup | Absent; a new browser device starts with an empty local database | **Implemented:** always-on account-local E2EE backup using a master-key-wrapped Chat root, independently derived segment/base/manifest/media keys, signed hash-chained manifests, and server-side base-plus-tail restore; device-to-device transfer is not supported (current contract: [`chat-backup.md`](chat-backup.md)) |
| Broadcast post and grants | Absent | Typed broadcast policy, epoch, account/device grant, history grant and post structures |

`AccountRecordV1` (docs/plans/w1-account-record.md) is encoded as magic
`KUTPAR1\0`, big-endian suite ID (1), big-endian u16 purpose, the big-endian
u32 master-key generation (never 0: the generation of the master key a
password or recovery wrap holds, or of the one that sealed any other record;
docs/plans/w6-key-hierarchy.md §2), big-endian context length, the context
(the account's key binding, a UUID v4, never an email, username or address:
docs/plans/account-identity.md), the object id's length byte and the object
id where the purpose has one record per object, an 8-byte big-endian revision
for a mutable purpose, the 32-byte key commitment, 24-byte nonce, big-endian
ciphertext length, and XChaCha20-Poly1305 ciphertext/tag. The bytes preceding
the ciphertext are the complete AAD. The AEAD key and the key commitment are
two HKDF-SHA256 outputs (salt `kutup/account-record/v1`, infos
`…/key/v1` and `…/commit/v1`) over the header before the commitment; a reader
compares the commitment in constant time before the AEAD, so no record opens
under more than one key (XChaCha20-Poly1305 alone does not commit to its
key). Each purpose has one policy (`AccountRecordPurpose::policy`),
checked on seal, open and by the server: whether it names an object (and its
length), how its plaintext's length shows (`Exact` for keys; `Fixed` or
`Bucket` padding, `0x80` then zeros, applied once by the envelope and checked
canonically on open), its longest padded plaintext (a format limit, never a
site setting) and whether it carries a revision:

| Purpose | Object | Length | Revision |
|---|---|---|---|
| PasswordMasterKey, RecoveryMasterKey, ChatBackupRoot | none | exactly 32 bytes | no |
| MailAddressPrivateKey | none | padded to a multiple of 256 bytes, at most 4096 | no |
| PassVaultSecret | the vault's file id (16 bytes) | padded to one length (`pass_vault::MAX_PAYLOAD_LEN` + 1 = 3121 bytes) | yes |
| OrganizationPrivateKey | the key's id (32 bytes) | exactly 32 bytes | no |
| ContactCard | SHA-256 of the contact's UID (32 bytes) | padded to a multiple of 256 bytes, at most 512 KiB | yes |
| MailName | the kind byte and the 16-byte id | padded to a multiple of 256 bytes, at most 400 bytes | yes |
| IdentityPins | none (one list per account) | padded to a multiple of 256 bytes, at most 4 MiB | yes |
| ChatGroupListEntry | `hashed_object` of the group id (32 bytes) | one length, at most 3972 bytes of plaintext | yes |
| ChatContactListEntry | `hashed_object` of the contact's account (32 bytes) | one length, at most 1988 bytes of plaintext | yes |

A hashed object is `HMAC(K_id, purpose ‖ id)` with `K_id` from the master key
(`kutup/account-record/object-id/v1`), so the server stores an entry under an
id it can't link to a group or a person. Vectors: `chat-group-list-v2.json`,
`chat-contact-list-v2.json`.

Every server write path checks a record with
`account_record::validate_for(purpose, binding, object)` before storing it,
and so rejects noncanonical base64, unknown or retired suites and purposes,
noncanonical context, the wrong purpose, binding or object, a missing or
extra object or revision, a length its policy never gives, and trailing data.
`account-record-v1.json` holds one envelope per purpose and, for each, the
envelopes that must be refused, read by the Rust and the WASM tests.

Contact cards, mail names and identity pin lists are mutable purposes: their
revision is in the record's header, covered by the AAD
(docs/plans/sealed-revisions.md), and all three are padded to a multiple of
256 bytes.

The account's own at-rest formats bind the key binding, never a name, and a
format that bound a name was replaced by a new version with no reader for the
old one (the private beta was reset): identity pins, contact cards and mail
names (now account records), contact summaries `kutup/contact-summary/v1` →
`/v2`, and Chat's wrapped profile key (`kutup/chat-profile/wrap/v1` → `-v2`, now an
account record, `ChatProfileKeyWrap`). Each vector file lists the values that
must be refused: another key binding, the address in place of the binding, a
changed header, nonce or ciphertext, and the old address-bound value.
Statements to other people keep naming the address, because the address is
what they are about: the Drive key binding, named shares and profile key
shares, MLS credentials, the mail key's own address and the peer-facing
profile envelopes. Safety numbers (V2) name only the two authority keys.

**The server name is not in the cryptography** (docs/plans/identity-rotation.md
§6, step 2 of its order). An account's server is a routing attribute:
`AccountRef` `(server, account id)` is the address things are looked up by
(JSON, federation requests, local store keys, pins, the libsignal address
name), and nothing signed, sealed, hashed or derived binds it. Self-statements
bind the 16-byte account id alone (`AccountRef::id_bytes`): the account
manifest's signing bytes (`kutup/account/manifest/v3`) and its identity binding,
safety numbers, the profile envelope (header and subkey), the sealed-delivery
capability, the Drive key binding, the group pseudonym binding and the
collaboration frame signature. Statements between two people bind both ids and
both incarnations: named and file shares, profile-key shares and a shared
mailbox's key shares. A Chat group's id binds its home's identity document
(hash and sequence), not the home's name; the name a pin carries is checked
where the home is reached (its history, fetched from that server, must follow
from the pinned document, which names its server under the home's signature),
before any pseudonym-signed request goes there, so a pin naming another
server with the true document leads nowhere. Nothing is ever looked up by
account id alone.

*Mirror accounts.* With the name unbound, a hostile server B can mint a
victim's account id X and serve the victim's whole public identity as its own
account (B, X): every signature verifies and the safety number is the
victim's. B reads nothing (it lacks the private keys), but a first-time
contact can bind (B, X) as a person, and what it sends then routes to B. The
guard is the synced identity pins' rule that one authority is one account
(`identity_pins::record`'s `AuthorityElsewhere`), checked before anything is
written on each path that takes a peer's identity: Chat's manifest fetch,
Drive's recipient check (which refuses also when the list can't be written)
and Chat's group member check. A client that never met the victim can't tell
the mirror apart, as with any first contact, and an in-person comparison of
the safety number doesn't either. This rule is load-bearing.
The routing form in binary (`AccountRef::routing_bytes`: u16 server length,
server, id) remains only where a server names an account beside a payload
(`envelope::deliver`) and as a store key (the Chat contact-list entry id).
Not moved yet: the organization documents (`KUTPOC1`, `KUTPOS1`, `KUTPOR1`,
`KUTPOE1`) still name their parties in the routing form, until the escrow's
next format change; group requests to a home (`group_route`) bind the home
they are addressed to, as an HTTP signature binds its audience. A Chat
group's member, slot and ban entries (`GroupMemberEntryV1`,
`GroupSlotEntryV1`, `GroupBannedAccountV1`) keep a full `AccountRef` inside
the signed, sealed group state: routing, consistent with §6 (the member
binding itself signs the id alone), but it goes stale on a server rename,
until the group state is rewritten with the new name.

`DriveEnvelopeV1` is encoded as magic `KUTPDE1\0`, big-endian suite ID,
purpose, zero reserved byte, epoch, revision, 16-byte object UUID, 16-byte
parent UUID, 24-byte nonce, exact ciphertext length, and XChaCha20-Poly1305
ciphertext/tag. The fixed header is AAD. Its stable scope also feeds
HKDF-SHA256, so raw Drive-root/collection/file/link roots are never AEAD keys
and each purpose, object, parent, epoch and revision has a distinct derived
key. The account's own copies, an owned folder's key (purpose 1) and a link's
key (purpose 9), are sealed under its stored Drive root, never under the
master key: the revision slot carries the Drive root's generation (purpose 1's
epoch is the folder key's, purpose 9's is 1). That meaning of the slot is
frozen for both purposes. The generation is never 0 (the context
constructor refuses 0, as `RootGeneration` does) and, like every header
field, it is in the AEAD associated data and in the HKDF info of the
envelope's key, so a server can't relabel an envelope as another
generation. After a future Drive-root
rotation a reader picks the root by the header, and a master-key rotation
re-wraps only the root's record. Only the typed exports
(`sealOwnerCollectionKey`, `sealOwnerLinkKey` and their openers) seal or open
them; the generic WASM export refuses both purposes. The top-level name hash
key comes from the current Drive root (`drive_names::top_level_hash_key`,
same label and derivation as under the master key), and each top-level
folder records the root's generation next to its hash
(`collections.name_hash_generation`, sent as `nameHashGeneration`), so a
reader knows which key made it; a Drive-root rotation rehashes the top level
(the rotation flow).

A file blob is `[header][blocks][sealed manifest][trailer]` in the block
format (docs/plans/drive-block-format.md §2). The 48-byte header is magic
`KUTPDB3\0`, big-endian Drive object suite 2, file-blob purpose, zero
reserved byte, the non-zero generation of the file key that sealed it, the
file UUID and the revision UUID the client chose. It names no folder, so a
file moves without re-encryption (docs/plans/drive-move.md). HKDF-SHA256
derives the block, nonce and manifest keys from the random file key using
the header as info. Each 4 MiB XChaCha20-Poly1305 block is bound to the
header, its index and whether it is the last; the sealed manifest carries
the block hashes, the plaintext size and the uploader's Ed25519 signature,
and fixes the size and the end. Truncation, trailing bytes and
file/generation/revision relocation fail closed. Multipart, tus, snapshot
and signed-federation ingestion validate the exact public header and the
structure (from the trailer and the length) before a revision is stored.
The streaming format before it (`KUTPDB2`, a secretstream with 5 MiB
frames, suite 1) was removed with the clean-slate wipe.

A file's key is wrapped under its folder's key as a purpose-3 envelope: object
= file, parent = folder, epoch = the folder epoch it is sealed at, revision =
the file key's generation. It is the only file object that names the folder;
moving a file re-seals it alone. The metadata (purpose 4) is sealed under the
file key with object = parent = file, epoch = key generation and revision =
metadata revision. Its plaintext is `FileMetadataV2` (`kutup-crypto`
`file_metadata`, vector `fileMetadata`): canonical JSON `{ name, mimeType,
size, content, originalRevisionId?, stateRevisionId?, sha256?, media? }`,
where `content` commits to the current revision and its sealed manifest's
SHA-256, decoded strictly (unknown fields and out-of-range values
refused) by the browser (WASM) and the CLI alike. `media` holds a photo's or
video's details (docs/plans/photos.md): when it was taken (UTC ms, the time
zone in minutes, and where the date came from), place, size on screen,
length, camera, a SHA-256 content hash, a caption and, for a live photo's
video, `liveOf` (its still's file id).

An album item is a photo's file key sealed under the album key as Drive
envelope purpose 12 (`AlbumFileKey`): object = file, parent = album, epoch =
the album's key epoch, revision = the file key's generation.

The Photos library record (`kutup-crypto` `photos_library`, vector
`photosLibrary`) is one chained account record (`KUTPAR1`, purpose
`PhotosLibrary`) under the master key, bound to the account's key binding;
its object is the account incarnation, and its header names the revision and
the previous record's SHA-256, which the server checks for compare-and-swap.
The plaintext is padded to 256-byte buckets. The plaintext is
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
bind the collection UUID, epoch, the sender's and recipient's account ids
(16 bytes each, never a server's name; the encoding carries the ids only, the
servers are the routing context it is checked in), and both account
incarnation IDs. The sender key is the manifest-bound Drive share
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
incarnation IDs and both account ids (16 bytes each), but no folder: one key serves
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
domain (`kutup/collab/frame/v3\0`), the sender's account id (16 bytes), the
header and the ciphertext; the trailing signature is not self-covered. The
account travels beside the frame in its routing form, unsigned
(`envelope::deliver`). The server accepts only the exact
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
profile-key-derived version, the owner's 16-byte account id (never the
server's name), 24-byte nonce and exact ciphertext length. The complete
fixed-length header is AAD. A
purpose-specific HKDF-SHA256 subkey binds the same context before
XChaCha20-Poly1305. Name padding remains the fixed 53/257-byte Signal-style
buckets; avatars are limited to 512 KiB. The profile suite code travels beside
the profile key inside encrypted Direct Chat content, and unknown codes do not
authorize a profile fetch.

Chat backup uses `ChatBackupRootV1`, wrapped with the Chat-backup purpose of
`AccountRecordV1`. Fixed HKDF-SHA256 labels derive independent message,
media-ID, media-encryption, manifest-signing and segment keys. Typed headers
bind every XChaCha20-Poly1305 object and block-format media object to its suite, account,
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
