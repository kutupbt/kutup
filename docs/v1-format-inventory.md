# V1 cryptographic format inventory

**Status:** normative pre-tag cutover inventory

This inventory names every persistent or federated ciphertext family that the
V1 cutover must replace or freeze. Kutup is preproduction, so legacy rows,
development object storage and browser databases are recreated rather than
dual-written. This destructive rule expires at the first stable `v*` tag.

| Purpose | Pre-V1 shape | V1 owner and format |
|---|---|---|
| Master-key password wrap | XSalsa20 secretbox plus separate nonce; implicit Argon parameters | **Implemented:** `AccountProtectionSuiteId` plus suite-bearing `AccountEnvelopeV1`, XChaCha and persisted Argon2id parameters |
| Master-key recovery wrap | XSalsa20 secretbox under random recovery entropy | **Implemented:** `AccountEnvelopeV1` with recovery purpose, canonical account context and XChaCha |
| Account sharing private key | XSalsa20 secretbox; public X25519 key stored separately | **Implemented:** account-scoped Drive keys in `AccountManifestV1`; private material wrapped by the Drive-private-key purpose of `AccountEnvelopeV1` |
| Collection name/key | Separate ciphertext/nonce columns with implicit secretbox | **Implemented end to end:** client-generated collection UUID, `DriveEnvelopeV1` owner-key/name records, immutable `CollectionEpochStatementV1` history and exact revision/epoch binding |
| File metadata/key | Separate ciphertext/nonce columns with implicit secretbox | **Implemented end to end:** client-generated file UUID plus `DriveEnvelopeV1` records bound to file, collection, exact revision and authenticated collection epoch across multipart, tus, trash, public-link and signed-federation paths |
| File blob and version snapshot | Raw secretstream header/chunks, or nonce-prefixed snapshot AEAD | **Implemented end to end:** one `DriveObjectSuiteId` file-blob format for originals and text/office/whiteboard snapshots, with 5 MiB secretstream framing bound to file, collection and epoch |
| Local/federated named share | Anonymous `crypto_box_seal` bytes | **Implemented end to end:** one `NamedShareEnvelopeV1` format for local and signed-federation routes, X25519 HPKE plus account-manifest-bound Ed25519 sender signature |
| Public-link collection wrap | Secretbox under link key plus separate nonce | **Implemented end to end:** public-link purpose `DriveEnvelopeV1` bound to collection, owner and epoch; the independent link capability remains only in the URL fragment |
| Collaborative frame | XChaCha frame with `doc_key_id`, device and sequence | **Implemented end to end:** canonical Rust `CollabFrameSuiteId = 1`, 96-byte authenticated context header, purpose-derived XChaCha key and Ed25519 signature; browser uses the Rust parser/KDF/AEAD through WASM |
| Whiteboard asset | XChaCha with asset AAD | **Implemented end to end:** `DriveEnvelopeV1` whiteboard-asset purpose bound to file, collection, epoch and asset ID across browser, CLI and server ingestion |
| Encrypted profile | AES-256-GCM nonce/ciphertext | **Implemented end to end:** `ProfileSuiteId = 1` plus account/revision/device/purpose-bound XChaCha `ProfileEnvelopeV1`; suite code accompanies every E2EE profile-key capability |
| Direct Chat | `DirectChatSuiteId = 1`, libsignal bytes | Unchanged pinned libsignal suite |
| MLS group | MLS `0x0002`, P-256 control and delivery keys | MLS `0x0003`, X25519/ChaCha/Ed25519 throughout Kutup-owned bindings |
| Account device directory | Chat-only `DeviceManifest` plus global transparency proofs | One account-signed `AccountManifestV1` with complete device set, previous hash, history and durable peer pin |
| Chat history transfer | Absent; a new browser device starts with an empty local database | `ChatHistoryTransfer*V1` two-device signed ephemeral-X25519 handshake, transcript-bound XChaCha frames and destination-signed completion; imported display history never includes live ratchet state |
| Broadcast post and grants | Absent | Typed broadcast policy, epoch, account/device grant, history grant and post structures |

`AccountEnvelopeV1` is encoded as magic `KUTPAE1\0`, big-endian suite ID,
purpose byte, zero reserved byte, big-endian context length, canonical lowercase
login email, 24-byte nonce, big-endian ciphertext length, and XChaCha20-Poly1305
ciphertext/tag. The bytes preceding the ciphertext are the complete AAD. The
server rejects noncanonical base64, unknown suites/purposes, noncanonical
context, wrong purpose/account binding, wrong plaintext size and trailing data.

`DriveEnvelopeV1` is encoded as magic `KUTPDE1\0`, big-endian suite ID,
purpose, zero reserved byte, epoch, revision, 16-byte object UUID, 16-byte
parent UUID, 24-byte nonce, exact ciphertext length, and XChaCha20-Poly1305
ciphertext/tag. The fixed header is AAD. Its stable scope also feeds
HKDF-SHA256, so raw master/collection/file/link roots are never AEAD keys and
each purpose, object, parent, epoch and revision has a distinct derived key.

A V1 file blob is `[DriveFileBlobHeaderV1][secretstream header][frames]`.
The 48-byte Drive header is magic `KUTPDB1\0`, big-endian
`DriveObjectSuiteId`, file-blob purpose, zero reserved byte, non-zero epoch,
file UUID and collection UUID. HKDF-SHA256 derives a purpose key from the
random file key using the fixed header as info. The same header is associated
data for every 5 MiB secretstream frame. Every blob, including an empty file,
contains an authenticated `TAG_FINAL` frame; truncation, trailing frames and
file/collection/epoch relocation fail closed. Multipart, tus, snapshot and
signed-federation ingestion validate the exact public header before storage.

`CollectionEpochStatementV1` is a fixed-width account-authority-signed record
over suite, collection UUID, owner UUID, non-zero epoch, exact previous-record
hash, collection-key commitment and authority-key ID. Epoch 1 has an all-zero
previous hash; later epochs require an exact predecessor. Its record hash
covers the original signed statement unchanged. The server verifies identity,
signature and continuity; a client also verifies the key commitment before it
uses a collection key.

`NamedShareEnvelopeV1` uses the fixed RFC 9180
DHKEM(X25519)/HKDF-SHA256/ChaCha20-Poly1305 suite. Its AAD and Ed25519 signature
bind the collection UUID, epoch, canonical sender and recipient accounts, and
both account incarnation IDs. The sender key is the manifest-bound Drive share
signer; the recipient key is the manifest-bound Drive HPKE key. V1 intentionally
provides no anonymous Drive sharing.

`CollabFrameSuiteId = 1` uses magic `KUTPCF1\0` and a fixed 96-byte
big-endian header containing suite, kind, collection-key epoch, document-key
generation, file UUID, collection UUID, sender device, sequence, nonce and
exact ciphertext length. The header is AEAD associated data. HKDF-SHA256 binds
the same suite, kind, epoch, document generation and UUIDs into a distinct
XChaCha20-Poly1305 key. Ed25519 signs the header and ciphertext; the trailing
signature is not self-covered. The server accepts only the exact current
file/collection/epoch/document binding and a registered sender device.

Whiteboard assets use `DriveEnvelopeV1` purpose 6. The object UUID is the file
UUID; the parent binding is a fixed-label SHA-256 commitment to the collection
UUID and canonical asset ID. Epoch and revision 1 are authenticated in the
normal Drive envelope header. Plaintext is limited to 25 MiB and the server
validates the complete public envelope before quota or object-storage mutation.

`ProfileEnvelopeV1` uses magic `KUTPPE1\0`, `ProfileSuiteId`, a closed purpose
(display name, avatar or wrapped profile key), revision, source device,
profile-key-derived version, canonical federated account, 24-byte nonce and
exact ciphertext length. The complete variable-length header is AAD. A
purpose-specific HKDF-SHA256 subkey binds the same context before
XChaCha20-Poly1305. Name padding remains the fixed 53/257-byte Signal-style
buckets; avatars are limited to 512 KiB. The profile suite code travels beside
the profile key inside encrypted Direct Chat content, and unknown codes do not
authorize a profile fetch.

`ChatHistoryTransferRequestV1` and `ChatHistoryTransferAcceptanceV1` use
domain-separated, big-endian canonical signing encodings and XEdDSA signatures
from the two exact manifest-bound libsignal identity keys. Their transcript
hash salts an ephemeral-X25519/HKDF transfer key. Each opaque relay frame uses
a fresh XChaCha nonce and AAD binding transfer ID, transcript hash, index,
finality and plaintext size. The destination-signed completion binds the frame
and record counts plus the ordered plaintext digest. V1 hard-limits a transfer
to 15 minutes, 1,024 frames, 100,000 records and 256 MiB plaintext.

Every V1 structure has a numeric typed suite, a fixed domain separator,
canonical big-endian length-prefixed signing/AAD encoding, deterministic test
vectors, strict byte limits and an explicit unknown-suite error. JSON is a
transport representation only and is never the signed encoding.

After V1, an old suite may remain readable while migration is active, but new
writes use exactly one locally allowed suite. Federation advertises supported
suites and returns `NoCommonSuite`; it never silently retries a legacy format.
