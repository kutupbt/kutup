# Post-quantum shares: X-Wing instead of X25519

Status: note for review (2026-10-18). This follows the user's decision from the
post-quantum audit. Next steps: the main session reviews it, then the user,
then the build starts.
- Clean-slate rule: no shims and no dual formats.
- Production has been live since the 2026-10-17 wipe with almost no data. The
  counts in "Existing data" decide what happens to any old envelope.

## What changes

Every HPKE envelope that is sealed to a person moves from DHKEM(X25519) to
X-Wing (X25519 + ML-KEM-768, draft-connolly-cfrg-xwing-kem-06, HPKE KEM
0x647a). KDF and AEAD stay as they are (HKDF-SHA256, ChaCha20-Poly1305).
- **Why:** a share recorded today must stay closed to a quantum computer later.
  Signatures stay Ed25519: a forged signature can't be made after the fact.
- **One suite in one place.** `kutup-crypto` gets a single X-Wing HPKE helper.
  The groups' gateway (`oblivious.rs`, the X-Wing PR) and every envelope below
  call it. The dependencies are the ones that PR settles on: `hpke-rs` 0.6.1
  with `hpke-rs-rust-crypto`'s post-quantum KEMs, over the released `x-wing`
  0.1.1 and `ml-kem` 0.3.3, pinned exactly. It is checked against the draft's
  vectors.

| Envelope | Code | Carries | Crosses servers |
|---|---|---|---|
| Named share `NamedShareEnvelopeV1` (`KUTPNS1`) | `named_share.rs` | a folder, album or collection key → a person (Drive, Photos, Office) | yes (invites, refresh) |
| File share `FileShareEnvelopeV1` (`KUTPFS1`) | `named_share.rs` | one file's key → a person | yes (`file-invite`) |
| Profile key `ProfileKeyEnvelopeV1` (`KUTPPK1`) | `profile_key_share.rs` | the Drive profile key between people who share | yes (`profile-keys`) |
| Mail group key share | `mail_key.rs` `seal_group_key_share` | a shared mailbox's key → a member | no (members are local) |
| Mail group signer share | `mail_group.rs` `seal_group_signing_share` | a shared mailbox's signer → a member | no |

The envelope layouts stay as they are, with three exceptions:
- the suite id becomes **2** (X-Wing, HKDF-SHA256, ChaCha20-Poly1305, Ed25519);
- `enc` is 1120 bytes instead of 32;
- a decoder refuses suite 1, so there is one format, with no reading of the old.

The mail shares' fixed 65-byte header becomes 1 + 32 + 1120 bytes, with the
version byte set to 2.

**Out of scope:**
- MLS anonymous delivery (`chat-core` `mls_engine/delivery.rs`, per-device
  X25519) and MLS itself. MLS groups are being replaced by pairwise groups and
  were never enabled, so they go with MLS rather than being migrated.
- OpenPGP mail keys: [`mail-pq-openpgp.md`](mail-pq-openpgp.md).
- libsignal (PQXDH already uses ML-KEM).

## The recipient's key

Today `identity.rs` derives the Drive HPKE key from the master key like this:
1. HKDF with the salt `kutup/account-identity/v1\0`, expanded under
   `kutup/account-identity/drive-hpke-x25519/v1\0`, gives a 32-byte seed.
2. dryoc's `crypto_box_seed_keypair` turns that seed into the X25519 pair.

Instead:
- **Derivation.** The same HKDF, under a new label
  `kutup/account-identity/drive-hpke-xwing/v1\0`, gives the 32-byte **X-Wing
  seed**. The seed is the decapsulation key (draft-06), and its 1216-byte
  public key is derived from it. The old label goes, with no second key beside
  it.
- **Private key at rest.** `users.drive_private_key_envelope`
  (`AccountEnvelopePurpose::DriveHpkePrivateKey`, `Exact(32)`) keeps its shape
  and now holds the seed. Sign-in and session forks carry 32 bytes as before.
- **Public key.** `users.public_key` holds the 1216-byte key, base64 at 1624
  characters. Nothing caps that column.
- **Drive key binding** (`drive_key_binding.rs`). The suite becomes **2**
  ("X-Wing + Ed25519"), and the signed message carries the 1216-byte key. Its
  layout is otherwise unchanged: domain, AccountRef, incarnation, authority key,
  suite, HPKE key, signing key.
- **Chat account manifest** (`AccountManifestV1.drive`). This gets a new
  `AccountIdentitySuiteId::XWingEd25519V2` with a 1216-byte `hpkePublicKey`, and
  the server still requires it to equal `users.public_key`. Clients pin it in
  `manifest_trust.drive_hpke_public_key` (chat-core SQLite and IndexedDB).
  - Rule: within one incarnation the key never changes. A suite change is a
    clean slate, so no account carries both keys.
- **Identity pins** hold only the authority key, which signs the binding.
  Nothing changes in the pins: a pinned contact's new X-Wing key verifies
  through the binding exactly as the X25519 one did.

## Server

- **Lengths.** The 32-byte checks become 1216 in:
  - `auth.rs` (`validate_account_identity`, `verify_drive_key_binding`);
  - `folder_access.rs`;
  - `drive_federation.rs` (`remote_keys_consistent` and the lookups);
  - chat-proto's manifest decoding;
  - the seal-time checks in `named_share.rs`, `profile_key_share.rs` and
    `mail_key.rs`;
  - the WASM `public_key_32` helpers and the CLI `key32`.
- **Limits.** A named or file share grows to about 1.4 KB, which is about 1,860
  base64 characters for kutup.dev's names. Two limits must move:
  - `MAX_ENVELOPE_CHARS` (`file_shares.rs`, `drive_profile_keys.rs`) and the
    CHECKs on `file_shares.share_envelope`,
    `federated_outgoing_file_shares.share_envelope` and
    `drive_profile_keys.envelope` rise from 2048 to 4096. At 2048 they would
    fail for long server names.
  - `mail_group_signing_shares.share` (≤ 1024 today) must rise: its share
    becomes 1,201 bytes. A cap of 2048 fits it.
- **Migration.** One migration raises those CHECKs. What it does with existing
  rows depends on the counts below; it contains no conversion code.

## Existing data (read-only counts on kutup.dev, before deciding)

Old envelopes can't be opened by the new code, and the old public keys can't
be sealed to. These columns hold them:

| table.column | holds |
|---|---|
| `users.public_key`, `users.drive_key_binding`, `users.drive_private_key_envelope` | the X25519 key, its binding, the wrapped private key |
| `chat_device_manifests.manifest`, `chat_device_manifest_history.manifest` | `drive.hpkePublicKey` (jsonb) |
| `collection_shares.named_share_envelope` | named shares |
| `federated_outgoing_shares.named_share_envelope`, `federated_incoming_shares.named_share_envelope` | named shares across servers |
| `file_shares.share_envelope`, `federated_outgoing_file_shares.share_envelope` | file shares |
| `drive_profile_keys.envelope` | profile-key shares |
| `mail_group_key_shares.share`, `mail_group_signing_shares.share` | shared-mailbox shares |

**If any of these hold rows**, every affected account needs new keys, which
only its own client can make (they come from the master key). The choices
are:
- (a) another wipe;
- (b) the client re-derives and re-publishes at its next sign-in, and every
  share to it is made again by its owner.

Choose once the counts are in. No fallback reader is built either way.

## Federation

- **Keys crossing servers.** The 1216-byte key crosses servers in
  `AccountLookupResponse.drive_hpke_public_key` (`/api/fed/drive/users/…`,
  `/accounts/…`) and in the Chat manifests.
- **Envelopes crossing servers.** Named, file and profile-key envelopes cross
  as opaque base64. Only their size limits move.
- **Mixed versions.** A server on the old version refuses a 1216-byte key, and
  a new one refuses a 32-byte key. Each side answers clearly ("the peer's Drive
  key is not this version's"), and the check logs it. Self-hosted peers upgrade
  together, which `docs/self-hosting.md` (Updating) will say.

## Web and WASM (third session's area, after #242/#245)

- **Same exports, new byte strings.** The WASM exports keep their names. Only
  the keys and envelopes they carry change size:
  - `deriveAccountIdentityKeys`
  - `seal/openNamedShareEnvelope`, `seal/openFileShareEnvelope`,
    `seal/openProfileKeyEnvelope`
  - the mail group share functions
  - `sign/verifyDriveKeyBinding`
- **TypeScript changes.** TypeScript changes only where it assumes 32 bytes
  for a Drive HPKE public key:
  - drive-core's `identityPins.ts`, `access.ts`, `people.ts` and
    `fileShares.ts`;
  - mail-core's `groups.ts`;
  - the session's stored key, which is unchanged at 32 bytes since it is the
    seed;
  - any IndexedDB schema that sizes `drive_hpke_public_key`.
- **Before the TypeScript work.** The third session gets the list of call sites
  with the PR.

## Tests

- **Vectors.** `crypto.json`, `identity-pins-v3.json`, the mail group share
  vectors and the named, file and profile vectors are regenerated:
  - derivation from a fixed master key yields a fixed X-Wing public key;
  - envelopes are recorded and reopened byte for byte;
  - suite 1 is refused.
- **WASM.** The same vectors run in WASM.
- **Gates.** Live tests run through both gates: shares to a person, across
  servers, and shared mailboxes.

## Order of the build

1. **kutup-crypto:** the shared helper, the envelopes, identity derivation and
   the binding. Then chat-proto (the manifest).
2. **Server:** lengths, limits, the migration, and federation checks with their
   clear errors.
3. **WASM exports and the CLI.**
4. **The web client** (third session).
5. **Gates.**
