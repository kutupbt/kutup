# Post-quantum shares: X-Wing instead of X25519

Status: accepted (user, 2026-10-18), with the one-way identity suite upgrade
below. Next: the build, in the order at the end.
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
  - Rule: within one incarnation the key changes only through the one-way
    suite upgrade below (a higher suite, consecutive manifests, the same
    authority). An account never holds both keys at once.
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

## Existing data and the upgrade

Read-only counts on kutup.dev (2026-10-18):
- every share table is empty: `collection_shares`, `federated_outgoing_shares`,
  `federated_incoming_shares`, `file_shares`, `federated_outgoing_file_shares`,
  `drive_profile_keys`, `mail_group_key_shares` and `mail_group_signing_shares`
  all have 0 rows;
- 3 users have an X25519 Drive key, with its binding and wrapped private key;
- there are 2 manifests and 3 history entries.

So no envelope has to move. The 3 accounts' keys do, and that must not need a
wipe. It can't be done by editing the key in place. Chat-core refuses a
changed Drive key within one incarnation (`manifest.rs:290-297`), and the
server only writes the Drive key at first-login setup (`auth.rs:1527-1545`)
or in an admin wipe.

The fix is a **one-way identity suite upgrade**: durable, and the only path
from suite 1 to suite 2. It isn't a shim, because no X25519 reader is kept.
Everything is derived again from the master key.

1. **Client, at its next sign-in.** A client that finds its account on suite
   1 derives the X-Wing seed and public key. It then signs a suite-2 binding
   with the **unchanged** authority key.
2. **Server: `POST /api/account/identity-suite`.** The body carries the new
   public key, the suite-2 binding and the new wrapped private key (the
   seed). The server checks that:
   - the binding verifies under the account's current authority key, at
     epoch 1 (the first suite-2 binding; any other epoch is `400`);
   - the suite **strictly increases**;
   - the key is 1216 bytes;
   - the account isn't in its first-login setup (that registers suite 2).

   It then replaces `public_key`, `drive_key_binding` and
   `drive_private_key_envelope` in one transaction under the account lock. A
   lower or equal suite is refused, so it can never go back.
3. **Manifest.** The client publishes its next manifest (sequence + 1) with
   `XWingEd25519V2`. The server requires it to match the new `public_key` as
   it does today, and takes the Drive keys' change from the stored manifest
   only as this rise: from suite 1 with a 32-byte key to X-Wing, the signing
   key unchanged, linked to the stored manifest (the same rule as chat-core's).
   A peer that sees the rise across a sequence gap treats it as a gap to
   recover: the manifest history must show it in a linked step.
4. **Chat-core's pin rule.** A Drive key change within one incarnation is
   accepted only when all of these hold:
   - the suite rises;
   - the two manifests link consecutively;
   - the authority key is the same.

   Anything else is still refused as it is now.
5. **Until an account has upgraded**, lookups of it say `keysPendingUpgrade`,
   and sharing to it is refused with that code. Nothing is sealed to an
   X25519 key again.
6. **Afterwards.** Once every account has upgraded (verified by count, as for
   these 3), a migration enforces 1216-byte keys. The suite-1 paths then go,
   the upgrade endpoint included.

**Binding replay.** A binding has no epoch today
(`drive_key_binding.rs:24-43`), so after a suite change the server could serve
an older, still validly signed binding. The suite-2 binding therefore carries
a monotonic `epoch` (u32, starting at 1) beside the suite. Clients remember
the highest `(suite, epoch)` they have seen per contact, in their pins and
manifest trust, and refuse a lower one as a rollback.

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

## Web and WASM (as built)

- **Same exports, new byte strings.** The WASM exports keep their names; the
  keys and envelopes they carry change size. `sign/verifyDriveKeyBinding`
  take the binding epoch as their last argument
  (`FIRST_DRIVE_KEY_BINDING_EPOCH` = 1 at registration and at the upgrade).
- **The upgrade, where a session starts** (`packages/session/src/identitySuite.ts`,
  called by `activateSession`: a sign-in, a session handed to another app,
  and one restored from this browser). When the server still publishes
  another Drive key than the X-Wing one the master key derives, the keys are
  derived again (`currentDriveKeys`), their binding is signed at epoch 1,
  the seed is sealed under the account's key binding, and
  `POST /account/identity-suite` goes with the session's token before the
  session is active; the activated (and persisted) keys are the new ones.
  `identitySuiteCurrent` means another device did it first, with the same
  keys. A failure keeps the old keys, and the next session start tries
  again. So a failed upgrade at sign-in, or a session from before the
  deploy, is upgraded before Chat starts.
- **The manifest.** Chat-core's `sync_own_manifest` signs a next manifest
  whenever the published one carries other Drive keys than the account's
  (`AccountAuthority::drive_keys`), so Chat publishes the X-Wing key the next
  time it starts.
- **Lookups.** Drive and Mail read `identitySuite` and
  `driveKeyBindingEpoch` from every lookup. A binding counts only on suite 2,
  verified at its epoch. A suite-1 account shows as not confirmed yet
  (`unproven`), never as invalid.
- **Nothing sealed to suite 1.** Every seal to a person goes through
  `confirmRecipient` or `sealableDriveKey`, which throw `KeysPendingUpgrade`
  (code `keysPendingUpgrade`) before any sealing: new shares, re-seals at a
  folder or file key rotation, permission changes, federated members and
  mail group members. Profile keys wait until the account has upgraded.
- **Messages.** `apiErrorMessage` says `keysPendingUpgrade` and
  `peerOutdated` in the user's language (`apiErrors.*` in the shared
  locales), from the server's answer or from the client's own refusal.
- **A removal and suite-1 members** (the user's decision, 2026-10-19). A
  rotation (removing someone from a folder, file or album) can't seal the
  new key to a remaining member still on suite 1. It stops first with
  `MembersPendingUpgrade`, naming them; the owner confirms
  (`PendingUpgradeConfirm`: "they haven't signed in since the security
  upgrade; they lose access; share again after they sign in"), and the same
  rotation removes them too, in its one request. The confirmation covers
  exactly the people it named: anyone else who turns up meanwhile is asked
  about again, and anyone who upgraded meanwhile stays. One dormant member
  never blocks a removal.
- **Catch-up re-seals** (a file's shares brought to its current key) leave
  suite-1 members and federated recipients behind, the pending state the
  server keeps, until they have signed in again; the next catch-up then
  reseals them. Changing a suite-1 member's permissions says why it can't.
- **Pins and the binding epoch.** Pins don't record the binding epoch yet:
  only epoch 1 exists, so there is nothing to roll back to. It goes into the
  pin format before a second epoch can be signed.
- **Spec 162** (account suite; it needs `E2E_PSQL` and `E2E_SUITE1_ACCOUNT`,
  the dev tool that makes a real suite-1 account, Chat manifests included)
  starts from an account that used Chat, turned suite 1. A share to it is
  refused with the message; it signs in again; `identity_suite = 2` with a
  1216-byte key, Chat starts and its current manifest is suite 2; then the
  share goes through. CI's single-server job sets only `E2E_PSQL`, so there
  it is skipped; the local account gate runs it.

## Details from review

- **No `derive_key_pair`.** hpke-rs's `derive_key_pair` hashes its input with
  SHAKE first (`kem.rs:153`), so it is never used. Everywhere (Rust, WASM, CLI)
  the key comes from HKDF → the 32-byte seed → `x_wing::DecapsulationKey::from`,
  as `oblivious.rs` does.
- **The backend's own warning.** hpke-rs-rust-crypto calls its post-quantum
  KEMs "broken and pre-releases" (`lib.rs:203-204`). So beside the draft's
  KEM vectors we keep:
  - HPKE-level known-answer tests;
  - a cross-check against `hpke-rs-libcrux` as a dev-dependency only, if
    cargo deny allows it there. If deny doesn't allow it, the libcrux-made
    vectors are checked in, as `oblivious-v1.json` already is.
- **Mail group shares.** Their HPKE info (the domain) moves to `/v2`
  (`kutup/mail-group-key-share/v2\0`, `kutup/mail-group-signing-share/v2\0`),
  and the version byte becomes 2.
- **Named shares get a database cap** like the others: `CHECK
  (length(named_share_envelope) <= 4096)` on `collection_shares`,
  `federated_outgoing_shares` and `federated_incoming_shares`, which have none
  today (baseline lines 2053, 2250 and 2318).
- **Mail group key shares.** `mail_group_key_shares` is measured again if group
  keys gain a v6 key ([`mail-pq-openpgp.md`](mail-pq-openpgp.md)).
- **Remaining 32-byte assumptions** to change:
  - `drive_key_binding`'s buffer capacity (32 × 4);
  - `profile_key_share.rs:24` and `:151` (`SUITE_V1`);
  - WASM `public_key_32` (`lib.rs:2943` and the others);
  - `drive_federation.rs:291`;
  - chat-proto's "raw X25519" doc comment.

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

1. **kutup-crypto:** the shared helper, the envelopes, identity derivation, and
   the binding with its epoch. Then chat-proto (the manifest suite) and
   chat-core's pin rule for a rising suite.
2. **Server:** the suite-upgrade endpoint, `keysPendingUpgrade`, lengths,
   limits, the migration, and federation checks with their clear errors.
3. **WASM exports and the CLI**, the CLI upgrading its account at sign-in as
   the web client does.
4. **The web client** (third session).
5. **Gates**, an upgrade from a suite-1 account included.
6. **Afterwards:** once every account is on suite 2 (counted), a migration
   enforces 1216-byte keys, and the suite-1 paths go.
