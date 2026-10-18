# Mail: post-quantum OpenPGP, following Proton

Status: note for review (2026-10-18), from the user's post-quantum audit. Next:
the main session, then the user; only then the build. Rule
([`mail-address-keys.md`](mail-address-keys.md)): copy Proton's answer where it
has one; where its code doesn't show one, say so and propose ours.

## What Proton does (read from its code)

Sources:
- `kutup-references/WebClients` at 4c408125 (2026-09-23);
- the npm packages it builds with: `@protontech/crypto` 2.1.3 (pmcrypto) and
  `@protontech/openpgp` 6.3.1;
- gopenpgp's `profile/preset.go`;
- ProtonMail/go-crypto's `packet.go` and `key_generation.go`.

The backend isn't public.

- **Two keys per address, v4 kept.** New accounts get v4 Curve25519, as Kutup
  has now (`constants.ts:904-919`). Post-quantum is opt-in, behind the
  `CryptoPostQuantumOptIn` flag and `UserSettings.Flags.SupportPgpV6Keys`.
  Opting in adds a **v6 key** beside the v4 one:
  - an ML-DSA-65+Ed25519 primary (algorithm 30);
  - an ML-KEM-768+X25519 encryption subkey (algorithm 35), per
    draft-ietf-openpgp-pqc-10, now RFC 9980, with the `OpenPGPCompositeKDFv1`
    combiner.
  - Keys come in v4 and v6 sets: one v4 primary, at most one v6 primary
    (`getPrimaryKey.ts:12-22`).
  - Proton never makes PQ v4 keys or non-PQ v6 keys. Web uses no SLH-DSA.
  - gopenpgp's `PQC()` preset: v6, ML-DSA-65+Ed25519, AES-256, AEAD (GCM),
    Argon2 S2K.
- **Published together.** The signed key list carries both keys, v6 after v4
  (`signedKeyList.ts:49-50`).
- **Proton to Proton.** Email prefers the recipient's primary v6 key, else the
  v4 one. The sender doesn't need to have opted in (`encryptionPreferences.ts:65`,
  `sortApiKeys` in `publicKeys.ts:52-127`). Calendar and other non-email uses
  stay on v4.
- **Signatures stay v4.** Outgoing mail is signed with the v4 key only.
  v6 signatures break RNP and older gopenpgp (`useGetMessageKeys.ts:17-20`).
- **Outside senders.** The attached public key is always the v4 one, since
  "the v6-PQC one is not standardized" (`messageAttachPublicKey.ts:42`). What
  WKD and the public keys API serve to outsiders is backend code: **not
  found**.
- **Mail arriving unencrypted.** Which key the server encrypts it to on
  arrival: **not found** (backend). The client encrypts its own drafts to the
  v6 primary when there is one.
- **The cost of opting in, in Proton.** End-to-end forwarding (proxy
  re-encryption, v4 only) is turned off, and old recovery files stop working.

## Ours

Kutup writes every client, so PQ isn't opt-in here. Every address gets
both keys from the start, with the same shapes as Proton:
- **The v4 key, unchanged.** Ed25519 (EdDSALegacy) primary and Curve25519 ECDH
  subkey. It's what outside senders and outside verifiers use.
- **The v6 key.** ML-DSA-65+Ed25519 primary and ML-KEM-768+X25519 subkey, with
  AES-256, SEIPDv2 (AEAD) and SHA3 preferences, as Proton's v6 keys.

Who uses which key:
- **Kutup to Kutup**, within a server or across servers: encrypt to the
  recipient's v6 subkey, Proton's rule for email.
- **Outside senders** get the v4 key. WKD, the attached key and the keys we
  publish carry v4 only. Proton's own WKD behaviour isn't in its code; v4-only
  is what its client attaches, and v6 keys break common readers.
- **Signatures:** the v4 key only, as Proton, for outside readers. A
  Kutup-only signature in v6 would add nothing Proton has.
- **Mail arriving unencrypted** (proposal, Proton's code doesn't show it):
  encrypted on arrival to the address's **v6** subkey. Only Kutup clients
  open stored mail, and they all read v6, so stored mail becomes
  post-quantum. Mail that arrived already PGP-encrypted to the v4 key stays as
  it came.
- **Shared mailboxes** ([`mail-groups.md`](mail-groups.md)). A group key gets
  the same v4 + v6 pair. Members get both through the group key share, which
  [`pq-shares.md`](pq-shares.md) moves to X-Wing.
- **Address key envelope and signed key list** (`mail-address-keys.md`). Both
  carry a v4 fingerprint (20 bytes) today. They take v6 fingerprints
  (32 bytes):
  - the payload records the key version;
  - `MailKeyListV1` entries carry the version and the fingerprint at its own
    length, with exactly one v4 primary and one v6 primary per address, as
    Proton's lists.
  - This is a format change with no dual reading (clean slate).

## The library

rPGP `0.21.0`, the version we pin, is the newest release. It already
implements RFC 9980, so no version bump is needed, only its `pqc` feature:
- The algorithm ids match Proton's go-crypto and OpenPGP.js: 30, 35, and 31-34
  and 36 for the others (`src/crypto/public_key.rs:40-62`).
- It has v6 keys, and its builder refuses to mix v4 and v6 in one key.
- The feature brings `ml-kem` 0.2.1, `ml-dsa` 0.0.4 and `slh-dsa` 0.0.3. Each
  needs a check before the build:
  - `ml-dsa` and `slh-dsa` are not at 1.0;
  - `ml-kem` 0.2 would sit beside the 0.3.3 the X-Wing route pins;
  - cargo deny, the four roots `--locked`, and a wasm32 build of `kutup-crypto`
    with `mail`.
- **Interop**, as the v4 spike did with GnuPG:
  - rPGP's v6 messages are opened by OpenPGP.js 6 (Proton's fork) and
    gopenpgp v3;
  - their v6 messages are opened by rPGP;
  - the v4 key is still read by GnuPG 2.4.

## Web, WASM and the server

- **WASM.** `kutup-crypto-wasm` exposes key generation for both keys. Its
  encrypt function picks v6 for Kutup recipients and v4 for outside ones, from
  the published lists, so the client never chooses a suite itself. This is
  the third session's area: they get the exports when this is built.
- **Server.**
  - Key tables hold a version and a fingerprint length per key.
  - Arrival encryption uses v6.
  - WKD and the keys endpoint serve v4.
  - Federation's mail key lookups carry both keys.
- **Existing data.** These columns hold today's v4-only keys and mail:
  `mail_address_keys.public_key`, `mail_address_keys.private_key_envelope`,
  `mail_group_keys.public_key`, `mail_group_keys.private_key_envelope` and the
  message bodies in `mail_messages`. Count them on kutup.dev before we decide
  (as in `pq-shares.md`). The v4 keys stay valid; each address gains a v6 key,
  so old mail remains readable without any fallback.

## Order

This goes after the shares work in `pq-shares.md`, in four steps:
1. A spike with the `pqc` feature: dependencies, deny, wasm32, and interop
   with OpenPGP.js and gopenpgp.
2. kutup-crypto: keys, the envelope and the key list.
3. Server: arrival encryption, publishing, federation.
4. WASM, then web, then gates.
