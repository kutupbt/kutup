# Mail: post-quantum OpenPGP, following Proton

Status: the user's decisions are in (2026-10-18, below). Next: the spike
(dependencies, deny, wasm32, interop), then the build after the shares work in
[`pq-shares.md`](pq-shares.md). Rule ([`mail-address-keys.md`](mail-address-keys.md)):
copy Proton's answer where it has one; where its code doesn't show one, say so
and propose ours.

## Decisions (user, 2026-10-18)

- **Post-quantum by default** for every address, a deviation from Proton's
  opt-in because Kutup writes every client. New addresses get their v6 key at
  creation, existing ones at their next sign-in.
- **The v6 key is Proton's shape:** an ML-DSA-65+Ed25519 primary with an
  ML-KEM-768+X25519 subkey. This holds subject to RustSec and the interop
  spike.
- **The identity suite upgrade** in `pq-shares.md` is accepted.
- **End-to-end forwarding** is added as Proton has it, and an address with
  forwarding on is not post-quantum while it lasts (section "End-to-end
  forwarding"). It comes after the PQ mail work.

## What Proton does (read from its code)

Sources (go-crypto, gopenpgp and OpenPGP.js are not cloned locally yet. The
claims from them come from npm packages and single files, so they are cloned
before the spike and every reference below is checked against them):
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
  v4 one. The sender doesn't need to have opted in (`packages/mail/store/messages/encryptionPreferences.ts:65`,
  `sortApiKeys` in `publicKeys.ts:54-88`). Calendar and other non-email uses
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

Kutup writes every client, so PQ isn't opt-in here (decided). Every address gets
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
- **The v4 key's storage stays byte for byte as it is.** The address-key
  envelope (`MailAddressPrivateKeyV1`, `mail_key.rs:280-292`) keeps its
  20-byte fingerprint and its purpose.
- **The v6 key's storage is its own.** It gets a new
  `AccountEnvelopePurpose::MailAddressPrivateKeyV6` and payload domain
  `kutup/mail-address-key-v6/v1\0`, with the 32-byte v6 fingerprint.
- **The signed key list goes to `MailKeyListV2`.** Its entries carry the key
  version and the fingerprint at that version's length. Each address has
  exactly one v4 primary and at most one v6 primary, as Proton's lists do. It
  is signed in the same step that adds the v6 key (below).
- **Room for a v6 key.** A v6 key with ML-DSA-65 and ML-KEM-768 is about
  10–14 KB secret and several KB public, so these caps move:
  - `MAX_SECRET_KEY_LEN` (3 KiB, `mail_key.rs:57`);
  - `mail_address_keys.private_key_envelope` ≤ 8192 (baseline 2745);
  - the fingerprint CHECKs `^[0-9a-f]{40}$` (baseline 2743, 2936) and
    `FINGERPRINT_LEN = 20` (`mail_key.rs:53`), per version;
  - `public_key` and the group shares at ≤ 16384, which are tight.

  The new caps are set from measured keys in the spike.
- **Getting there: Proton's opt-in path, run for every account.** This copies
  `pqcActions.ts`. At its next sign-in a client:
  1. generates a v6 key for each address;
  2. seals it under the new purpose;
  3. re-signs the V2 list with the v4 primary unchanged and the v6 primary
     added.

  The server encrypts arrivals to v6 once an address's list has a v6
  primary, and to v4 until then. The 4 stored messages stay as they are.

## End-to-end forwarding

Decided 2026-10-18. It comes after the PQ mail work and is on the Mail parity
list.

**What Proton does** (its code read):
- **The scheme** is draft-wussler-openpgp-forwarding (proxy re-encryption).
  - The forwarder's client makes a **forwardee key**: one Curve25519 ECDH
    subkey per forwarder encryption subkey. Each subkey's KDF parameters are
    version `0xFF` and carry the forwarder subkey's 20-byte fingerprint, so
    the forwardee derives the same key-encryption key.
  - It also makes a **proxy factor** per subkey, k = d_forwardee⁻¹ ·
    d_forwarder mod n.
  - The forwardee subkey is flagged 0x40 (forwarded communication) and 0x10
    (split key).
  - Sources: pmcrypto `lib/key/forwarding.ts:100-164`; go-crypto's Proton
    branch `v2/forwarding.go:18-167`.
- **What the server gets:** the proxy instances `{PgpVersion,
  ForwarderKeyFingerprint, ForwardeeKeyFingerprint, ProxyParam}` and the
  forwardee key, locked with a passphrase that is encrypted to the forwardee
  (the activation token). WebClients: `api/forwardings.ts:73-127`,
  `keys/forward/forward.ts`.
- **What the server does.** For each arriving v3 ECDH PKESK addressed to the
  forwarder's key, it replaces the ephemeral point eB with k·eB (with a
  small-subgroup check), keeps the wrapped key, and rewrites the key ID to
  the forwardee's (`packet/encrypted_key.go:644-676`). It never sees the
  plaintext or a session key.
- **Only v4 Curve25519 keys work.** Nothing exists for v6, X25519
  (algorithm 25), ML-KEM or the composite KEMs in any of Proton's code, and
  no PQ-safe scheme exists.
  - When forwarding is set up, Proton removes the v6 key's primary status, so
    arrivals go to v4 (`unsetV6PrimaryAddressKey`,
    `addressKeyActions.ts:57-91`).
  - Deleting the last outgoing forwarding makes v6 primary again
    (`outgoingForwardingActions.ts:150-159`).
- **Proton's wording** (`ForwardModal.tsx:82-129`, `c('email_forwarding_2023:
  Info')`):
  - before: "For compatibility, post-quantum encryption will be disabled for
    {address}."
  - after: "For compatibility, post-quantum encryption has been disabled for
    {address}."
  - The confirmation on deleting a forwarding says nothing about PQ coming
    back. The address shows no label beyond a "Forwarding" badge on the key.

**Ours:**
- **The library has it.** rPGP 0.21.0 implements the draft behind the feature
  `draft-wussler-openpgp-forwarding`:
  - the `Replaced` KDF;
  - decryption, once `enable_draft_forwarding()` opts in;
  - the 0x40 flag;
  - `generate_proxy_parameter`;
  - the server's `forwarding_transform`, with its small-subgroup and identity
    checks;
  - the draft's vectors as tests.

  Nothing goes upstream. Our code in `kutup-crypto` is the setup Proton keeps
  in pmcrypto: build the forwardee key per forwarder subkey, copy the
  forwarder's KDF hash and cipher, set the flags, reuse the original
  replacement fingerprint for chained forwarding, and keep forwardee subkeys
  out of exported keys and the key list.
- **Arrival keys follow the forwarding state, per address.** While an address
  has an end-to-end forwarding on, its v4 key is the arrival key and the v6
  key isn't primary for arrivals; the list is re-signed accordingly. Turning
  the last forwarding off makes v6 primary again, and arrivals go back to v6.
  Kutup↔Kutup senders follow the list, so they also use v4 for that address
  while forwarding is on.
- **The person is told plainly**, which is a requirement (en and tr):
  - When turning forwarding on, a confirmation dialog says, in Proton's style:
    "Mail to this address will use classic encryption while forwarding is on.
    It won't be protected against future quantum computers. Turning
    forwarding off switches back."
  - While it is on, the address in settings shows a visible label:
    "Classic encryption (forwarding on)".
  - When it is turned off, a short note: "Post-quantum encryption is back on
    for this address."
- **Interop.** Proton's own forwarding uses this same v4 scheme, so a Kutup
  forwardee key works the same way. The spike checks rPGP's forwarded
  messages against go-crypto's Proton branch.

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

## What follows from it

- **Readers outside the web app.** The IMAP bridge and exports must read v6.
  GnuPG implements LibrePGP's Kyber (v5), not RFC 9980, so a person who
  exports their mail to GnuPG reads only what was sealed to v4.
- **A v6 key stays.** Once an address has one, mail sealed to it needs it, so
  it is never removed, only retired from encrypting.
- **Drafts and Sent** are sealed to the v6 key too, as Proton does when one
  exists.
- **Mixed recipients.** A message to Kutup and outside recipients becomes
  separate packages: SEIPDv2 to the v6 keys, SEIPDv1 to the outside v4 keys.
- **What outsiders get.** Autocrypt and WKD carry the v4 key only.
- **Outside v6 keys.** Proton accepts a v6 key found unverified on WKD. Whether
  we encrypt to an imported or discovered outside v6 key is left to the user.
- **Interop is decided by the spike.** rPGP follows the published RFC 9980
  combiner; drafts that Proton's libraries tracked earlier differ in places.
- **Dependency checks in the spike:**
  - RustSec for `ml-dsa` 0.0.4 and `slh-dsa` 0.0.3;
  - the wasm size cost of `ml-kem` 0.2.1 beside 0.3.3.

## Spike findings (2026-10-19)

Step 1 of the order below, read and measured on master `82d9cdc9`; no code
was kept. **rPGP's post-quantum support can't be used yet**, for two reasons
upstream fixes:

1. **It doesn't compile next to our X-Wing route.** rPGP 0.21.0 (the newest
   release, and `main` as of 2026-10-19) pins `ml-kem` 0.2.1, whose `kem`
   requirement (`^0.3.0-pre.0`) resolves to the released `kem` 0.3.0 that
   `x-wing` 0.1.1 and `ml-kem` 0.3.3 already bring in. `ml-kem` 0.2.1 doesn't
   build against it (`kem::Encapsulate` changed shape). One `kem` 0.3 sits in
   the graph, so the two can't coexist.
2. **Its ML-DSA has an advisory.** `pqc` pins `ml-dsa` 0.0.4, under
   RUSTSEC-2025-0144, fixed in `ml-dsa` 0.1.0-rc.3 and later (0.1.1 is
   current). `slh-dsa` is at 0.0.3 there, against 0.2.0-rc.5 upstream.

The forwarding draft (`draft-wussler-openpgp-forwarding`) needs nothing new: it
builds today (Curve25519 only).

**What it takes.** rPGP's `pqc` must move to `ml-kem` 0.3, `ml-dsa` 0.1 and a
current `slh-dsa`. We have three ways to get there:
- **(a, proposed)** contribute that update to rPGP upstream: the APIs moved,
  so it's a real change, but it's mechanical and their test vectors (the
  RFC 9980 ones) check it;
- **(b)** wait for rPGP to make it;
- **(c)** carry a patched rPGP in `vendor/`, as `keepass` is. Only if (a)
  stalls.

**Interop**, once rPGP builds:
- OpenPGP.js 6 runs here (Node 22 is installed), so Proton's fork can be
  exercised live.
- Go isn't installed, so go-crypto's side uses its checked-in test vectors
  (`openpgp/v2` PQC tests, in the Proton branch clone) rather than a live
  build.
- GnuPG 2.4.7 is here for the v4 side.

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
- **Existing data** (kutup.dev, 2026-10-18): 3 address keys, no group keys, 4
  messages. The v4 keys stay valid and each address gains a v6 key at its
  next sign-in (above), so the stored mail stays readable without a fallback
  or a wipe.

## Order

This goes after the shares work in `pq-shares.md`, in four steps:
1. A spike with the `pqc` feature: dependencies, deny, wasm32, and interop
   with OpenPGP.js and gopenpgp.
2. kutup-crypto: keys, the envelope and the key list.
3. Server: arrival encryption, publishing, federation.
4. WASM, then web, then gates.
