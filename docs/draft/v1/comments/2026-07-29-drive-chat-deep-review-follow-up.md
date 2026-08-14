# External comment: Drive and Chat deep-review follow-up

**Recorded:** 2026-07-29

**Source category:** AI-generated external review supplied by the maintainer

**Preservation:** verbatim review content below; headings are part of the
original comment

**Decision status:** untriaged. Nothing in the preserved comment is an accepted
Kutup design, completed audit, or security endorsement. Kutup/Codex annotations
follow the preserved text in a separately marked section.

---

Let me verify the corrections against the code before responding.

Verified all of it against the code. Your corrections hold; two of them I'd
sharpen further.

## Confirmed against source

**Recovery — you're right, and the doc is the actual bug.**
`frontend/src/crypto/index.ts:55-73`: `recoveryKeyEntropy =
randombytes_buf(32)`, the mnemonic is an *encoding* of that entropy, and
`encrypt(masterKey, recoveryKeyEntropy)` uses the raw 32 bytes directly as the
secretbox key. No Argon2id anywhere on that path, and the design is correct as
built. `architecture.md` registration steps 4–6 describe a different scheme —
"derives a recovery key from a freshly generated BIP39 mnemonic using Argon2id
(`kdfSalt`)" — and `kdfSalt` is in fact the password-KEK salt, not a recovery
salt. So the doc is wrong twice over on the security-critical path. That
belongs on the adoption list as item 0: it is an hour of work, and it will
mislead the next reviewer exactly as it misled me.

**Suite registries — my count was wrong.** Four exist: `MlsCipherSuiteId`
(`mls/conversation.rs:9`), `DirectChatSuiteId` (`lib.rs:107`),
`SealedSenderSuiteId` (`security_policy.rs:126`),
`FederationAuthProfileId` (`federation-proto/lib.rs:98`). All four are
Chat/federation. The three Drive-side registries named in `crypto-agility.md` —
`DriveObjectSuiteId`, `CollabFrameSuiteId`, `AccountProtectionSuiteId` — have
zero implementations. Same conclusion, correct arithmetic.

**Federated share capability — accept.** `drive_federation.rs` canonicalizes
recipient username and domain and rejects a directory response whose
`username`/`server` don't match. It is origin-bound. The accurate statement is
narrower than mine: anyone *at that domain* holding the fragment can redeem it,
so it's bound to the origin rather than the account — which is exactly the
strengthening you propose.

**PQ scope — accept, with one thing added back.** Content is XChaCha20 and
quantum-fine, and unshared collections wrap their keys under the master key
symmetrically, so there is no public-key exposure at all there. The recorded
classical exposure is the `crypto_box_seal` on *shared* collection keys only.
The part worth keeping: one broken wrap yields a collection key, hence every
file key, hence every blob in that collection, retroactively. Narrow surface,
large blast radius per hit.

**AAD framing — accept.** Rollback, substitution and relocation between
compatible fields is the correct characterization; direct plaintext disclosure
is not implied.

**TOFU — accept, and your own stack already names the anchor.**
`chat-protocol.md:§5.4` already states the resolution: the client policy carries
verifier keys and a quorum obtained independently, and "response-carried keys
never add trust." So the bootstrap design is *independent witness keys shipped
with the client*, and the log is what makes equivocation attributable afterward.
Federation identity needs that same policy-distribution question answered, not
another leaf type.

**OPAQUE — accept.** `chat-protocol.md:§5.4` makes the point verbatim: a web app
that fetches code and trust policy from the same compromised origin cannot
bootstrap independence. Scope OPAQUE to native/CLI, server-database compromise,
and closing the precomputation window opened by the unauthenticated preflight
salt.

**STREAM/Merkle and OpenMLS-for-LKH — your call stands.** LKH-via-OpenMLS was
hand-wavy; drop it. On STREAM I'd only note it is a published, analyzed
construction shipped in Google Tink and the AWS Encryption SDK rather than
something novel — but the *combination* with a Merkle tree is a new storage
format and does need its own spec and vectors, which is your actual objection
and it's right.

## Two additions to your plan

**Your item 2 is much cheaper than it reads.** The account self-authority key
already exists: `chat-protocol.md:§5.3` derives it as `HKDF-SHA-256(master key,
"kutup/chat/self-authority/v1")` — deterministic, stable across recovery,
private half never server-visible, already wrapped by transparency. Drive does
not need a new authority, a new log, or a new proof format. It needs the same
authority under a Drive-scoped label and the existing signed manifest extended
to carry the Drive X25519/HPKE key alongside the chat identity keys. The
verifier, the sparse-map binding, the witness quorum, the fail-closed pinning
and the auditor are all written and tested. That reframes item 2 from "build
Drive transparency" to "add a key to an existing signed manifest," which is
likely the highest value-per-effort item on the whole list.

**Reorder 6 ahead of 3–5.** Per-account account-protection suite/KDF parameters
is a schema change whose cost scales with registered accounts, and it is the one
item that gets monotonically harder with time rather than with scope. It is
also independent of every other item. Land it first. Related: items 3 and 5 are
coupled — the epoch has to live in the envelope AAD, so if the envelope ships
without at least a reserved epoch field you will version the Drive object
format twice.

## On your closing question

Every item on your list is a wire or persistent-format change to Drive.
CLAUDE.md's standing position is that breaking changes are free until the first
`v*` tag and that the bar for done is production-grade. Those two together
answer it: Drive V2 should block v1. Not because the findings are individually
release-blocking — most are not exploitable by a passive adversary — but because
doing them after the tag converts every one of them into a migration against
real user ciphertext, and the account-protection-parameters item in particular
becomes materially harder with each registered account. The cost asymmetry is
entirely on one side of the tag.

Keeping the review untriaged until that scheduling decision is made is the right
sequencing.

---

## Kutup/Codex annotations — 2026-07-29

These annotations do not alter the preserved follow-up above.

### Agreed

- Correcting the account/recovery hierarchy in `docs/architecture.md` is item
  zero.
- The corrected suite-registry inventory is accurate in substance: the
  implemented typed registries are concentrated in Chat/federation, while the
  named Drive/account/collaboration registries remain absent.
- The classical public-key exposure is narrow in occurrence but broad in blast
  radius: recovering one shared collection-key wrap exposes content protected
  by that collection key.
- Per-account account-protection suite and KDF parameters should land before
  the Drive ciphertext redesign because they are independent and cheapest
  before real accounts exist.
- Drive envelope design and collection-key epochs must land together. The epoch
  is authenticated context, not a field to reserve without semantics.
- A clean Drive persistent-format change is substantially cheaper before the
  first stable tag. A minimal Drive V2 security boundary should therefore block
  the first production-format release.

### Important refinement: make identity common, not Drive-inside-Chat

The existing authority, log, sparse map, witness verifier, auditor, and
fail-closed persistence provide most of the required machinery. Kutup should
reuse them.

Because Kutup is pre-production, V1 should not permanently make Drive depend on
a structure named `DeviceManifest` with the domain label
`kutup/chat/self-authority/v1`, nor should it derive parallel Chat and Drive
self-authorities. Prefer a clean common account layer:

- derive one `AccountSelfAuthorityV1` under a
  `kutup/account/self-authority/v1` label;
- define an `AccountIdentityManifestV1` that binds account-level Drive
  encryption keys and the complete feature-specific device keys;
- retain separate purpose keys for Direct Chat, MLS, Drive encryption, and
  future features;
- reuse the existing append-only log, sparse-map semantics, proof profiles,
  witness verifier, auditor, and evidence persistence through a common crate;
- migrate the current pre-production Chat manifest cleanly rather than adding a
  compatibility shim.

This is still far cheaper than building a second transparency system, but it
keeps the trust foundation genuinely shared and avoids naming/protocol debt.

### Important correction: independent witnesses are not yet a universal
federation-identity bootstrap

`chat-protocol.md` correctly states the security requirement: verifier keys
must be obtained independently and response-carried keys add no trust.
However, the current remote `ChatTransparencyPolicyV1` is accepted only after
the remote federation identity is authenticated, and its witness keys arrive
inside that feature policy. The local security floor checks quorum strength; it
does not by itself pin an independently distributed per-domain witness set.

Independent witnesses therefore strengthen equivocation detection after the
policy is authenticated, but the default web path must not be described as
having solved hostile first-contact federation identity. V1 must explicitly
choose one or more bootstrap mechanisms, such as administrator-pinned
federation/witness fingerprints, a separately distributed client catalog, or a
future externally anchored transparency directory. A self-signed log leaf is
not enough.

### OPAQUE and public salts

An unauthenticated endpoint returning a unique password-KDF salt is not itself a
password disclosure; salts are normally public. An attacker still needs a
verifier or another password-checking oracle for an offline attack. OPAQUE may
improve native/CLI authentication and server-verifier compromise resistance,
but it is a separate account-authentication protocol decision and is not
required to fix per-account KDF agility.

### What “Drive V2 blocks V1” includes

The recommended release blockers are deliberately smaller than every proposal
in the original review:

1. correct account/recovery documentation;
2. version and persist account-protection/KDF parameters;
3. introduce the common account authority/identity manifest and bind Drive
   encryption keys through existing transparency semantics;
4. define purpose-specific Drive/collaboration/asset keys;
5. define typed, versioned, context-bound Drive envelopes;
6. implement collection-key epochs and cryptographic revocation semantics;
7. authenticate share creation to the verified sender identity;
8. write the Drive threat model and complete migration, restart, federation,
   parser, and adversarial gates.

OPAQUE, a hybrid post-quantum Drive suite, random-access chunk trees, binary Chat
content, and broadcast channels do not automatically block V1. Each requires a
separate maturity, interoperability, performance, and audit decision.
