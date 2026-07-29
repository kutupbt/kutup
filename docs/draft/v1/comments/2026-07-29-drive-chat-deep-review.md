# External comment: Drive and Chat deep review

**Recorded:** 2026-07-29

**Source category:** AI-generated external review supplied by the maintainer

**Preservation:** verbatim review content below; headings are part of the
original comment

**Decision status:** untriaged. Nothing in this file is an accepted Kutup
design, completed audit, or security endorsement. Resolved decisions belong in
`docs/draft/v1/`.

---

Let me dig much deeper — threat model, federation, the full chat protocol, MLS
details, and the actual crypto implementations.

Deep read done — `crypto-agility.md`, `chat-protocol.md` (1065 lines),
`chat-mls.md`, `chat-security-threat-model.md`, `federation-protocol.md`,
`research/13`, and the actual `kutup-crypto` + `kutup-chat-proto` sources. Much
more to say than last time.

---

# The meta-finding: you built two projects

Chat has a genuinely world-class trust stack: signed device manifests
hash-linked with rollback detection, an RFC 6962 log **plus** a 256-level sparse
Merkle map so "included somewhere but not current" is closed, operator-signed
checkpoints, independent witness quorum, a standalone auditor crate, immutable
fork evidence, fail-closed pinning that survives restart, sealed sender as all
three parts, HPKE anonymous delivery with 1024-byte padding, RFC 9421 federation
signatures with destination+feature binding, coverage fuzzing. This is better
than Matrix and competitive with Signal.

Drive is 2019-era Ente: `crypto_secretbox` with no AAD, `crypto_box_seal`, and a
public key fetched from `GET /api/users/by-email/:email`
(`architecture.md:103`) with **no proof, no manifest, no transparency, no
padding, no suite ID, and no threat-model document** — `docs/` contains
`chat-security-threat-model.md` and no Drive equivalent.

So the honest answer to "is our algorithm selection ideal" is: **for chat, yes,
with two fixable choices. For Drive, no — and the gap is not algorithm strength,
it's that Drive never got the trust architecture you already proved you can
build.**

---

# Q1 — What is not ideal

## Tier 1 — real attacks against your own stated threat model

**1. Drive share keys are server-asserted.** `research/13` §4.3 calls
device-list authenticity "the top unmitigated risk" and correctly identifies it
as the exact IEEE S&P 2023 Matrix/Megolm break. You then fixed it
comprehensively — for chat only. Drive sharing still trusts `users.public_key`
served by the homeserver with nothing signed over it. A malicious operator
substitutes its own X25519 key and silently reads every folder shared afterward.
Same break, one layer over, in the product that holds the long-lived data.

**2. `crypto_secretbox` key wrapping has no AAD and no binding.**
`secretbox.rs` is raw XSalsa20-Poly1305. Nothing cryptographically binds
`encryptedFileKey` to *which* file, collection, owner, or version it belongs to.
A server that can write DB rows can relocate a wrapped key envelope between
objects. You solved exactly this for collab frames — `envelope.rs:53` uses a
30-byte AAD header over `(version, kind, doc_key_id, sender_device_id,
sequence)`. Drive never got the same treatment.

**3. The collab rekey field exists but is not connected.** `envelope.rs:45`
carries `doc_key_id: u32` in the signed AAD header. `kdf.rs:86` is
`derive_content_key(collection_master, file_id)` — **no epoch parameter**. The
key is a pure deterministic function of the collection master and file id.
Consequence: `doc_key_id` can change on the wire while the actual key never
changes, and revoking a collaborator is cryptographically impossible — they
keep deriving the key forever from a collection master they already hold.
`research/02` §108 explicitly specifies rekey-on-revocation; the derivation
makes it unreachable.

**4. Drive is classical, chat is post-quantum — backwards.** Chat gets PQXDH
ML-KEM-1024 + SPQR ML-KEM-768 on ephemeral messages. Drive gets X25519
`crypto_box_seal` on data intended to sit in object storage for a decade.
Harvest-now-decrypt-later is a *storage* threat far more than a messaging
threat. This is the one item that gets strictly more expensive every day,
because it applies retroactively to everything already uploaded.

**5. One key, two protocols.** `asset.rs` and the collab frame path both use
`derive_content_key(collection_master, file_id)` — identical key, separated
only by AAD prefix (`"kutup-asset/v1"` vs the binary frame header). It is not
currently breakable (random 24-byte XChaCha nonces, distinct AAD), but it
directly violates your own `crypto-agility.md` rule that a suite fixes its own
domain-separation labels. And separately, the same `fileId` has *two independent
key paths*: a random `fileKey` wrapped under the collection key for the stored
blob, and this deterministic HKDF key for collab frames on the same file.

## Tier 2 — structural

**6. Only one of nine suite registries actually exists in code.**
`crypto-agility.md` defines `AccountProtectionSuiteId`,
`AccountIdentitySuiteId`, `DriveObjectSuiteId`, `CollabFrameSuiteId`,
`DirectChatSuiteId`, `GroupChatSuiteId`, `ProfileSuiteId`,
`KeyTransparencySuiteId`, `FederationAuthProfileId`. Grepping the workspace:
`DirectChatSuiteId` exists (`kutup-chat-proto/src/lib.rs:107`).
`DriveObjectSuiteId`, `CollabFrameSuiteId`, `AccountProtectionSuiteId` return
**zero hits**. Drive ciphertexts carry no version byte and no suite code point
at all. Every migration you described in that document is currently a flag day
for Drive.

**7. Argon2id parameters are unraisable.** `kdf.ts` hardcodes t=3/m=64 MiB, no
`memlimit`/`opslimit` column exists in any migration. You cannot ever raise the
cost for existing accounts. Also `kdf.ts:2` says "4 threads" — libsodium's
`crypto_pwhash` forces p=1, so the comment is wrong and CLAUDE.md's locked fact
is right.

**8. 1:1 chat messages are not padded; MLS group messages are.**
`chat-mls.md:512` pads HPKE anonymous delivery to 1024-byte buckets.
`chat-protocol.md:557` pads profile names to Signal's 53/257 buckets. Direct
message plaintext gets neither — `maxContentBytes: 65536` and no padding rule.
So group metadata resistance is strictly better than 1:1 metadata resistance,
which is inverted from the usual sensitivity ordering.

**9. Login sends a password-equivalent.** `loginKey =
Argon2id(password, loginKeySalt)` goes to the server, bcrypted on arrival. The
preflight endpoint hands the salt to any unauthenticated caller, enabling
targeted precomputation, and a runtime-compromised server sees a deterministic
function of the password on every login.

**10. Federation identity is TOFU-pinned.** `federation-protocol.md` builds
beautiful hash-chained, dual-signed identity documents — then bootstraps them
with trust-on-first-use. You already run an append-only transparency log with
witnesses and an auditor; server identities are not in it. First contact with a
hostile network pins a hostile key permanently.

**11. MLS ciphersuite `0x0002`
(P-256/AES-128-GCM/SHA-256).** Lowest security level MLS defines, and P-256
appears *twice* — the MLS suite and the anonymous-delivery HPKE
(`chat-mls.md:512`). Everything else in the codebase is
X25519/Ed25519/XChaCha. AES without AES-NI on WASM and mid-range Android is both
slower and harder to keep constant-time. **The one legitimate justification is
hardware keystores** — Secure Enclave and StrongBox are P-256-only, and
`kutup-ios`/`kutup-android` are real. If that is the reason, write it into
`chat-mls.md:81`; right now no document states it, and an undocumented P-256
choice reads as an accident.

## Tier 3 — nobody has flagged these

**12. A 1000-member group is not a 1000-leaf tree.** `chat-mls.md` "Linked
devices": every installation is an independent MLS leaf, never a copied
snapshot. 1000 members × 3 devices ≈ 3000 leaves. Worse, every device add/remove
is a `DeviceSync` — a full ordered Commit through a BFT quorum of up to 64
servers. At 3000 devices with normal churn (phone replaced, app reinstalled,
browser cleared), the **control plane**, not the crypto, is your scaling wall.
Your scale test proves 256 leaves; the number that matters is Commits-per-hour
at 3000 leaves.

**13. The authority quorum has dead zones.** `floor(2N/3)+1` at N=2 gives 2 and
at N=3 gives 3 — both tolerate **zero** faults, so they are strictly worse than
N=1 (three times the failure surface, no availability gain). N=5→4 and N=6→5
each tolerate 1, same as N=4. Only N ∈ {1, 4, 7, 10, …} is efficient. This is
correct BFT math, but the operator-facing table should say so outright, or
operators will deploy N=3 and be surprised.

**14. Drive federation shares use a bearer capability.**
`Kutup-Share-Capability` with a SHA-256 verifier, handed out in a URL fragment.
It is a bearer token: anyone who obtains it is the recipient. Meanwhile chat's
equivalent (`chat-protocol.md` §7.6) is HKDF-derived and *recipient-bound*. Same
asymmetry again.

**15. Argon2id over a 24-word BIP39 mnemonic** is 64 MiB of wasted work — 256
bits of entropy is not brute-forceable, HKDF is the right function. And BIP39 is
a cryptocurrency artifact; a user pasting a kutup phrase into a wallet recovery
box is a real support and phishing surface.

---

# Q2 — From zero, what I would build

## Drive

**One AEAD. One envelope. One header.** XChaCha20-Poly1305 everywhere; delete
XSalsa20/secretbox entirely. Every ciphertext in the system starts with the same
typed header, and the header **is** the AAD:

```
suite_id:u16 | purpose:u8 | epoch:u32 | object_id:16 | parent_id:16 | nonce
```

That single change closes items 2, 5, and 6 at once — key envelopes become
non-relocatable, purposes are domain-separated by construction, and every
object self-describes its suite so migration is per-object instead of a flag
day.

**HPKE (RFC 9180) for every public-key wrap**, not `crypto_box_seal`. Use **auth
mode** so the recipient learns who shared (sealed box is sender-anonymous *and*
sender-unauthenticated — a recipient cannot tell a legitimate share from a
server-injected one). Set the KEM to hybrid **X25519 + ML-KEM-768 (X-Wing)**.
HPKE's KEM is a swappable slot; that is precisely why it is the right envelope
for a system that must survive a PQ transition. You already use HPKE in
`chat-mls.md:512` — same primitive, better parameters, applied to Drive.

**Tink/STREAM instead of `crypto_secretstream`.** Nonce = `header ‖
chunk_counter ‖ final_flag`, XChaCha20-Poly1305, 1 MiB chunks. Identical
truncation/reorder resistance, but you gain random access, parallel decrypt,
and HTTP range requests. Secretstream forces strictly sequential decryption
from byte 0 — which is why video seek, partial download, and multi-core decrypt
are all structurally impossible today. Add a **Merkle tree over chunks** so
partial downloads are verifiable and resumed uploads are checkable.

**Collection keys get epochs.**
`derive_content_key(collection_master, epoch, file_id)` with the epoch bound
into HKDF and into the frame AAD — the `doc_key_id` field you already wrote is
exactly the right shape, it just needs to reach the KDF. Revocation becomes:
bump epoch, re-wrap for remaining members, force a snapshot. Without this,
"unshare" is a UI lie.

**Padmé length padding on filenames and blobs**, plus a written
`docs/drive-security-threat-model.md` stating what remains visible (tree shape,
object count, access timing). You wrote an excellent one for chat; Drive
deserves the same honesty.

**OPAQUE (RFC 9807) for login**, with Argon2id as its internal KSF at 256 MiB–1
GiB on desktop/CLI, **and the parameters stored per-account** so the floor can
rise over time. HKDF, not Argon2id, over the recovery phrase.

**Extend the transparency log to account identity.** You have the log, the
sparse map, the operator signature, the witness quorum, the auditor binary, and
the fail-closed client. Point it at the account HPKE/X25519 key so a Drive share
gets the same inclusion + consistency + quorum proof as a chat bundle, and
reuse the safety-number UX. `crypto-agility.md` already anticipates it
("extraction from Chat is required if Drive adopts it"). This is the single
highest value-per-effort change in the entire codebase, because the hard
machinery is already written and tested.

**Put federation identity documents in that same log.** TOFU becomes a fallback
rather than the root of trust, and equivocating on a server identity becomes
detectable rather than permanent.

## Chat

**1:1: change nothing.** PQXDH + Triple Ratchet is the state of the art and
there is nothing better to move to.

**Add plaintext padding to direct messages** — the same bucket scheme MLS
already uses.

**MLS: `0x0003`**
(`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`) unless hardware
keystores dictate P-256 — in which case document that reason at
`chat-mls.md:81` and keep `0x0002`. Keep the old code point read-only either
way; your registry already handles this correctly. PQ MLS is a genuine
standards gap, not your error.

**Deterministic binary content encoding** (protobuf or deterministic CBOR)
instead of JSON plaintext. JSON canonicalization is a recurring footgun, and
its length is highly content-correlated, which undermines padding.

**Model the control plane, not just the crypto.** Before advertising 1000-member
groups, measure Commits/hour at 3000 leaves through a 4-server quorum, and add
device-churn batching — coalesce `DeviceSync` transitions into windowed Commits
rather than one per device event.

## Broadcast to 1,000,000 — the design you do not have yet

Your instinct in `chat-mls.md:65` is right: *"a separate deferred fan-out
design, not an oversized MLS group."* Nothing in MLS or Signal reaches 1M — at
that size every member processes every join and leave. But you already own
every piece needed, in the wrong drawer. The right architecture is **Drive
object + capability + key tree**, with chat used only for notification:

1. **One ciphertext, pull-based.** A post is a Drive object: random content key,
   XChaCha20-Poly1305, stored once in SeaweedFS/CDN, fetched by subscribers. No
   per-recipient fan-out ever — that is the only way 1M works. Chat delivers a
   tiny pointer, not the payload. Your `attachment` content kind
   (`chat-protocol.md` §6) is already this shape.

2. **Break the symmetry — subscribers must not be able to forge.** The channel
   holds an **Ed25519 signing key** that only publishers have; subscribers get
   decryption keys only. In any symmetric-only design, one of a million
   subscribers can impersonate the channel. For broadcast, sender authenticity
   is the *harder* requirement, not confidentiality.

3. **LKH (Logical Key Hierarchy) for revocation.** A balanced key tree over 1M
   subscribers gives **O(log n) ≈ 20 rekey messages** to evict one subscriber,
   instead of 1M re-encryptions. This is the same idea as MLS's ratchet tree
   with per-member contribution removed — which means you can likely reuse
   OpenMLS tree-math rather than write new crypto. Batch evictions into
   scheduled epochs; do not rekey per unsubscribe.

4. **Capability-gated subscription, epoch-rotated.** Derive a 16-byte subscriber
   capability with HKDF from a channel key and the canonical subscriber
   address, store only `SHA-256(capability)`, compare in constant time. That is
   `chat-protocol.md` §7.6 verbatim — reuse it.

5. **Say out loud what leaks.** At 1M, *who subscribes* is more sensitive than
   post content, which is semi-public by nature. Either issue blind-signed
   subscription tokens so the server cannot enumerate the roster, or state
   plainly in the threat model that the subscriber set is server-visible. Do
   not pretend anonymous delivery solves it — a 1M-row anonymous mailbox is a
   fan-out tax with no privacy gain.

6. **Do not federate the roster.** Each home server holds its own subscribers
   and pulls posts by content hash. Subscriber counts stay local; only the
   signed post pointer crosses servers.

---

# If you only do four things

| # | Change | Why this one |
|---|---|---|
| 1 | Transparency log over account identity keys (Drive + federation) | Closes a live Megolm-class break; ~80% of the machinery is already built and tested |
| 2 | Typed AAD header on every Drive ciphertext | Kills key relocation, and is the prerequisite for every future migration |
| 3 | Hybrid X25519+ML-KEM-768 HPKE for share wrapping | Only item whose cost grows daily — it is retroactive on stored data |
| 4 | Epoch parameter into `derive_content_key` | Turns "unshare" from a UI claim into a cryptographic fact |

Items 2 and 4 are days of work. Item 1 is weeks but reuses existing code. Item
3 is a suite addition your registry design was built to absorb.

---

## Kutup/Codex annotations — 2026-07-29

These annotations do not alter the preserved review above.

### Findings accepted in direction

- Drive recipient encryption keys are authenticated only as server directory
  assertions. Federation authenticates the responding server, not the
  end-user-held Drive key.
- Existing Drive key/metadata wraps lack stable object, purpose, suite, and
  epoch binding. Treat this as substitution, relocation, and rollback exposure;
  it does not by itself disclose plaintext.
- `doc_key_id` does not currently affect `derive_content_key`, so it is not a
  cryptographic rekey epoch.
- Asset and collaborative-frame code derive the same per-file key. V1 should
  derive separate purpose-bound subkeys even when both use XChaCha20-Poly1305.
- Drive/account/collaboration persistent formats do not yet implement the
  purpose-specific suite/version registries promised by `crypto-agility.md`.
- Account-protection KDF parameters need an authenticated, per-account format
  version and stored parameters.
- Direct-message length padding and realistic MLS device-churn/capacity
  measurements are valid metadata and scalability work.
- Drive needs a normative threat model before its next wire format is frozen.

### Corrections to the review

- Recovery does not run Argon2id over a BIP39 phrase. The client generates
  random 32-byte recovery entropy, represents it as a mnemonic, and uses the
  entropy directly. `docs/architecture.md` is wrong.
- More than one suite registry exists. Direct Chat, MLS, sealed sender, and
  federation authentication have typed suite/profile identifiers. The
  Drive-side registry gap remains.
- A federated Drive capability is bound to the authenticated recipient origin
  domain. It is not a globally redeemable bearer token, although binding it to
  an exact recipient account would be stronger.
- The post-quantum exposure is recorded classical public-key wraps of shared
  collection keys, not symmetrically encrypted unshared content. One recovered
  collection key still has a large retrospective blast radius.
- Adding federation identity as a leaf in a log controlled by the same
  federation identity is circular at first contact. Independent bootstrap
  policy or an external anchor remains necessary.
- OPAQUE cannot protect a browser from a server that can replace the delivered
  JavaScript. Its possible value is narrower: native/CLI clients and resistance
  to server-verifier/database compromise.
- The asserted Secure Enclave/StrongBox reason for P-256 is speculative.
  Kutup's V1 MLS suite remains an open, benchmarked protocol decision.

### Proposals not adopted from this comment

- one universal ciphertext suite or one universal key across purposes;
- the proposed Tink/STREAM plus Merkle storage format without a separate
  normative design and vectors;
- custom or draft hybrid HPKE merely to claim post-quantum coverage;
- rewriting all Chat content as protobuf/CBOR for V1 without a demonstrated
  canonicalization failure;
- reusing stripped-down OpenMLS internals as an LKH implementation;
- adding million-recipient broadcast to the MLS/Drive V1 hardening scope.

The preferred architectural rule is: reuse a small primitive portfolio,
audited libraries, trust infrastructure, and typed-envelope code; retain
purpose-specific keys, suite IDs, migration boundaries, and failure semantics.
