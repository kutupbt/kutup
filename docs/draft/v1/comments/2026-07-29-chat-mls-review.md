# External comment: Chat and MLS review

**Recorded:** 2026-07-29

**Source category:** AI-generated external review supplied by the maintainer

**Preservation:** verbatim review content below; headings are part of the
original comment

**Decision status:** triaged in
[`../security-review-follow-ups.md`](../security-review-follow-ups.md). This raw
comment remains review input, not an audit or security endorsement.

---

First, a correction I owe you from last turn.

## I was wrong about the login key

I flagged the master-key derivation as potentially fatal based on
`architecture.md`. Having now read `crates/kutup-crypto/src/kdf.rs`, the code is
correct:

```rust
derive_kek(password, kdf_salt)              // decrypts the master key
derive_login_key(password, login_key_salt)  // goes to the server
```

Two independent Argon2id runs with **separate salts**. The server never sees
anything that decrypts the master key. The comment in the source even says so
explicitly.

The bug is in `docs/architecture.md`, which says "Client encrypts `masterKey`
with the login key" and "the client decrypts the master key locally with the
login key." That's describing a broken design you didn't build. Fix the doc —
it's the first thing a security reviewer reads, and it made me (and will make
them) file a critical-severity issue against working code.

Minor note while you're there: you pay two full Argon2id runs per login where
Ente pays one (they derive the login subkey *from* the KEK).
Security-equivalent, but it's double the client-side cost.

## Revised rating

**Chat crypto design: 8.5/10.** That's a large jump from the 5 I gave the
storage layer, and it's earned.

I gave you a list last turn of things to fix before touching chat — key
transparency, credential binding, real revocation, a threat model. You'd already
built all of them, on a branch, more thoroughly than I described. Specifically:

- RFC 6962 inclusion and consistency proofs, current-map proofs, independently
  administered witnesses with quorum, and durable fork evidence. That's a real
  key transparency system, not a fingerprint screen.
- `BasicCredential` made safe by binding every KeyPackage's ciphersuite,
  KeyPackageRef, lifetime, identity, and signature key to a
  transparency-verified manifest, with fail-closed on mismatch. This is the
  correct way to use BasicCredential and almost nobody does it.
- Coverage fuzzing on every untrusted parser, including through libsignal's
  real decrypt entry point.
- A completion gate whose claims are actually executable —
  `openmls_group_operates_with_256_manifest_bound_members` exists and builds a
  real 256-leaf tree, not a mock.
- Correctly refusing to model 100k-recipient announcement channels as oversized
  MLS groups.

The threat model table is better than most funded products ship. The
`floor(2N/3)+1` multi-authority ordering log is a genuinely more ambitious
answer to the federation-ordering problem than MIMI's single hub.

## Where I'd push back

**The quorum formula has a liveness cliff that will bite operators.** Your table
is arithmetically consistent, but look at what it means:

| N | quorum | failures tolerated |
|---:|---:|---:|
| 1 | 1 | 0 |
| 2 | 2 | 0 |
| 3 | 3 | 0 |
| 4 | 3 | 1 |
| 7 | 5 | 2 |

N=2 and N=3 buy you **zero** fault tolerance while doubling or tripling the
number of servers that must be simultaneously reachable. An admin who picks 3
authorities "for redundancy" gets strictly worse availability than 1. Either
restrict the UI to N ∈ {1, 4, 7, 10, …} or put an unmissable warning on the
intermediate values.

**Interrogate ciphersuite `0x0002`.** P-256 + AES-128-GCM is the only place in
the codebase that leaves the X25519/XChaCha20/Ed25519 family. I can guess the
reasons — WebCrypto native support, hardware AES, and Secure Enclave only doing
P-256 for the mobile bindings you're planning — and those are legitimate. But
P-256 needs point validation you can get wrong in ways X25519 structurally
prevents, and you've now got two primitive families to audit. Whatever the
reason is, write it down in `crypto-agility.md`; right now it reads as
unexplained.

**The `0xff4b` extension reintroduces O(N) on the control plane.** Carrying the
full group-private roster, role assignments, and authority/owner sets in a
GroupContext extension is what keeps rosters off the ordering servers — good.
But GroupContext extension changes ride in proposals, so every membership
change ships the entire roster to every member. At 1000 accounts that's tens of
KB per add. TreeKEM stays O(log N) for key agreement, but your control messages
don't. Measure it at the real cap before you raise the limit.

**256 tested, 1000 claimed — and the units are ambiguous.** The doc says
"1-1000 members," and separately says each linked device is a distinct MLS
leaf. So is 1000 the account cap or the leaf cap? A 1000-account group at 3
devices each is 3000 leaves, which is 12× your tested tree. Pin the definition,
then test at the leaf count the cap actually implies.

**PQ asymmetry, stated plainly.** Your 1:1 path gets libsignal's SPQR
negotiation. Your group path is `0x0002`, classical only. So the *stronger*
protocol has the *weaker* long-term confidentiality, and
harvest-now-decrypt-later is a live threat for archived group history. That's a
defensible V1 call given library maturity, but it should be an explicit line in
the threat model rather than a footnote about future suite upgrades.

**The real risk is the design's own size.** MLS + BFT ordering + transparency
with witnesses + sealed sender + pseudonymous owner governance + incarnation
recovery + joint-consensus authority changes + DeviceSync + invitation
feedback, at 33k LOC in `kutup-chat-core` alone, with 281 test functions across
~95k LOC of Rust and one maintainer. Every subsystem is a place where a bug
silently voids a guarantee while all the tests still pass. Fail-closed design
means the failure mode is stuck groups rather than leaked messages — much
better — but there will be a lot of them.

## Development strategy

1. **Fix `architecture.md`.** Today. It actively misrepresents your best work.
2. **Freeze scope on this branch.** Do not add threshold roots, calls, or
   announcement fan-out. What's here is already more than can be validated by
   one person.
3. **Get an external review, and make it easy to get.** You now have the
   artifact that makes a review tractable: a normative protocol doc, a threat
   model with explicit adversaries, executable adversarial gates, and fuzz
   targets. That package is what gets a cryptographer to say yes. Approach the
   OpenMLS maintainers, Trail of Bits, or an academic group working on MLS
   formal analysis — several have looked for real deployments to study. Frame
   it as "here's the threat model, find where the implementation diverges."
4. **Write the ops runbook before merging to main.** Enumerate every fail-closed
   state, how an admin diagnoses it from `/api/admin/chat/mls/status`, and what
   the recovery path is. Your OTel instruments are the right foundation; wire
   alerts to stuck-quorum and pending-Commit states.
5. **Then merge, then announce.** The story writes itself now: a self-hosted
   E2EE suite with real MLS groups, multi-server BFT ordering rather than a
   single hub, and working key transparency. That's a genuinely novel position
   — nobody else in the self-hosted space has it. Lead the announcement with
   the threat model, not the feature list; this audience will respect the
   candor and the fail-closed philosophy far more than a bullet list.

The gap between the storage layer and the chat layer is now large enough that
it's worth asking whether the chat branch's rigor should be backported —
collection key rotation on member removal is still the outstanding item from
last turn, and it looks small next to what you've already built here.
