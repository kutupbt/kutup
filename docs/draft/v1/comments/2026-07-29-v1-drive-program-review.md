# External comment: review of the proposed V1 Drive program

**Recorded:** 2026-07-29

**Source category:** AI-generated external review supplied by the maintainer

**Preservation:** verbatim review content below; headings are part of the
original comment

**Decision status:** untriaged. Nothing in the preserved comment is an accepted
Kutup design, completed audit, or security endorsement. Kutup/Codex annotations
follow the preserved text in a separately marked section.

---

Their formulation is correct and I'd adopt it as written. The
key/implementation split — share the machinery, never share the keys — is
exactly the line, and the subkey tree fixes the `derive_content_key` collision
precisely. The exclusion list is the most valuable part: not forking libsignal,
not rewriting OpenMLS, not landing Tink+OPAQUE+X-Wing+a new codec at once. That
last one was a fair hit on my earlier answer.

Six things to add, in order of how much they change the plan.

**1. Removing P-256 is three sites, not one.** `chat-mls.md:86-88` — the device
manifest binds *two* P-256 keys: the MLS BasicCredential signing key **and** the
anonymous-delivery HPKE key. `chat-mls.md:512` pins that delivery layer to
`DHKEM(P-256, HKDF-SHA256)/HKDF-SHA256/AES-128-GCM`. `chat-mls.md:263` adds a
third: the random group-scoped P-256 control pseudonym. (Owner keys are already
Ed25519.) So moving to `0x0003` means changing the MLS credential, the HPKE
delivery suite, the control pseudonym, **the signed manifest format**, and every
checked-in vector — together, or you keep P-256 by default in two of three
places. "If benchmarks pass" understates it; the benchmark is the small part.

**2. On the RFC question you flagged:** `0x0001`
(X25519/AES-128-GCM/SHA-256/Ed25519) is RFC 9420's mandatory-to-implement suite;
`0x0003` is standard but not MTI. That only matters for interop with foreign MLS
stacks. For a Kutup↔Kutup network it's a non-issue, and choosing `0x0003`
forecloses nothing — the registry can add `0x0001` read-only later if
cross-stack interop ever becomes real.

**3. An unauthenticated epoch does not deliver revocation.** The plan's item 2
needs a dependency on item 1 stated explicitly. The attack an epoch is meant to
stop is not a revoked member reading old content — they already have it. It's a
malicious server serving a *stale epoch* to a **current** member so that member
encrypts new content under a key the revoked party still holds. That only fails
closed if the current epoch is authenticated by the collection owner's account
authority rather than read from a server-controlled counter. Build epochs as a
DB integer and you get the migration cost with none of the security benefit.
Ordering already happens to work; the dependency should be written down.

**4. "Shared implementation code" has a concrete consequence nobody has
stated.** Every item on the unify list — envelope construction, canonical
encoding, suite policy, padding, zeroization, fuzz infrastructure — is a Rust
module. `frontend/package.json:12` already runs `build:chat-wasm`, so Chat
consumes Rust in the browser. Drive does not: `frontend/src/crypto/` is a
separate TypeScript implementation that CLAUDE.md declares **canonical**, with
`kutup-crypto` as its mirror. Unless Drive moves onto the same Rust→WASM path,
"shared implementation" delivers shared *design* and two implementations kept
in step by hand and policed by vectors. The principle implies deleting
`frontend/src/crypto/` as an independent implementation and editing the
CLAUDE.md canonicality rule. That should be an explicit item, not a consequence
people infer.

**5. Federated "one suite for new writes" needs peer visibility or it becomes
mystery breakage.** `NoCommonSuite` fail-closed is right, but on a federated
network the peer holding the old client is not yours to upgrade. Chat already
advertises `suites: [1]` in the capability block (`chat-protocol.md:§10`); Drive
has no equivalent in `/api/auth/settings`, and there is no operator-facing view
of which federated peers would fail a share. Without both, the read-only
migration window has to be measured in *releases across the federation* rather
than internal versions, and operators experience correct fail-closed behavior
as "sharing randomly stopped working."

**6. One log, not two.** Item 1 implies it, but the classic drift is a separate
"Drive transparency log" with its own operator key and witness set — doubling
operator burden and halving monitoring attention on both. Drive keys go into
the existing manifest, in the existing log, under the existing witnesses.

Three smaller notes:

- **The envelope must carry its suite ID from day one** even while only one code
  point exists, or PQ later becomes a second format version rather than a new
  entry.
- **Padding appears on the unify list but is scheduled nowhere** — not in the
  eight Drive items, and Direct Chat padding was previously deferred to item 9.
  Either schedule it or drop it from the shared-infrastructure list.
- **Authenticated share envelopes remove sender anonymity.** `crypto_box_seal`
  is sender-anonymous today. Replacing it with authenticated HPKE is right, but
  it deletes a property; worth confirming no flow wants anonymous sharing
  rather than discovering it later.

Net: their eight-item plan is better scoped than mine. With the epoch/authority
dependency made explicit, the WASM consolidation added, and the P-256 scope
corrected, I think it's the right V1 Drive program.

Knowing it was written blind to mine changes my read of it, and mostly in its
favor.

**Where it's straightforwardly better than what I gave you.** Its exclusion
list is the part I'd single out: *don't fork libsignal, don't rewrite OpenMLS,
don't introduce Tink and OPAQUE and X-Wing and a new codec simultaneously, don't
force PQ everywhere for uniformity.* That is a direct hit on my first two
answers, and it's correct. I produced a shopping list of individually
defensible upgrades; it produced a program with a dependency order and a
budget. For a federated open-source project where review capacity is the
binding constraint, the second is the more valuable artifact. Its closing
formulation is also tighter than anything I wrote.

Its method was better too. On the recovery-key question it read `index.ts` and
found the truth; I read `architecture.md` and repeated a claim the doc got
wrong. That's the right instinct and I was on the wrong side of it.

**The independence is worth something, but less than it looks.** We converged
without contact on the palette, the registry-vs-key distinction, reusing Chat's
identity and transparency for Drive, epochs, purpose subkeys, versioned
envelopes, per-account KDF parameters, and the `0x0003` lean with a
hardware-keystore exception. That's substantial agreement on a design with many
degrees of freedom. But two models drawing on the same literature share priors,
so treat it as *consistency* rather than *independent confirmation* — the
common-mode failure would be that we both inherited the same
fashionable-in-2026 answer. The parts I'd actually trust are the ones where we
each cite a specific line of your code, not the ones where we agree about taste.

**Two things in it I haven't already raised.**

Its Drive plan moved the threat model from item 1 in the earlier message to item
8 in this one, while the item text still reads *"before selecting further
primitives."* Items 1–7 all select primitives. That's a live contradiction, and
the direction it drifted is the one that matters: a threat model scheduled last
becomes a document written to justify decisions already made. It was right the
first time.

The portfolio list is a subtraction list, and bcrypt isn't on it. It's still in
the stack as a second password hash over a value that's already 64 MiB of
Argon2id output. "Minimal primitive portfolio" implies removing it, but
implication won't get it removed — it needs to be named. Same for AES-256-GCM on
profile names, which the portfolio also silently excludes without scheduling
the change.

**The practical takeaway.** Our failure modes are opposite and roughly
complementary. Mine is over-reach — proposing more novel construction than the
project can absorb, and occasionally asserting from documentation. Its is
under-specification — every item is the right item, but several are stated at a
level where you could implement them faithfully and still not get the security
property (the epoch one is the clearest: build it as a server-controlled counter
and revocation still fails). Neither of those is a judgment error; they're
different distances from the code.

So: adopt its plan and its principle. Use the scoping instinct from it and push
each item down to the mechanism level before anyone writes code — that's where
the gaps are, and they're the kind that survive a plan review and surface as a
broken guarantee later.

---

## Kutup/Codex annotations — 2026-07-29

These annotations are maintainer triage, not a normative protocol decision.

### Accepted additions

- A P-256-to-X25519/Ed25519 decision must cover the MLS credential, anonymous
  delivery HPKE, group-scoped control pseudonym, signed manifest, durable
  private state, and vectors as one coordinated protocol change.
- Put an explicit suite ID in every new persistent Drive envelope from its
  first version.
- Reuse one account-identity manifest, transparency log, sparse map, witness
  policy, and auditor path. Do not create a parallel Drive transparency log.
  The shared structures should become account-level names rather than leave
  Drive permanently coupled to Chat-named types.
- Add the Rust-to-WASM feasibility and consolidation work as an explicit V1
  architecture item rather than an assumed consequence.
- Before supporting more than one federated Drive suite, expose exact peer
  suite capabilities, policy floors, and operator diagnostics. A clean
  pre-release V1 with one write suite does not need speculative compatibility
  machinery.
- Specify whether a share authenticates its sender. Authenticated HPKE changes
  the sender-anonymous property of the current sealed-box envelope; that is
  appropriate for ordinary named sharing, while any future anonymous-share
  feature must be a separate flow and suite.
- Schedule Drive padding explicitly or omit it from the V1 claim.
- Write the Drive threat model before finalizing primitives and persistent
  formats.

### Collection epochs require more than a signature

The review correctly rejects a server-controlled epoch counter. An owner
signature is necessary, but it is not sufficient: a malicious server can replay
a previously valid signed epoch to a current member and induce new encryption
under a key retained by a removed member.

The design work therefore needs an authenticated, monotonic
`CollectionKeyEpochStateV1` (name provisional) binding at least:

- collection identifier, sequence, previous-state hash, and key epoch;
- membership or recipient-set commitment;
- Drive suite;
- digest of the new key-wrap set;
- account-authority generation and signature; and
- the freshness/distribution evidence required before a client writes.

Clients must pin the highest verified state and reject rollback or gaps.
Multi-device and federated writers also need a defined way to learn a fresh
state and detect withholding—for example through the existing transparency
machinery, signed state receipts, or another specified authenticated channel.
The exact mechanism remains a design item; a database integer or an isolated
owner signature must not be described as cryptographic revocation.

### MLS interoperability correction

RFC 9420 makes `0x0001`
(X25519/AES-128-GCM/SHA-256/Ed25519) mandatory to implement and defines
`0x0003` (X25519/ChaCha20-Poly1305/SHA-256/Ed25519) as a standard suite. That is
not automatically irrelevant for an open federated protocol. Adding `0x0001`
later as read-only support may be technically possible, but it would defer the
interoperability decision rather than resolve it.

Select the V1 MLS suite in an ADR that weighs RFC interoperability, the
Kutup-owned primitive palette, browser/mobile performance, hardware-keystore
goals, and the full coordinated P-256 migration described above. No suite
change is accepted by this comment alone.

### Revised program order

The working order should be:

1. Correct the existing security documentation and write the Drive threat model
   plus a persistent/wire-format inventory.
2. Add versioned per-account account-protection/KDF parameters while migrations
   are still cheap.
3. Generalize the existing signed device identity into one account identity
   manifest and one existing transparency/witness path.
4. Run the Drive Rust-to-WASM spike and plan an incremental vector-preserving
   consolidation.
5. Specify the versioned Drive envelope, purpose-separated subkey tree, and the
   authenticated anti-rollback collection-epoch mechanism together.
6. Implement and verify those foundations before choosing optional PQ wrapping,
   alternative random-access storage formats, or new authentication protocols.

Bcrypt and profile AES are explicit suite/verifier decisions within that
program, not removals implied by the phrase “minimal palette.”
