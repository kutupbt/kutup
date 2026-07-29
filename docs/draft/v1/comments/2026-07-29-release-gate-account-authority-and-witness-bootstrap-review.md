# External comment: V1 release gate, account authority, and witness bootstrap

**Recorded:** 2026-07-29

**Source category:** AI-generated external review supplied by the maintainer

**Preservation:** verbatim review content below; headings are part of the
original comment

**Decision status:** untriaged. Nothing in the preserved comment is an accepted
Kutup design, completed audit, or security endorsement. Kutup/Codex annotations
follow the preserved text in a separately marked section.

---

The strongest thing in this pass is the release-gate test, and it's worth naming
explicitly because it generalizes: **everything that cannot be added later as a
new code point is in the gate; everything that can is out.** Applied to the
eight items, that's exactly right — KDF parameters, key derivation, envelope
shape, epoch-in-AAD and share-envelope shape are all one-way doors before the
first `v*` tag; OPAQUE, PQ wrapping, chunk Merkle trees and broadcast are all
additive by construction. Drawing the line there rather than by perceived
severity is what keeps V1 shippable.

**On `AccountSelfAuthorityV1` — right, and it's a pre-tag-only change for a
reason worth stating.** The authority is derived as `HKDF-SHA-256(master key,
"kutup/chat/self-authority/v1")` (`chat-protocol.md:§5.3`). That label is a
derivation input, so renaming it changes every account's authority key,
invalidates every published manifest, and breaks every peer's TOFU pin — the
trust-resetting change §4.3 of the research warns about. Two ways out: keep the
chat-named label forever as a locked fact and rename only the Rust type, or
actually re-derive. Re-deriving is free today and impossible after the tag, so
if the clean split is wanted, it has to happen inside this gate rather than
after it. Don't let a naming cleanup become an unplanned key rotation.

**The witness observation is correct and sharper than my version.** The docs
assert both "response-carried keys never add trust" (§5.4) and "a high-assurance
client must obtain/pin the same values independently" (§10) — which concedes
that the default client does not. For a remote domain, the witness set arrives
through a policy chain authenticated by the peer's own identity, which was
TOFU'd. Circular, as stated.

The federation-native fix is **cross-witnessing**: require a server's
checkpoints to be countersigned by N peers the client already has pins for, so a
fake server plus a matching fake log has no signatures from anyone established.
A new server joins by being witnessed by existing peers rather than by asserting
its own witness set. That keeps the trust graph inside the federation instead
of importing a central anchor, and it degrades gracefully — a server with no
cross-signatures is usable but visibly unanchored. Pair it with documentation
honesty: what the log actually buys at first contact is *detectable equivocation
over time*, not authenticated first contact. Those are different properties and
the current text claims the stronger one.

**On salts and OPAQUE — you're right and I was overstating.** Per-user random
salts served publicly are standard practice and the precomputation gain is
marginal against 64 MiB Argon2id. OPAQUE as a scoped native/CLI decision outside
the gate is the correct disposition.

**One thing the gate framing misses: gate membership and implementation order
are different questions.** The Rust→WASM consolidation is correctly *excluded*
from the gate — it's an implementation change, not a format change. But items 4
through 7 all mean writing new crypto code, and if that code lands in
`frontend/src/crypto/` first it gets written twice. So the WASM move belongs
*before* items 4–7 in sequence despite not being in the release gate. Otherwise
the gate ships correctly and you've doubled the implementation you then have to
consolidate.

**Last note, and I'll leave it here:** item 8 still carries "write the threat
model" in final position. If it's bundled with "complete security gates," split
it — the gates legitimately come last, the threat model gates items 4–7 by its
own description. Item 1 is the right home for it.

---

## Kutup/Codex annotations — 2026-07-29

These annotations are maintainer triage, not a normative protocol decision.

### Release-gate rule: accepted with one qualification

The proposed one-way-door test is the correct default for a pre-tag persistent
and federated protocol:

- gate KDF metadata, derivation labels, account trust roots, suite identifiers,
  envelope framing/AAD, collection-epoch semantics, and share authorization
  shape;
- defer independently negotiable additions such as OPAQUE, PQ suites,
  random-access chunk formats, and broadcast protocols.

Code-point additivity is not the only release criterion. A technically additive
feature may still gate a release if the product otherwise claims a security
property it does not provide. Conversely, internal refactoring need not be a
wire-format gate but can remain a quality gate. The rule is therefore:
freeze irreversible trust and format choices before the tag, and separately
require every advertised V1 security claim to be true end to end.

The phrase “release-gate test” here describes that design heuristic. It is not a
new executable test in commit `54b788b`; that commit hardens MLS invitation
readiness and development bootstrap.

### Account self-authority: change the derivation deliberately now

The code confirms that `kutup/chat/self-authority/v1` is an HKDF input in
`crates/kutup-chat-core/src/manifest.rs`. Changing it derives a different
Ed25519 authority and invalidates existing manifest signatures and peer pins.
Renaming only the Rust type would not change the key and would permanently lock
the Chat-scoped label into the account trust root.

Because Kutup has no production deployment and development databases may be
recreated, the recommended V1 choice is a deliberate clean cutover to
`kutup/account/self-authority/v1` together with:

- `AccountSelfAuthorityV1` and `AccountIdentityManifestV1`;
- regenerated canonical vectors and manifests;
- reset development transparency histories and client pins;
- one documented format/protocol generation change; and
- no compatibility shim or silent key replacement.

If preserving existing development identities becomes a requirement, retain
the old label as a locked protocol fact instead. Do not change the label under
an existing manifest version or present the operation as a cosmetic rename.

### First-contact trust: diagnosis accepted, cross-witnessing not yet accepted

The current default remote path authenticates
`ChatTransparencyPolicyV1` through the already TOFU-pinned federation identity;
the witness keys are inside that policy. Consequently, those witnesses provide
strong checkpoint attribution and later split-view detection, but they do not
independently authenticate the original federation identity or first policy.
The normative documentation and UI must distinguish:

- unverified first-contact TOFU;
- manually or administratively verified federation identity;
- independently pinned transparency/witness policy; and
- later witnessed consistency/equivocation evidence.

Cross-witnessing is a promising candidate, not a complete design. Counting
signatures from federated peers does not by itself establish independence:
operators can create Sybil peers, existing peers can collude, trust paths can
become circular, and witness-set rotation or partitions can strand a new
server. Requiring ordinary homeservers to act as witnesses would also blur the
deliberate separation between federation, witness, and auditor roles.

Any cross-witnessing proposal needs an ADR and threat model covering:

- how clients select already trusted roots and prevent circular trust;
- diversity or independence policy rather than signature count alone;
- new-server admission and recovery after all original witnesses disappear;
- witness rotation, revocation, expiry, and compromise;
- privacy implications of peers observing another server;
- partition behavior and whether “unanchored” is warning or denial under each
  local security floor; and
- preservation of original signed statements as fork evidence.

A safer incremental shape is to accept cross-witness statements as additional
evidence while retaining explicit administrator/client pins and local trust
floors. It must not silently turn transitive federation TOFU into “verified.”

### Rust-to-WASM ordering: accepted as an engineering gate

Rust-to-WASM consolidation is not inherently a persistent-format gate, but the
implementation-source decision must precede new Drive V2 crypto work. First run
the feasibility spike recorded in
`2026-07-29-primitive-palette-and-wasm-review.md`. If it passes, implement the
new envelope, subkey, epoch, and share operations once in Rust and expose them
to the browser. If it fails, record the exact blocker and consciously retain
the vector-locked dual implementation for V1 rather than accidentally writing
the redesign twice.

### Threat model ordering: accepted

Split “write the Drive threat model” from the final verification gates. The
threat model and persistent-format inventory are item 1 and constrain the
design. Executable vectors, fuzzing, migration, crash/restart, federation, and
browser gates remain last and verify that the implementation matches it.
