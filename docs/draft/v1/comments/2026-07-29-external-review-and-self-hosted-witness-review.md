# External comment: external review and the self-hosted witness model

**Recorded:** 2026-07-29

**Source category:** AI-generated external review supplied by the maintainer

**Preservation:** verbatim review content below; headings are part of the
original comment

**Decision status:** untriaged. Nothing in the preserved comment is an accepted
Kutup design, completed audit, or security endorsement. Kutup/Codex annotations
follow the preserved text in a separately marked section.

---

Two things, both outside the design frame — which is why five rounds of review
didn't surface them.

**Nothing in this loop substitutes for an external cryptographic review, and
the one-way-door logic applies to that too.** `roadmap.md`'s v1 blockers list
signed builds and nothing about a security audit. The format and trust-root
decisions being frozen right now are precisely the ones an outside
cryptographer would most want to see *before* they're frozen — after the tag,
their findings become migration projects rather than edits. Two AI reviewers
converging is useful for specification consistency and for catching claims that
don't match the code; it is not the same as someone spending a week trying to
break the epoch chain or the manifest continuity rules. If an audit is going to
happen at all, it belongs during the Drive V2 design window, not after it.

**The witness model assumes an ecosystem that doesn't exist yet.** The threat
model requires "independently administered witnesses," and `api.md` defaults to
`transparencyWitnessQuorum: 1`. For the typical deployment — one person
self-hosting for a household or a small org — who runs that witness? If the
answer is "the same operator," the quorum attests the operator to themselves and
the property collapses to self-consistency. If it's "some public witness
infrastructure," that has to be built, funded, and independently governed, and
it's not on any list I read. This doesn't invalidate the design; the log still
makes equivocation detectable over time. But a large amount of carefully built
machinery only pays out at federation scale, and the gap between the threat
model's assumption and a v1 deployment's reality should be written down
honestly rather than discovered by a user reading the docs and asking who's
watching.

Beyond that, no — the direction is settled and the remaining questions are
empirical. Good luck with the build.

---

## Kutup/Codex annotations — 2026-07-29

These annotations are maintainer triage, not a normative protocol decision.

### External review: accepted as distinct from AI review

The accumulated comments are useful requirements review and code/doc
cross-checking. They are not an independent cryptographic audit or security
endorsement.

`security-review-follow-ups.md` already requires an external
implementation-versus-spec review before production-ready security claims, but
the canonical `roadmap.md` V1 blocker list does not currently carry that gate.
The roadmap and review bundle need reconciliation before tagging: threat model,
normative encodings, vectors, fuzz targets, adversarial gates, and the local
reproducible topology should be reviewed while destructive pre-tag corrections
remain affordable.

The scope and acceptance criteria must be explicit. A review should produce
tracked findings and resolutions; merely requesting one or receiving a generic
assessment does not satisfy the gate.

### Witness defaults: factual correction

`docs/api.md` shows an example capability block with
`transparencyWitnessQuorum: 1`; that is not the configuration default.
`CHAT_TRANSPARENCY_WITNESS_QUORUM` defaults to `0` in server configuration,
`.env.example`, and ordinary Compose. The dedicated witness and two-server
federation topologies explicitly set it to `1`.

This correction strengthens the operational concern: a default small
self-hosted deployment has no independent witness unless its operator arranges
one, while an authenticated federated transparency policy currently requires a
nonzero quorum.

### Self-hosted witness limitation: accepted

A witness operated under the same administrative boundary as the log operator
does not meet Kutup's “independently administered” threat-model assumption. It
can still detect accidental inconsistency and provide process/key separation,
but it cannot reliably detect a malicious operator who controls both systems.

V1 must expose deployment assurance honestly rather than treating every
configured witness count as equivalent:

- **operator-signed/unwitnessed:** append-only proofs, current-map binding, and
  durable client pins remain useful, but there is no independent split-view
  observer;
- **independently witnessed:** the configured quorum is controlled through
  genuinely separate administrative boundaries and clients independently pin
  the relevant verifier policy; and
- **unavailable/stale witness evidence:** retains the last valid pin and follows
  local freshness policy without being mislabeled as an identity-key change.

The server and administrator UI need to state the active assurance mode, who
controls each configured witness, and which features or remote trust floors
require independently witnessed evidence. Kutup must not advertise
“independently witnessed” merely because a second process with another key is
running on the same operator's infrastructure.

### Recommended self-hosting posture

Do not force a household self-hoster to pretend to operate an independent
witness. Permit an explicitly lower-assurance operator-signed mode for local or
policy-authorized use, with honest UI and documentation. Allow administrators
and clients to require independently witnessed evidence for federation or
high-assurance sends.

An ecosystem of reciprocal or public witnesses may be developed later, but it
needs separate governance, availability, abuse, privacy, key-rotation, and
funding design. It is not solved by the current witness binary or by
cross-signing among arbitrary homeservers.
