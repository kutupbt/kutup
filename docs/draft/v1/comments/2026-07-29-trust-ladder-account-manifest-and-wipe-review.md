# External comment: trust ladder, account manifest, and destructive wipe

**Recorded:** 2026-07-29

**Source category:** AI-generated external review supplied by the maintainer

**Preservation:** verbatim review content below; headings are part of the
original comment

**Decision status:** untriaged. Nothing in the preserved comment is an accepted
Kutup design, completed audit, or security endorsement. Kutup/Codex annotations
follow the preserved text in a separately marked section.

---

Let me verify one thing before closing — it's a new finding and it should be
right.

Closing input, then — the trust-ladder call is right and I'll concede it, plus
two things that follow from combining your own accepted principles, and a seed
for the next topic.

**Cross-witnessing: your objection lands.** Counting peer signatures is
Sybil-able — an adversary stands up N servers that witness each other — and it
does conflate homeserver and witness roles. The four-level ladder is the correct
V1 answer because it stops trying to solve first contact cryptographically and
instead makes the assurance level explicit and non-promotable. One mechanism
note, since this is where these things usually thin out: the levels have to
**gate behavior**, not just render in a UI. A first Drive share to a TOFU-level
peer should require explicit confirmation, and a peer that drops a level should
quarantine rather than warn. If the ladder is only a label, it's documentation
of a weakness rather than a control.

**The two premises you've now accepted have a conjunction neither states.** The
one-way-door rule says irreversible formats and trust roots gate V1. The
preproduction premise says breaking changes are free. Together: *the
free-change window is a depleting resource, and the one-way-door set is exactly
the list of work that must finish before it closes.* The practical consequence
is that those items don't just have priority — they have to land **as a set**.
The worst outcome available is tagging with half the format work done, because
the remaining half instantly converts from "recreate dev state" to "migrate
real user ciphertext," and you'd be running the compatibility layer you just
decided not to build. I'd write the one-way-door items as a single explicit
*"cannot tag `v1` until"* checklist in `security-review-follow-ups.md`, because
that list literally is the boundary of the affordable-change window.

**Scope the preproduction premise to expire at the first tag.** As drafted,
"remove old parsers, routes, suite entries, and fallback behavior" and "no
dual-write, compatibility shim, or legacy read-only suite" read as standing
architectural rules. Post-tag they contradict `crypto-agility.md`, whose policy
floors require exactly a read-only *migrate* lane per registry. Without an
explicit expiry line, a contributor two years out reads the premise doc as
"Kutup does cutovers, not migrations" and the policy-floor design quietly rots.
One sentence fixes it: this premise governs until the first `v*` tag, after
which the registry migration lanes apply.

**Seed for `AccountIdentityManifestV1`** — agreed it's the right next topic, and
two decisions inside it are themselves one-way doors:

*Lifetime split.* Account-scoped keys (self-authority, Drive X25519/HPKE) and
device-scoped keys (chat identity, MLS credential, anonymous-delivery HPKE)
rotate on completely different triggers. Collapse them into one monotonic
manifest and every phone reinstall bumps the version that Drive peers have
pinned, forcing re-verification on an unrelated event. I'd have the account
manifest carry account keys and **commit to a device-manifest hash** — two
chains, one authority, one transparency leaf. Drive pins then move only when
account keys actually move, and the leaf shape you already have (`username,
manifestVersion, manifestHash, authorityKeyId`) covers both without change.

*The admin wipe is an unhandled authority discontinuity.* `POST
/api/admin/users/:id/wipe` (`api.md:1196`) erases the key bundle and resets to
first-login, so the account regenerates a new master key — and the
self-authority is `HKDF(master key, …)`, so it becomes a **different**
authority. Publication requires "stable authority" (`chat-protocol.md:253`) and
peers reject authority replacement outright (§5.3). So a wiped account is
cryptographically unreachable to every prior contact, with no defined path
back. Recovery via phrase is fine — same master key, same authority — wipe
specifically is not. This has to be solved at the account-identity layer: either
a signed discontinuity record that peers surface as a hard
safety-number-style reset, or wipe becomes an account-termination operation
with a new identity rather than a reset of the old one. Both are account-level
and both are one-way doors, so they belong in this design, not after it.

That's my last input. The direction is settled and correct; what's left is
empirical (the WASM spike, the MLS ADR) and specification work.

---

## Kutup/Codex annotations — 2026-07-29

These annotations are maintainer triage, not a normative protocol decision.

### Trust levels must enforce policy: accepted with precise failure classes

The trust ladder must affect authorization:

- a local policy may deny first sensitive traffic to a TOFU/unanchored domain;
- an allowed first Drive share to such a domain requires an explicit,
  fingerprint-bearing confirmation;
- a federation identity mismatch, invalid authenticated rotation, rollback, or
  cryptographic contradiction quarantines the peer; and
- an administrator must never infer “verified” from response-carried policy or
  a number of transitive TOFU signatures.

Witness unavailability or stale monitoring evidence is not itself an identity
downgrade. It retains the last cryptographic pin, warns visibly, and may block
new sensitive operations when the local freshness floor requires it.
Conflating temporary evidence availability with identity replacement would
create avoidable denial-of-service and contradict the existing failure model.

### Pre-tag boundary and expiry: accepted

The one-way-door items must be an explicit atomic no-tag checklist. The
preproduction destructive-cutover rule expires at the first stable `v*` tag.
After that tag, `crypto-agility.md` create/read/migrate/reject lanes, durable
migrations, and compatibility policy govern all persistent and federated
changes.

### Account/device lifetime split: insight accepted, proposed leaf is incomplete

Account-scoped and device-scoped state need independent sequences and rotation
triggers under one account authority. However, an account manifest that commits
to the **current** device-manifest hash necessarily changes whenever the device
chain changes. That cannot simultaneously make the account pin move only when
account keys change. The existing single `{manifestVersion, manifestHash}` leaf
also cannot represent two independently advancing chains without an aggregate
wrapper whose hash changes on either update.

The V1 specification should instead define:

- `AccountIdentityManifestV1`: account authority generation and account-scoped
  Drive/share keys;
- `AccountDeviceManifestV1`: the complete feature-specific device keys, signed
  by the same account authority and bound to the account identity generation;
  and
- one typed transparency current-state commitment containing both exact
  `{sequence, hash}` pairs.

This retains one log, sparse map, witness policy, and auditor while allowing
Drive verifiers to pin the account substate and Chat verifiers to follow the
device substate. It requires a new pre-tag leaf/profile definition; the current
leaf does not cover it unchanged.

### Admin wipe finding: confirmed and broader than documented

The wipe handler empties the master-key bundle and returns the account to
first-login, so setup derives a new authority. It currently deletes Drive and
collaboration state but does not retire the account's `chat_devices`, current
and historical Chat manifests, transparency entries, delivery capabilities, or
MLS identity/membership state. The unchanged user row means foreign keys do not
perform that cleanup.

No server-signed record can prove that the holder of a new master key is the
same cryptographic person as the holder of the lost authority. The recommended
model is therefore:

- destructive wipe terminates the old cryptographic account incarnation;
- the reused username begins a new, explicit account incarnation with a new
  authority;
- the transparency log preserves an operator-signed termination/discontinuity
  statement but never calls it user-authorized continuity;
- peers quarantine the address until an explicit safety-number-style
  acceptance or independent verification;
- old Direct sessions, capabilities, device records, prekeys, and local mailbox
  access are retired atomically;
- old MLS membership does not transfer to the new incarnation—group
  administrators explicitly remove/re-add it; and
- Drive collections and shares are recreated or re-shared, never inherited by
  the new key merely because the username is unchanged.

The exact tombstone and incarnation structures belong in the account-identity
specification and no-tag checklist. Recovery using the original recovery
entropy remains continuity, because it restores the same master key and
authority.
