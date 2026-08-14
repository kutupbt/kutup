# External comment: Drive formats, WASM measurements, and epoch continuity

**Recorded:** 2026-07-29

**Source category:** AI-generated external review supplied by the maintainer

**Preservation:** verbatim review content below; headings are part of the
original comment

**Decision status:** untriaged. Nothing in the preserved comment is an accepted
Kutup design, completed audit, or security endorsement. Kutup/Codex annotations
follow the preserved text in a separately marked section.

---

This list is converged and I'd build from it. One concession, two additions,
then I think the review phase is done.

**Concession: you're right on bcrypt and profile AES, and my "pure subtraction"
framing was wrong.** Neither is a swap. `login_key_hash` can only be re-derived
at a successful login, so removal is a dual-read migration with an indefinite
tail of dormant accounts. Profile ciphertexts are deliberately readable by
peers holding older capabilities (`chat-protocol.md:§7.5`), so changing that
AEAD means re-encrypting every retained version or supporting two readers. Both
are well-trodden dual-read migrations — which is exactly why they're safely
deferrable and don't belong in the gate. Correctly excluded.

**The format inventory is the right first task, and one property makes it useful
or not.** Drive ciphertexts carry no suite ID today, so the inventory's job is
to enumerate every persistent shape currently in the database and object store
and retroactively assign each one an implicit code point — everything written
before the V2 cutover is `DriveObjectSuite 0`. Without that, V2 has no way to
name the data it must still read, and "one previous suite available read-only
during migration" has no referent. The inventory is what makes the registry
apply to data that predates the registry.

**The WASM spike needs pass/fail numbers, or it will return "seems fine" and the
problem surfaces in month three.** The headline risk is specific:
`frontend/src/crypto/` runs libsodium-wrappers — hand-optimized C compiled to
WASM — while `kutup-crypto` runs dryoc, which is pure Rust. Argon2id at 64 MiB is
the case where that gap is most likely to be material, and it sits directly in
the login path. I'd gate the spike on four measurements:

- Argon2id 64 MiB/t=3 in a Worker on a mid-range Android browser, dryoc vs.
  current libsodium — this is the one that can sink it
- secretstream throughput over ~1 GB with 5 MiB chunks crossing the JS↔WASM
  boundary, versus current TS, with the copy overhead isolated (zero-copy views
  vs. per-chunk copies)
- peak linear-memory during a concurrent upload and download
- bundle-size delta on top of the existing `build:chat-wasm` output

If Argon2id regresses badly, the fallback is a partial consolidation — Rust for
envelopes, derivation, and framing; libsodium for the password KDF — which keeps
most of the divergence win. Worth deciding that fallback before the spike runs,
so a bad number doesn't reopen the whole question.

**The epoch chain should reuse the manifest continuity machinery rather than
being designed fresh.** Your list for epochs — signatures, hash chaining,
client pinning, freshness, withholding detection — is item-for-item what
`DeviceManifest` plus the checkpoint model already implements: monotonic
version, `previousHash`, TOFU-pinned authority, rollback and same-version
equivocation rejected, staleness warns while retaining the last valid pin. Same
authority key, same verifier shape, same failure semantics. Building a parallel
epoch-chain verifier would violate the principle you just adopted at exactly
the place it's most tempting to.

That's everything I have. The remaining open questions — the `0x0001`/`0x0003`
ADR and the WASM spike — are both empirical, and neither resolves in a review
thread. Next artifact is the threat model and format inventory.

---

## Kutup/Codex annotations — 2026-07-29

These annotations are maintainer triage, not a normative protocol decision.

### Bcrypt and profile AES: deferral accepted

The correction is accepted. Both are versioned migration projects rather than
primitive deletions. Neither blocks the pre-tag Drive/account format work.

Because Kutup is preproduction, a later decision made before the first tag
could still replace them destructively. They are excluded from the present gate
because they are not prerequisites for a coherent Drive V1 trust and ciphertext
format—not because compatibility already constrains them.

### Format inventory: inventory accepted, implicit legacy suite rejected for V1

The inventory must enumerate every encrypted or signed shape in the database,
object store, browser persistence, federation payloads, public shares, and
recovery bundle. It must identify its key source, purpose, authenticated
context, nonce/framing, owner, lifetime, and all readers/writers.

However, the proposed implicit `DriveObjectSuite 0` read path conflicts with
Kutup's preproduction premise. There is no production ciphertext to preserve.
The V1 cutover should:

- replace all old Drive shapes with one explicit typed suite;
- recreate development databases, object storage, shares, and browser state;
- remove the old readers and writers;
- start the stable registry at its documented V1 code point; and
- prove by source audit and tests that no implicit-format path remains.

The inventory is still essential, but its V1 purpose is deletion completeness,
not naming a compatibility lane. After the first stable tag, every retired suite
must instead follow `crypto-agility.md` read/migrate/reject policy.

### WASM spike: quantitative gate accepted

Define devices, browser versions, datasets, repetitions, warm/cold behavior,
and pass/fail thresholds before collecting results. At minimum measure the four
cases in the preserved review and record both absolute user-visible latency and
relative regression. Include cancellation, error cleanup, Worker termination,
and whether peak memory returns after each operation.

The partial-consolidation fallback is acceptable only as an explicit outcome:
Rust owns the canonical envelopes, key hierarchy, framing, and vectors, while a
small browser adapter invokes libsodium for the password KDF. It must not leave
two independent definitions of a persistent or signed format.

### Epoch continuity: reuse machinery, not semantics blindly

Kutup should extract and reuse common authenticated-chain machinery:
domain-separated canonical encoding, monotonic sequence and previous-hash
verification, authority pinning, rollback/equivocation evidence, atomic
persistence, and parser/fuzz scaffolding.

`CollectionKeyEpochStateV1` remains a distinct typed protocol. Its failure
semantics are stricter than a stale device-manifest observation: a client must
not create new ciphertext under stale collection membership merely because it
retains the last valid epoch pin. It also has different scale and privacy
properties; blindly appending every collection event as a public account-log
leaf could expose collection activity and overload the manifest log.

The threat model must decide how current epoch freshness and withholding are
authenticated. Reuse the verifier implementation and evidence model, but do
not reuse `DeviceManifest` as the epoch structure or claim identical warning
semantics.

### Next artifact

Agreed: write the Drive threat model and exhaustive format inventory before
selecting the final V1 envelope, epoch, and share structures. The MLS suite ADR
and Rust/WASM benchmark remain separate empirical work.
