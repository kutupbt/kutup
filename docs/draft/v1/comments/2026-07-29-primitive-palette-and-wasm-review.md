# External comment: primitive palette and Rust-to-WASM consolidation

**Recorded:** 2026-07-29

**Source category:** AI-generated external review supplied by the maintainer

**Preservation:** verbatim review content below; headings are part of the
original comment

**Decision status:** untriaged. Nothing in the preserved comment is an accepted
Kutup design, completed audit, or security endorsement. Kutup/Codex annotations
follow the preserved text in a separately marked section.

---

Let me verify the primitive inventory and the WASM story before answering — one
of these matters a lot for your point.

Agreed — and it resolves a tension in my earlier advice rather than
contradicting your own `crypto-agility.md`. The distinction that matters:

**Unify the primitive palette and the implementation. Keep the registries
separate.** Those are different axes. `crypto-agility.md` is right that a
universal `CryptoSuite` and cross-feature primitive selection are dangerous —
that's about *negotiation surface*. It says nothing against every registry's
current entry drawing from the same small set of primitives. The elegant target
is **N registries, one palette**: a new suite code point is a new reviewed
construction, but it is assembled from primitives the project already ships,
tests, and audits.

The federated part makes this sharper than it would be for a centralized app.
Signal can flag-day its clients in a week; you cannot. Every construction you
admit is effectively permanent, must be implemented correctly by every
independent implementation forever, and has to be reviewed by volunteers with
finite time. Interop surface = constructions × implementations.

## The current palette is wide

From what's in the tree and docs: X25519, Ed25519, XEd25519, P-256 (DHKEM +
signature), ML-KEM-768, ML-KEM-1024 · XSalsa20-Poly1305,
XChaCha20-Poly1305, AES-128-GCM (MLS + anonymous-delivery HPKE), AES-256-GCM
(`chat-protocol.md:557`, profile names) · SHA-256, HKDF-SHA256, Argon2id,
bcrypt.

Roughly six asymmetric primitives and four AEADs. A unified palette:

| Role | One choice | Drops |
|---|---|---|
| AEAD | XChaCha20-Poly1305 (ChaCha20-Poly1305 where HPKE/MLS mandate a 12-byte nonce) | XSalsa20-Poly1305, AES-128-GCM, AES-256-GCM |
| Signature | Ed25519 | P-256 signatures |
| DH / KEM | X25519, PQ parameter ML-KEM-768 only | P-256 DHKEM, ML-KEM-1024 for new work |
| Hash / KDF | SHA-256 + HKDF-SHA256 | — |
| Password | Argon2id | bcrypt |

Two of those are easy wins available today. **AES-256-GCM for profile names** is
a third AEAD carried for one field — it's Signal-inherited, and nothing about
the bucket-padding scheme requires AES. **bcrypt** is a second password hash
applied to a value that is already 64 MiB of Argon2id output; a salted
HMAC-SHA256 verifier is sufficient there and deletes a dependency plus its
72-byte/null-byte quirks. Neither needs a new design.

ML-KEM-1024 is libsignal's handshake parameter, inherited rather than chosen —
fine. The point is that when PQ reaches Drive, it should be **768**, which is
also what X-Wing specifies, so the palette stays at one PQ parameter set.

## This changes some of what I recommended

**Drop the STREAM + Merkle idea properly.** Your reviewer was right on process
grounds; your principle is a second, independent reason. `crypto_secretstream`
is one construction, libsodium-standard, already vector-tested across
languages. Replacing it buys random access that no shipped feature requires. If
video seek later becomes a product requirement, that is a **new
`DriveObjectSuiteId` code point** with its own spec and vectors — added, not
substituted. That is the registry design working exactly as intended, and it's
the cheapest possible answer.

**Drop the CBOR/protobuf suggestion.** A third serialization is the opposite of
what you want. You already wrote an elegant canonical binary encoding in
`federation-protocol.md` — fixed domain separators, big-endian, four-byte length
prefix then exact UTF-8, JSON formatting never signed. Make that **the**
canonical signing encoding project-wide and reuse it for Drive envelopes
instead of inventing anything.

**Reuse the capability pattern, don't parallel it.** Chat derives
recipient-bound capabilities with HKDF (`chat-protocol.md:§7.6`) and stores only
a SHA-256 verifier. Drive federation uses an origin-bound bearer string. One
pattern should cover both.

## The largest unification win is not on anyone's list

`frontend/package.json:12` runs `build:chat-wasm` — **Chat's crypto is Rust,
compiled to WASM, and the browser consumes it.** Drive's crypto is a separate
TypeScript implementation in `frontend/src/crypto/`, which CLAUDE.md declares
*canonical*, with `kutup-crypto` as its mirror and a standing rule to keep them
byte-compatible plus checked-in vectors to police the divergence.

So the project already contains both models, pointing opposite directions.
Chat: one Rust implementation, every client. Drive: two implementations that
must be manually kept in sync, forever, across TS and Rust — and Swift/Kotlin
arrive through FFI from the Rust side, meaning mobile Drive would consume the
*mirror*, not the canonical one.

Moving Drive crypto onto the same Rust→WASM path that Chat already uses would
delete `frontend/src/crypto/` as an independent implementation, remove the
"keep them mirrored" rule from CLAUDE.md, retire a class of cross-language
divergence bugs entirely, and give web, desktop, CLI, iOS and Android one
audited implementation. For an open-source federated project where review
capacity is the scarce resource, halving the amount of crypto that exists is
worth more than any single algorithm upgrade on the list. The build plumbing
already exists.

## Two tensions worth deciding deliberately

**P-256 has one legitimate defender: hardware keystores.** Secure Enclave and
StrongBox are P-256-only. Unifying on X25519/Ed25519 means MLS identity keys live
in software. That is a real trade between one-curve simplicity and hardware key
protection on mobile, and it's the single place where your principle has an
honest opponent. It should be decided explicitly in `chat-mls.md` rather than
inherited by default — right now no document states a reason, which is the worst
of both.

**PQ migration is where "stable" and "simple" pull apart.** Adding hybrid
wrapping to Drive means two suites live simultaneously across a federated
network for a long time — inherently not simple. The resolution is the
machinery you already designed: new code point, explicit
create/read/migrate/reject policy floors, no in-band negotiation, no downgrade.
The agility design is precisely what buys simplicity during that window; the
failure mode is bypassing it and doing an implicit format change.

For the Drive V2 ordering, this argues for putting the palette cleanup and the
WASM consolidation early — they're subtractive, low-risk, and they shrink the
surface that every later item has to be built and reviewed against.

---

## Kutup/Codex annotations — 2026-07-29

These annotations are maintainer triage, not a normative protocol decision.

### Accepted direction

- Keep separate, feature-scoped suite registries while drawing Kutup-owned
  constructions from a deliberately small primitive palette.
- Share reviewed implementation machinery, canonical field encoders, vectors,
  fuzz infrastructure, padding helpers, and zeroization utilities. Never reuse
  a key across purposes merely because two features use the same primitive.
- Treat primitives inside pinned dependencies such as libsignal and OpenMLS as
  dependency constraints. Kutup must not fork either project merely to make the
  final binary appear to have a smaller primitive inventory.
- Put the Drive threat model before final Drive V2 construction choices, not at
  the end of their implementation.

### Rust-to-WASM consolidation

Moving Drive toward one Rust implementation consumed by web, native, CLI, and
server code is accepted as an architectural goal. It is not yet an existing
capability: Chat has a Rust-to-WASM build, while `kutup-crypto` currently has no
equivalent browser binding.

Before committing the persistent Drive format to that implementation, run a
bounded spike that verifies:

- browser support and vectors for the current `dryoc`/secretstream operations;
- Argon2id memory use, responsiveness, cancellation, and worker isolation;
- BIP39/recovery compatibility;
- bundle-size and startup cost;
- secret lifetime and zeroization across the JavaScript/WASM boundary; and
- compatibility with the mobile and CLI consumers.

Migrate operations incrementally under the same checked-in vectors. Delete the
TypeScript implementation and revise `CLAUDE.md` only after the Rust/WASM path
has reached parity and all callers have moved. A big-bang deletion would turn a
sound simplification into a migration risk.

### Primitive-palette corrections

- AES-256-GCM is used by the shared profile-field encryption helpers, including
  avatar/profile fields, not only one profile-name field. Replacing it requires
  a typed Profile suite/version, migration semantics, and vectors.
- Bcrypt protects both the Argon2-derived login verifier and the recovery
  verifier. The current encoded login key is below bcrypt's 72-byte boundary,
  so the cited truncation and NUL concerns do not establish a current bug.
  Replacing bcrypt with HMAC is only useful if the HMAC has a protected
  server-side key, with startup validation, rotation, backup, and failure
  semantics; a public-salt HMAC would merely be another fast stored verifier.
  This remains an explicit design decision, not an automatic cleanup.
- Kutup cannot claim to remove AES or ML-KEM-1024 from the deployed primitive
  inventory while pinned libsignal protocols require them. The minimal-palette
  rule therefore governs Kutup-owned constructions and new suite choices.
- MLS `0x0001` versus `0x0003` remains open. Palette alignment favors
  X25519/Ed25519/ChaCha20-Poly1305, while RFC 9420 mandatory-to-implement
  interoperability favors `0x0001`. The project needs one explicit ADR after
  measuring the full migration and platform implications.

### Reuse boundaries

The federation encoder is a useful pattern, but it should become shared,
domain-separated field-encoding primitives rather than one universal wire
format imposed on unrelated protocols.

Likewise, Drive should reuse Chat's capability construction pattern only after
specifying Drive's own authorization semantics. An account-bound Drive
capability must bind the exact canonical recipient into authenticated
federation requests and be enforced at redemption; changing the HKDF alone is
not sufficient.

### Scheduling consequence

The unification work is part of the proposed minimal Drive V2 program, but the
first deliverable is a Drive threat model and format inventory. Subtractive
changes are valuable only when their persistence, federation, browser, and
recovery consequences are specified first.
