# Crypto agility and purpose-specific suites

**Status:** accepted

**Date:** 2026-07-20

**Scope:** all Kutup-owned cryptographic wire and persistent formats

This is the authoritative project-wide decision for changing cryptographic
protocols without creating downgrade paths. Feature specifications may add
details, but must not weaken these rules.

## Decision

Kutup uses a separate, closed suite registry for each cryptographic purpose.
A suite identifier selects one complete, reviewed protocol construction. It is
not a bag of independently selectable primitives.

For example, a Direct Chat suite fixes the session-establishment protocol,
ratchet, key and parameter sizes, message versions, serialization, validation,
domain-separation labels, and migration behavior together. A caller cannot ask
for that suite's KEM with another suite's KDF or wire format.

Suite identifiers are opaque code points. Their numeric values do not express
strength or preference. Assignment is permanent: changing any
security-relevant part of a suite requires a new identifier.

Kutup will not define a universal `CryptoSuite`, accept a raw untyped suite ID
across feature boundaries, or expose primitive selection to users,
administrators, peers, or feature code.

## Registries and ownership

The owning protocol defines the type, code points, exact construction,
parsing, policy, migration rules, and cross-language test vectors. Other
features may carry its ciphertext as opaque bytes but may not interpret or
select its suite.

| Registry | Protected purpose and lock unit | Authoritative owner |
|---|---|---|
| `AccountProtectionSuiteId` | Password/recovery derivation and wrapping of account secrets; one account protection revision | `kutup-crypto` account-protection module and Auth wire contract |
| `AccountIdentitySuiteId` | Account root authority, feature-key authorization, and authenticated identity rotation; one identity epoch | account-identity protocol crate (to be extracted from Chat before Drive uses it) |
| `DriveObjectSuiteId` | The complete Drive E2EE object family: collection/file metadata, key envelopes, content streams, assets, and share key wrapping; one independently decryptable object | `kutup-crypto` Drive-object module, mirrored by web/native clients |
| `CollabFrameSuiteId` | Collaborative frame KDF, AEAD, signature, framing, and validation; one document-key epoch | `kutup-crypto` collaboration-envelope module, mirrored by web/native clients |
| `DirectChatSuiteId` | Direct-session establishment, ratchet, message format, and validation; one device-to-device session | `kutup-chat-proto` and `kutup-chat-core` |
| `GroupChatSuiteId` | Group key agreement, encrypted authoritative group state, message protection, and epoch rules; one group/epoch | Group Chat protocol/core; created with the group feature, not as a placeholder |
| `ProfileSuiteId` | Encrypted-profile key derivation, field envelopes, padding, wrapping, and access capability; one profile-key version | `kutup-chat-proto` and the profile module in `kutup-chat-core` |
| `KeyTransparencySuiteId` | Log/map hashing, proof formats, checkpoint, operator, and witness authentication; one log generation | transparency protocol module; extraction from Chat is required if Drive adopts it |
| `FederationAuthProfileId` | Federation discovery authentication, server identity/rotation, HTTP request/response authentication, and replay profile; one federation protocol version/exchange | `kutup-federation-proto` |

The extra Account Protection, Collaboration, and Key Transparency boundaries
are intentional. They have different keys, authorities, migration events, and
failure consequences from Account Identity, Drive objects, and Chat sessions.
Combining them would allow an unrelated protocol to select or block their
cryptography.

TLS, WebRTC, database-at-rest encryption, and primitives internal to a suite do
not get Kutup suite IDs merely because they use cryptography. Their owning
standards or platform configurations control them. If Kutup later adds its own
protected protocol above one of them, that protocol receives a purpose-specific
registry then.

## Required behavior

### Complete suites

Every registry entry must specify at least:

- the protocol and serialization versions;
- every algorithm, mode, key/nonce/tag size, and fixed parameter;
- key derivation and domain-separation labels;
- signed/transcript/AEAD-associated data and canonicalization;
- validation limits and mandatory error behavior;
- the persistent state it protects and its migration boundary; and
- normative cross-language positive and negative vectors.

Adding an optional primitive or changing a parameter, label, covered field,
validation rule, or wire encoding creates a new suite unless the existing suite
specification already defines that exact behavior.

### Authenticated capabilities and selection

A capability list used to choose a suite must be authenticated by the identity
that controls the protected object or participant. It must be covered by a
signature, an authenticated protocol transcript, or an already authenticated
E2EE control message. TLS or an unsigned server settings response alone does
not authenticate an end user's or device's capabilities.

Capabilities do not create trust; they are accepted only after the advertising
identity is authenticated. A server may publish availability information for
UI gating, but it cannot override a device, account, group, or peer-server
capability statement.

For a new shared object, the creator selects from:

1. suites implemented locally;
2. suites permitted for new writes by local policy; and
3. suites present in every required participant's authenticated capabilities.

The creator uses the owning registry's fixed local preference order. A peer's
ordering is not trusted. If the intersection is empty, creation fails with a
typed `NoCommonSuite` error. It never retries with a weaker or legacy suite.

Local-only objects need no artificial negotiation. The writer selects its
locally preferred allowed suite and records it in the object.

### Local security policy floors

Each registry owns a local policy with separate decisions for:

- **create/send:** suites allowed for new state, in local preference order;
- **read/receive:** historical suites that may be opened while still supported;
- **migrate:** suites that may only be read as the source of an upgrade; and
- **reject:** suites forbidden even when implemented or advertised.

This is the policy floor. It is an explicit per-suite decision, never a numeric
comparison such as `suite >= minimum`. Product releases can raise the built-in
floor. An operator may make it stricter, but remote input and ordinary users
cannot make it weaker. Capability advertisement cannot re-enable a suite that
policy rejects.

Dual-read/single-write during a planned transition is allowed: metadata selects
one exact historical decoder, while all new state uses the new suite. Trying
several decoders until one succeeds is forbidden.

### Authenticated binding and suite locking

Every protected value must have exactly one unambiguous suite selector:

- carry the suite ID in an authenticated envelope; or
- use an authenticated format/protocol version that maps to exactly one suite.

Do not add a second wire field when a version already has a one-to-one mapping.
For example, Federation protocol version 2 selects the sole
`FederationAuthProfileId::HttpSignaturesV2`; it does not also negotiate an
`authProfile` header. Collaboration frame version 1 may likewise be the
authenticated selector for `CollabFrameSuiteId` version 1.

The selector and purpose must be bound into the signature/transcript, AEAD
associated data, or suite-specific KDF context. When dispatch must occur before
authentication, the clear selector may choose only the exact parser, and
successful processing must authenticate the same selector and purpose inside
the protected context.

After creation, the suite is locked to the session, group epoch, profile-key
version, stored object revision, account-identity epoch, document-key epoch, or
federation version. It cannot change in place and cannot be chosen independently
for individual fields or messages within that unit.

Keys are purpose- and suite-bound. APIs must not accept a key from another
registry merely because its bytes have the same length.

### Unknown suites and downgrade failures

Unknown, malformed, unsupported, and policy-rejected suite IDs fail closed as
distinct typed errors. Parsers and database reads must never use `unwrap_or`, a
default enum value, a primitive-based guess, or a “legacy” decoder for unknown
input.

An authentication, decryption, signature, transcript, capability, or policy
failure terminates that operation. The caller must not retry with a different
suite. Transport retry may resend the exact same authenticated operation; it
must not renegotiate it.

Opaque relays may preserve bytes they are explicitly designed not to
interpret, but must not advertise, validate, transform, or claim support for an
unknown suite.

## Migration protocol

A suite change is an explicit authenticated protocol operation, not an error
recovery branch:

1. Add the new immutable registry entry, implementation, negative tests, and
   cross-language vectors.
2. Ship readers for the old and new suites while new writes remain on the old
   suite.
3. Authentically advertise new support and measure non-secret suite adoption.
4. Switch new writes to the new suite by raising the create policy.
5. Migrate existing state using the owning protocol's authenticated boundary:
   create a new direct session, reinitialize/new-epoch a group, rotate and
   republish a profile, rewrap account secrets, copy-and-swap a Drive object,
   rotate a document key, cross-sign an identity epoch, or bump the federation
   protocol version.
6. Commit migrations atomically or with a crash-resumable authenticated journal.
   Never relabel old ciphertext with a new suite ID.
7. Move the old suite to migrate-only, then reject it after the documented
   support and recovery window.

Migration authorization must bind the purpose, object identity, old suite and
state hash/version, new suite and state hash/version, and a monotonic revision
or epoch. The same authority that controls the object or protocol transition
must authenticate it. For local zero-knowledge data, the client decrypts and
reencrypts; the server provides only compare-and-swap storage and never sees
plaintext keys or content.

## Versioning and review rules

- Code point zero is reserved as invalid in Kutup-owned numeric registries.
- Registry code points and meanings are never reused, renamed semantically, or
  deleted; retired entries remain documented as forbidden.
- JSON/OpenAPI fields use the purpose type in code even if the serialized form
  is a number or short string.
- A protocol version may map to one suite. If it permits multiple suites, their
  selection and capabilities must be authenticated by that protocol.
- Adding a suite requires a threat-model update, migration plan, test vectors,
  policy status, interoperability tests for every supported client, and an
  explicit removal criterion for the predecessor.
- Shared helpers may reduce serialization duplication, but may not erase the
  registry's Rust/TypeScript/UniFFI type or introduce cross-purpose conversion.

## Consequences for current Kutup code

Direct Chat now uses the purpose-specific `DirectChatSuiteId`. Database schema
and read paths require an explicit known code point, while code point 1 and its
wire encoding remain unchanged. Authenticated per-device suite capabilities
and suite-tagged local libsignal sessions remain the next Direct Chat slice;
they must land before a second Direct Chat suite is introduced.

Drive, Account Protection, encrypted profiles, account identity, and key
transparency currently encode most of their constructions implicitly. Their
current formats become explicit legacy-v1 entries for exact reads; changing
their binding or format requires a new suite and explicit migration. The
collaboration frame's signed-and-AEAD-bound version byte can remain its sole
suite selector after strict version validation is added.

The unified federation implementation owns only
`FederationAuthProfileId`. It must treat Chat and Drive payloads as opaque and
must not negotiate their feature suites.

## Research basis

- [RFC 7696 / BCP 201](https://www.rfc-editor.org/rfc/rfc7696.html) requires a
  protocol mechanism to identify its algorithm or suite, recommends
  integrity-protected selection, and warns that complex negotiation creates
  downgrade and implementation risk. It also favors a small set of
  mandatory-to-implement choices.
- [RFC 9180 (HPKE)](https://www.rfc-editor.org/rfc/rfc9180.html) defines a
  ciphersuite as a complete KEM/KDF/AEAD tuple, domain-separates derivation by
  suite, and leaves downgrade prevention to the embedding application.
- [RFC 8446 (TLS 1.3)](https://www.rfc-editor.org/rfc/rfc8446.html) binds the
  negotiated version and algorithms into the authenticated handshake
  transcript rather than trusting an unauthenticated choice.
- [RFC 8725 / BCP 225](https://www.rfc-editor.org/rfc/rfc8725.html) requires
  applications to configure allowed algorithms rather than trust a received
  algorithm identifier, and recommends using each key with one algorithm.
- [RFC 9420 (MLS)](https://www.rfc-editor.org/rfc/rfc9420.html) authenticates
  member capabilities, requires all group members to support the group's fixed
  version and ciphersuite, and changes them through an authenticated `ReInit`
  that creates a new group.
- [RFC 9106 (Argon2)](https://www.rfc-editor.org/rfc/rfc9106.html) shows why the
  variant, version, memory, passes, parallelism, salt, and output length are all
  part of a password-derivation configuration rather than merely the name
  “Argon2id”.
- [The Update Framework specification](https://theupdateframework.github.io/specification/v1.0.26/)
  provides the old-and-new authorization and sequential update model used for
  authenticated trust-root transitions.
