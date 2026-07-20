# Unified federation protocol

**Status:** v2 protocol and pure verification implemented; server persistence
and runtime cut-over are pending

**Version:** 2

**Authentication profile:** `FederationAuthProfileId::HttpSignaturesV2`

This is the normative wire and verification contract for Kutup's common
server-to-server identity, discovery, and authentication layer. Chat and Drive
are separate feature protocols above it. Their ciphertext and authorization
rules do not live in the federation layer.

Federation version 2 selects exactly one complete authentication profile. It
does not negotiate individual algorithms and never falls back to version 1.
The project-wide evolution rules in [`crypto-agility.md`](crypto-agility.md)
also apply.

The pure reference implementation is `kutup-federation-proto`. It performs no
DNS, HTTP, database, admission-policy, replay-store, or feature-payload I/O.
Its checked-in deterministic vector is
[`../crates/kutup-federation-proto/test-vectors/federation-v2.json`](../crates/kutup-federation-proto/test-vectors/federation-v2.json).

## Canonical values

- A server identity is a canonical lowercase multi-label DNS name. IP
  literals, ports, trailing dots, uppercase, and Unicode are rejected.
- Key IDs are lowercase hex SHA-256 of the raw 32-byte Ed25519 public key.
- Public keys and signatures use padded RFC 4648 standard base64. Alternate
  but decodable representations are rejected.
- Times are non-negative Unix seconds.
- Signed binary documents use fixed domain separators and big-endian integers.
  Every variable string is encoded as a four-byte unsigned length followed by
  its exact UTF-8 bytes. JSON formatting is never signed.

## Identity documents

An identity document has this closed JSON shape:

```text
FederationIdentityDocumentV1 {
  identityVersion: 1,
  server,
  sequence,
  key: { algorithm: "ed25519", keyId, publicKey },
  previousDocumentHash?,
  issuedAt,
  previousSignature?,
  currentSignature
}
```

The current signature covers, in order:

```text
"kutup-federation-identity-document-v1\0"
identityVersion:u16
server:length-prefixed
sequence:u64
algorithm:length-prefixed
publicKey:32 raw bytes
keyId:32 raw bytes
hasPreviousHash:u8
previousDocumentHash:32 raw bytes when present
issuedAt:i64
```

The document hash is SHA-256 over
`"kutup-federation-identity-document-hash-v1\0" || signingBytes`. Signatures
authenticate the canonical payload but are not included in its hash.

Genesis is sequence zero, has neither predecessor field, and is self-signed.
Every rotation advances by exactly one, hash-links the exact predecessor,
introduces a different key, does not move `issuedAt` backwards, and carries
Ed25519 signatures from both the old and new keys over the new document's
signing bytes. A verifier fetches and checks every intermediate document.
Rollback, gaps, equivocation, wrong-domain documents, bad links, and either bad
signature fail closed.

## Signed discovery

`/.well-known/kutup/federation.json` has this closed shape:

```text
FederationDiscoveryV2 {
  fedVersion: 2,
  server,
  apiBase,
  capabilities: ["chat.v1", "drive.v1", "identity.v1"],
  identity,
  identityDocumentHash,
  signedAt,
  expiresAt,
  signature
}
```

Capabilities are unique and byte-sorted; `identity.v1` is mandatory. `apiBase`
is canonical HTTPS without credentials, query, fragment, a default `:443`, or
a trailing slash. Delegation to a different DNS host is allowed because the
server identity signs that endpoint.

The identity's current key signs these deterministic bytes:

```text
"kutup-federation-discovery-v2\0"
fedVersion:u16
server:length-prefixed
apiBase:length-prefixed
capabilityCount:u16
each capability:length-prefixed
identityDocumentHash:32 raw bytes
signedAt:i64
expiresAt:i64
```

The validity window must be positive and at most 24 hours. Verification binds
the expected DNS identity, embedded identity and its hash, endpoint,
capabilities, version, and validity window before the caller applies TOFU,
pin-advance, or quarantine policy.

## HTTP message signatures

Federation v2 is a strict application profile of
[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) with exact-body
`Content-Digest` from [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html).
The signature label is `kutup`, algorithm is `ed25519`, and application tag is
`kutup-federation-v2`.

Every request covers this exact ordered component list:

```text
@method
@authority
@path
@query
content-digest
content-type
kutup-federation-version
kutup-federation-feature
kutup-origin
kutup-destination
```

`Signature-Input` must then carry, in this exact order, `created`, `expires`,
full `keyid`, `alg="ed25519"`, `nonce`, and
`tag="kutup-federation-v2"`. The signed lifetime is positive and no longer
than five minutes. An absent query is represented by `?`. The digest is the
canonical structured-field value `sha-256=:BASE64:` over the exact body,
including an empty body.

Every response covers its status, digest, content type, federation version,
feature, origin, and destination, followed by every request component above
using RFC 9421's `;req` parameter. It repeats the request nonce. Response
origin/destination are the reverse of the request and the feature/version must
match. Thus TLS endpoint delegation does not let the endpoint forge or replay
a response for another request, peer, or feature.

Missing, extra, reordered, duplicated, selectively covered, or unknown
components are rejected. So are non-canonical targets, wrong digests, unknown
versions, wrong keys, altered profile labels, expired/future signatures,
cross-destination replay, cross-feature replay, and request/response mismatch.
The HTTP `Signature` and `Signature-Input` fields themselves are not covered,
as required by the RFC construction.

## Runtime transition

The currently deployed experimental Chat federation v1 implementation is
isolated in the server-private `legacy_chat_federation_v1` module. It is not a
public Chat protocol type and is not a fallback from v2. Phase B adds common
identity and trust persistence. Phase C atomically moves the server transport
and Chat adapter to this v2 profile and deletes the private v1 module. Drive is
cut over to the same stack afterward.
