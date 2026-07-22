# Unified federation protocol

**Status:** implemented. Chat and Drive both use the shared v2 identity,
resolver, admission, trust, replay, and authenticated transport. The old
feature-specific federation stacks and v1 downgrade paths have been removed.

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
server identity signs that endpoint. Plain HTTP and private addresses exist
only behind an explicit `APP_ENV=test` harness guard and are not accepted by
the production profile.

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

After verification, `FederationVerifiedRequest::replay_metadata()` exposes the
authenticated nonce, signed time window, skew-adjusted reservation expiry, and
a domain-separated SHA-256 hash of the stable covered request content. The
hash excludes signature timestamps so an exact logical retry can be freshly
signed with the same nonce; changing any method, target, body digest, content
type, version, feature, origin, or destination changes the hash.

## Runtime behavior

The resolver applies feature admission before DNS, fetches discovery from the
canonical server name, verifies the signed endpoint and complete identity
history, then connects only to the already-validated address set. Redirects
are disabled, response sizes and identity history are bounded, successful
discovery is cached only through its signed expiry, failures have a short
negative cache, and concurrent first contact is single-flight per domain.

Only the persisted pinned key authenticates feature requests and responses.
An exact signed-request replay is distinguishable from reuse of a nonce with
different content; the latter is rejected. Feature protocols keep their own
semantic idempotency keys. In particular, a Chat device-list correction keeps
its stable Chat transaction ID but derives a different transport nonce for the
corrected payload; byte-identical retries retain that payload-version nonce.

Drive capabilities remain feature authorization, not server authentication.
They travel in the dedicated `Kutup-Share-Capability` header after the v2
request has authenticated its origin. An outgoing share is bound to that
canonical origin domain and stores only a SHA-256 verifier; the plaintext
capability is returned once inside the invite URL fragment, which is not sent
to the web origin in an HTTP request. A recipient server retains the capability
only for its local user's accepted share. It never returns it in list APIs.

Drive mutations use a stable feature request ID derived from the local user,
accepted share, operation, and exact upload body or file ID. The source stores
the authenticated request hash and exact response under that ID. Exact retries
return the stored result; reuse for different covered content fails. Uploads
hash the exact ciphertext while spooling it, persist that digest with the file
row, and never inspect plaintext.

Large Drive downloads are authenticated before release to the browser. The
source signs a precomputed RFC 9530 digest and streams the ciphertext. The
recipient server spools the response to an unnamed temporary file while
hashing it, verifies the pinned peer's response signature and exact digest,
then exposes the verified stream to its local client. A digest, signature,
origin, destination, or request mismatch releases no bytes.

The Phase C migration deliberately clears only experimental Chat federation
transport state and removes the old Chat-only trust stack. The breaking Phase D
migration drops the experimental Drive federation share state, recreates it
with canonical domains and capability verifiers, and adds persistent mutation
results and ciphertext digests. Local users, collections, files, and ordinary
same-server shares remain intact. There is no legacy route, raw remote URL,
configuration alias, or downgrade fallback.

## Operational control plane

The admin control plane is a projection over this one stack. It reports the
local identity/capabilities, feature policies, directional domain rules,
TOFU/verified/quarantined peers, Chat outbox health, Drive incoming/outgoing
share counts, and active replay reservations. Search/trust filters and
single/bulk retry only select peers and evict the common resolver cache; they do
not alter the authentication or admission rules.

Accepted, superseded, and quarantined peer identity documents remain immutable
in `federation_peer_identity_documents` and are inspectable with their exact
document hash, key fingerprint, sequence, acceptance state, and recorded time.
Quarantine never replaces the accepted document. Verification and break-glass
re-pin still call the same transactional trust state machine and write the same
audit store. Federation audit reads and CSV export filter that generic store;
there is no Chat audit store, Drive audit store, or alternate trust cache.
