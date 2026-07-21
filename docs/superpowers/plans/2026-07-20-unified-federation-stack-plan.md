# Unified federation stack implementation plan

**Date:** 2026-07-20

**Status:** accepted; Phases A-D implemented and two-server live verified;
Phase E is next. Phase F's Drive/Chat harness, migration fixtures, and primary
documentation are implemented alongside Phase D.

**Compatibility decision:** Kutup has no live federation deployment. Replace
the current experimental Chat and Drive protocols atomically; do not preserve
legacy wire formats, raw-URL shares, routes, environment names, or database rows.
**Security priority:** establish one small, auditable trust boundary and fail
closed on authenticated identity conflicts.

## 1. Decision

Kutup will have one server-level federation stack. Chat and Drive will be
feature protocols above it, not separate trust or networking implementations.

The common stack owns:

- canonical server identity (`domain`, never an operator-entered API URL);
- `.well-known` discovery and API delegation;
- the persistent Ed25519 server identity and authenticated rotation history;
- TOFU pins, manual verification, quarantine, and break-glass re-pinning;
- one admission engine with a global emergency stop and feature-scoped modes
  plus directional per-domain rules;
- outbound URL/DNS/SSRF enforcement and a no-redirect HTTP client;
- request signing, inbound authentication, clock bounds, and replay defense;
- capability negotiation, bounded response handling, audit, and observability.

Feature adapters retain only their application semantics:

- **Chat:** E2EE device-directory reads, encrypted profile reads, durable
  ordered ciphertext delivery, gaps, retries, and idempotency.
- **Drive:** remote account-key lookup, invitation retrieval, and proxied
  collection operations authorized by a per-share capability.

One trust failure quarantines the peer for every feature and both directions.
Admission remains distinct from identity: an allowed server still has to pass
cryptographic authentication, and a cryptographically known server can still
be operationally blocked. “Unified” does not force operators to expose Chat and
Drive together: the same policy engine evaluates a feature dimension.

The deferred multi-root/multi-authority enterprise profile remains documented
in [`../../research/14-enterprise-federation-identity.md`](../../research/14-enterprise-federation-identity.md).
This implementation deliberately establishes the simpler single-key chain that
the future profile can replace without changing feature adapters.

## 2. Current-state problems being removed

| Concern | Chat today | Drive today | Target owner |
|---|---|---|---|
| Peer identifier | canonical DNS domain | caller-provided base URL | common stack |
| Discovery | `.well-known` + delegated `apiBase` | none | common stack |
| Server authentication | signed requests using live discovery keys | TLS plus bearer capability only | common stack |
| Persistent peer pin | missing | missing | common stack |
| Rotation | live key replacement is silently trusted | no server key | common stack |
| Admission lists | chat-only modes/rules | not applied | common engine, feature-scoped policy |
| SSRF validation | chat-specific validator | separate URL validator | common stack |
| Replay control | feature transaction idempotency | capability only | common stack plus feature idempotency |
| Remote endpoint storage | domain in chat outbox | raw URL in incoming shares | canonical domain |
| Operational UI | “Chat federation” policy | none | “Federation” control plane |

The duplicate stacks are historical implementation debt, not a desired security
boundary.

### 2.1 Research validation

The v2 design was pressure-tested against the current primary specifications
and the local Prosody/Monal implementations:

- [OMEMO XEP-0384](https://xmpp.org/extensions/xep-0384.html) is client/device
  E2EE and explicitly leaves trust management out of scope. Monal adds its own
  TOFU/manual states and stops automatically trusting new device keys after a
  contact has a manually verified key. Kutup adopts that policy lesson through
  an enforceable `verified` federation requirement, but OMEMO is not a server
  federation authentication protocol.
- [XMPP Core RFC 6120](https://www.rfc-editor.org/rfc/rfc6120) prefers TLS plus
  SASL EXTERNAL with PKIX certificates. [XEP-0220](https://xmpp.org/extensions/xep-0220.html)
  describes DNS-based dialback as weak without DNSSEC; Prosody correspondingly
  defaults to secure certificate authentication and optionally supports DANE.
  Kutup keeps mandatory WebPKI TLS and adds application-key continuity; it does
  not copy dialback or introduce a downgrade fallback.
- [Matrix server-server v1.15](https://spec.matrix.org/v1.15/server-server-api/)
  confirms canonical-domain versus delegated-endpoint separation, signed
  origin/destination/method/target/body requests, bounded key freshness, and
  retrying the same transaction before advancing. Kutup retains those useful
  properties without Matrix room DAG/state replication. Matrix authenticates
  responses only with TLS; Kutup strengthens this for a separately pinned
  application identity by signing responses too.
- [TUF root rotation](https://theupdateframework.github.io/specification/v1.0.26/)
  requires every intermediate root and both the old and new authorization on a
  transition. Kutup's sequential old+new rotation chain follows that rule for
  its simpler one-key identity profile.
- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) and
  [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) already specify HTTP
  message signatures, response/request binding, nonces, and content digests.
  Federation v2 uses a strict Kutup profile of these standards instead of a
  new authorization serialization.
- [DANE with DNSSEC](https://www.rfc-editor.org/rfc/rfc7673) can strengthen
  first contact, but requiring a validating resolver and correct TLSA
  operations would materially increase self-hosting complexity. It is an
  optional future bootstrap-evidence source, never an opportunistic fallback.
- [ActivityPub](https://www.w3.org/TR/activitypub/) validates durable
  asynchronous inbox delivery, retry/backoff, stable activity identifiers,
  recipient de-duplication, origin-authorized mutations, server-level shared
  inboxes, and strict bounds on recursive dereferencing. Kutup already has the
  useful equivalents: feature-owned durable outboxes, stable request/send IDs,
  one server endpoint per feature, and canonical origin/destination binding.
  Modern Mastodon also accepts [RFC 9421 request signatures](https://docs.joinmastodon.org/spec/security/#http-message-signatures-rfc9421),
  reinforcing the profile choice. Kutup does not adopt ActivityStreams/JSON-LD,
  global URL actor identity, generic inbox forwarding, or fetch-live actor keys:
  ActivityPub leaves federation authentication unspecified, and its open-ended
  URL dereferencing/forwarding model would enlarge Kutup's SSRF, amplification,
  canonicalization, and downgrade surfaces without helping opaque E2EE Chat or
  capability-authorized Drive operations. WebFinger can be added later as a
  public contact-discovery adapter; it is not a trust or key-discovery source.

The deferred independent-notary/multi-authority design remains in research.
It is not necessary for the first unified stack and would not replace the
subject domain's own authenticated rotation chain.

## 3. Target module and crate boundaries

### 3.1 Protocol crate

Create `crates/kutup-federation-proto`, with no server I/O and no dependency on
chat types. It owns:

- `FederationIdentityDocument`;
- `FederationDiscovery` and feature capability identifiers;
- the strict Kutup RFC 9421/9530 message-signature profile;
- key identifiers, fingerprints, validation, and golden test vectors.

`kutup-chat-proto` depends on this crate directly. Common federation types are
removed from `kutup-chat-proto`; only Chat transaction DTOs remain there. Every
workspace consumer is updated in the same change. This avoids placing
Drive-wide trust primitives in a crate whose name and release surface are
chat-specific or retaining two nominal owners through re-exports.

### 3.2 Server modules

Replace the present `chat_federation_policy.rs` and the identity/discovery/auth
parts of `chat_federation.rs` with this boundary:

```text
crates/kutup-server/src/federation/
  mod.rs          FederationStack public API
  config.rs       canonical local domain and key loading
  identity.rs     local history, peer pins, rotation, quarantine
  discovery.rs    fetch/validate/signed delegation/history
  policy.rs       emergency stop + feature/direction-aware admission
  transport.rs    SSRF-safe resolution, signed requests, response bounds
  inbound.rs      shared request authentication and replay reservation
  admin.rs        trust-control service methods (HTTP handlers stay in handlers/admin.rs)

crates/kutup-server/src/chat_federation.rs
  chat adapter: directory/profile/delivery/outbox only

crates/kutup-server/src/handlers/drive_federation.rs
crates/kutup-server/src/handlers/drive_federation_proxy.rs
  Drive adapter: account lookup/invites/share operations only
```

The existing ambiguous `handlers/federation.rs` and abbreviated `fedproxy.rs`
names are removed. Only `src/federation/` may mean the common stack; every
feature-owned federation module says which feature it implements.

`AppState` contains one `Option<Arc<FederationStack>>`. Chat and Drive receive
the same object. There must not be a second signing key, peer cache, discovery
client, policy evaluator, or pin table in either feature.

### 3.3 Public service contract

The central APIs are conceptually:

```rust
FederationStack::send(domain, direction, feature, feature_request, limits)
    -> AuthenticatedFederationResponse

FederationStack::authenticate_inbound(headers, method, uri, body, capability)
    -> AuthenticatedFederationPeer
```

Feature code never constructs a remote origin, performs DNS checks, selects a
live discovery key, receives a delegated `apiBase`, or verifies a server
signature itself. `feature_request` contains a feature-relative operation, not
an absolute URL; the common stack resolves and retains the authenticated peer
internally.

### 3.4 Cryptographic-suite boundary

The authoritative cross-project decision is
[`../../crypto-agility.md`](../../crypto-agility.md). This plan implements only
the federation-owned `FederationAuthProfileId`; it does not define or negotiate
Chat, Profile, Group, Account, Transparency, Collaboration, or Drive suites.

Federation version 2 maps in code to exactly one value,
`FederationAuthProfileId::HttpSignaturesV2`, denoting the complete RFC
9421/9530 Ed25519/SHA-256 request-and-response profile in section 4.3. There is
no second authentication-profile field or negotiation step. A future profile
requires a new authenticated federation protocol version and the migration,
policy, and no-downgrade rules in the authoritative decision.

The common federation stack treats feature ciphertext as opaque bytes and
cannot select, reinterpret, advertise, or weaken a feature-owned suite.

## 4. Canonical identity and discovery protocol

### 4.1 Addressing and delegation

The peer identity is a canonical lowercase DNS name. User-facing addresses are
`username@server`. Drive APIs also accept `server`, not `https://server/path`.

The stack fetches:

```text
https://<server>/.well-known/kutup/federation.json
```

Development/test HTTP remains possible only behind the existing test-only
guard. Production requires public HTTPS. The signed discovery document selects
an `apiBase`; feature code uses only that authenticated base. Raw remote URLs
are never accepted for new federation records.

### 4.2 Identity document

Version 1 uses one Ed25519 identity key:

```text
FederationIdentityDocumentV1 {
  identityVersion: 1,
  server,
  sequence,                 // genesis = 0
  key: { algorithm, keyId, publicKey },
  previousDocumentHash?,
  issuedAt,
  previousSignature?,       // required after genesis
  currentSignature
}
```

- Genesis is self-signed by the current key.
- Rotation increments `sequence` exactly once and hash-links the exact previous
  document.
- Rotation is signed by both the previously pinned key and the new key.
- The document hash covers a canonical payload, not its signatures.
- Signatures use versioned, domain-separated, deterministic length-prefixed
  bytes. JSON serialization is not a signature algorithm.
- `keyId` is lowercase SHA-256 of the raw public key; the UI displays the full
  fingerprint and a grouped, readable rendering.

The current document is embedded in discovery. Every immutable document is
also available at:

```text
GET /.well-known/kutup/federation/identity/{sequence}.json
```

A peer missing several rotations fetches and verifies every intermediate
document. Rollback, skipped sequence, hash mismatch, wrong domain, invalid
old/new signature, or same-sequence equivocation is a cryptographic failure.

### 4.3 Signed discovery

The experimental chat-only discovery document is replaced with a clean
federation v2 document:

```text
FederationDiscoveryV2 {
  fedVersion: 2,
  server,
  apiBase,
  capabilities: ["chat.v1", "drive.v1", "identity.v1"],
  identity: FederationIdentityDocumentV1,
  identityDocumentHash,
  signedAt,
  expiresAt,
  signature
}
```

The identity key signs the version, server, normalized API base, sorted
capability set, current identity hash, and validity window. This prevents an
attacker from retaining the pinned public key while rewriting delegation or
stripping a feature capability. An unknown or missing federation version is
rejected; version 2 never probes or negotiates another authentication profile.

Discovery validity is short and bounded (recommended maximum: 24 hours).
Tampering that fails the pinned-key signature is rejected without modifying
the stored trust state; arbitrary invalid network data must not let an attacker
force a persistent operator-cleared denial of service. A well-formed conflicting
identity does quarantine. A routing/capability change correctly signed by the
pinned identity is an authenticated operational change and is accepted.

The request-signing key is the current identity key in this profile; discovery
does not duplicate that key in a second `signingKeys` trust source. A future
identity-document version may authorize distinct online transport-role keys.

All Chat and Drive traffic uses a single strict RFC 9421 profile. There is no
negotiation over which fields are covered. A request signature must cover, in
the specified order:

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

`created`, `expires`, `keyid`, `alg="ed25519"`, `nonce`, and
`tag="kutup-federation-v2"` are mandatory signature parameters.
`expires-created` is at most five minutes and the verifier applies the bounded
clock-skew policy. `nonce` is the request id and is unique per logical
operation, not per transport attempt. An exact retry therefore reuses the same
nonce, covered components, and content; changing any covered value under an
existing nonce is a conflicting replay.
`Content-Digest` is RFC 9530 SHA-256 of the exact transmitted content, including
the empty content of bodyless requests. The canonical origin/destination
headers remain distinct from `@authority`, which names the signed delegated API
endpoint. The signed federation-version header prevents profile/version
relabeling, and the feature header prevents cross-feature signature confusion
in addition to the signed path and required discovery capability.

Requests carry the standard RFC 9421 `Signature-Input` and `Signature` fields.
The old chat-named authorization header and deterministic encoding are removed.
The protocol crate supplies one parser/profile validator; feature code cannot
accept a subset of components, a different order, a longer lifetime, an
unknown signature tag, or an unpinned key.

### 4.4 Authenticated responses

Every response to an authenticated federation request—including typed
application errors—is signed by the destination's pinned identity key. The RFC
9421 response signature covers `@status`, `content-digest`,
`content-type`, federation version/feature/origin/destination
headers, and the original request's method, authority, path, query, content
digest, and nonce using RFC 9421 request-response binding. A valid TLS response
without this signature is not a federation response.

Pre-authentication syntax/rate/auth failures may return an unsigned minimal
error; the caller treats it only as an untrusted transport failure and never
consumes its body as protocol data.

Signed responses prevent a compromised delegated TLS terminator, CDN, or reverse proxy
that lacks the server identity key from fabricating directory, invitation, or
mutation results. It also prevents a valid response being attached to another
request. Bounded JSON/control responses are buffered up to their endpoint limit,
digested, verified, and only then decoded or committed.

Streamed encrypted Drive blobs carry a signed RFC 9530 `Content-Digest` known
from ciphertext metadata persisted when the object is uploaded. The recipient
verifies the response signature before streaming and verifies both the
ciphertext digest and end-to-end AEAD before committing the downloaded file.
Existing local ciphertext objects receive a resumable background digest
backfill; this reads ciphertext only and does not require client keys. HTTP
trailers are not a required security dependency because RFC 9421/9530 permit
intermediaries to drop them.

## 5. Trust-state machine

Each remote domain has exactly one shared state:

```text
unseen -> tofu -> verified
tofu|verified -> quarantined
tofu|verified -> tofu|verified after valid chained rotation
quarantined -> verified only through explicit break-glass re-pin
```

Rules:

1. **First authenticated contact:** validate a genesis document and signed
   discovery, then atomically pin it as `tofu` before returning a peer handle.
2. **Manual verification:** the administrator compares the full fingerprint
   through an independent channel and changes `tofu` to `verified` by typing
   that exact fingerprint.
3. **No change:** refresh `lastSeenAt`; never replace pin material from DNS/TLS.
4. **Valid rotation:** verify all intermediate old+new signatures, persist the
   complete history atomically, and retain `verified` if it was already set.
5. **Protocol floor:** a peer without federation v2, a signed identity document,
   or the required feature capability is rejected and never enters a weaker
   trust mode.
6. **Unexpected change:** persist the candidate and evidence, set
   `quarantined`, and deny both inbound and outbound Chat and Drive operations.
7. **Network failure:** report availability failure; do not quarantine and do
   not discard a prior pin.
8. **Break-glass re-pin:** require a quarantined candidate, the typed complete
   old and new fingerprints, a typed domain confirmation, admin auth, and an
   immutable audit event. Never expose private keys.

Concurrent first contact/rotation uses a database transaction and a row lock or
conflict retry. Two workers cannot accept different first pins.

Trust state is operationally enforced, not merely displayed. Each feature
policy has `minimumTrust: tofu | verified`, and a domain rule may override it
with `inherit | tofu | verified`. Fresh Chat and Drive policies are
`allowlist + verified`: an allowed first contact may fetch, validate, and store
a TOFU candidate, but application traffic remains denied until an administrator
compares and confirms the full fingerprint out of band. Operators may
deliberately select TOFU for open federation or lower-risk deployments. No
setting can admit a quarantined identity.

## 6. Local key lifecycle

New generic environment variables are:

```text
FEDERATION_SERVER_NAME
FEDERATION_SIGNING_KEY
FEDERATION_NEXT_SIGNING_KEY           # explicit rotation command only
FEDERATION_TEST_ALLOW_PRIVATE
```

Phase B introduces the generic variables for the new, not-yet-routed stack.
The existing `CHAT_FEDERATION_*` variables continue to feed only the isolated
v1 runtime during that phase. Phase C atomically removes those old variables
from code, Compose, tests, and documentation when it deletes v1. They are never
aliases for the generic variables, and no runtime probes one after the other as
a fallback.

After migrations, startup behaves as follows:

- No current key: the federation stack is absent; no federated Chat or Drive
  operation is advertised or accepted.
- Empty local history: create and persist genesis from the configured stable
  key.
- Configured key equals the latest document: load normally.
- Configured key differs from the persisted latest key: refuse startup. A typo
  or secret-manager change must never become an implicit identity rotation.

Local rotation is an explicit maintenance operation:

```text
FEDERATION_SIGNING_KEY=<current> \
FEDERATION_NEXT_SIGNING_KEY=<new> \
kutup-server federation-identity rotate
```

The command obtains a database advisory lock, verifies the current seed against
the latest persisted document, constructs and verifies the old+new-signed next
document, and commits it once. The operator then atomically switches all server
replicas to the new current seed and removes the next seed. Until a staged
multi-key activation protocol is implemented, multi-replica deployments use a
documented short maintenance window; mixed old/new discovery behind a load
balancer is forbidden. This is safer than pretending an unsafe rolling key
change is supported.

Seeds remain in secret management, never PostgreSQL or the admin API, and the
v2 identity seed must be distinct from temporary v1 and key-transparency
seeds. The self-hosting guide includes backup, rotation, rollback, and lost-key
behavior. A later offline signer can produce the same public document format
without changing peer verification.

## 7. Staged persistence and clean schema cut-overs

Schema changes are staged so every completed phase remains runnable. There is
no requirement to preserve experimental federation data, but a migration must
not invalidate handlers that have not yet been cut over. The destructive work
therefore happens atomically with the owning feature's code change rather than
in an earlier phase.

Migration `033` in Phase B is additive. It creates the generic identity,
authentication, replay, and policy tables below without dropping or renaming
the tables still used by the v1 Chat and Drive runtimes. It must not touch
local collections/files, local shares, local Chat mailboxes, user keys, or
plaintext/ciphertext client history.

Create the generic identity/authentication tables:

```text
federation_local_identity_documents
  sequence PK, document_hash UNIQUE, key_id, document JSONB, created_at

federation_peer_identities
  domain PK, trust_state, current_sequence, current_document_hash,
  current_key_id, current_public_key, first_seen_at, last_seen_at,
  verified_at, quarantine_reason, pending_document, pending_identity_chain,
  pending_document_hash, updated_at

federation_peer_identity_documents
  (domain, sequence, document_hash) PK, key_id, document, acceptance, recorded_at
  // partial unique index: one accepted document per (domain, sequence)

federation_request_replays
  (origin, request_id) PK, request_hash, first_seen_at, expires_at
```

Replace chat-only policy storage with generic tables:

```text
federation_policy
  global_enabled                 // emergency stop

federation_feature_policies
  feature PK, mode, minimum_trust
  // chat, drive; disabled/allowlist/blocklist/open; tofu/verified

federation_domain_rules
  (domain, feature) PK, inbound_action, outbound_action, trust_requirement
  // trust requirement: inherit/tofu/verified
```

The engine and semantics are shared, while results remain least-privilege and
feature-scoped. A global `all` rule may be added to the admin service as a
transactional convenience, but is expanded into explicit feature rows rather
than creating ambiguous precedence. Trust state and quarantine are always
global and cannot be weakened per feature.

Both feature policies start in `allowlist + verified`, with the emergency stop
released. No old chat rules are copied because their meaning was chat-only and
the new control plane should begin explicitly. During Phase B the old
chat-named policy tables remain readable only by the isolated v1 runtime; no
generic-stack decision consults them.

The Phase C cut-over migration clears the experimental v1 Chat federation
outbox/sequence/inbound transaction state because it was authenticated under a
removed wire protocol, then removes the old chat-only policy tables after the
Chat runtime and admin policy service use the generic tables. It keeps all
local Chat state. Mixed v1/v2 server replicas are not supported during this
breaking cut-over: old replicas are stopped before migration and only v2
replicas start afterward.

The Phase D migration drops and recreates the two federated Drive share tables
in the same release that switches every Drive handler to the new schema:

- incoming shares contain `remote_domain`, never `remote_server`/`apiBase`;
- outgoing shares contain `recipient_domain`, never `recipient_server` URL;
- outgoing shares store only `capability_hash`, not the plaintext secret;
- feature idempotency tables retain mutation request/result records;
- canonical-domain indexes support quarantine and operations reporting.

The Phase C and D migration fixtures independently prove their destructive
boundaries. Neither cut-over may remove local users, collections, files, local
shares, local Chat mailboxes, user keys, or client-held history.

## 8. Shared admission and request authentication

At the Phase C Chat cut-over, replace the admin contract with
`/api/admin/federation` and update the web UI in the same release. Remove
`/api/admin/chat-federation`; there is no route alias or second DTO. This is
required at Chat cut-over—not deferred polish—because the default `verified`
trust floor needs an operable fingerprint-verification path.

Each feature's mode keeps the current semantics:

- `disabled`: no federation for that feature and its capability is not
  advertised;
- `allowlist`: deny unless the direction is explicitly allowed;
- `blocklist`: allow unless the direction is explicitly blocked;
- `open`: allow every cryptographically authenticated, non-quarantined peer.

After mode/rule admission, the effective `minimumTrust` is enforced. Thus
`open + verified` discovers candidates but still requires manual verification;
`open + tofu` is automatic first-use federation. The UI presents these as two
separate decisions rather than hiding trust strength inside the mode name.

The global emergency stop denies every feature and hides discovery. With the
stop released, discovery is public when at least one configured feature is not
disabled and advertises only those enabled capabilities.

Order of inbound work is fixed:

1. cheap syntax/body-size/rate checks;
2. feature-scoped admission check before outbound discovery;
3. resolve the peer through shared identity trust;
4. verify the complete RFC 9421 profile, destination, freshness, and capability;
5. enforce the effective minimum trust state;
6. atomically classify `(origin, requestId, requestHash)` as first-seen, exact
   replay, or conflicting replay;
7. invoke the feature handler and sign the bound response.

A conflicting replay is rejected. An exact replay reaches only a handler that
declares and implements idempotency: Chat returns its stored transaction
result; Drive reads are safe; Drive mutations persist a feature-level request
record and return the original result. The shared replay table alone is not
allowed to turn an uncertain upload retry into a duplicate file.

The stable federation operation identity is `(origin, requestId)`, where the
request ID is an opaque value rather than a dereferenceable URL. The same
logical operation and exact covered content retain that ID through retries.
Feature handlers validate that every claimed sender, recipient, share, and
mutable resource belongs to the signed origin/destination and the applicable
feature authority or capability.

Unlike ActivityPub inbox forwarding, receiving a Kutup request never authorizes
the receiver to relay it to a third domain. Feature payloads cannot direct the
common stack to dereference arbitrary URLs or recursively fetch linked objects.
Only the common resolver may fetch the fixed discovery and identity-history
paths described in section 4; a feature-initiated remote operation starts from
a canonical domain and a fixed typed endpoint under the authenticated
`apiBase`. This is a protocol invariant, not merely an SSRF-client convention.

Outbound work applies feature-scoped admission before DNS/network activity.
The emergency stop and quarantine are checked independently and cannot be
overridden by `open` or an allow rule.

The common transport keeps redirects disabled, validates scheme/host/port,
rejects credentials/query/fragment in API bases, constrains DNS answers, and
binds the connection to validated addresses so DNS rebinding cannot create a
gap between validation and connection. Every feature supplies an explicit
request/response byte limit and timeout.

Discovery is cached only through its signed expiry (maximum 24 hours), uses
per-domain single-flight so concurrent requests cannot amplify lookups, caches
negative results briefly, and applies jittered exponential backoff. An expired
document is never silently used for new traffic; durable Chat work remains
queued and Drive returns an availability failure.

Resource controls have two stages: per-IP/body/concurrency limits before
authentication, then per-origin-domain and per-feature request/concurrency/byte
budgets after authentication. Outbound peers have per-domain concurrency and
circuit-breaker limits. Admission and identity trust never substitute for
these abuse/overload controls.

## 9. Chat adapter migration

The Chat wire payloads, durable outbox, per-destination sequence, remote
device-mismatch recovery, and inbound transaction idempotency remain unchanged.

Change only the trust/transport edges:

- directory, profile, and delivery call the common stack's domain-based
  `send(..., "chat.v1", ...)` API;
- outbound signing is performed by the common stack;
- inbound handlers use the common authenticated-peer extractor;
- the request-signature verification key is taken from the persistent pin,
  never directly from a newly fetched discovery document;
- a quarantined peer leaves outbox rows pending with a clear terminal-until-
  operator-action reason; rows are never deleted;
- retry workers wake after a valid rotation, re-pin, or admission change.

Chat capabilities advertised by `/api/auth/settings` depend on the shared
stack plus policy, not a separate `ChatFederation` identity object.

## 10. Drive adapter migration

### 10.1 Remote user lookup and share creation

The client sends `username` plus canonical `server`. The local server resolves
the peer with `drive.v1`, signs `GET /api/fed/drive/users/{username}`, and
returns the remote account public key.

The public key remains an assertion by that authenticated remote server. Server
pinning prevents a different server from being substituted, but it does not
prevent the genuine remote server from lying about an account key. Account-key
signatures or transparency are a separate later hardening item and must be
documented honestly.

`POST /api/collections/{id}/federated-shares` stores `recipient_domain`, not an
API URL. The generated link uses a fragment so the bearer capability is not
sent in an HTTP path or referrer:

```text
https://<sharer-web-origin>/invite#server=<sharer-domain>&capability=<secret>
```

The recipient's paste/accept UI parses the canonical domain and capability,
then submits them as separate fields. The server does not trust the link's
origin as an API base; it resolves `server` through signed discovery. A compact
versioned invite code carries the same two values for QR/non-HTTPS transport.

### 10.2 Invite and proxy operations

New Drive federation endpoints live under `/api/fed/drive/...`. Every request
has both layers:

- shared RFC 9421 `Signature-Input` and `Signature` fields authenticate the
  calling server and bind method, URI, origin, destination, feature, time,
  request id, and content digest;
- a separate `Kutup-Share-Capability` header authorizes the particular share.

The capability is never used as the server identity. The old unsigned
token-in-path endpoints are removed.

The sharer's database stores a SHA-256 capability hash and returns the plaintext
secret only once. The recipient server must retain the plaintext capability in
order to exercise the share, but never writes it to logs or responses after
acceptance. The sharer also binds the share to the authenticated recipient
domain recorded at creation: possession of a leaked capability from a different
server is insufficient.

Incoming shares persist `remote_domain` and the capability. Every list,
download, upload, and delete resolves that domain through the same pin before
network I/O; it never reuses a stored raw API URL. Consequently a server-key
substitution quarantines both Drive and Chat immediately.

## 11. Admin and operator experience

Rename the UI card to **Federation** and show:

- local canonical domain, current fingerprint, identity sequence, and enabled
  capabilities;
- global emergency stop plus Chat/Drive modes, minimum trust, and directional
  domain rules/overrides;
- each known peer's state (`tofu`, `verified`, `quarantined`), full
  fingerprint, sequence, first/last seen, and capabilities;
- pending fingerprint/document and precise quarantine reason;
- actions to verify a fingerprint, retry discovery, and break-glass re-pin.

Mutating actions produce audit events:

```text
federation.policy.update
federation.rule.upsert
federation.rule.delete
federation.identity.verify
federation.identity.rotate-local
federation.identity.advance-remote
federation.identity.quarantine
federation.identity.repin
```

Automatic cryptographic events use a system actor representation rather than
pretending an administrator initiated them.

## 12. Implementation phases

Each phase must compile, pass its focused tests, and leave every still-routed
feature operational before the next begins. New v2 services may be constructed
and tested before routing, but a public endpoint, environment name, or database
schema switches only in the same phase as all of its consumers. Breaking
cut-overs use a documented stop-migrate-start maintenance boundary; mixed
old/new replicas are not supported.

### Phase A — protocol and pure verification

**Status (2026-07-20): implemented and focused-test verified.** The common v2
crate owns the typed profile registry, identity chain, signed discovery, strict
RFC 9421/9530 request/response profile, and published deterministic vectors.
The former common definitions were removed from `kutup-chat-proto`; its direct
dependency now supplies the Chat feature identifier while only Chat DTOs stay
there. The still-running experimental v1 code is explicitly server-private and
is deleted—not retained as a fallback—during the atomic Phase C runtime
cut-over.

1. Create `kutup-federation-proto`, move common concepts, and delete their old
   chat-owned definitions.
2. Add the closed, typed `FederationAuthProfileId` registry, the exact
   `fedVersion: 2` mapping, and deterministic identity/discovery signing and
   verification with the version bound into the signed document.
3. Implement the strict RFC 9421/9530 request/response profile with published
   Ed25519 golden vectors.
4. Add genesis, old+new rotation, hash-link, and fingerprint test vectors.
5. Test every malformed field, rollback, skip, equivocation, signature, and
   discovery-binding failure without database/network code.

### Phase B — generic persistence and local identity

**Status (2026-07-20): implemented.** The v2 stack is constructed and tested
but deliberately has no public routes. Migration `033` is additive; the
temporary Chat v1 and Drive runtimes remain unchanged until their atomic
cut-over phases.

1. ✅ Add migration `033` with the generic identity/replay/policy tables only;
   leave all v1 Chat and Drive tables intact and add migration isolation tests.
2. ✅ Implement local genesis loading and the explicit current-to-next-key
   rotation command, including its audit event.
3. ✅ Implement transactional peer trust-state transitions.
4. ✅ Implement and test signed discovery and immutable-history services, but do
   not mount them on the public `.well-known` routes yet.
5. ✅ Add the generic `FEDERATION_*` configuration for the unpublished stack while
   keeping `CHAT_FEDERATION_*` scoped exclusively to the running v1 module.

### Phase C — common transport and Chat cut-over

**Status (2026-07-20): implemented and live two-server verified.** Migration
`034` performs the deliberate Chat-only destructive cut-over. The legacy Chat
stack, routes, policy tables, and configuration no longer exist.

1. ✅ Implement one resolver, SSRF-safe client, signed request/response transport,
   discovery single-flight/cache, and inbound auth.
2. ✅ Atomically mount v2 signed discovery/history, switch the generic
   `FEDERATION_*` configuration, and remove all `CHAT_FEDERATION_*` handling.
3. ✅ Ship `/api/admin/federation` plus the peer list, verify, retry, and tightly
   confirmed re-pin endpoints, their audit events, and the web policy/trust UI;
   remove the chat-named admin routes and policy storage.
4. ✅ Cut Chat directory/profile/delivery over to the common stack and add
   quarantine behavior plus post-recovery wake-up to the durable retry path.
5. ✅ In the same stop-migrate-start release, clear v1 Chat federation transaction
   state and delete `legacy_chat_federation_v1` plus the duplicate
   identity/discovery/auth code. Do not leave a fallback second stack.

### Phase D — Drive cut-over

1. ✅ In the same stop-migrate-start release, replace the experimental Drive
   federation tables with their canonical-domain/capability-hash schema and
   test that local Drive data survives.
2. ✅ Add signed `/api/fed/drive/*` endpoints with separate capability headers.
3. ✅ Change remote account lookup and new share creation to canonical domains.
4. ✅ Change invite acceptance and all proxy operations to resolve the pinned
   peer on every operation.
5. ✅ Persist ciphertext SHA-256 during upload, add the resumable ciphertext-only
   digest backfill, and verify signed streamed-download digests before commit.
6. ✅ Remove the unsigned raw-URL/token-path Drive federation code.

### Phase E — control-plane completion

1. Complete the shared Chat/Drive operational views, filters, diagnostics, and
   responsive UI around the generic control plane introduced in Phase C.
2. Add operational evidence inspection and bulk retry conveniences without
   creating another trust or policy path.
3. Complete audit-event presentation and export for both features.
4. Prove no feature-owned policy, identity, signing-key, or peer-cache path
   remains.

### Phase F — documentation, integration, and cleanup

1. Update architecture, API, protocol, self-hosting, roadmap, and test docs.
2. Extend the two-server harness to exercise both Chat and Drive through the
   same identity and policy.
3. Run the separate Phase C Chat and Phase D Drive destructive-migration
   fixtures proving only their experimental federation state is reset and all
   local data is retained.
4. Run Rust tests, frontend tests/typecheck/lint, OpenAPI checks, migration
   up/down checks, and the live federation harness.
5. Confirm with `rg` that feature modules no longer create federation clients,
   accept new raw remote URLs, or load independent signing keys.

## 13. Required test matrix

### Pure protocol

- deterministic genesis and discovery golden vectors;
- valid single and multi-step rotation;
- bad old signature, bad new signature, wrong hash, wrong domain, skipped or
  rolled-back sequence, future version, malformed base64/key/fingerprint;
- API-base, federation-version, or capability tampering invalidates discovery;
  a missing or unknown version fails without fallback;
- RFC 9421 request/response vectors cover Ed25519, canonical request-response
  binding, SHA-256 `Content-Digest`, nonce, tag, and expiry;
- missing, reordered, duplicated, unknown, or selectively covered components,
  incorrect digest, profile relabeling, response/request mismatch, and
  cross-feature replay fail;
- federation v1 discovery/authorization is rejected rather than downgraded.

### Database/concurrency

- simultaneous first contact converges on one pin;
- conflicting first pins result in quarantine, never last-writer-wins;
- multi-document advance commits all-or-nothing;
- quarantine preserves last trusted and pending evidence;
- replay reservation is atomic and expires;
- effective `tofu`/`verified` policy and domain overrides cannot admit a
  quarantined peer;
- the additive Phase B migration leaves v1 Chat and Drive tables usable;
- the Phase C Chat and Phase D Drive destructive migrations remove only their
  respective experimental federation rows and retain every local user,
  collection, file, local share, and local Chat mailbox row.

### Two/three-server integration

- one first contact made by Chat is reused by Drive and vice versa;
- valid rotation keeps both features working;
- substituted discovery key/API base quarantines both features;
- a delegated TLS endpoint without the identity key cannot forge a successful
  control response or bind a response to another request;
- Chat outbox survives quarantine and resumes only after valid recovery;
- Drive proxy refuses every operation while quarantined;
- the same allowlist/blocklist/open/disabled semantics are enforced
  independently for Chat and Drive, and the emergency stop denies both;
- inbound blocked peers cause no discovery network request;
- invite, list, streamed download, upload, and delete use signed transport plus
  the share capability;
- request replay and cross-destination replay are rejected;
- feature payload URLs cannot trigger dereferencing or third-domain forwarding,
  and origin-owned resources cannot be mutated by a different signed origin;
- an exact retried Chat or Drive mutation returns its stored result rather than
  duplicating delivery/upload;
- streamed Drive ciphertext rejects a signed-metadata/body digest mismatch and
  never commits before digest plus AEAD verification;
- expired discovery stops traffic, concurrent discovery is single-flight, and
  per-domain overload does not starve unrelated peers;
- raw-URL Drive requests and old unsigned endpoints are absent/rejected;
- API delegation works without changing the canonical peer identity.

### Admin/frontend

- full fingerprints are visible and copyable;
- verify rejects abbreviated or mismatched fingerprints;
- re-pin requires old/new/domain confirmations and quarantine evidence;
- audit entries contain old/new fingerprints and reason without secrets;
- responsive desktop/mobile surfaces expose the same trust state.

## 14. Acceptance criteria

The unified stack is complete only when all of these are true:

- one configured local server identity is used by Chat and Drive;
- one discovery resolver, peer pin, feature-aware admission evaluator, signed
  transport, and SSRF policy serve both features;
- federation uses its own closed `FederationAuthProfileId`; no universal crypto
  enum or feature-level suite can enter the federation-authentication API;
- every authenticated request and non-pre-auth response conforms to the one
  strict RFC 9421/9530 profile and is bound to its authentication profile,
  feature, and request;
- new Drive APIs and records use canonical domains, never caller-supplied API
  origins;
- every new Drive server-to-server operation is signed and capability-checked;
- request verification uses the persisted pin, not a freshly downloaded key;
- `verified` minimum-trust policy actually denies TOFU traffic until an exact
  out-of-band fingerprint confirmation;
- valid remote old+new rotation advances automatically; local rotation is an
  explicit locked command; conflicting identity changes quarantine globally
  while unsigned network garbage cannot force persistent quarantine;
- administrators can verify and recover trust with full-fingerprint,
  audited workflows;
- the old raw-URL Drive schema, endpoints, configuration, and UI paths are
  removed rather than retained as a second stack;
- no current Chat delivery durability or E2EE behavior regresses;
- streamed Drive downloads verify signed ciphertext digests and client AEAD
  before durable commit;
- documentation distinguishes server identity from remote user/account-key
  authenticity;
- the complete test matrix passes.

## 15. Deliberate non-goals

This work does not implement the threshold-root/multi-authority design, account
key transparency for Drive, anonymous/sealed sender, Matrix-style room state,
or a general-purpose arbitrary URL proxy. It also does not create one universal
crypto registry or implement the feature-owned Direct Chat, Group, Profile,
Drive-object, and Account-identity suite registries. It establishes the typed
boundary and implements the federation-owned profile; each feature registry is
specified and implemented with its owning protocol. This creates the stable
seam needed for those independent future decisions without weakening the
immediate server identity guarantee.
