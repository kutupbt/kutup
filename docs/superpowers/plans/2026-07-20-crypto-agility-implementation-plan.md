# Purpose-specific crypto agility implementation plan

**Date:** 2026-07-20

**Status:** proposed

**Authority:** [`../../crypto-agility.md`](../../crypto-agility.md)

**Scope:** planning only; this document does not authorize an algorithm change
without the suite-specific threat model and vectors required below

## 1. Outcome

Implement the project-wide crypto-agility decision without a universal crypto
abstraction and without a downgrade negotiation layer. When complete:

- every Kutup-owned protected wire or persistent format has one
  purpose-specific typed suite selector;
- every selector is authenticated or maps one-to-one from an authenticated
  protocol/format version;
- authenticated participants advertise only the suites they actually support;
- local policy independently controls create, read, migrate, and reject status;
- persistent state is locked to its suite;
- suite changes use explicit, authenticated, crash-safe migration; and
- unknown or rejected suites never default, guess, or retry another decoder.

This is a staged refactor. It first closes the existing fail-open edges and
establishes types, then upgrades formats one owner at a time. Chat, Drive,
Account, Collaboration, Transparency, and Federation remain independent
protocol owners throughout.

## 2. Compatibility and rollout decisions

1. Existing local user and Drive data must remain recoverable. Schema
   migrations may backfill an implicit current format to its exact legacy-v1
   suite only when the row comes from a database schema that predates suite
   metadata. Runtime parsers may not apply that default to unknown input.
2. The experimental federation protocol has no compatibility requirement. Its
   version 2 wire format will map directly to one
   `FederationAuthProfileId`; federation v1 is removed rather than negotiated.
3. Existing direct-chat wire code point `1` remains `1`; the Rust type is
   renamed from the ambiguous `SuiteId` to `DirectChatSuiteId`.
4. A current v1 format is documented exactly before a v2 format is designed.
   Old ciphertext is never relabeled as v2.
5. Each new suite first ships as read-capable, then becomes the sole write
   suite, then migrates old state. Removing old read support is a later explicit
   policy change after recovery tests and adoption evidence.
6. No placeholder code point is allocated for Group Chat. Its registry is
   implemented with the group protocol.

## 3. Current-state inventory and gaps

| Purpose | Current selector | Main code/data locations | Gap to close |
|---|---|---|---|
| Direct Chat | typed `DirectChatSuiteId = 1` on devices and envelopes | `crates/kutup-chat-proto/src/lib.rs`, `kutup-chat-core`, migrations `021_chat*` and `032_chat_suite_constraints*` | capability is not yet in the signed manifest and local libsignal records do not yet carry the Kutup suite |
| Encrypted profile | profile-key-derived `version`, not a format suite | `kutup-chat-proto/src/profile.rs`, `kutup-chat-core/src/profile.rs`, migration `027_chat_profiles*` | no `ProfileSuiteId`; suite/purpose/field are not AEAD associated data |
| Account identity | hard-coded manifest and KDF domain strings | `kutup-chat-core/src/manifest.rs`, `kutup-chat-proto/src/lib.rs` | account authority is Chat-owned; no typed identity suite or authenticated suite transition |
| Key transparency | hard-coded v1 hash/signature encodings | `kutup-chat-proto/src/transparency.rs`, migrations `028`–`030` | no distinct registry; unknown future formats cannot be policy-controlled independently |
| Account protection | implicit Argon2id parameters plus secretbox formats | `kutup-crypto/src/kdf.rs`, `frontend/src/crypto/kdf.ts`, Auth DTOs, `users` | KDF parameters and wrapped-secret format are implicit; preflight cannot select the exact historical decoder |
| Drive objects | implicit libsodium/HKDF constructions | `kutup-crypto`, `frontend/src/crypto`, `collections`, `files`, shares, uploads, assets, versions | no suite metadata; small fields lack purpose-bound AAD; content/share subformats can drift independently |
| Collaboration | signed and AEAD-bound `Frame.version` byte | `kutup-crypto/src/envelope.rs`, `frontend/src/collab/envelope.ts`, migration `012_collab_edit*` | unknown versions are parsed; a document-key epoch is not explicitly locked to one frame suite |
| Federation | planned v2 protocol | unified federation plan | avoid a redundant `authProfile` negotiation field; implement only the federation-owned typed profile |
| Group Chat | not implemented | future group protocol/core | create the registry with Signal-style group state; keep the API neutral enough for a later MLS suite |

The fail-closed Direct Chat baseline is implemented: the ambiguous type and
mailbox default are removed, all database reads use one checked conversion,
and PostgreSQL requires an explicit known suite. The next Direct Chat slice is
authenticated capability and local session locking.

## 4. Target code boundaries

### 4.1 Existing crates

- `kutup-chat-proto` owns `DirectChatSuiteId` and `ProfileSuiteId` wire types.
  `kutup-chat-core` owns their cryptographic implementations and state
  migrations. Libsignal types remain private to the core.
- `kutup-crypto` gains high-level `account_protection`, `drive_object`, and
  `collab_frame` modules. The current primitive modules remain implementation
  details and are made `pub(crate)` after all callers use the high-level
  construction APIs.
- The browser mirrors only the high-level Drive and Account construction APIs
  under `frontend/src/crypto/`. It does not expose a UI or generic function for
  choosing primitives.
- `kutup-federation-proto`, created by the unified federation work, owns
  `FederationAuthProfileId` and maps federation version 2 to its one profile.

### 4.2 New account-identity boundary

Before Drive relies on account-authenticated keys, extract the cross-feature
authority from Chat into a small I/O-free `kutup-account-identity` crate. It
owns:

- `AccountIdentitySuiteId`;
- the master-key-to-authority derivation;
- account authority public documents and old/new cross-signed rotation;
- canonical feature-key authorization statements; and
- verification plus golden vectors.

Chat retains `ChatDeviceManifest`, while Drive receives a separate
`DriveKeyManifest`. Both are signed feature statements under the account
authority. The account crate does not depend on Chat, Drive, Federation, HTTP,
or database code.

Move key-transparency protocol types into an I/O-free transparency module or
crate when they become cross-feature. That owner defines
`KeyTransparencySuiteId`; the server remains only the log operator/storage
implementation.

### 4.3 No shared suite erasure

Do not create a common `CryptoSuite` enum, `suite_id: u16` domain model,
cross-registry `From` conversion, or a generic runtime registry. A few lines of
duplicated `TryFrom<u16>` code are preferable to erasing the purpose type.

Each owner exposes:

```text
PurposeSuiteId             closed wire identifier
PurposeSuitePolicy         create/read/migrate/reject decisions
PurposeCapabilities        authenticated supported-set representation, if needed
PurposeMigration           authenticated transition representation, if needed
PurposeCryptoError         Unknown / Unsupported / PolicyRejected / NoCommon / AuthFailed
```

The exact types are purpose-named; this is a shape, not a shared trait callers
can use to mix registries.

## 5. Implementation phases

Every phase lands independently with tests. A phase that changes protected
bytes must include its suite specification and vectors in the same change.

### Phase A — fail-closed Direct Chat baseline — **implemented 2026-07-20**

1. Rename `SuiteId` to `DirectChatSuiteId` in
   `crates/kutup-chat-proto/src/lib.rs` and every server/core/test consumer.
   Preserve numeric serialization and code point 1.
2. Replace every default/guess on suite parsing with a typed error. In
   particular, make mailbox row conversion fallible and return a server data
   integrity error for an unknown `chat_mailbox.suite` value.
3. Add database `CHECK` constraints for currently known Chat suite values.
   Future suite migrations extend the constraint atomically with the code that
   implements the new suite.
4. Replace the frontend's raw `REQUIRED_SUITE = 1` with a closed parser/literal
   for `DirectChatSuiteId`. Treat `/auth/settings` suites as server
   availability only, not device-authenticated capability.
5. Add negative tests for JSON, OpenAPI conversion, database row conversion,
   inbound envelopes, and frontend capability parsing with `0`, `2`, `65535`,
   negative, fractional, string, and missing values.
6. Keep every current API explicitly typed as `DirectChatSuiteId`. Add the
   cross-purpose compile-fail test when the second typed registry creates an
   actual boundary to test; there is no generic suite API in the baseline.

**Gate:** no `unwrap_or`, `unwrap_or_default`, default serde value, or primitive
guess remains on a suite conversion. Existing direct messages still round-trip
byte-for-byte.

### Phase B — authenticated Direct Chat capability and session lock

1. Introduce the next account-identity/manifest format. Add an explicit
   `accountIdentitySuite` to the manifest and a sorted
   `directChatSuites: Vec<DirectChatSuiteId>` to each `ManifestDevice`.
2. Include both fields in canonical signed bytes. Reject empty, duplicate,
   unsorted, unknown, or policy-forbidden lists. The account authority signs
   the capability; the homeserver cannot add or relabel a suite.
3. Require every served `DevicePreKeyBundle.suite` to appear in that exact
   device's authenticated list. The selected suite's verifier still validates
   all prekey types, signatures, sizes, and libsignal message versions.
4. Add a suite tag around each persisted local libsignal session:
   `StoredDirectSession { suite, record }`. Update `ChatDb`, SQLite, IndexedDB,
   pending transactions, exports, and tests. Do not infer a suite from record
   bytes during normal reads.
5. Implement a schema-versioned one-time local migration: records stored by the
   pre-suite schema become suite 1. Any tagged record with an unknown suite is
   rejected, not migrated.
6. Enforce the local Direct Chat policy before session creation and every
   session use. A policy increase archives the old session and establishes a
   new allowed suite; it never mutates or translates ratchet state.
7. Add downgrade tests where the server removes the stronger capability,
   relabels a bundle, supplies a weaker bundle after a cryptographic failure,
   or replays an old manifest. Each must fail before session mutation.

**Gate:** suite choice is authenticated by the signed manifest and remains
fixed for the complete device-to-device session lifetime.

### Phase C — federation profile alignment

This phase is implemented inside the unified federation plan, not by a shared
crypto layer.

1. Add `FederationAuthProfileId::HttpSignaturesV2` to
   `kutup-federation-proto`.
2. Map `fedVersion: 2` to that profile in code. Do not serialize a second
   `authProfile` discovery property or `kutup-federation-auth-profile` header.
3. Bind the federation version, feature, origin, destination, request target,
   digest, nonce, time bounds, and request/response relationship into the
   strict RFC 9421/9530 profile.
4. Signed discovery advertises feature capabilities, not Chat/Drive payload
   crypto suites. Feature adapters remain opaque to those suites.
5. Reject every missing, unknown, or old federation version. A failed v2
   signature or capability check must not invoke a v1 client.

**Gate:** one authenticated federation version selects one exact profile, with
no profile negotiation matrix.

### Phase D — encrypted profiles

1. Add `ProfileSuiteId` to profile DTOs, local/peer profile records, IndexedDB,
   and `chat_profiles`. Backfill existing rows to the documented v1 profile
   format only in the database migration.
2. Specify the current v1 construction exactly, including HKDF labels, AES-GCM
   nonce/tag layout, padding, wrapped-key format, and its missing context
   binding. Mark it read/migrate-only once v2 is available.
3. Define a v2 suite whose authenticated context binds at least the suite,
   canonical account address, profile-key version, revision, source device, and
   field kind (`name`, `avatar`, or `wrapped-key`). Its specification fixes
   padding and maximum plaintext/ciphertext sizes.
4. Carry `ProfileSuiteId` in the E2EE `profileKeyUpdate` control message. The
   surrounding Direct Chat message authenticates the capability; the profile
   ciphertext independently authenticates the same suite and context.
5. Migration generates a new profile key, publishes a new v2 profile revision,
   durably stores it, and distributes its capability. Old v1 profile rows stay
   tied to their old capability for the retention window; they are never
   rewritten or relabeled.
6. Test field swapping, address/version/revision relabeling, stale profile
   replay, unknown suite, wrong policy, and interrupted rotation.

**Gate:** new profiles are v2-only, and every field rejects cross-purpose or
cross-profile substitution.

### Phase E — account protection and identity extraction

1. Move account authority construction and verification behind
   `kutup-account-identity`. Introduce an identity document whose signed bytes
   contain `AccountIdentitySuiteId`, authority sequence, previous document
   hash, feature keys/capabilities, issuance time, and old/new authorization for
   rotation.
2. Migrate the current Chat authority without silently changing identity:
   publish an account-identity transition signed by the existing authority and
   the new authority when derivation/domain separation changes. Peers pin and
   verify the complete transition.
3. Add `AccountProtectionSuiteId` to registration, login preflight/response,
   recovery preflight, password change, first-login setup, frontend API types,
   `users`, and CLI/native account stores.
4. Document account-protection v1 exactly: Argon2id version 19, 64 MiB, three
   passes, one lane, 32-byte output, independent salts, BIP39 recovery format,
   and every secretbox field. Correct the inaccurate “4 threads” frontend
   comment as part of this phase.
5. Before defining v2, write a focused threat model covering malicious-server
   parameter rollback, account-bundle rollback, field swapping, password
   change, recovery, and interrupted rewrap. The v2 suite must bind suite,
   account identity, bundle revision, and field purpose through AEAD associated
   data or suite/purpose-separated derived keys.
6. Registration chooses the local v2 write suite. Login/recovery reads the
   exact stored suite from preflight and rejects it before expensive KDF work
   if policy forbids it. It never tries a second KDF configuration after auth or
   decryption fails.
7. After successful password login or recovery, migrate v1 by decrypting and
   rewrapping all affected account secrets client-side, then compare-and-swap
   the old bundle revision to the new authenticated revision. Password-change
   and recovery tests must cover process death between every step.

**Gate:** account protection parameters are explicit and rollback-aware;
account identity is a cross-feature authority rather than a Chat-owned key.

### Phase F — Drive object family

This is the largest data migration and must be delivered in bounded slices:
collection/key envelopes, file metadata/key envelopes, streamed content,
assets/versions, then local/public/federated sharing.

1. Define `DriveObjectSuiteId::LegacyV1` as the exact existing construction
   family. Document its Argon/HKDF dependencies, secretbox fields, X25519 sealed
   boxes, secretstream framing/chunk size, asset AEAD, encodings, and limits.
2. Add `driveSuite` to every independently decryptable record and API object:
   collections, files, pending uploads, collection shares, public shares,
   federated shares, file versions, and file assets. A blob also carries an
   authenticated envelope/header so database metadata is not the sole selector.
3. Backfill existing database rows to LegacyV1 only in the schema migration.
   File assets and historical versions receive their own suite metadata rather
   than inheriting a mutable parent value.
4. Introduce high-level APIs such as `encrypt_collection`, `encrypt_file`,
   `open_file_stream`, `wrap_share_key`, and `open_asset`. Each takes a typed
   context, not algorithm names. Move frontend, CLI, Tauri/native, upload,
   download, sharing, and collaboration snapshot callers to them.
5. Define Drive v2 with a canonical authenticated header and purpose-bound
   context for every small envelope. The stream format binds the same header,
   file identity, and chunk framing; share-key plaintext binds suite,
   collection, owner, recipient, and grant revision. The entire configuration
   is one registry entry even though it contains several artifact subformats.
6. Add an account-signed `DriveKeyManifest` containing the account's wrapping
   public keys and supported Drive suites. Local sharing verifies it through
   Account Identity/Transparency. Federated lookup transports the same
   end-user-authenticated document over the server-authenticated federation
   stack; server authentication is not treated as user-key authenticity.
7. Implement copy-and-swap client migration with a durable journal:
   read exact old suite, authenticate/decrypt, encrypt a new v2 object, upload
   to a temporary object, verify digest plus AEAD locally, compare-and-swap the
   metadata revision, then garbage-collect the old object. Resume safely after
   interruption and never overwrite the only recoverable ciphertext first.
8. Migrate hierarchy from keys outward: account/private wrapping key,
   collection key envelope and name, file key/metadata/content, versions/assets,
   then share wrappers. A collection is not marked complete while a reachable
   child or grant remains on an unapproved suite.
9. Test field/object/user substitution, blob-header/database mismatch, chunk
   truncation/reordering, wrong share recipient, stale grant replay, unknown
   suite, migration crash/resume, quota correctness, and old-object cleanup.

**Gate:** all new Drive writes and grants use v2; v1 is exact-read/migrate-only;
the server never sees plaintext during migration.

### Phase G — collaboration frames and document epochs

1. Rename the semantic use of `Frame.version` to the selector for
   `CollabFrameSuiteId` while preserving the single authenticated byte on the
   wire. Do not add a redundant suite field.
2. Make Rust and TypeScript unpackers reject zero and unknown versions before
   verification/decryption. Add the same rule to the server frame validator.
3. Persist the selected collaboration suite with each document-key epoch.
   Reject a frame whose version differs from the locked epoch even if its
   signature is otherwise valid.
4. A suite change rotates the document key and creates an authenticated epoch
   transition; it never mixes frame suites under one `docKeyId`.
5. Extend Rust/TypeScript golden vectors and tests for version relabeling,
   cross-document replay, mixed-suite epochs, unknown versions, and truncated
   frames.

**Gate:** the existing version byte is strictly validated and a document epoch
cannot contain mixed frame suites.

### Phase H — key transparency

1. Add `KeyTransparencySuiteId` to log-generation metadata, leaves, map proofs,
   checkpoints, operator signatures, witness attestations, client pins, and
   policy.
2. Make suite/version part of every domain-separated hash and signed canonical
   checkpoint. An unknown suite cannot be interpreted as the current Merkle
   construction.
3. Lock one log generation to one suite. A change creates a new generation and
   an authenticated bridge checkpoint signed according to the old and new
   policy; it does not reinterpret old tree nodes.
4. Preserve exact v1 verification for historical proofs while policy permits
   it. Test suite relabeling, cross-generation proofs, rollback, split view,
   wrong operator/witness key type, and transition quorum failures.

**Gate:** transparency evolution cannot weaken account-identity verification or
silently reset a client's pinned log state.

### Phase I — Group Chat registry with the group feature

1. Define `GroupChatSuiteId` in the Group Chat protocol, independent of Direct
   Chat. The first suite specifies both Signal-style encrypted authoritative
   group state and Sender Keys; it is not merely an AEAD choice.
2. Include supported Group Chat suites in each device's account-signed
   capabilities. Group creation intersects every initial member's
   authenticated capabilities with local policy and selects once.
3. Bind suite and protocol version into group state, membership commits, epoch
   secrets, messages, and backups. The suite remains fixed within the group
   lifecycle defined by that suite.
4. A future MLS suite is a new `GroupChatSuiteId`, not a flag inside the Signal
   suite. Migration follows an authenticated reinitialization/new-group flow
   linking old and new state; no message-level fallback is possible.
5. Test malicious capability stripping, mixed member support, add-member policy,
   state rollback, suite relabeling, migration authorization, and an old client
   encountering an unknown suite.

**Gate:** the public Group API is protocol-neutral, while each implementation's
state machine and migration stay explicit and independently auditable.

### Phase J — policy, telemetry, and retirement

1. Give each owner a compiled default policy and an optional stricter local
   override. Do not expose algorithm menus. Admin UI may show purpose, suite
   name/status, affected object count, and migration progress.
2. Record only non-secret counters: suite IDs by purpose, selection failures,
   policy rejections, remaining migration counts, and unknown-suite errors. Do
   not log keys, ciphertext, account addresses, object names, or capability
   contents.
3. Add a release checklist for `supported -> preferred -> migrate-only ->
   forbidden`. A suite cannot become forbidden until recovery, rollback, and
   backup restore paths have been tested against the new floor.
4. Remove obsolete writers and primitive-level call sites. Keep historical
   readers only while policy and the documented support window allow them.
5. Add repository checks rejecting ambiguous `SuiteId`, generic `CryptoSuite`,
   raw suite-number comparisons, and default-on-parse patterns in security
   code.

## 6. Persistence and API migration map

Use the next free migration number at implementation time; the unified
federation work also has pending migrations, so this plan deliberately does not
reserve numeric filenames.

| Storage/API | Change | Migration rule |
|---|---|---|
| `chat_devices`, `chat_mailbox` | retain numeric column; add/refresh closed constraints and typed model conversion | existing 1 stays 1; unknown row aborts read |
| client `sessions` in SQLite/IndexedDB | store `{ directChatSuite, record }` | pre-tag schema records become 1 once; tagged unknown rejects |
| Chat manifest/history/transparency leaf | new signed manifest format with account/direct capability fields | append a valid higher manifest linked to v1 |
| `chat_profiles` and profile DTOs | add `profile_suite` | current rows become exact profile v1; v2 is a new key/version |
| `users` and Auth DTOs | add `account_protection_suite` and bundle revision | current rows become exact account-protection v1; migrate by client rewrap/CAS |
| account identity persistence | add identity suite, sequence, previous hash, signed transitions | import current Chat authority through an authenticated transition |
| Drive tables and DTOs | add `drive_suite` per independently decryptable artifact | current rows become exact Drive LegacyV1; migrate copy-and-swap |
| collaboration frames | retain authenticated `version`; add epoch suite metadata | version 1 maps exactly; no redundant wire field |
| transparency tables/client pins | add suite and log generation | v1 stays a separate generation; bridge to a new generation |
| federation discovery/messages | `fedVersion` maps to profile | destructive replacement of experimental v1; no `authProfile` field |

All SQL backfills must be bounded and reversible at the schema level. Any
migration requiring plaintext is a client workflow, never a SQL or server job.

## 7. Required test matrix

### Registry and type safety

- zero, unknown, malformed, duplicate, and cross-purpose IDs reject;
- registry assignments are unique and immutable in golden snapshots;
- numeric ordering has no effect on policy or preference;
- no public API can accept a different purpose's suite type;
- JSON, database, WASM, UniFFI, CLI, and TypeScript representations agree.

### Capability and selection

- signed capability add/remove/reorder tampering fails;
- unsigned server availability cannot replace device/account capability;
- local preference wins over peer ordering;
- no-common-suite produces one terminal typed error;
- policy-rejected suites stay rejected when every peer advertises them;
- a crypto failure never triggers selection of another suite.

### Binding and locking

- suite, purpose, object, peer, field, revision, and epoch relabeling fails;
- old ciphertext under a new ID and new ciphertext under an old ID both fail;
- direct sessions, group epochs, profiles, Drive objects, account epochs,
  collaboration epochs, transparency generations, and federation versions
  cannot change suite in place;
- exact transport retry is accepted only where the feature's idempotency rules
  allow it and does not renegotiate.

### Migration and recovery

- old/new positive vectors work in every supported implementation;
- every intermediate crash point resumes without losing the last decryptable
  value or exposing plaintext;
- concurrent migration uses compare-and-swap and cannot last-writer-wins over a
  newer revision;
- migration authorization binds source/destination suite and hashes;
- backup restore retains suite metadata and applies the current local floor;
- old readers cannot mistake a new object for old format;
- raising the floor reports remaining blocked objects before retirement.

### Fuzzing and observability

- fuzz every untrusted suite/version parser and protected envelope dispatcher;
- property-test canonical capability ordering and migration state machines;
- telemetry contains purpose/status/counts only and no secret or user content;
- alerts distinguish unknown suite, unsupported known suite, policy rejection,
  authentication failure, and corruption.

## 8. Documentation changes per implementation slice

Each slice updates, in the same commit:

- this decision's registry table and the owning protocol specification;
- `docs/architecture.md` for the current format and migration state;
- `docs/api.md` and generated OpenAPI for new wire fields/errors;
- `docs/chat-protocol.md` for Chat/Profile/Identity/Transparency changes;
- `docs/self-hosting.md` for any operator-visible floor or migration status;
- `docs/roadmap.md` for shipped versus remaining owners; and
- the relevant crate/frontend crypto README plus vector regeneration commands.

The unified federation plan references the authoritative decision and describes
only `FederationAuthProfileId`. It must not duplicate or redefine the feature
registries.

## 9. Delivery order and stopping points

The recommended order is:

1. Phase A (fail-closed Direct Chat) — **complete**, with no ciphertext change.
2. Phase C (Federation profile alignment) — required before unified federation
   implementation begins.
3. Phase B (authenticated Direct Chat capability/session lock).
4. Phase D (Profile suite and v2 rotation).
5. Phase E (Account Protection plus cross-feature Account Identity).
6. Phase G (strict Collaboration version/epoch lock).
7. Phase F (Drive v2), delivered in its bounded sub-slices.
8. Phase H (Transparency extraction/generation agility).
9. Phase I with Group Chat, then Phase J retirement as suites evolve.

This order does not block the unified server federation stack on redesigning
Drive ciphertext or Group Chat. It establishes federation's own strict profile
first, then lets each feature adopt its registry behind the common transport.

## 10. Definition of done

The decision is implemented only when:

- every current Kutup cryptographic construction appears in exactly one owned
  registry or is explicitly documented as platform-owned and out of scope;
- all protected state has one authenticated, purpose-typed suite selector;
- all negotiated capabilities are authenticated by the controlling identity;
- all local policies distinguish create/read/migrate/reject without numeric
  ranking;
- no unknown-suite default, decoder probing, or fallback retry remains;
- suite changes create authenticated new state and are crash recoverable;
- cross-language positive, negative, downgrade, and migration tests pass; and
- the documentation reflects the deployed suite and migration state rather
  than only the desired architecture.
