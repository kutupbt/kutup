# V1 security-review follow-ups

**Status:** draft; decisions and completion gates for V1, not a description of
the currently implemented protocol

**Recorded:** 2026-07-29

**Source:** an external AI review followed by a code- and standards-backed Kutup
maintainer triage. The review is input, not an audit or security endorsement.

This note preserves the useful recommendations from that review, records where
Kutup disagrees with it, and prevents unresolved claims from being lost while
the MLS branch is prepared for `main`.

## Governing premise: V1 is preproduction

Kutup has no production deployment or stable wire/persistent-format release.
Development databases, browser state, manifests, identity histories, and
federation pins may be recreated while V1 is finalized.

Therefore V1 work must prefer the cleanest reviewed structure:

- replace superseded protocol types and database shapes rather than retaining
  compatibility shims;
- use one intentional cutover instead of dual-writing old and new formats;
- remove old parsers, routes, suite entries, and fallback behavior once the new
  path is complete;
- regenerate development fixtures, canonical vectors, manifests, trust pins,
  and test databases when a derivation label or authenticated structure changes;
- never advertise a partially converted feature; and
- document each destructive development reset so local contributors understand
  why existing test state no longer opens.

Preproduction status makes breaking changes affordable; it does not make
underspecified cryptography acceptable. The replacement must still have
canonical encodings, explicit failure semantics, complete local and federated
paths, adversarial tests, and restart/crash verification before it is enabled.

This premise expires at the first stable `v*` tag. That tag is Kutup's permanent
compatibility boundary: people may retain V1 user data, ciphertext, trust pins,
clients, and federated servers. From that point onward, breaking changes require
versioned readers and writers, durable data migration, advertised peer
capabilities, a supported interoperability/deprecation window, and explicit
failure instead of silent downgrade. `docs/crypto-agility.md`
create/read/migrate/reject policy governs persistent and federated changes.

## Cannot tag V1 until the one-way-door set lands

The affordable destructive-change window closes at the first stable tag. The
following account and Drive foundations must land and pass their gates as one
set before that tag:

- correct account-protection and recovery documentation;
- version and persist per-account account-protection/KDF parameters;
- write the Drive threat model and exhaustive persistent/wire-format inventory;
- replace the Chat-scoped self-authority derivation with the final
  account-scoped authority and regenerate development trust state;
- define one complete, account-signed `AccountManifestV1` under that authority,
  carrying account keys and up to ten complete active device records with a
  monotonic sequence and previous-manifest hash;
- remove the global transparency log, sparse map, checkpoints, proofs, policy,
  monitors and dormant routes; retain only account-signed manifest history,
  durable peer pins, TOFU, QR verification and fail-closed identity change;
- define explicit account-incarnation termination and discontinuity semantics
  for destructive administrative wipe;
- define purpose-separated Drive, collaboration, and asset subkeys;
- define one typed, suite-bearing, context-bound V1 Drive envelope family;
- define authenticated collection-key epochs, bind the epoch into derivation
  and AAD, and make removal rotate and redistribute keys atomically;
- authenticate named share creation and redemption to the exact verified
  account identity;
- make `kutup-crypto` the canonical Rust implementation used by the browser
  through WASM; retain a narrow primitive-only libsodium adapter only when a
  reproducible operation is at least ten times slower or cannot complete; and
- pass canonical-vector, parser/fuzz, transaction-failure, restart, federation,
  browser, migration/reset, and adversarial gates, followed by an independent
  implementation-versus-spec security review.

Do not tag with a partial set and promise to migrate the remainder later.
OPAQUE, a post-quantum Drive wrapping suite, random-access chunk trees and
other independently addable code points remain outside this checklist.
Confidential broadcast is a separate V1 blocker because V1 promises that
feature at a one-million-account, ten-million-device-grant boundary.

## Accepted decision: administrator-controlled device limit

Kutup V1 will add a durable server-administrator setting named
`maximum_active_chat_devices_per_account`.

- The allowed range is **1 through 10 total active Chat devices per account**.
- The default and immutable V1 protocol ceiling are **10**.
- Signal's current limit—one primary device plus at most five linked
  devices—is retained below as a comparison baseline, not as Kutup's ceiling.
  Kutup deliberately permits four more devices.
- Kutup does not expose a primary/secondary distinction; every active Kutup
  Chat installation counts toward the total.
- The limit applies consistently to Direct Chat, Note to Self/device sync,
  sealed sender, MLS KeyPackages, and MLS leaves.
- The setting is global to the local server. A remote server's advertised
  setting is not identity evidence and does not replace verification of its
  account's signed device manifest.

Signal comparison evidence pinned when this decision was recorded:

- Signal Support documents one registered mobile device and up to five linked
  secondary devices:
  <https://support.signal.org/hc/en-us/articles/360007320451-Troubleshooting-multiple-devices>
- Signal Server commit
  [`ed90c1c`](https://github.com/signalapp/Signal-Server/blob/ed90c1c15c1dcd72b7adfec25d92cafc6b61da22/service/src/main/java/org/whispersystems/textsecuregcm/controllers/DeviceController.java#L91)
  enforces `MAX_DEVICES = 6`.

### Required implementation semantics

1. Enforce the limit transactionally when registering a device. Concurrent
   registration attempts for one account must not both pass the count check.
2. Idempotently re-registering the same authenticated device must not consume a
   second slot.
3. Count the same manifest-active, non-revoked devices everywhere. Device
   registration, signed manifests, prekey directories, sealed delivery, MLS
   KeyPackage retrieval, linked-device synchronization, and admin inspection
   must not use different definitions of "active."
4. Reject an over-limit registration with one typed error. Do not silently
   remove the oldest device or partially publish device/prekey/manifest state.
5. Lowering the setting must not silently revoke an existing device. Accounts
   already above the new value retain their current devices but cannot add
   another until explicit revocation or expiry brings them below the limit.
6. Increasing the setting is allowed only up to ten. Every change creates a
   structured administrative audit event containing the old and new values,
   never user identifiers.
7. The admin UI shows the current value, hard ceiling, and the effect of
   lowering it. Startup and API validation reject values outside `1..=10`.
8. Restart, concurrent-registration, lowering, expiry, revocation, and
   rollback tests are completion gates.

The current implementation has a 127 device-ID ceiling while MLS package and
delivery paths separately reject more than 32 devices. The V1 implementation
must remove these inconsistent effective capacity rules: the identifier space
may remain larger than ten, but all active-device admission and enumeration
paths must enforce the administrator setting and hard ceiling of ten.

## Accepted correction: distinguish accounts from MLS leaves

`maximum_group_members` currently counts accounts, while every linked device is
a distinct MLS leaf. The existing 256-member scale gate uses one device per
account and therefore proves a 256-leaf tree, not the worst case for 256
multi-device accounts.

V1 will use two unambiguous limits:

- `maximum_group_accounts`;
- `maximum_group_leaves`.

The V1 account limit is 256 and the V1 leaf limit is 2,560. Both limits are
enforced on genesis, membership change, device sync, recovery, history replay,
and server materialization. The exact 2,560-leaf boundary must pass native,
WASM, browser, restart, multi-authority and adversarial gates before groups are
advertised as V1-ready.

The UI and documentation must state whether every displayed capacity refers to
accounts or devices/leaves. Kutup must not advertise 1000-account operation
until the corresponding realistic multi-device boundary passes the complete
protocol and browser gates.

## Accepted pre-merge corrections

### Account-protection documentation

`docs/architecture.md` and the implementation must use the final hierarchy:

- one per-account parameterized `Argon2id(password, accountSalt)` derives an
  account-protection root;
- domain-separated HKDF derives the master-key KEK and server-facing login key;
- random 32-byte recovery entropy wraps the master key and is encoded as the
  BIP39 mnemonic; and
- a distinct HKDF-derived recovery-auth proof, bound to the canonical lowercase
  login email, is sent to the server. The raw recovery entropy never leaves the
  client.

The login key does not decrypt the master key. The current "four threads"
frontend KDF comment must also be corrected because libsodium uses one lane.
The account-protection suite, Argon2 version, memory, passes, parallelism,
output length and salt are persisted per account. Canonical vectors and
negative label-swap tests gate the cutover.

### Authority availability guidance

`floor(2N/3)+1` requires every authority at `N=2` and `N=3`, so these sets
tolerate no unavailable server. They can provide additional independent veto
or compromise resistance, but they are not high-availability configurations.

The creation and authority-change UI must display:

- authority count `N`;
- required signatures `q`;
- unavailable authorities tolerated, `N - q`;
- an explicit warning when the tolerated value is zero.

Kutup does **not** accept the external suggestion to permit only
`N ∈ {1, 4, 7, 10, ...}`. For example, five or six authorities also tolerate
one unavailable server. V1 may hide `N=2` and `N=3` behind an advanced warning
or reject them for a simpler product policy, but that is a UX/product decision,
not a requirement of the quorum formula.

### MLS ciphersuite decision

Kutup V1 uses RFC 9420 ciphersuite `0x0003`
(`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`). Kutup-to-Kutup
federation does not require the `0x0001` mandatory-to-implement suite used for
generic MLS interoperability. The clean preproduction cutover also replaces
the P-256 MLS BasicCredential signer, anonymous-delivery HPKE binding and
group-scoped control pseudonym with Ed25519/X25519 equivalents; the manifest
shape, canonical vectors and all gates change together.

The choice keeps Kutup-owned group cryptography on the shared X25519,
Ed25519 and ChaCha portfolio. It does not rewrite OpenMLS or libsignal, and it
does not claim hardware-keystore protection for these software-held keys.

### Linear private-control state

Kutup's mandatory group-private extension carries the complete genesis roster,
current roster, roles, owners, authorities, and policies. Updating a
GroupContext extension replaces its complete value, so Kutup's control plane
adds linear-in-account data even though TreeKEM key agreement remains
logarithmic.

Before retaining or increasing the account limit, benchmarks must record at
least:

- canonical private-control bytes;
- Commit and Welcome bytes;
- creation, add, remove, policy-change, and device-sync latency;
- peak memory and durable snapshot size in native and browser clients;
- one-device and maximum-device distributions at the advertised boundary.

A compact authenticated state commitment with encrypted deltas and bounded
checkpoints is a possible future design, not an approved V1 rewrite. Benchmark
the existing construction before changing its verification model.

### Post-quantum scope

Direct Chat currently receives libsignal's negotiated post-quantum protection;
MLS Group V1 is classical. The group threat model must say plainly that
harvest-now-decrypt-later protection is not provided for group history.

Kutup will not adopt an expiring MLS post-quantum Internet-Draft as the only V1
group suite. A future authenticated suite upgrade uses the existing
crypto-agility and incarnation/reinitialization boundaries after a stable
standard and production-capable OpenMLS support exist.

### Operations and external review

Before the MLS feature is described as production-ready:

- freeze new cryptographic and governance scope on the branch;
- write an operator runbook mapping every fail-closed state to inspection,
  safe retry/recovery, immutable evidence export, and forbidden manual actions;
- alert on unavailable quorum, aged pending Commits, bootstrap/recovery stalls,
  identity-change quarantine and durable outbox backlog;
- prepare a reproducible review bundle containing the normative protocol,
  threat model, canonical vectors, fuzz entry points, adversarial tests, and
  local two-server harness;
- request independent implementation-versus-spec review.

An external review does not require a public Kutup server. It can operate on
the source and reproducible local deployment. It gates a production-security
claim, not ordinary integration into a development `main` branch.

The canonical production-readiness roadmap must include this review before the
first stable tag. AI-generated review comments are useful inputs but do not
satisfy the independent-review gate.

### V1 identity decision: Signal-like manifests and QR verification

Kutup V1 does not ship a global transparency log, sparse map, checkpoint,
inclusion/consistency proof, transparency policy, monitor, witness or auditor.
Without independently governed observation, the operator log added substantial
security-critical code but did not authenticate first contact for ordinary
self-hosted deployments.

V1 instead uses one stable `AccountSelfAuthorityV1` and one complete
`AccountManifestV1`. The manifest binds account-scoped Drive keys and up to ten
complete device records, and is signed over a monotonic sequence and
`previousHash`. Clients persist the complete accepted history and peer pin.
Missing, reordered, duplicated, rolled-back or same-sequence-conflicting
history blocks new sensitive operations.

First contact is explicitly TOFU and displays a gray shield. Face-to-face QR
comparison pins the account authority and incarnation and displays a green
verified shield across Drive, Direct Chat, groups and channels. An unexpected
authority/incarnation change displays red, quarantines new sends/shares and
requires explicit safety-number-style acceptance. A server response can relay
history but cannot promote trust. A future independently observed transparency
system is a new versioned feature, not dormant V1 compatibility code.

## Accepted separate Drive security work

Outgoing collection-share listing and revocation do not yet exist. Adding a
delete endpoint alone would revoke server authorization but could not make a
recipient forget a collection key it already learned.

The future Drive share-revocation design must rotate to a new collection-key
epoch before future content is written and redistribute that epoch only to
remaining members. Previously authorized ciphertext cannot be made secret
again. File-key wrapping, collaborative-content derivation, offline writers,
federated shares, crash atomicity, and restart recovery all need explicit epoch
semantics. This belongs in a separate Drive security change, not the MLS merge.

Administrative wipe is also an account-identity discontinuity, not recovery.
The current handler clears the master-key bundle but leaves the existing Chat
identity/manifests and related state attached to the same user row. First-login
setup then creates a new master key and therefore a different self-authority
that cannot satisfy the old stable-authority chain.

V1 must model wipe as termination of the old cryptographic account incarnation
and creation of a new incarnation under the reused human-readable address.
Peers hard-stop and surface a safety-number-style reset until explicitly
accepted; old Direct sessions, device/prekey/capability/mailbox access, and
local MLS identity state are retired atomically; old group membership and Drive
shares never transfer merely because the username is unchanged. A server-signed
termination record may explain the event but cannot assert user-authorized
continuity without the lost old authority.

## Claims not adopted

- A numerical AI review score is not a security assurance.
- Kutup should not claim that no comparable self-hosted system exists without a
  separate, current comparative study.
- The ordering design should be described conservatively as a
  quorum-certified, fail-closed multi-authority ordering log until independent
  analysis justifies a broader "BFT consensus" claim.
- P-256 parser risk is not evidence of a known vulnerability in Kutup's use of
  OpenMLS/RustCrypto.
- Neither the experimental post-quantum MLS draft nor calls, threshold roots,
  or new governance mechanisms enter the V1 MLS branch. Confidential broadcast
  uses a separate V1 design rather than an oversized MLS group.

## V1 completion order

1. Freeze the dependency inventory, threat models and persistent-format list.
2. Replace global transparency with account-signed manifest history, durable
   pins, account-incarnation handling and QR verification.
3. Implement the one-Argon account-protection suite and derived recovery proof.
4. Move Drive format ownership to canonical Rust/WASM and cut over typed,
   context-bound XChaCha envelopes, authenticated shares and collection epochs.
5. Implement and test the 1–10 active-device administrator setting.
6. Cut MLS and anonymous delivery to X25519/ChaCha/Ed25519, then pass the exact
   256-account/2,560-leaf boundary and authority availability gates.
7. Implement confidential broadcast at one million accounts and ten million
   device grants using the separate LKH/control-group design.
8. Write and exercise the operations runbook and independent review bundle.
9. Rerun complete Rust, WASM, web, Playwright, Compose, restart, federation,
   recovery, scale, parser/fuzz and adversarial gates.
10. Merge to development `main`; reserve production-security claims for after
    independent review and resolution of its findings.

The initial desktop comparison for item 3 is recorded in
`docs/research/account-protection-wasm-baseline-2026-07-29.md`: canonical
Rust/WASM was 1.19x the current libsodium-WASM primitive, well below the 10x
adapter threshold. The required mid-range Android Web Worker measurement is
still a pre-tag gate.
