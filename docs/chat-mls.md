# Kutup MLS conversations

This document is the normative architecture for Kutup MLS SelfSync, Direct,
and private Group conversations. It replaces the earlier GV2/sender-key group
proposal. RFC 9420 MLS 1.0 is the V1 cryptographic protocol; post-quantum MLS
remains a later suite upgrade after the relevant IETF work and interoperable
library support stabilize.

The feature is intentionally **not advertised yet**. Protocol types, durable
storage, authenticated federation routes, OpenMLS client state, WASM bindings,
anonymous delivery, authority catch-up, participant membership transitions,
identified invitation decisions, privacy-bounded telemetry, and admin
inspection routes exist. Advertisement remains gated on browser product
orchestration/UI, federated invitation-rejection feedback, and the complete
two-server adversarial E2E.

## Conversation model

One implementation serves three typed conversation kinds:

- `SelfSync`: the account's devices. The authority set is the account's own
  server (`N=1`, `q=1`); there is no anonymous delivery.
- `Direct`: two accounts. The initial authority set is exactly the participant
  server set, including the `N=1` local case. First contact is identified and
  bounded; established delivery is capability-authenticated and anonymous.
- `Group`: 1-1000 members at the protocol layer. Server policy must permit at
  least 256 and may permit up to 1000. Announcement channels with 100,000+
  recipients are a separate deferred fan-out design, not an oversized MLS
  group.

Every conversation has a random UUID, an independent 16-255-byte MLS GroupId,
and append-only incarnations. Recovery creates a new incarnation; it never
rewrites security history.

A Group genesis contains only its creator. Every later addition is an explicit
MLS membership transition and identified invitation; creating a group never
silently enrolls remote accounts. Direct remains a two-member genesis in the
unadvertised foundation and must gain the same consent/product treatment before
the existing libsignal Direct path can be replaced.

## Cryptographic profile

Kutup MLS V1 accepts exactly RFC 9420 ciphersuite `0x0002`
(`MLS_128_DHKEMP256_AES128GCM_SHA256_P256`). OpenMLS owns the state machine.
Kutup code owns persistence, manifest binding, policy, federation ordering,
and delivery.

Each device manifest binds two distinct uncompressed P-256 keys:

- the MLS BasicCredential signing key;
- the anonymous-delivery HPKE key.

Claimed KeyPackages are accepted only when their ciphersuite, KeyPackageRef,
lifetime, credential identity, and signature key exactly match a
transparency-verified manifest. Welcome, Commit, application, and sender-leaf
processing all fail closed on a manifest mismatch.

Anonymous KeyPackage retrieval carries the requester's prior transparency tree
size as a lossless canonical decimal string. Its response includes the complete
signed current manifest plus inclusion, current-map, consistency, operator, and
witness evidence. The shared Rust engine authenticates and durably pins that
evidence, recovers every skipped manifest version, requires one package for
every MLS-enabled manifest device, and validates each OpenMLS KeyPackage before
returning it to browser orchestration. This path consumes no Signal prekeys.

The OpenMLS provider snapshot, pending Commit bytes, Welcome retry bytes,
group-scoped control key, secret-tree progress, and application outbox are
committed atomically. A restart returns exact retry bytes; it never regenerates
a Commit or silently replaces a key.

## Roles

Administrators manage ordinary membership and may promote another member to
administrator without owner voting.

Owners exist only for security governance. `floor(2N/3)+1` owner approval is
required to:

- change the owner set;
- add or remove ordering authorities;
- change authorization or cryptographic policy;
- close or recover a conversation;
- approve a protocol/suite upgrade.

Owners are group-scoped pseudonyms with group-scoped Ed25519 keys. Ordering
authorities receive the original signed approvals but not account identities.
The member-visible MLS-encrypted control payload binds each owner/control
pseudonym to the manifest-verified MLS sender.

## Ordering authorities

A group is not owned by one homeserver. It chooses 1-64 independent Kutup
servers that replicate and order only the pseudonymous MLS control log. The
required quorum is always `floor(2N/3)+1`; examples are:

| N | quorum |
|---:|---:|
| 1 | 1 |
| 2 | 2 |
| 3 | 3 |
| 4 | 3 |
| 7 | 5 |
| 64 | 43 |

This is a deliberately small, deterministic, safety-first BFT control log, not
a cryptocurrency consensus network. V1 has one round. An authority signs at
most one block hash per incarnation/height; a conflicting race fails closed
and requires explicit recovery.

Control proposals expose conversation/incarnation, epoch, action class,
ciphertext digest, and a random group-scoped P-256 control pseudonym. The
actual operation is MLS-encrypted. External authorities can hold a proposer
accountable inside one group without correlating that device across groups.

Participant clients connect only to their own server. Servers exchange signed
federation requests through the common DNS/SSRF/admission/identity transport.
There is no Matrix room DAG and no permanent home server.

### Authority changes

Changing the authority set is joint consensus:

1. owners approve the exact transition proposal;
2. the current authority quorum signs the exact transition block;
3. every newly contacted authority receives bounded pages (at most 64 control
   requests and 8 MiB per page) of the complete finalized history;
4. the new authority verifies genesis, the hash-chained page stream, the whole
   history digest, every old quorum/owner certificate, exact heights/epochs,
   and the current-set transition certificate;
5. only then may it sign under the next authority set;
6. the final block contains both old- and new-set quorum certificates.

Bootstrap pages and progress survive restart. A cryptographically invalid
history is durably rejected and audited. The finalized-control retry worker
reconstructs and re-sends bootstrap pages before retrying a transition to a
new authority, so a temporarily unavailable non-voting authority can catch up
later. Replay materialization is idempotent after a crash, while normal voting
and new control finalization remain blocked until the durable bootstrap state
is `materialized`.

The group remains writable while any required quorum is online. Losing more
than the tolerated authority fraction stops new control operations but does
not destroy client MLS keys or message history. Recovery is an owner-approved
new incarnation, never unilateral server takeover.

## Membership transitions and invitations

An administrator stages one destination-private
`MlsMembershipDeliveryV1` for every server affected by an add, remove, or role
change. The public `MlsMembershipTransitionV1` commits the exact old/new roster
hashes, member counts, participant-domain sets, and one private-delivery digest
per affected server. Ordering-only replicas carry the public transition and no
private membership delivery.

Finalization reconstructs the complete roster from the staged destination
snapshots and verifies its exact commitment before changing any durable state.
Each destination receives only its local snapshot. Every active-after local
device receives exactly one Commit or Welcome envelope; missing, duplicate,
extra, or wrongly typed envelopes reject the transition. The public control
block, local membership rows, mailbox envelopes, epoch/routing state, promoted
staging records, and federation retry rows commit atomically.

A newly added participant server receives the complete public control history
as hash-chained pages of at most 64 commits and 8 MiB. It verifies genesis,
every predecessor/epoch, old quorum and owner certificate, authority
transition, final membership certificate, history digest, and its committed
private delivery before materializing the conversation. Only the final page
carries that destination-private delivery. Page progress and cryptographic
rejection survive restart.

New local members are `pending` for at most 30 days. Acceptance activates the
membership; rejection or expiry marks it rejected and deletes its staged
membership-control mailbox material. Pending/rejected members cannot authorize
control changes or publish/use group delivery capabilities. The server records
structured accept/reject/expiry audit events. V1 advertisement additionally
requires a federated rejection notification so administrators can promptly
remove a rejecting account from the cryptographic roster; until that lands,
rejection remains local and the account stays in MLS until an administrator
commits its removal. A rejected account never receives a later Commit merely
because another membership change occurs; an attempted delivery to it rejects
the whole transition rather than silently restoring access.

The dedicated authenticated MLS mailbox exposes bounded cursor pages and
idempotent UUID acknowledgements. Membership-control rows bind the exact
conversation incarnation; anonymous rows are structurally forbidden from
carrying conversation or incarnation metadata. Browser cursors are canonical
decimal strings so JavaScript cannot round a 64-bit value.

The unadvertised browser coordinator replenishes durable KeyPackages and
implements a restart-safe invitation boundary. It decrypts the Welcome only
into untrusted `account@server#device` claims, then calls the shared Rust engine
to fetch authenticated policy history and current-manifest proofs, recover
every skipped manifest, pin rollback/fork state, and compare the exact P-256
credential key. Only that result can reach OpenMLS join. It commits OpenMLS
state first, activates the server invitation second, and acknowledges the
Welcome last. If the network fails after the local commit, retry reads the
existing group and resumes activation without attempting a second join.

## Federation privacy

Genesis replication sends each participant server only accounts hosted on
that destination. Other usernames never appear in its replica. Authority-only
servers receive an empty member list. All replicas receive the participant
domain routing set, roster commitment, authority set, owner pseudonyms, and
encrypted control data.

Anonymous established delivery uses:

- a 16-byte recipient capability derived from the MLS epoch exporter and bound
  to conversation, incarnation, epoch, and recipient;
- only `SHA-256(capability)` at the destination, compared in constant time;
- RFC 9180 Base-mode HPKE
  `DHKEM(P-256, HKDF-SHA256)/HKDF-SHA256/AES-128-GCM`;
- a fresh encapsulation per destination device;
- authenticated recipient/device/send-ID/suite AAD;
- padding inside HPKE to 1024-byte buckets.

The destination transaction and anonymous mailbox contain recipient, send ID,
and opaque per-device envelopes, but no sender, sender device, conversation,
group, or epoch. This padding is not the deferred constant-rate
traffic-inspection feature.

## Failure semantics

- A network failure queues exact retry material.
- A pending local Commit blocks another membership Commit and capability epoch
  advancement.
- Wrong suite, key, roster, epoch, predecessor, quorum, owner approval,
  history digest, or sender manifest is a hard cryptographic failure.
- No established MLS/anonymous send falls back to identified delivery.
- Unknown recipients and invalid capabilities use the same unavailable
  response.
- Authority and control histories are append-only. Evidence and administrative
  cryptographic events are retained.

Admin-only inspection is available at `/api/admin/chat/mls/status` and
`/api/admin/chat/mls/conversations/{conversationId}`. It exposes exact policy
and key fingerprints, roster and routing commitments, quorum sets, progress
counts, failure evidence digests, and bounded audit history. It never returns
usernames, ciphertext, raw capabilities, mailbox contents, or
sender/recipient correlations.

## Completion gate

Do not advertise MLS until all of the following pass together:

- browser orchestration for destination-specific add/remove, voting, Commit
  merging, application delivery, and UI integration of the implemented
  authenticated invitation-roster verifier;
- federated invitation-rejection feedback and administrator removal flow;
- group conversation, invitation, admin/owner, and exact
  policy/fingerprint UI;
- WebSocket/restart reconciliation and multi-device linked-state flow;
- native Rust, WASM, web, Playwright, PostgreSQL migration, Docker Compose,
  witness/auditor, and two-server federation suites;
- adversarial tests for authority rollback/fork, invalid bootstrap pages,
  forged Welcome/Commit/certificate, roster mismatch, capability theft and
  rotation, replay, enumeration, oversized requests, and downgrade;
- destination logs/audit/metrics verified to contain no sender identity or
  sender-recipient correlation.
