# Kutup MLS conversations

This document is the normative architecture for Kutup MLS SelfSync, Direct,
and private Group conversations. It replaces the earlier GV2/sender-key group
proposal. RFC 9420 MLS 1.0 is the V1 cryptographic protocol; post-quantum MLS
remains a later suite upgrade after the relevant IETF work and interoperable
library support stabilize.

The feature is intentionally **not advertised yet**. Protocol types, durable
storage, authenticated federation routes, OpenMLS client state, WASM bindings,
anonymous delivery, authority catch-up, participant membership transitions,
identified invitation decisions, federation-authenticated rejection/expiry
feedback, routine administrator changes, browser group management and
messaging, privacy-bounded telemetry, and admin inspection routes exist. The
live browser gate covers creation, cross-server invitation, rejection feedback
and manual cryptographic removal, promotion, administrator-authored add/remove,
anonymous bidirectional messages, and reload persistence. Owner-set changes use
durable MLS-encrypted manual
approval requests and responses with explicit browser approve/reject controls;
the two-server gate proves requester and approver restart recovery, that no
control block is ordered before quorum, and successful finalization after the
approval arrives. Owner-approved closure is also complete: the gate proves an
unchanged-roster terminal Commit, requester and approver reload recovery,
closure on both participant servers, send blocking, and immutable-history
visibility after restart. Owner-approved incarnation recovery is likewise
complete: the two-server gate proves manual quorum across requester/approver
reloads, authenticated immutable evidence retrieval, recipient-side Welcome
and manifest verification before durable join, post-recovery messaging, and
recovered-state persistence after reload. Advertisement remains gated on
linked-device group state and the remaining adversarial suites. The two-server
private-policy gate now passes:
it proves owner-approved administrator-only sending, a tightened 1 KiB
user-message ceiling, control availability under both restrictions, exact
remote policy pinning, and recovery after the tightened policy.

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
group-scoped control and Ed25519 owner keys, exact pending genesis request,
secret-tree progress, and application outbox are committed atomically. A
restart returns exact retry bytes; it never regenerates a genesis, owner key,
Commit, or silently replaces a key. The browser has no raw group-creation
binding: group genesis is available only through this atomic boundary.

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

An owner-set proposal automatically carries the initiating owner's signature.
If the current owner quorum is not yet met, the client persists the staged MLS
Commit and sends an invisible `groupControl` approval request only to the other
current owners. The request contains the exact signed proposal, transition
digest, next owner set, and group-private next roster, expires after at most
seven days, and survives restart. An approving client independently verifies
its current control pin and every prospective owner's prior MLS-authenticated
proof-of-possession candidate before signing. Its response is another ordinary
anonymous MLS application message sent only to the requester. No server or
client votes automatically, rejection cannot count as approval, and ordering
does not begin until the exact current-owner certificate reaches quorum.

### Private authorization and cryptographic policy

Every incarnation begins with two canonical, sequence-one policies carried
only in the mandatory MLS GroupContext extension:

- `MlsGroupAuthorizationPolicyV1` selects whether all members or only
  administrators may send user-visible application messages.
- `MlsGroupCryptographicPolicyV1` fixes suite `0x0002`, private-control
  extension `0xff4b`, anonymous delivery, 1024-byte padding, two retained past
  epochs, and a maximum canonical user-application plaintext size. Typed MLS
  governance controls are exempt from that configurable user-message ceiling
  so a tightened policy cannot deadlock recovery or reconfiguration; they
  remain bounded by the fixed 1 MiB V1 control and transport limits.

Changing either policy is one unchanged-roster MLS Commit and requires the
current owner quorum. The approval request contains exactly one next policy,
its contiguous sequence, the signed Commit proposal, and the unchanged-roster
transition. The policy value stays MLS-encrypted; ordering authorities see
only the action class, ciphertext digest, delivery commitment, and
pseudonymous owner certificate.

V1 authorization policy may switch between all-member and
administrator-only sending. Group-control approval messages remain permitted
so governance cannot deadlock. The shared Rust engine enforces the sender role
on encryption and after authenticating an inbound MLS sender leaf. The
cryptographic policy may only lower the user-application plaintext maximum
within 1 KiB–1 MiB; it cannot change the suite, disable anonymous delivery or
padding, or enlarge the past-epoch window. A suite/protocol change requires
the separately typed future upgrade/new-incarnation flow.

Both current and incarnation-genesis policies, pending Commit, exact
destination deliveries, partial owner certificate, authority vote request,
and final request share one encrypted snapshot transaction. Restart restores
the exact pending operation. Public history replay counts each typed policy
action and requires the private policy sequences to match, while recipients
independently verify that only the selected policy changed and that a
cryptographic change tightened the previous pin.

### Conversation closure

Closing a conversation is an owner-governed terminal transition for one exact
incarnation. A current owner stages a self-update MLS Commit whose public
transition preserves the complete roster, member count, participant domains,
roles, authority set, and owner set. The initiating owner signs automatically;
when more approvals are required, the same bounded, group-private approval
request/response path used by owner-set changes carries the exact close proposal
and transition digest only to current owners. No authority vote is requested
before the current-owner certificate reaches quorum.

After owner quorum, the current authority quorum orders one
`CloseConversation` control block. Every participant server receives its
destination-private Commit delivery, while ordering-only replicas learn no
membership. Server finalization atomically stores the block, delivery rows,
closed incarnation/conversation status, and administrative audit event. Each
client independently verifies the previous owner, owner certificate, authority
quorum, unchanged roster/routing commitments, private GroupContext, Commit, and
manifest-bound sender before atomically advancing its MLS state to `closed`.

`closed` is durable and idempotent. The conversation and authenticated history
remain visible after restart, but application sends and all further control
changes fail closed; there is no identified-delivery fallback. Incarnation
recovery does not reopen or rewrite a closed incarnation.

### Incarnation recovery

When the current ordering quorum cannot make progress, a current owner may
explicitly recover an active group into the exact next incarnation. Recovery
does not ask the unavailable old authorities to vote. The owner-signed recovery
plan binds the previous genesis and finalized head, preserved roster and owner
set, fresh GroupId, epoch-one replacement genesis, authenticated replacement
authority set, participant domains, and the digest of every destination-private
Welcome delivery. V1 replacement authorities must be prior participant or
authority servers because only those servers possess the immutable old public
history needed to verify the owner keys.

The initiating browser claims fresh, transparency-verified KeyPackages for
every preserved manifest device except its own initiating device, stages a
fresh OpenMLS group and one full-roster Commit from epoch zero to epoch one,
and persists the exact request before any network write. The initiating owner
approves automatically. When more owner signatures are required, the existing
bounded MLS-encrypted owner approval path shows the exact recovery plan to the
other current owners. No server signs on behalf of an owner.

After owner quorum, each server atomically stores the immutable signed recovery,
marks the previous incarnation read-only, creates the next active incarnation,
copies only its local active membership, queues exact-device Welcomes, records
an administrative event, and queues destination-specific federation replicas.
The dedicated recovery outbox survives restart and does not duplicate the
ordered-control stack.

A recipient treats an incarnation+1 membership-control envelope as a recovery
candidate. It fetches the signed recovery only through its authenticated
same-origin server, verifies the statement against its exact durable old head,
inspects the Welcome without joining, resolves every device credential through
the shared transparency verifier, and then atomically archives the old local
state and installs epoch one. Mailbox acknowledgement occurs only after this
transaction. Invalid, missing, reordered, replayed, or mismatched recovery
material leaves the old pin unchanged and blocks the transition; there is no
ordinary-invitation or identified-message fallback.

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
structured accept/reject/expiry audit events.

Rejection and expiry also atomically create canonical
`MlsInvitationFeedbackV1`. Same-server feedback is stored directly; remote
feedback is delivered through a restart-safe outbox and the shared signed
federation transport. The receiving server accepts it only from the member's
authenticated home domain and only when its unchanged finalized membership
delivery proves the exact member, invited epoch, and Welcome. Feedback history
is append-only, exposed only to active local group administrators, and visible
in the browser against the exact current roster/incarnation. It is advisory:
no server may mutate MLS state from feedback, so an administrator must commit
the member's cryptographic removal. A rejected account never receives a later
Commit merely because another membership change occurs; an attempted delivery
to it rejects the whole transition rather than silently restoring access.

The dedicated authenticated MLS mailbox exposes bounded cursor pages and
idempotent UUID acknowledgements. Membership-control rows bind the exact
conversation incarnation; anonymous rows are structurally forbidden from
carrying conversation or incarnation metadata. Browser cursors are canonical
decimal strings so JavaScript cannot round a 64-bit value.

Every V1 KeyPackage advertises, and every V1 group requires, the private-use
`0xff4b` GroupContext extension. Its canonical
`MlsPrivateControlStateV1` value carries the full group-private account roster,
administrator/owner assignments, current authority and owner sets, immutable
genesis state, proposal id, height, epoch, and predecessor. Ordering servers
still see only public commitments and pseudonyms. A Commit or Welcome that
omits, duplicates, or changes this mandatory state inconsistently is rejected.

An authenticated same-origin control-history route returns the stored genesis
and original quorum-certified `CommitMlsControlBlockV1` values in canonical
pages of at most 64 entries and 8 MiB. Pending members may read only through
their adding epoch; removed members may read through their removal epoch.
Clients accept no URL from message content and never trust a server verdict:
the shared verifier replays proposal signatures, old-set quorums,
predecessors, epochs, roster transitions, authority/owner transitions, and
then binds the resulting public commitments to the private GroupContext.

The unadvertised browser coordinator replenishes durable KeyPackages and
implements restart-safe genesis and invitation boundaries. For genesis, it
fetches each authority's complete policy history through the same-origin
federation route, asks the shared Rust engine to authenticate the federation
identity/policy chain and typed payload, and then atomically creates the
OpenMLS group, owner key, and exact server request. A failed publication leaves
that request pending; reconciliation replays it byte-for-byte and activates it
only when the server returns the exact canonical genesis hash.

The browser holds a separate account-scoped Web Lock across every complete MLS
workflow, including its network phases. Group sends, membership and governance
changes, recovery, KeyPackage maintenance, and background reconciliation cannot
interleave across tabs between prepare, order, and finalize. The existing
engine lock still protects each individual durable cryptographic transaction;
using distinct lock names preserves a fixed, non-recursive lock order.

For invitations, the coordinator decrypts the Welcome only into untrusted
`account@server#device` claims, then calls the shared Rust engine to fetch
authenticated policy history and current-manifest proofs, recover every
skipped manifest, pin rollback/fork state, and compare the exact P-256
credential key. Only that result can reach OpenMLS join. It commits OpenMLS
state, reconstructed genesis/control pin, and exact mailbox receipt in one
encrypted transaction, activates the server invitation second, and
acknowledges the Welcome last. If the network fails after the local commit,
retry authenticates the same history and receipt, then resumes activation
without attempting a second join.

For locally authored ordinary membership changes, the shared Rust engine now
atomically commits the OpenMLS pending Commit together with the exact signed
control proposal, public roster transition, destination-private Commit/Welcome
deliveries, pinned authority-set vote request, and next roster. The browser
only stages those exact deliveries, asks the server to collect votes, returns
the certificate to Rust for quorum verification, and submits the resulting
typed finalization request. A restart replays the stored operation without
regenerating a Commit, Welcome, proposal, envelope identifier, or block.
OpenMLS state and the local control-log pin advance only after the server
acknowledges the exact block hash, height, incarnation, and epoch. Additions and
removals are separate V1 transitions; neither can change administrator or
owner assignments. Server finalization independently requires an active local
administrator, while exact already-committed retries are checked by immutable
block hash before consulting the post-transition roster.

Authority changes use a distinct durable governance operation. A current
administrator proposes the next authenticated policy set and a current owner
signs the proposal; these are separate authorization checks even when the same
account holds both roles. The public `MlsAuthorityChangeV1` jointly commits the
next contiguous authority set and an unchanged-roster delivery transition for
the exact MLS Commit. The client first pins a quorum certificate from the old
set, then requests the same block from the new set. Newly added authorities
must import and verify the complete hash-chained history before voting. Only a
joint old/new certificate can finalize the block. Every participant server
still receives its destination-private Commit delivery, including a server
removed from ordering. The encrypted client snapshot persists the Commit,
deliveries, owner approval, both quorum stages, and final request atomically;
restart reconciliation never recollects or substitutes an already pinned
stage. The owner-only web control displays exact authority domains, sequence,
and quorum before accepting a replacement set.

A routine administrator change uses the same committed private-roster delivery
shape but must preserve member count and participant-domain routing exactly. It
carries no KeyPackage or Welcome, advances MLS with a self-update Commit, must
change at least one administrator bit, and cannot change an owner assignment.
The initiating shared engine checks its own account against the previously
pinned administrator roster. Receiving engines independently authenticate the
actual MLS Commit sender credential and require that account to be an
administrator in the previous encrypted roster before merging. Consequently a
malicious participant server can withhold or disorder control traffic, but it
cannot make an honest client accept a non-administrator's role or membership
change.

For inbound roster changes, the browser processes mailbox rows in
cursor order, stages each Commit without writing state, resolves every claimed
MLS device key through the transparency verifier, and fetches exactly the next
canonical public history entry. Rust requires that the quorum-certified block,
Commit digest, current pin, public transition, private GroupContext, and exact
manifest-bound device roster all agree. It then merges one epoch, advances the
control pin, and stores the mailbox id/cursor/send id receipt atomically.
Only afterward may the browser acknowledge the row. A crash replay reads that
receipt and acknowledges without attempting to process the old Commit again.

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
- A pending local Commit blocks every other membership, authority, owner,
  close, recovery, or policy Commit and capability epoch advancement.
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
counts, every incarnation head, immutable original owner-signed recovery
statements, failure evidence digests, and bounded audit history. It never
returns usernames, ciphertext, raw capabilities, mailbox contents, or
sender/recipient correlations.

## Completion gate

Do not advertise MLS until all of the remaining items pass together. Private
authorization/cryptographic owner actions now have protocol, browser
orchestration, explicit approval UI, and two-server coverage.

- group owner and exact authority-policy/fingerprint UI;
- WebSocket/restart reconciliation and multi-device linked-state flow;
- native Rust, WASM, web, Playwright, PostgreSQL migration, Docker Compose,
  witness/auditor, and two-server federation suites;
- adversarial tests for authority rollback/fork, invalid bootstrap pages,
  forged Welcome/Commit/certificate, roster mismatch, capability theft and
  rotation, replay, enumeration, oversized requests, and downgrade;
- destination logs/audit/metrics verified to contain no sender identity or
  sender-recipient correlation.
