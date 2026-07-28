# Chat transparency and sealed-sender threat model

This document is normative for one-to-one web Chat and the unadvertised MLS
conversation foundation. Calls, anonymous relays, traffic-shape obfuscation,
native product integration, HA, threshold roots, and large announcement
channels are outside this milestone.

## Assets and trust boundaries

- Account authority keys authenticate complete device manifests. A homeserver
  may serve bundles, but it may not add, remove, reorder, or replace a device
  without an account-signed manifest update.
- Federation identity authenticates typed feature-policy histories. It does not
  interpret Chat policy payloads. Identity rotation and feature-policy rotation
  are separate contiguous old-to-new authenticated chains.
- Transparency operators sign append-only log and current-map checkpoints.
  Independently administered witnesses attest exact operator statements.
- A sealed-sender offline root signs only an online server certificate. Normal
  operation has the online key and certificate, never the root private key.
- A random profile key grants profile reads and derives the recipient-bound
  16-byte delivery capability. Servers persist only its SHA-256 verifier.
- MLS device credentials and anonymous HPKE keys are bound into the complete
  account manifest. Group-scoped owner and control keys are distinct from
  account-wide credentials.
- MLS control ordering is replicated by a replaceable 1-64 server authority
  set. External authorities see participant domains and pseudonymous encrypted
  control data, not member usernames.

The sender's origin server necessarily knows the authenticated sender while it
creates or retries a federated transaction. The destination server learns the
recipient, origin domain, timing, size, device fan-out, and send UUID. It must
not receive or persist sender account/device identity, sender certificates,
ciphertext in logs, raw capabilities, or sender-recipient metric labels. Sealed
sender does not conceal IP addresses from the local origin, traffic timing,
message size, origin domain, or recipient identity.

## Adversaries and failure semantics

| Threat | Required control | Client/server result |
|---|---|---|
| Malicious remote server serves an attacker device | Account signature, exact manifest leaf, RFC 6962 inclusion/consistency, current-map proof, authenticated policy | Invalid proof/signature or unresolved version gap durably blocks new sends. |
| Policy rollback, gap, wrong domain/type, or silent key replacement | Complete federation identity and typed policy histories with sequence and predecessor hashes | Reject and retain the last valid pin; cryptographic policy-chain failures quarantine the domain. |
| Split log view | Pinned log ID, operator signature, witness quorum, scheduled checkpoint consistency, cross-view audit | Signed same-size root/map conflict or log replacement creates immutable fork evidence and hard-blocks. |
| Compromised or unavailable witness | Independent configured keys and quorum; original witness statements retained | Invalid/contradictory signed statements block. Missing witness, unavailable auditor, or withheld cross-view proof warns but does not override an otherwise valid quorum. |
| Skipped manifest updates | Append-only complete history and checkpoint-bound pages of at most 64 individual RFC 6962 proofs | The new manifest remains pending until every exact increment, previous hash, authority, proof, and final map binding verifies atomically. |
| Stolen delivery capability | Recipient-bound HKDF capability, database limits, profile-key rotation on block | Capability permits bounded anonymous bundle/send attempts only; block publishes a new verifier before redistributing the new profile key. |
| Recipient enumeration | Identical not-found response for unknown user and invalid capability | Callers cannot distinguish these cases through status/body. Timing leakage remains an operational concern. |
| Sealed-envelope forgery | Libsignal outer envelope, authenticated service-policy/root chain, 24-hour sender certificate, transparent manifest identity match | Inner Signal ratchet is not touched until every certificate and manifest check succeeds. |
| Replay | UUID/capability/recipient deduplication locally; signed origin sequence remotely; Signal replay protection at recipient | Exact retry is idempotent; changed payload for a pending ID is rejected. |
| Downgrade | Capability advertisement gate and a durable sealed outbox bit | First contact remains identified. Once a send is sealed, any failure remains on the anonymous route; there is no identified fallback. |
| Denial of service | IP outer limiter, database-backed capability/recipient/origin counters, 32-envelope and 1 MiB limits, bounded parsers and retries | Requests are rejected uniformly without consuming unbounded memory or process-local-only quota. DoS cannot be eliminated. |
| Compromised signing key | Purpose-specific signer interfaces, explicit rotation commands, offline sealed root, immutable audit events | Existing evidence remains verifiable. Recovery is an explicit audited operation bound to the active evidence digest. |
| Single group server outage or takeover | No permanent homeserver; `floor(2N/3)+1` authority quorum and owner-approved joint authority transitions | Control operations continue while quorum exists. A minority cannot rewrite the log; loss of quorum stops control writes rather than selecting a new owner implicitly. |
| New authority receives a forged or truncated past | Hash-chained bounded pages, complete history digest, exact height/epoch/predecessor replay, all old quorum and owner certificates, current-set certificate over the transition | Invalid history is durably rejected and audited. The server cannot vote under the next set until verified materialization finishes. |
| New ordering authority crashes during history materialization | Preverified hash-chained history, idempotent genesis/block replay, durable bootstrap cursor/state, and a write/vote gate until `materialized` | Restart resumes exact replay; partially built state cannot vote on or finalize a new control block. |
| New participant receives a forged or truncated past | Complete hash-chained public history, exact old quorum/owner/authority-transition replay, final membership certificate, and destination-private delivery digest | Invalid or partial bootstrap is durably rejected. Conversation state and Welcome/Commit material are not exposed until the complete history verifies. |
| Membership delivery is omitted, swapped, or leaks another server's roster | Public per-destination delivery commitments, exact global roster reconstruction at the origin, destination-local snapshots, and exact active-device Commit/Welcome coverage | The control block, membership state, mailbox, epoch, and retry outbox remain unchanged unless every affected delivery verifies and commits atomically. |
| A linked device is forged, cloned, stale, or revoked | Every installation has an independent manifest-bound MLS leaf; typed `DeviceSync` requires the active member's exact current device set, one ordered Commit, destination-private leaf snapshot, and history-verified Welcome | No group secret or provider snapshot is copied. Partial/mismatched sync leaves the prior epoch pinned; revocation removes ephemeral KeyPackages, capability, and mailbox access while retaining immutable leaf history. |
| Unwanted or expired group invitation | Creator-only group genesis, identified pending membership, 30-day expiry, explicit accept/reject, no pending-member authorization or capability publication | Reject/expiry deletes membership-control mailbox material and is audited. Until federated rejection feedback lands, an administrator must commit removal before the rejected account leaves the MLS roster. |
| Rejected invitee is silently restored by a later membership transition | Rejected status is durable, its Welcome is deleted, it is excluded from later envelope coverage, and any envelope addressed to it rejects the transition | No new Commit/Welcome is stored; access resumes only through an explicit future protocol flow. |
| Ordering-authority cross-group correlation | Random group-scoped P-256 control credential bound inside MLS-encrypted control data | Authorities can attribute actions inside one group but cannot use the outer credential to link the device across groups. |
| Malicious MLS Welcome, Commit, truncated control history, or sender leaf | Mandatory group-private control extension; complete quorum-certified history replay; exact ciphertext digest, predecessor, roster transition, GroupId/epoch, transparency-verified manifest credential, and signature-key match | The client does not join, merge, decrypt, acknowledge, or advance durable state. |
| Forged, skipped, or downgraded private MLS group policy | Contiguous typed policy actions, unchanged-roster delivery commitments, current-owner certificate, authority quorum, exact Commit digest, immutable genesis policies, and policy-action counts during history replay | Any mismatch leaves the previous policy and MLS epoch pinned. Administrator-only sending and the plaintext ceiling are enforced by the shared engine on outbound and inbound application data; no delivery fallback is attempted. |
| Crash or replay between an inbound MLS Commit and mailbox acknowledgement | OpenMLS epoch, public control pin, and exact mailbox id/cursor/send-id receipt commit in one encrypted snapshot | Restart acknowledges an exact durable receipt without reprocessing the old Commit; changed receipt or block material is a trust failure. |
| Malicious, rollback, or partially delivered MLS incarnation recovery | Current-owner signatures bind the exact old genesis/head, preserved roster and owners, fresh GroupId and epoch-one genesis, authenticated authority set, and every private-delivery digest; clients verify manifest-bound Welcome leaves before one atomic archive/install/receipt write | The old incarnation remains pinned and readable, the new incarnation is not installed or acknowledged, and no ordinary invitation or identified fallback is attempted. |
| Malicious or replayed anonymous MLS KeyPackage directory response | Capability-authenticated request, lossless prior-checkpoint cursor, exact current manifest plus policy-authenticated inclusion/map/consistency/quorum proof, complete device coverage, and OpenMLS KeyPackage validation | No membership proposal is created; valid proof/key material is pinned only through the shared rollback-safe verifier. |
| Destination server enumerates a federated group roster | Destination-specific genesis replicas contain only locally hosted members; authority-only replicas contain none | The server learns participant domains and its own accounts, but not remote usernames. |

## Pinning and recovery rules

Network failures, stale checkpoints, and unavailable witnesses are warnings and
retain the last valid checkpoint. Rollback, invalid signatures/proofs, policy
chain failure, log replacement, same-size equivocation, and certificate/manifest
identity mismatch are cryptographic failures. They block new sends for the
affected domain and survive restart.

Hard blocks never clear merely because a later scheduled poll succeeds. An
administrator must name the active evidence digest, supply a reason, and obtain
a fresh valid observation through the recovery endpoint. Fork evidence and the
administrative audit event are not deleted. If contradictory witness views
remain present, scheduled auditing re-applies the block.

## Key compromise playbooks

- Federation identity: publish the existing old-and-new-signed identity
  successor, then rotate each typed policy explicitly. An unchained replacement
  is an incident, not bootstrap.
- Transparency operator: publish an authenticated feature-policy successor and
  retain the log ID. Clients remain fail-closed where an old checkpoint pin
  cannot authenticate the transition.
- Witness: publish a policy successor that changes the witness set while still
  satisfying the local quorum floor. Preserve all prior signed statements.
- Sealed root: publish old and new roots, activate a server certificate under
  the new root, wait at least the maximum sender-certificate lifetime plus clock
  skew, then remove the old root in a later policy version.
- Delivery capability: rotate the profile key and verifier atomically, then
  distribute the new key only through still-authorized conversations.

## Logging and telemetry

Allowed dimensions are feature, domain-class (local/federated), outcome class,
proof type, and limiter type. Raw capabilities and hashes, usernames, sender
certificates, ciphertext, send IDs, account/device IDs, and destination-side
sender-recipient correlations are forbidden in logs, traces, and metric labels.
Administrative cryptographic events store a digest plus the original signed
evidence in restricted tables.

The backend exposes the following bounded OpenTelemetry instruments when an
OTLP/gRPC exporter is configured:

- `kutup.chat.policy.events`
- `kutup.chat.transparency.monitor.events` and
  `kutup.chat.transparency.monitor.checkpoint_age_seconds`
- `kutup.chat.transparency.proof.events` and
  `kutup.chat.transparency.proof.entries`
- `kutup.chat.transparency.witness.events` and
  `kutup.chat.transparency.witness.quorum`
- `kutup.chat.transparency.fork.events`
- `kutup.chat.sealed_sender.certificate.events`
- `kutup.chat.sealed_sender.send.events` and
  `kutup.chat.sealed_sender.send.envelopes`
- `kutup.chat.mls.control.events`
- `kutup.chat.mls.quorum.events`, `kutup.chat.mls.quorum.available`, and
  `kutup.chat.mls.quorum.required`
- `kutup.chat.mls.bootstrap.events` and
  `kutup.chat.mls.bootstrap.pages`
- `kutup.chat.mls.anonymous_delivery.events` and
  `kutup.chat.mls.anonymous_delivery.envelopes`
- `kutup.chat.rate_limit.rejections`

Export is disabled only when no endpoint is configured. A shared
`OTEL_EXPORTER_OTLP_ENDPOINT` enables both signals; otherwise both the trace and
metric signal-specific endpoints are required. Invalid exporter construction
fails startup and never falls back to logs-only operation.

## Parser fuzzing

The standalone [`fuzz`](../fuzz/README.md) package coverage-fuzzes every
untrusted structure added by this milestone. One target covers authenticated
policy envelopes and histories, typed Chat policies, checkpoints, manifest
range pages, witness views, and fork evidence. The second covers anonymous and
federated sealed-send JSON, sender certificates, inner unidentified-sender
content, and raw libsignal sealed-sender outer envelopes through libsignal's
real decrypt/parser entry point. The package is outside the release workspace,
pins its own lockfile, and has no production feature flag or alternate parser.
