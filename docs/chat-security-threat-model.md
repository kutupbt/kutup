# Chat security threat model

This document is normative for V1 Direct Chat, Note to Self, private MLS
groups, signed account manifests, contacts-only sealed delivery, and the common
identity/delivery foundation used by Chat media. Attachment-specific storage,
quota and parser threats are defined in `chat-media-security-threat-model.md`.
Calls, group calls, native product UI, million-account broadcast channels,
anonymity relays, and traffic-shape protection are separate milestones.

## Trust boundaries and protected assets

- The recoverable account master key derives purpose-separated account
  authority, Drive X25519, and Drive share-signing Ed25519 keys. Private keys
  never leave the client.
- `AccountManifestV1` binds the canonical account, incarnation, account-scoped
  Drive keys, and every active device. At most ten devices are active. Each
  manifest is account-authority signed and hash-links its predecessor.
- A homeserver distributes current and historical manifests. It cannot promote
  TOFU to verified, silently replace an authority, or manufacture a device.
- First observation is explicit TOFU. Face-to-face safety-number/QR comparison
  binds both canonical accounts and both authority keys. Gray means valid TOFU,
  green means user-verified, and red means a durable quarantine.
- Direct Chat and Note to Self use pinned libsignal. Private groups use pinned
  OpenMLS. Kutup does not fork either implementation.
- MLS credentials are Ed25519; anonymous group delivery keys are X25519. Both
  are exact device fields in the signed account manifest.
- Federation identity authenticates transport, endpoint discovery, sealed
  sender policy, and MLS ordering-policy chains. It does not authenticate an
  end-user identity.
- The sealed-sender root remains offline. An online server key issues 24-hour
  sender certificates under a root-signed server certificate.
- A profile key grants encrypted-profile reads and derives the recipient-bound
  16-byte delivery capability. Servers store only its SHA-256 verifier.
- A private group chooses 1-64 ordering authorities. They see participant
  domains and group-scoped pseudonyms, not the encrypted account roster.

Kutup V1 deliberately has no global key-transparency log, sparse map,
checkpoint monitor, witness, or auditor. The self-hosted deployment model does
not pretend that an operator witnessing itself is independent. Consequently,
TOFU can detect later replacement and equivocation but cannot authenticate the
first network observation. Face-to-face verification is the high-assurance
answer in V1.

The sender's homeserver knows its authenticated local sender while preparing
or retrying federation. A destination learns origin domain, recipient, timing,
size, device fan-out, and send UUID. It must not receive or persist sender
account/device identity, sender certificates, plaintext, ciphertext in logs,
raw capabilities, or sender-recipient metric labels. Sealed sender does not
hide IP addresses from the origin, timing, size, origin domain, or recipient.

## Threats and fail-closed behavior

| Threat | Required control | Result |
|---|---|---|
| Homeserver adds or replaces a device | Account signature, exact complete manifest, stable authority/incarnation pin | Reject before session, MLS, or Drive-key mutation. |
| Rollback, skipped update, or same-sequence equivocation | Monotonic sequence, `previousHash`, append-only complete history, atomic pin/history commit | Retrieve every missing version. Missing, reordered, duplicated, rolled-back, or conflicting history blocks sensitive operations. |
| Signed authority/incarnation replacement | Durable retained pin plus separately stored complete candidate history | Red quarantine. No send/share proceeds. Exact pair-bound QR verification atomically accepts the replacement while retaining old history. |
| Malformed or forged manifest | Strict bounded canonical encoding and Ed25519 verification | Reject; a contradiction against an existing pin is durably quarantined. |
| Hostile first-contact server | Explicit TOFU state and face-to-face verification | UI remains gray until independent comparison. V1 makes no stronger first-contact claim. |
| Stolen delivery capability | Recipient-bound HKDF capability, database limits, profile-key rotation on block | Bounded anonymous attempts only. Blocking publishes a new verifier before the new profile key is redistributed. |
| Recipient enumeration | Uniform status/body for unknown recipient and invalid capability | Network caller cannot distinguish the two through the defined response. Timing remains an operational concern. |
| Forged sealed envelope or certificate | Libsignal sealed envelope, authenticated root/service policy, 24-hour certificate, manifest identity/device match | Inner ratchet is untouched until every outer check succeeds. |
| Anonymous-delivery replay | Recipient/capability/send-ID deduplication locally; signed origin sequence remotely; Signal/MLS replay checks at the client | Exact retry is idempotent; changed content under an existing ID is rejected. |
| Downgrade after sealed delivery | Capability advertisement plus durable sealed outbox/delivery mode | First contact remains identified. Established sealed traffic never falls back to identified delivery. |
| Capability or profile revocation race | Capability verifier and encrypted-profile revision change atomically | The old capability stops before remaining contacts receive the new profile key. |
| Oversized or high-rate anonymous traffic | Process-local IP outer limit, database capability/recipient/origin counters, 32-envelope and 1 MiB limits | Uniform bounded rejection. Denial of service cannot be eliminated. |
| Destination sender-metadata collection | Sender-free federated transaction, mailbox and audit schema; identifier-free metrics | Schema and two-server tests reject sender fields and scan destination logs. |
| Forged MLS KeyPackage, Welcome, Commit, or sender leaf | Suite/key/lifetime/identity binding to the exact signed device manifest plus OpenMLS validation | No join, merge, decrypt, acknowledgement, or durable epoch advance. |
| More than ten devices or 256 group accounts | Shared constants: 10 devices/account, 256 accounts/group, 2,560 leaves/tree | Server, protocol, Rust, WASM and browser validators reject excess independently. |
| Group ordering fork | Hash-linked control log, exact previous block/epoch/roster commitment, authority certificate, encrypted private control state | A conflicting branch cannot advance an honest client. Signed evidence remains inspectable. |
| One ordering authority fails | `q=floor(2N/3)+1`; owner-approved joint authority changes | Writes continue only while quorum exists. Loss of quorum stops control changes without inventing a home server. |
| Malicious or unavailable authority majority | Client verifies MLS Commit and private state independently | Authorities can halt the group but cannot decrypt it or cause acceptance of unauthenticated state. |
| Invitation without consent | Creator-only genesis, identified pending invite, expiry, explicit accept/reject, no capability before acceptance | Invitee does not join or receive established anonymous traffic without acceptance. |
| Removed/re-added member reuses old acceptance | Acceptance binds incarnation and exact join epoch | Old acceptance cannot authorize a new leaf or later membership. |
| Linked device is cloned, stale, or removed | Independent MLS leaf per installation; exact manifest-bound `DeviceSync` Commit | No provider snapshot or group secret is copied. Partial sync leaves the old epoch pinned. |
| Compromised online sealed signer | Offline root, short certificate lifetime, explicit staged root policy | Root rotation is policy-versioned; normal operation cannot export or use the root key. |
| Compromised account authority/master key | Safety-number change, quarantine, recovery phrase preserves the same key | An attacker with the master key can impersonate the account. Contacts must re-verify after a destructive reset. |
| Destructive admin wipe | Wipe deletes mutable device/profile/capability state, retains old signed history, and starts a new incarnation at sequence 1 | Prior contacts quarantine the signed replacement until explicit safety verification. |
| Crash during security state change | One database transaction for manifest history+pin, ratchet+outbox, MLS snapshot+receipt, capability+profile revision | Restart observes either the old state or the complete new state, never a partial transition. |

## Group authority availability

The BFT quorum formula protects safety only when the deployment size can
tolerate a fault. `N=1` is the simple local mode. `N=2` and `N=3` require every
authority and therefore add no failure tolerance. Fault-tolerant choices begin
at `N=4` (`q=3`) and then `N=7` (`q=5`). The administrative UI must show this
availability consequence; it must not market three authorities as redundancy.

Group owners authorize changes to the authority set, group cryptographic or
authorization policy, protocol-suite upgrades, and permanent closure. Routine
member administration remains an administrator action. Ordering servers relay
owner approvals but cannot cast them.

## Recovery and verification rules

Network unavailability is not cryptographic evidence. It retains the last pin
and retries. A valid complete skipped-update chain may clear a temporary gap.
Rollback, equivocation, invalid signature, stable key substitution, or signed
incarnation replacement survives restart as a red quarantine.

Quarantine never clears because a later network request says “healthy.” The
client derives the expected safety payload locally. Only an exact scanned
payload can promote the retained identity or a separately stored replacement
candidate. The comparison binds the two sorted canonical addresses and two
raw authority public keys under `kutup/chat/safety-number/v1`.

## Logging, metrics, and audit

Allowed dimensions are feature, local/federated class, outcome class, action
type and limiter type. Usernames, account/device IDs, capabilities and hashes,
sender certificates, ciphertext, send IDs, and destination sender-recipient
correlations are forbidden in logs, traces, and metric labels.

Implemented instruments include:

- `kutup.chat.policy.events`
- `kutup.chat.sealed_sender.certificate.events`
- `kutup.chat.sealed_sender.send.events`
- `kutup.chat.sealed_sender.send.envelopes`
- `kutup.chat.mls.control.events`
- `kutup.chat.mls.quorum.events`
- `kutup.chat.mls.quorum.available`
- `kutup.chat.mls.quorum.required`
- `kutup.chat.mls.bootstrap.events`
- `kutup.chat.mls.bootstrap.pages`
- `kutup.chat.mls.anonymous_delivery.events`
- `kutup.chat.mls.anonymous_delivery.envelopes`
- `kutup.chat.rate_limit.rejections`

Administrative audit records cover bootstrap, explicit rotation, quarantine,
recovery, wipe, policy change and cryptographic failure. They retain bounded
exact fingerprints/evidence, never secrets or message content.

## Parser and test obligations

Every public policy, manifest, history page, certificate, sealed transaction,
MLS control structure, and anonymous envelope has deterministic vectors,
strict size limits, malformed-input tests and a fuzz entry point. Release gates
also cover restart atomicity, two-server federation, no destination sender
metadata, capability invalidation, no sealed fallback, skipped manifest
recovery, identity replacement quarantine, 256-account groups and the
2,560-leaf hard bound.
