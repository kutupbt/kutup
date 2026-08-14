# Chat media security threat model

**Status:** normative for V1 Chat media

This document extends `chat-security-threat-model.md` for immutable attachment
objects, destination persistence, encrypted attachment ledgers and quota
accounting. It assumes Direct Chat, MLS, account manifests, sealed delivery and
unified federation are already valid; it does not replace their verification.
The independently outer-encrypted history-media lifecycle is covered by
`chat-backup-security-threat-model.md`.

## Assets and trust boundaries

- Attachment plaintext, key, filename, MIME type, caption, dimensions,
  duration, preview, message ID and conversation association are client-only.
- The authenticated origin server knows its local sender and intended
  recipients so it can enforce quota and retry federation.
- A destination server knows origin domain, local recipient, opaque attachment
  ID, ciphertext size, timing and delivery outcome. It must not receive or
  persist sender identity or private media metadata.
- Object storage sees opaque paths, ciphertext length and access timing.
- The encrypted account ledger is untrusted storage. Its server-visible fields
  are insufficient to calculate a named per-chat total.
- Recipient quota accounting is server-authoritative because the server bears
  the storage cost. Client-decrypted category presentation is not trusted for
  admission.

## Threats and required outcomes

| Threat | Control | Outcome |
|---|---|---|
| Server substitutes or relocates a blob | Typed header, UUID-bound HKDF/AAD, complete digest and final-frame verification | Recipient rejects before plaintext release. |
| Truncation, reordering, duplication or trailing bytes | Secretstream tags, fixed frame bounds and mandatory final frame | Decryption fails closed. |
| Malicious filename/MIME/preview | Encrypted metadata is treated as untrusted presentation input; bounded sanitization and decoder isolation | No path traversal, script execution or unbounded decode. |
| Client-provided remote URL/SSRF | Descriptor carries a canonical domain and opaque token, never a URL; own homeserver uses unified federation resolution | Arbitrary hosts and rebinding targets are never fetched. |
| Stolen retrieval token | Recipient, destination, object digest and expiry binding; contacts/group capability; constant-time verifier | Token cannot be moved to another recipient/domain/object. |
| Anonymous storage exhaustion | No message-request fetch before acceptance, dedicated Chat-quota reservation, capability/origin/IP limits and 2 GiB object ceiling | Unknown senders cannot allocate media; established abuse is bounded. |
| Temporary retention removes protected media | Separate ordinary-delivery and history-media references/namespaces | The delivery sweep releases only ordinary copies; committed protected media remains lazily recoverable. |
| Quota race or crash | Row locks plus one transaction for reservation/ref/quota; stale temporary-object sweep | No overcommit, leak or partial logical ownership. |
| Retry changes content | Idempotent operation ID bound to suite/UUID/digest/length/recipient/destination | Exact retry succeeds; changed replay conflicts permanently. |
| Origin disappears after delivery | Destination verifies and durably commits its own copy before acknowledgement | Received media remains available. |
| Destination falsely acknowledges | Sender cannot cryptographically force storage; signed acknowledgement is attributable and operationally auditable | Availability failure is visible; confidentiality remains. |
| Destination correlates sealed sender | Sender-free offer/ref/mailbox schema and identifier-free logs/metrics | Destination learns no sender identity from the media protocol. |
| Ledger server reads chat usage | Purpose-specific E2EE ledger and local projection | Only total opaque byte accounting is server-visible. |
| Ledger rollback or overwrite | Per-entity revision/predecessor digest, idempotent operations and durable client pins | Observed rollback/conflict is rejected; withholding warns. |
| Compromised linked device corrupts ledger | Account-authenticated device write plus exact revision; device remains an authorized account endpoint | It can alter the user's private index, as it can alter other account state; revoke the device to stop future writes. |
| Clear one recipient deletes others | Per-recipient references and transactional refcount | Only the requesting account loses access/quota. |
| Save-to-Drive rebinds ciphertext | Client decrypts and re-encrypts under a new Drive file/collection/epoch header | Server cannot promote by metadata substitution. |
| Delete-for-everyone promises revocation | UI states deletion is best effort after delivery; saved/decrypted copies cannot be revoked | No false cryptographic erasure claim. |
| Oversized decompression/image/video bomb | Ciphertext and plaintext-class caps plus bounded client decoders | Resource use is bounded; malformed media does not affect crypto state. |

## Abuse defaults

- V1 object ceiling: 2 GiB plaintext-class content plus exact suite overhead.
- Message requests: descriptor only; origin retention at most 30 days.
- Concurrent upload, destination-fetch and per-origin transfer counts are
  database-backed and administrator configurable.
- A destination storage-full response is authenticated and typed. Anonymous
  probes retain uniform not-found behavior.
- No raw capability, digest, object UUID, account, filename, MIME type,
  conversation or sender-recipient pair is a metric label.

## Residual metadata

V1 does not hide origin/destination domains, recipient account at its own
server, ciphertext length, transfer timing, retention duration, group local
fan-out or whether two local recipient references share one physical object.
The optional traffic-inspection-protection milestone may pad sizes/timing; it
does not change this protocol's authorization or storage semantics.

## Verification obligations

Security tests must cover hostile origin and destination servers, invalid
capabilities, token replay, concurrent quota reservations, object replacement,
stream truncation/trailing frames, database failure after object upload,
object-store failure after reservation, refcount races, ledger rollback,
message-request storage attempts, linked-device rebuild and destination log
privacy. Production advertisement requires the two-server browser scenario in
`chat-media.md` section 10.
