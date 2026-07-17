# Signed transparency checkpoints and independent witnesses

**Status:** implemented and live-verified locally, with an independent witness,
and across two federated servers

## Decision

Kutup promotes the existing append-only manifest log/current sparse map from an
unsigned proof system to authenticated, witnessable checkpoints. Each
homeserver has a dedicated persistent Ed25519 transparency operator identity,
separate from its federation transport identity. Every exact non-empty
`(logId, treeSize, logRoot, mapRoot, issuedAt, operatorKeyId)` statement is
signed once and persisted in the transaction that advances the head.

The protocol carries that stable operator statement and zero or more witness
attestations in every manifest proof. Clients always verify the operator
signature. Application policy may additionally pin the operator identity,
select independent witness identities/keys, and require a quorum. Keys carried
inside the proof do not add trust.

An independent `kutup-transparency-witness` process polls the public checkpoint
endpoint with its own prior tree size, verifies the operator signature and RFC
6962 consistency, signs the exact operator statement, submits it, and advances
its own state only after acceptance. Its signing seed and state must not share
the log-server administrative boundary.

## Implementation slices

1. Add domain-separated operator and witness signature wire records plus a
   public checkpoint/consistency response to `kutup-chat-proto`.
2. Persist operator identity, exact signed heads, and historical witness
   attestations. Reject silent operator replacement, unknown witnesses, and
   same-tree witness contradiction; make exact replay idempotent.
3. Expose public, rate-limited monitor and witness-submission endpoints and
   advertise operator/witness deployment policy in chat capabilities.
4. Persist operator/witness observations in SQLite and IndexedDB. Verify policy,
   quorum, monotonic issuance time, and key continuity atomically with manifest
   trust before any libsignal session mutation.
5. Thread typed transparency policy through WASM and UniFFI. The web client
   constructs its local scope from capabilities; native/static applications can
   provide independently distributed local and remote roots.
6. Ship the witness as a second server-image binary, including a public-key
   derivation mode and an isolated quorum-1 Docker contract harness.

## Threat boundary

This makes a checkpoint attributable and allows an independently trusted
witness to detect append-history forks. It does not make same-origin browser
configuration independent of a compromised server that can replace both the
web application and its advertised policy. It also does not yet compare views
between multiple witnesses. Remote federation scopes without application policy
remain durably first-observation pinned.

Scheduled monitoring of the local web scope is now implemented. The next
transparency work is skipped-update range proofs, authenticated policy
distribution/rotation and monitoring for remote scopes, and cross-witness
gossip or an auditor that compares checkpoint views. Kutup's
username-hash map also intentionally does not claim Signal's VRF index privacy.

## Verification gates

- Protocol tamper, duplicate-witness, inclusion/map, and consistency tests.
- Core fail-closed policy, quorum, rollback, and operator-continuity tests.
- Server tests and strict clippy for all targets; native FFI smoke and web
  TypeScript/capability tests.
- Production WASM/frontend Docker build and live HTTPS chat contract.
- Isolated quorum-1 operator + witness live contract.
- Two-server federation setup, offline queue, origin restart, and retry contract
  with distinct transparency operator keys.
