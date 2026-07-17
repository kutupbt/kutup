# Federated manifest key-transparency foundation

**Status:** append-only log and authenticated current map implemented;
periodic/range monitoring and witness/gossip follow-up remains

## Decision

Kutup adopts the trust boundary visible in the current Signal code without
pretending Signal's deployment can be copied wholesale. Signal-Server proxies
unauthenticated search/monitor/distinguished requests to a separate KT service;
Android and iOS persist verified tree heads and per-account monitoring state in
the client. Signal's open `libsignal-keytrans` is the verifier, not the missing
self-hostable service implementation.

For Kutup's federated deployments, phase one is a homeserver-owned RFC
6962-style manifest log:

- append the exact signed account manifest identity in the publication
  transaction;
- store complete Merkle subtrees for logarithmic appends and proofs;
- carry inclusion and consistency proofs atomically with local/federated bundle
  responses;
- persist one highest checkpoint per homeserver in the shared client database;
- verify proof + signed manifest before libsignal session mutation;
- backfill the current manifest of pre-existing accounts when an empty new log
  is first initialized.

The browser passes its known tree size as a decimal string to avoid JavaScript
`u64` truncation. Federation includes the query in the destination-bound signed
URI, and remote servers return their own proof unchanged.

## Threat boundary

This slice detects rollback, same-size root changes, changed log identity,
omission, corrupt inclusion, and append-history rewriting for returning clients.
An inclusion proof only establishes that a manifest occurs in the history; it
does not establish to a first-contact client that the leaf is the account's
current manifest. It also does not detect two internally consistent forks shown
to clients that have never exchanged checkpoints. Calling that complete key
transparency would be misleading.

The authenticated current map now proves that the served manifest is the value
in the operator's presented checkpoint, and clients persist a per-account event
position for update/non-update monitoring. Remaining work is periodic self
checks plus skipped-update/range proofs, then independent auditing/checkpoint
witnessing or encrypted checkpoint gossip. Only the external consistency layer
can replace first-contact TOFU and claim split-view resistance. Safety-number
verification remains available throughout.

## Validation gates

- exhaustive small-tree inclusion/consistency proof tests;
- adversarial missing/tampered proof tests in the shared engine;
- durable SQLite/IndexedDB checkpoint storage;
- local live test that grows the log and verifies non-trivial consistency;
- two-server live test that verifies remote proof passthrough and growth;
- full Rust tests/clippy, production WASM, TypeScript/Vitest, web build, and
  Docker live contract.
