# Authenticated current-manifest map

**Status:** implemented and live-verified

## Decision

Kutup adds the missing current-value property without pretending the public
Signal repositories contain a deployable Signal KT backend. Signal-Server is a
proxy to a separate service; public `libsignal-keytrans` contains client proof
verification, VRF public-key logic, distinguished heads, and monitoring state,
but not the proof-producing service.

The Kutup server therefore maintains a domain-separated 256-level sparse
Merkle map from canonical local username to the current signed manifest
version/hash and account authority id. Only non-empty nodes are stored.
Compressed membership proofs omit deterministic empty siblings.

Every new map root is hashed as a typed map-checkpoint leaf and appended as the
final leaf of the existing RFC 6962 chronological log in the same database
transaction as manifest publication. A client accepts the served manifest only
after verifying all of:

- the account signature and exact device set;
- inclusion of the manifest event in the chronological log;
- sparse-map membership of that same manifest value;
- inclusion of the map-root commitment as the checkpoint's final leaf;
- consistency from the client's durable homeserver checkpoint;
- a stable per-account event position for an unchanged value, or a strictly
  increasing position for an update.

Migration 029 builds the current sparse map from existing signed manifests and
appends its first map-root commitment to the existing log. This lets a client
verify continuity across the upgrade instead of resetting its prior log pin.

## Explicit non-goals

- This is not wire-compatible with Signal's missing private KT service.
- The SHA-256 map key does not claim Signal's VRF index-privacy property.
- A server can still create two internally consistent log+map forks until
  checkpoints are independently audited, witnessed, or gossiped.
- A multi-version offline jump remains visibly marked as a continuity gap until
  range monitoring proves every skipped update.
