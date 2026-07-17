# Scheduled web transparency monitoring

**Status:** implemented; static/adversarial, production WASM/web, and live
Chromium chat E2E verification pass

## Decision

The browser must not learn about transparency checkpoints only when it happens
to start a new session. Kutup therefore adds an independent monitor operation
to the shared engine and schedules it from the web client for the authenticated
`local` homeserver scope.

The operation fetches the public checkpoint with the engine's highest durable
tree size, verifies the same operator policy, witness quorum, exact signature,
and RFC 6962 consistency used by bundle acceptance, and atomically advances the
existing trust pin with a durable monitor status. It never consumes prekeys or
mutates a peer manifest/libsignal session.

## Status semantics

- `healthy`: the returned head verified; store the head and success time.
- `unavailable`: the endpoint/network failed; retain the last valid head and
  success time, warn the user, but do not call this evidence of compromise.
- `verificationFailed`: authentication, consistency, policy, or quorum failed;
  retain the last valid head, persist the failure across restart, show a
  security banner, and block creation of new sends until a later valid monitor
  response verifies. Existing durable ciphertext may still retry.

The web service polls on open, browser-online, visible foreground return,
WebSocket reconnect, and every 15 minutes while visible. Cross-tab Web Locks
serialize the monitor with all other engine/database operations.

## Boundary and follow-up

This slice intentionally monitors only `local`. Browsers cannot safely fetch an
arbitrary remote homeserver directly and do not yet possess authenticated
remote operator/witness policy. The next slice distributes remote policy with
an explicit rotation chain and adds a same-origin authenticated federation
monitor proxy. Skipped-update range proofs and cross-witness view comparison
remain separate follow-up work.

## Verification gates

- Valid head advances and persists across SQLite restart.
- Network failure preserves the last success and is not mislabeled.
- Missing witness quorum and tampered operator signature persist a verification
  failure without advancing trust.
- A durable verification failure blocks a new send before bundle fetch.
- A later valid response recovers the monitor state.
- Browser transport keeps the `u64` cursor as a decimal string and rejects a
  remote scope until authenticated remote monitoring exists.
- Strict Rust/TypeScript tests, production WASM/frontend build, and live HTTPS
  checkpoint monitoring.
