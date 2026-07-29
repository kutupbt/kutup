# V1 external review comments

This directory preserves third-party and AI-generated review comments that may
inform Kutup V1.

Files here are **review inputs, not accepted designs, normative protocol
documents, security audits, or security endorsements**. Preserve the original
claims and recommendations so they can be checked against the implementation.
Record Kutup's accepted, modified, rejected, and deferred decisions separately
in `docs/draft/v1/`.

Each comment should identify:

- when it was recorded;
- its source category;
- whether it is verbatim or summarized; and
- the decision document that eventually resolves it, when one exists.

## Recorded comments

- [`2026-07-29-chat-mls-review.md`](2026-07-29-chat-mls-review.md) — account
  KDF documentation, MLS authority availability, ciphersuite, scale, PQ, and
  operational-review comments.
- [`2026-07-29-drive-chat-deep-review.md`](2026-07-29-drive-chat-deep-review.md)
  — Drive trust/crypto, account protection, Chat metadata, MLS scaling, and
  deferred broadcast comments.
- [`2026-07-29-drive-chat-deep-review-follow-up.md`](2026-07-29-drive-chat-deep-review-follow-up.md)
  — corrections to the Drive review, common account-identity reuse, KDF
  sequencing, and the proposal to make a minimal Drive V2 a V1 release gate.
- [`2026-07-29-primitive-palette-and-wasm-review.md`](2026-07-29-primitive-palette-and-wasm-review.md)
  — minimal Kutup-owned primitive palette, separate registries, shared
  implementation machinery, and Drive Rust-to-WASM consolidation comments.
- [`2026-07-29-v1-drive-program-review.md`](2026-07-29-v1-drive-program-review.md)
  — mechanism-level additions to the proposed V1 Drive program, including
  authenticated collection epochs, MLS suite interoperability, one transparency
  log, and migration ordering.
- [`2026-07-29-release-gate-account-authority-and-witness-bootstrap-review.md`](2026-07-29-release-gate-account-authority-and-witness-bootstrap-review.md)
  — the pre-tag one-way-door test, account self-authority derivation-label
  consequences, first-contact witness bootstrap, Rust-to-WASM sequencing, and
  threat-model ordering.
- [`2026-07-29-drive-format-wasm-and-epoch-review.md`](2026-07-29-drive-format-wasm-and-epoch-review.md)
  — Drive format inventory, quantitative Rust-to-WASM gates, and reuse of
  authenticated continuity machinery for collection epochs.
- [`2026-07-29-trust-ladder-account-manifest-and-wipe-review.md`](2026-07-29-trust-ladder-account-manifest-and-wipe-review.md)
  — behavioral trust floors, the pre-tag boundary, account/device manifest
  lifetimes, and destructive account-wipe discontinuity.
- [`2026-07-29-external-review-and-self-hosted-witness-review.md`](2026-07-29-external-review-and-self-hosted-witness-review.md)
  — independent cryptographic review and the operational limits of witnesses
  for small self-hosted deployments.

Current maintainer triage and accepted/deferred decisions:
[`../security-review-follow-ups.md`](../security-review-follow-ups.md).
