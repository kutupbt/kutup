# `docs/research/`

Forward-looking research, library surveys, and planning notes that inform — but don't replace — the canonical documentation in `docs/`.

Documents in this directory are **exploratory**: they may be opinionated, contradicted by later research, or describe features that don't yet exist. Once a feature ships, the corresponding `docs/` files (`architecture.md`, `api.md`, `self-hosting.md`) become authoritative; the research note here is preserved for posterity.

## Research index

### Collaborative E2EE editing (historical research, May 2026)

This series led to the shipped real-time text, Office, whiteboard, and version
history implementation. It is retained as design and debugging history;
[`../architecture.md`](../architecture.md) and
[`../onlyoffice.md`](../onlyoffice.md) describe the current system.

| File | Topic |
|---|---|
| [`01-cryptpad-collab-stack.md`](./01-cryptpad-collab-stack.md) | How CryptPad implements E2EE collab editing for text/markdown/code. ChainPad CRDT, Netflux signaling, crypto layer, editor binding, persistence model, footguns. |
| [`02-modern-collab-stack-2026.md`](./02-modern-collab-stack-2026.md) | Survey of modern alternatives — Yjs vs Automerge vs Loro, CodeMirror 6 vs ProseMirror vs Tiptap, Hocuspocus vs custom Go relay, the E2EE-Yjs wrapper pattern. Recommends a stack. |
| [`03-version-history-design.md`](./03-version-history-design.md) | Versioning research — Google Drive's actual behavior, CryptPad's checkpoint cadence, SeaweedFS S3 versioning, snapshot+delta patterns from Secsync/Notesnook. Recommends a two-tier model. |
| [`04-office-collab-engines.md`](./04-office-collab-engines.md) | Comparison of office-doc engines — OnlyOffice DS, Collabora Online, LOOL, WebODF, Etherpad, CryptPad. Conclusion: only the CryptPad pattern preserves E2EE. |
| [`05-cryptpad-onlyoffice-integration.md`](./05-cryptpad-onlyoffice-integration.md) | Deepest artifact. Code-grounded map of how CryptPad bundles a forked OnlyOffice client + x2t WASM converter, captures OnlyOffice's native OT ops, wraps them in chainpad, persists checkpoints. With footgun list and implications for kutup. |
| [`07-collab-architecture-comparison.md`](./07-collab-architecture-comparison.md) | Point-in-time comparison used to diagnose the then-open XLSX second-direction synchronization problem; the lock-state implementation later resolved it. |
| [`08-office-cell-formatting-getlock.md`](./08-office-cell-formatting-getlock.md) | Investigation record for the then-open cell-formatting lock failure; the issue is resolved and guarded by Office Playwright specs. |

### Other forward-looking notes

| File | Topic |
|---|---|
| [`06-webdav-support.md`](./06-webdav-support.md) | Future feature: mount kutup as a native filesystem (Finder / Explorer / KIO). Why server-side WebDAV breaks E2EE; why a client-side proxy in the kutup CLI is the only viable path; references to Cryptomator / Filen / rclone precedents. No spec, no committed scope — captured so the idea isn't lost. |
| [`10-admin-password-reset.md`](./10-admin-password-reset.md) | Shipped admin recovery/wipe decision under the E2EE boundary. |
| [`account-protection-wasm-baseline-2026-07-29.md`](./account-protection-wasm-baseline-2026-07-29.md) | Time-stamped Rust/WASM selection measurements for account-protection operations. |
| [`perf-baseline-2026-05-06.md`](./perf-baseline-2026-05-06.md) | Historical Go/frontend performance snapshot; its Go rerun command no longer applies after the Rust cutover. |

### Mobile (work in progress)

| File | Topic |
|---|---|
| [`09-mobile-strategy.md`](./09-mobile-strategy.md) | Historical Tauri-mobile strategy and secure-storage survey. The dedicated native `kutup-ios` and `kutup-android` apps are now separate work in progress; they are not release-ready. See [`../mobile-build.md`](../mobile-build.md). |

### Federated E2EE chat — "ileti" (July 2026)

These files preserve the research trail. They do not describe current
implementation status; [`../chat-protocol.md`](../chat-protocol.md) is
normative and [`../roadmap.md`](../roadmap.md) tracks the remaining product and
hardening slices.

| File | Topic |
|---|---|
| [`11-federated-chat.md`](./11-federated-chat.md) | Original architecture for a Signal-class federated chat feature (libsignal v0.97.2 study, Matrix take-vs-leave, single-443 topology, phased plan). The direct-message and transport-federation foundation it proposed is implemented; its original group-blob direction is superseded by `13-…`. |
| [`12-chat-improvements-for-clients.md`](./12-chat-improvements-for-clients.md) | Historical wire-freeze proposal. Its versioned content schema, `sendId` idempotency, capability block, account-scoped prekey limiting, WS tickets, and shared-core durability boundaries are implemented by the server/core/web stack. |
| [`13-chat-architecture-comparative-research.md`](./13-chat-architecture-comparative-research.md) | **The verdict.** Confirms the dumb mailbox, pinned libsignal, and DAG-free transport federation; changes groups to the GV2 pattern, treats sealed sender as a complete abuse-gated system, requires signed device manifests, and corrects the SPQR parameter. Manifest history/range recovery, federation delivery, durability, encrypted profiles, authenticated remote transparency policy/monitoring, and contacts-only sealed sender are implemented. The document's earlier witness/auditor recommendation is not part of V1. |
| [`14-enterprise-federation-identity.md`](./14-enterprise-federation-identity.md) | Deferred high-assurance profile: configurable threshold domain roots, TUF-style old/new quorum rotation, and per-peer quorums of manually pinned independent authority domains. Preserved for enterprise adoption; the current implementation path intentionally uses single-key TOFU pinning and authenticated rotation. |
