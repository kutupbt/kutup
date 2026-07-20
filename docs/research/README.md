# `docs/research/`

Forward-looking research, library surveys, and planning notes that inform — but don't replace — the canonical documentation in `docs/`.

Documents in this directory are **exploratory**: they may be opinionated, contradicted by later research, or describe features that don't yet exist. Once a feature ships, the corresponding `docs/` files (`architecture.md`, `api.md`, `self-hosting.md`) become authoritative; the research note here is preserved for posterity.

## Current research notes

### Collaborative E2EE editing (in progress, May 2026)

A planned major feature: real-time collaborative editing of files inside kutup, end-to-end encrypted, where the editor opens in place when the user clicks a `.txt`/`.md`/code/office file.

| File | Topic |
|---|---|
| [`01-cryptpad-collab-stack.md`](./01-cryptpad-collab-stack.md) | How CryptPad implements E2EE collab editing for text/markdown/code. ChainPad CRDT, Netflux signaling, crypto layer, editor binding, persistence model, footguns. |
| [`02-modern-collab-stack-2026.md`](./02-modern-collab-stack-2026.md) | Survey of modern alternatives — Yjs vs Automerge vs Loro, CodeMirror 6 vs ProseMirror vs Tiptap, Hocuspocus vs custom Go relay, the E2EE-Yjs wrapper pattern. Recommends a stack. |
| [`03-version-history-design.md`](./03-version-history-design.md) | Versioning research — Google Drive's actual behavior, CryptPad's checkpoint cadence, SeaweedFS S3 versioning, snapshot+delta patterns from Secsync/Notesnook. Recommends a two-tier model. |
| [`04-office-collab-engines.md`](./04-office-collab-engines.md) | Comparison of office-doc engines — OnlyOffice DS, Collabora Online, LOOL, WebODF, Etherpad, CryptPad. Conclusion: only the CryptPad pattern preserves E2EE. |
| [`05-cryptpad-onlyoffice-integration.md`](./05-cryptpad-onlyoffice-integration.md) | Deepest artifact. Code-grounded map of how CryptPad bundles a forked OnlyOffice client + x2t WASM converter, captures OnlyOffice's native OT ops, wraps them in chainpad, persists checkpoints. With footgun list and implications for kutup. |

### Other forward-looking notes

| File | Topic |
|---|---|
| [`06-webdav-support.md`](./06-webdav-support.md) | Future feature: mount kutup as a native filesystem (Finder / Explorer / KIO). Why server-side WebDAV breaks E2EE; why a client-side proxy in the kutup CLI is the only viable path; references to Cryptomator / Filen / rclone precedents. No spec, no committed scope — captured so the idea isn't lost. |

### Mobile (in progress, May 2026)

| File | Topic |
|---|---|
| [`09-mobile-strategy.md`](./09-mobile-strategy.md) | Why we're on Tauri-mobile (not React Native or Capacitor) given the DOM-bound editor stack — with prior-art table (Spacedrive, OneKeePass, Padloc). Survey of Tauri-mobile secure-storage plugins for the Android Keystore follow-up — recommends `tauri-plugin-keystore` + `tauri-plugin-biometric`. iOS half shipped (`feat/ios-keychain`); Android half is the open follow-up. |

### Federated E2EE chat — "ileti" (July 2026)

These files preserve the research trail. They do not describe current
implementation status; [`../chat-protocol.md`](../chat-protocol.md) is
normative and [`../roadmap.md`](../roadmap.md) tracks the remaining product and
hardening slices.

| File | Topic |
|---|---|
| [`11-federated-chat.md`](./11-federated-chat.md) | Original architecture for a Signal-class federated chat feature (libsignal v0.97.2 study, Matrix take-vs-leave, single-443 topology, phased plan). The direct-message and transport-federation foundation it proposed is implemented; its original group-blob direction is superseded by `13-…`. |
| [`12-chat-improvements-for-clients.md`](./12-chat-improvements-for-clients.md) | Historical wire-freeze proposal. Its versioned content schema, `sendId` idempotency, capability block, account-scoped prekey limiting, WS tickets, and shared-core durability boundaries are implemented by the server/core/web stack. |
| [`13-chat-architecture-comparative-research.md`](./13-chat-architecture-comparative-research.md) | **The verdict.** Confirms the dumb mailbox, pinned libsignal, and DAG-free transport federation; changes groups to the GV2 pattern, treats sealed sender as a complete abuse-gated system, requires signed device manifests, and corrects the SPQR parameter. The manifest, federation-delivery, durability, encrypted-profile, transparency, and witness recommendations are implemented; groups, sealed sender, richer messaging/media, remote policy, and native integration remain. |
| [`14-enterprise-federation-identity.md`](./14-enterprise-federation-identity.md) | Deferred high-assurance profile: configurable threshold domain roots, TUF-style old/new quorum rotation, and per-peer quorums of manually pinned independent authority domains. Preserved for enterprise adoption; the current implementation path intentionally uses single-key TOFU pinning and authenticated rotation. |
