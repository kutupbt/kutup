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

| File | Topic |
|---|---|
| [`11-federated-chat.md`](./11-federated-chat.md) | Architecture for a Signal-class federated chat feature. Code-grounded study of libsignal v0.97.2 (PQXDH behind the `Handshake` trait, Triple Ratchet + SPQR, sender keys, sealed sender, key transparency, the no-negotiation algorithm-agility mechanics). Matrix take-vs-leave analysis (keep `.well-known` + signed s2s over 443; reject the replicated room DAG). Recommends: libsignal as a pinned dependency, transport-only federation via per-device mailboxes, media in the existing E2EE drive, SNI-demuxed single-port 443 incl. TURN for calls, PQ always-on with a versioned suite registry (never a user downgrade toggle). Phased plan; phase 1 is a libsignal-on-wasm go/no-go spike. |
