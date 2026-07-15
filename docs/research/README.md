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
| [`11-federated-chat.md`](./11-federated-chat.md) | Original architecture for a Signal-class federated chat feature (libsignal v0.97.2 study, Matrix take-vs-leave, single-443 topology, phased plan). **Partly superseded by `13-…`** — see the banner at its top for the three changed decisions. |
| [`12-chat-improvements-for-clients.md`](./12-chat-improvements-for-clients.md) | Wire-contract fixes to lock in before the three clients (web/wasm, Android, iOS) freeze against the chat protocol: a versioned inner **content schema** (the plaintext inside libsignal envelopes) with a `kind` registry, send **idempotency** (`sendId`), a chat **capability block** in `/api/auth/settings`, per-account (not per-IP) prekey rate limiting, WS tickets, and the `kutup-chat-core` engine shape (transport/db ports, engine-owned invariants, durable outbox, single event stream, federation-ready address type, golden fixtures shared by native+wasm CI). |
| [`13-chat-architecture-comparative-research.md`](./13-chat-architecture-comparative-research.md) | **The verdict.** Adversarially-verified comparison against Signal, Matrix, and XMPP (Prosody/ejabberd) + read-only study of local `libsignal`/Prosody/ejabberd/Monal checkouts. Confirms the core (dumb mailbox, pinned libsignal, DAG-free federation — the last CVE-backed) and pins **four changes**: groups → GV2 pattern (not client blobs — Signal's abandoned 2014 design); sealed sender as a 3-part system; **device-list authenticity as a v1 requirement** (else the Matrix/Megolm malicious-homeserver break applies); ratchet is ML-KEM-768 not 1024. Plus adopt-verbatim mechanisms for federation delivery (durable in-order retry + sequence gaps; X-Matrix signing), mailbox paging/prekey lifecycle (from XMPP), and the iOS engine model (from Monal: NSE-as-same-engine, content-free push, persist-before-send, catchup-vs-live state, single `idle` predicate). Consolidated keep/change/add table + open questions. |
