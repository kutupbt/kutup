# Kutup documentation

This directory contains current product documentation, normative protocol and
security contracts, operations guides, implementation records, and historical
research. The running code, embedded database migrations, generated OpenAPI
document, and required CI workflow are authoritative when a historical record
disagrees with current behavior.

## Start here

| Need | Document |
|---|---|
| Feature overview and first Compose start | [`../README.md`](../README.md) |
| Production deployment, TLS, quotas, retention, and backups | [`self-hosting.md`](self-hosting.md) |
| System boundaries, keys, storage, and federation | [`architecture.md`](architecture.md) |
| HTTP operations and payloads | [`api.md`](api.md) and `GET /api-docs/openapi.json` |
| Local development and required test gates | [`contributing.md`](contributing.md) and [`../tests/e2e/README.md`](../tests/e2e/README.md) |
| Remaining release work | [`roadmap.md`](roadmap.md) |

## Current protocol and security references

| Area | Protocol/current state | Threat model or policy |
|---|---|---|
| Drive and collaboration | [`architecture.md`](architecture.md), [`v1-format-inventory.md`](v1-format-inventory.md) | [`drive-security-threat-model.md`](drive-security-threat-model.md) |
| Unified Drive/Chat federation | [`federation-protocol.md`](federation-protocol.md) | Federation sections in the Drive and Chat threat models |
| Direct Chat and Note to Self | [`chat-protocol.md`](chat-protocol.md) | [`chat-security-threat-model.md`](chat-security-threat-model.md) |
| Private MLS groups | [`chat-mls.md`](chat-mls.md) | [`chat-security-threat-model.md`](chat-security-threat-model.md) |
| Chat media | [`chat-media.md`](chat-media.md) | [`chat-media-security-threat-model.md`](chat-media-security-threat-model.md) |
| Continuous Chat recovery | [`chat-backup.md`](chat-backup.md) | [`chat-backup-security-threat-model.md`](chat-backup-security-threat-model.md) |
| Crypto ownership and upgrades | [`cryptographic-dependencies.md`](cryptographic-dependencies.md), [`crypto-agility.md`](crypto-agility.md) | Purpose-specific threat models above |
| Confidential broadcast | Architecture sections in the format inventory and roadmap | [`broadcast-security-threat-model.md`](broadcast-security-threat-model.md) |

## Clients and integrations

- [`desktop-build.md`](desktop-build.md) documents the Tauri desktop shell.
- [`mobile-build.md`](mobile-build.md) documents the native iOS/Android work in
  progress and the experimental Tauri-mobile path retained in this repository.
- [`chat-native-bindings.md`](chat-native-bindings.md) documents the shared
  Rust/UniFFI Chat boundary being integrated by the native mobile clients.
- [`onlyoffice.md`](onlyoffice.md) documents client-only Office editing and the
  digest-pinned asset bundle.

## How to read document status

- Files directly under `docs/` are living current-state or normative documents
  unless their introduction explicitly says otherwise.
- `docs/plans/` records delivery plans and their completion evidence. A
  completed plan is not the current protocol contract; follow its primary
  reference links.
- `docs/research/` preserves time-stamped investigations and alternatives.
  Conclusions may be superseded after the captured date.
- `docs/draft/` contains proposals and external review inputs. These are not
  accepted requirements unless a current normative document adopts them.
- `docs/superpowers/` and `docs/rust-conversion/` are implementation history.
  Their old paths, branches, and pre-cutover baselines are deliberately
  preserved behind historical-status notices.

Third-party licensing and trademark documents are legal records, not product
status pages; do not rewrite them merely to mirror feature terminology.
