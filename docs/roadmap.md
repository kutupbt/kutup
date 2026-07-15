# Production-readiness roadmap

Kutup is **pre-production**: there is no public release yet (until the first `v*` / `desktop-v*` git tag — see CLAUDE.md). This document is the canonical list of everything between today and "ready to tag v1".

It is the bridge between `docs/` (current state, authoritative) and `docs/research/` (forward-looking design notes that may never ship). Items here are committed work — we know we want them; they're scoped, just not built yet.

**When a feature lands**, move it out of this file and update the appropriate `docs/*.md`. The roadmap should always describe the gap to v1, not the past.

---

## What "production-ready" means for kutup

The bar for the first `v*` tag:

1. **No silent stubs in admin-facing UI.** Every clickable action that exists in the UI must work end-to-end. No "wire-up pending" toasts in shipped builds.
2. **Deletion is recoverable.** ✅ Shipped: owner-scoped trash with restore + permanent delete, and an hourly retention sweeper (`TRASH_RETENTION_DAYS`, default 30). See `docs/api.md` → Trash.
3. **Self-hosters can recover broken users without SSH.** ✅ Shipped: force-disable 2FA (lost authenticator), re-enable account (accidental disable), rotate temp password (first-login accounts), and the destructive wipe for users who lost both password and recovery phrase — all from the admin UI on desktop + mobile. `docs/research/10-admin-password-reset.md` records why "reset password" is two actions under E2EE.
4. **Builds are signed.** Unsigned binaries trigger macOS Gatekeeper and Windows SmartScreen warnings that look like malware to non-technical users.
5. **Admin actions leave an audit trail.** ✅ Shipped: every mutating admin endpoint writes an `admin_audit_log` row; `GET /admin/activity` serves the feed and the Recent-activity cards render it on desktop + mobile Admin Overview. See `docs/api.md` → Admin.
6. **Basic abuse protection.** ✅ Shipped: per-IP limits on login/preflight/register/recovery/federation/admin (env-overridable `RATE_LIMIT_*`), per-account login lockout (`LOGIN_LOCKOUT_*`), per-token TOTP blocking, and proxy-aware client-IP resolution (X-Real-IP). See `docs/self-hosting.md`.
7. **Documentation tracks reality.** ✅ Shipped: full docs sweep against the shipped code (stale Go-stack references scrubbed, env vars + endpoints verified), and every HTTP operation is annotated with `#[utoipa::path]` so `GET /api-docs/openapi.json` lists the complete API (a coverage test in `openapi.rs` keeps it honest). Interactive Swagger UI remains deferred (see below).

Items below are organized by **whether they block v1** vs. whether they can ship in a subsequent release.

---

## Blockers for v1 (must-have)

### Signed builds

CLAUDE.md explicitly notes: **"Builds are currently unsigned."** macOS Gatekeeper and Windows SmartScreen treat unsigned `.dmg` / `.msi` as untrusted; non-technical users see scary warnings.

| What's needed | Where |
|---|---|
| Apple Developer ID for macOS signing + notarization | external — requires Apple Developer Program ($99/yr) |
| Microsoft Authenticode certificate for Windows | external — DigiCert / Sectigo (~$300/yr) |
| `.github/workflows/release-desktop.yml` — accept signing secrets, run `codesign` (mac) + `signtool` (win) | repo |
| iOS distribution: TestFlight + App Store Connect setup | external |
| iOS App Store icon: re-render with a non-transparent background (`pnpm tauri:icon src-tauri/icons/source.png --ios-color <hex>`) — App Store Connect rejects transparent / alpha-channel app icons at submission | `package.json` + `src-tauri/icons/` |
| Android: Play Store key + Play Console | external |
| Documentation: `docs/release-signing.md` covering how to rotate keys | new doc |

---

## Important (should-have, can ship after v1)

These aren't blockers — kutup can release without them — but they're real production gaps and should land in v1.1 or shortly after.

### SMTP integration

Without SMTP, kutup can't:
- Send welcome emails (we cut the "Send welcome email" toggle from the admin create-user dialog because there's no flow)
- Send password-reset links (admins currently share temp passwords out-of-band)
- Send share notifications ("Maya shared a folder with you")

| What's needed | Where |
|---|---|
| Backend: SMTP client + env-var config (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`) | `crates/kutup-server/src/email.rs` (new) |
| Backend: template system for welcome / reset / share emails (HTML + plaintext) | `crates/kutup-server/templates/email/` |
| Frontend: re-enable the "Send welcome email" toggle in `AdminCreateUserDialog` (currently dropped) | `frontend/src/components/admin/AdminCreateUserDialog.tsx` |
| Documentation: `docs/email.md` setup guide | new |

### Admin · System status endpoint

The desktop Admin Overview's System card is hidden today because the backend doesn't expose uptime, TLS expiry, or the public URL. Useful for self-hosters at a glance.

| What's needed | Where |
|---|---|
| Backend: `GET /admin/system` returning `{ uptime, tlsExpiry, publicURL, version }` | new handler |
| Backend: track process start time, parse cert expiry from TLS config | service-level |
| Frontend: unhide the System card on `AdminOverviewTab` | `frontend/src/components/admin/AdminOverviewTab.tsx` |

### Admin · Server-driven required-2FA + default-quota + trash-retention settings

`/admin/settings` exposes only `registrationEnabled` today. The admin Settings page on both mobile and desktop hides the Defaults / Security / Danger zone cards because we can't honestly render them.

| What's needed | Where |
|---|---|
| Backend: extend `admin_settings` JSON to include `require_2fa_users`, `require_2fa_admins`, `default_quota_bytes`, `trash_retention_days` | `crates/kutup-server/src/handlers/admin.rs` |
| Backend: enforce `require_2fa_users` on next sign-in (force-set TOTP within N days or block) | `crates/kutup-server/src/handlers/auth.rs` |
| Backend: apply `default_quota_bytes` when creating new users | `crates/kutup-server/src/handlers/admin.rs` |
| Frontend: unhide the three cards in `AdminSettingsTab` | `frontend/src/components/admin/AdminSettingsTab.tsx`, mobile equivalent |

### Admin · Danger-zone actions

The design has "Re-index search" and "Purge soft-deleted files now" in a Settings → Danger zone card. Both hidden today.

| What's needed | Where |
|---|---|
| Backend: `POST /admin/actions/reindex-search` (kicks off the encrypted-search reindex) | new |
| Backend: `POST /admin/actions/purge-trash` (forces the trash retention sweeper — `jobs::trash_sweep_once` — to run now) | new |
| Frontend: unhide the danger zone card | both admin Settings tabs |

### Mobile · Android Keychain

iOS keychain ships (PR 22). Android still re-logs the user in on every app launch.

| What's needed | Where |
|---|---|
| Tauri plugin — `tauri-plugin-keystore` (Android Keystore) | `src-tauri/Cargo.toml`, `src-tauri/src/lib.rs` |
| Optional: `tauri-plugin-biometric` for biometric unlock | same |
| Frontend: detect Android in `restoreSession` and route through the keystore plugin | `frontend/src/lib/restoreSession.ts`, `sessionVault.ts` |
| Test: build + verify session survives app restart on Android | manual |

Survey + recommendation already exists at `docs/research/09-mobile-strategy.md`.

### Mobile · Selection mode (PR 9)

Per the design + user direction: long-press / "Select" button on mobile turns the page into Google-Drive-style full-screen takeover with checkboxes, top "Cancel · N selected · Select all" bar, bottom action bar (Share / Move / Delete / More).

Desktop selection is **explicitly carved out** — kutup keeps its existing no-layout-shift selection pattern there.

| What's needed | Where |
|---|---|
| Frontend: selection state in MobileShell or a context | `frontend/src/components/mobile/` |
| Frontend: row checkboxes on FolderTile + FileListRow when selection mode is on | mobile components |
| Frontend: replace MobileBottomNav with a selection action bar while active | shell |
| Frontend: replace MobilePageHeader with the selection top bar while active | shell |

### Mobile · Files chip filters + List⇄Grid + swipe (PR 3)

Today the Files tab shows category chips (All / Recent / Photos / Documents / PDFs / Audio) but they're visual-only. Same for the List/Grid toggle.

| What's needed | Where |
|---|---|
| Frontend: wire chip filters to filter the rendered items | `frontend/src/pages/mobile/MobileFilesPage.tsx` |
| Frontend: List vs Grid toggle with localStorage persistence | same |
| Frontend: iOS-style swipe-to-share / swipe-to-delete on file rows | new |

### Mobile · Page transitions (PR 4)

Sub-pages currently appear / disappear instantly. iOS users notice the missing slide-in / slide-out.

| What's needed | Where |
|---|---|
| Frontend: a thin `<RouteTransition />` wrapper that animates push (left → right) and pop (right → left) | `frontend/src/components/mobile/` |

### Mobile · Recently-shared-by-me (PR 5)

The Shared tab has an empty hero for this section. Data is derivable from the shares table; just needs wiring.

### Mobile · Viewer touch tweaks (PR 8)

Excalidraw / photo / PDF viewers work on mobile but some tap targets are desktop-sized + the top status bar overlaps content in places. **Carve-out**: the viewers themselves are NOT redesigned (user said they're "clean and useful"). Just touch + safe-area tweaks.

### Mobile · Push notifications

iOS notifications for shared-file events ("Maya shared a folder with you"). Not v1.

| What's needed | Where |
|---|---|
| Apple Push Notification Service setup | external |
| Backend: APNS sender + per-user device-token registry | new |
| Tauri: `tauri-plugin-notification` integration | `src-tauri/` |

### Recovery-phrase verification on mobile

The mobile Encryption Keys page renders the recovery phrase. There's no "verify you wrote it down" word-by-word test like the desktop has during onboarding. Production self-hosters lose users to "I lost my recovery phrase" support tickets.

### Backup / restore CLI

Self-hosters need an easy way to back up + restore the full encrypted dataset (DB + S3 blobs). The Rust CLI exists (`crates/kutup-cli`); adding `kutup backup` / `kutup restore` subcommands is mostly tooling around `pg_dump` + `mc mirror`.

---

## Post-v1 major track · Federated E2EE chat ("ileti")

A Signal-class chat feature — 1:1 + group text, media, voice/video — federated between kutup instances, E2EE on the Signal protocol, media stored in the user's existing E2EE drive, everything (client *and* server, including calls) on port 443 only. Chat UI at its own domain (e.g. `ileti.` vs `depo.` for the drive) but the same backend binary and port.

The full architecture is captured in `docs/research/11-federated-chat.md` (libsignal v0.97.2 study, Matrix take-vs-leave, single-443 topology, risks), the wire-contract fixes in `docs/research/12-chat-improvements-for-clients.md`, and — decisively — the adversarially-verified comparative study `docs/research/13-chat-architecture-comparative-research.md` (Signal/Matrix/XMPP + local libsignal/Prosody/ejabberd/Monal code). Direction is committed and validated. **Locked decisions:** libsignal-protocol as a pinned wrapped dependency (AGPL-compatible, never reimplement the ratchet); transport-only federation (signed s2s over 443 + `.well-known`, no Matrix-style replicated room state — the DAG is CVE-confirmed as the mistake); PQ (PQXDH + SPQR) always-on with a versioned suite registry, algorithm agility as a protocol mechanism **not** a user downgrade toggle.

The normative wire contract the three clients freeze against is **`docs/chat-protocol.md`** (v1) — it consolidates the wire-affecting decisions from `11-`/`12-`/`13-` into one spec, tagging every field **[IMPL]** (phase-2 server, frozen), **[ADD]** (additive, phase-2b), or **[RSV]** (reserved now, implemented later so it's not a breaking migration). Implement against that.

**Changes from the comparative study (read `13-…` before implementing phase 2b+):** groups move to the **GV2 pattern** (server-held *encrypted, versioned* authoritative state + signed membership manifest, sender keys for fan-out) — **not** client-managed blobs (Signal's abandoned 2014 design); **device-list authenticity** (a signed per-account device manifest / cross-signing) becomes a **v1 wire-contract requirement**, not deferred research, because server-assigned device lists otherwise reproduce the malicious-homeserver break that defeated Matrix/Megolm; **sealed sender** ships as a whole system (sender certs + delivery-token abuse gate + contacts-only default) or not at all, with `Option`-typed sender fields reserved now; s2s delivery adds **durable in-order retry + per-destination sequence numbers + gap detection** (Matrix's retry rule minus its DAG backfill) and **X-Matrix-style Ed25519 request signing with destination binding + 401-on-mismatch**; the SPQR ratchet is **ML-KEM-768** (ML-KEM-1024 is PQXDH-handshake-only).

Phases (each lands as its own PR-series; do not start N+1 with N unmerged):

| # | Slice | Gate |
|---|---|---|
| 1 | **Spike**: `libsignal-protocol` + `spqr` on wasm32 | ✅ **GO** (2026-07-12, `spikes/libsignal-wasm/`) — compiles for the browser target on stable, full PQXDH+Triple-Ratchet round-trip executes in wasm; web client shares `kutup-chat-core` |
| 2 | Server slice: `kutup-chat-proto` + prekey directory, per-device mailboxes, WSS drain | ✅ landed — `crates/kutup-chat-proto`, migration 021, `handlers/chat.rs`, `chat_hub.rs`, nginx `/api/chat/ws`; full REST + WS contract smoke-verified against the live stack (incl. one-time-prekey consumption, last-resort fallback, the 409 missing/stale/extra device contract, live envelope push). Playwright chat spec lands with phase 2b |
| 2b | Client slice: `kutup-chat-core` engine (wraps libsignal, native + wasm) + minimal 1:1 web UI | **In progress — web slice implemented and live-stack verified on `codex/chat-architecture-hardening`.** Complete: durable typed inbound journal/quarantine, async DB boundary, SQLCipher fail-closed native store, crash-safe registration and prekey refill, signed manifests, atomic IndexedDB, WASM transport facade, capability-gated bilingual 1:1 UI, Web Locks cross-tab serialization, WS-hint/REST reconciliation, outbound history, a passing Playwright two-account encrypted exchange + IndexedDB reload test, and a generated/host-smoke-tested UniFFI 0.32 Swift/Kotlin boundary in `kutup-client-ffi`. XCFramework/AAR cross-compilation plus Keychain/Keystore and app integration in `kutup-ios`/`kutup-android` are the remaining phase-2b gates. |
| 3 | Federation: server signing keys, `.well-known/kutup/federation.json`, X-Matrix-style signed delivery + destination binding, **durable in-order retry queues with per-destination sequence numbers + gap detection** | |
| 4 | Groups: sender keys for fan-out + **GV2-pattern server-held encrypted+versioned group state with a signed membership manifest** (not client-managed blobs) | |
| 5 | Media: attachments via drive/tus + federated capability tokens | |
| 6 | Calls: 1:1 WebRTC → SFU group calls; TURN + SNI demux on 443 | |
| 7 | Hardening: key transparency (wrapping the device manifest), sealed-sender-in-federation with its delivery-token gate, full zkgroup anonymous credentials | research first (§11 of `13-…`) |

Device-list authenticity (the signed per-account device manifest) is **not** in phase 7 — it is a phase-2b/2 wire-contract requirement per the comparative study.

---

## Polish / smaller items (future)

### Desktop Drive redesign (chat1.md in the design bundle)

The mobile UI pulled ahead. The desktop Drive page hasn't gotten the color-palette refresh's full follow-through. From the design's `kutup-drive.html`:

- Slide-in details panel on right-click (kutup currently uses a context menu)
- Folder color picker
- Sort controls (Name / Modified / Size with asc/desc)
- Live search results
- Upload progress bar (driven by existing `UploadState`)
- Drag-to-upload overlay
- Keyboard-shortcuts panel — **carved out**: kutup's existing implementation stays per user feedback ("for keyboard shortcut panel also our implementation is definitely better")
- Per-file viewers (Excalidraw / photo / PDF) — **carved out**: kept as-is

### Federation polish

Cross-server presence indicators in collab, share-revocation on remote federations, federation discovery UX. Federation works today but rough.

### Test coverage gaps

- Tauri session-persistence — no E2E test today
- Federation flows — limited coverage
- Mobile flows — Playwright doesn't exercise the mobile shell

### Performance baselines

`docs/research/perf-baseline-2026-05-06.md` is a single point. Continuous benchmarking (or even a manual quarterly pass) would catch regressions.

### Mobile · Real OnlyOffice / Office docs

Desktop OnlyOffice was stripped from the Tauri build to avoid the OOM on `tauri::generate_context!()` (the ~2.6GB SDK gets embedded as a static byte array). Same applies to mobile. The follow-up sketched in CLAUDE.md is "load the SDK from `${serverUrl}/onlyoffice/…` so the app streams it from the user's server" — that's a real piece of work.

### Mobile · Federation share-with from sheet

The mobile share sheet doesn't yet expose federated share flows (cross-server) — only public link sharing.

### CLI follow-ups (from the CLI improvements batch)

The `.excalidraw` whiteboard asset extraction/hydration deferral is **done**
(`crates/kutup-cli/src/whiteboard.rs` — upload extracts + re-snapshots,
download re-inlines; Go-CLI parity reached). What remains around the CLI:

- **Share lifecycle management (needs server slices first).** There is no
  endpoint to list a collection's outgoing user shares, revoke one, or
  list/delete public links (the web UI can't either — only recipient-side
  `DELETE /fed-proxy/incoming/:shareId` exists). Server work:
  `GET /api/collections/:id/shares`, `DELETE /api/collections/:id/share/:userId`,
  `GET`/`DELETE /api/user/shares` (public links, owner-scoped via
  `public_shares.created_by`); then `kutup share ls / revoke / unlink` and
  matching web UI. Until then the CLI ships no affordance (no stubs).
- **Server improvements that unlock better CLI behavior** (noted per the
  "do when we touch the server" decision):
  - `latestVersionId` on the `GET /collections/:id/files` rows (one
    `LEFT JOIN LATERAL`) — kills the sync engine's per-file `list_versions`
    polling (its remote-change signal; `files.updated_at` is never bumped).
  - `trashRetentionDays` in `GET /api/auth/settings` — lets `kutup trash ls`
    show an accurate EXPIRES column on any server config (currently omitted
    rather than hardcoding 30).
- **Sync engine: whiteboard assets.** `kutup sync` pushes/pulls `.excalidraw`
  files as opaque bytes; the extract/hydrate steps only run in
  `upload`/`download`. Wire `crate::whiteboard` into the engine's
  push/pull paths.
- **Streaming multipart uploads** for `share upload` (fed-proxy) — still
  buffers the whole encrypted file in memory (`Part::bytes`); switch to
  `Part::reader` with an encrypting reader for large-file parity with tus.
- **`kutup versions restore` vs collab snapshots.** CLI restore re-encrypts
  with the file key in secretstream framing, while web collab snapshots are
  AEAD envelopes under a derived content key — CLI restore round-trips
  CLI/sync-created files, not live-collab documents. Needs the collab
  content-key path if full parity is wanted.
- **`kutup admin` command group.** The full `/api/admin/*` surface (users,
  quotas, stats, activity, settings, 2FA reset, wipe) has no CLI coverage;
  useful for self-hosters. Deliberately deferred from the improvements batch.

### Go→Rust server rewrite · interactive Swagger UI

The Rust `kutup-server` (`crates/kutup-server`)
generates its OpenAPI spec with `utoipa` and serves the machine-readable document at
`GET /api-docs/openapi.json`. The Go server served an **interactive Swagger UI** at
`/swagger/*` (`swaggo/fiber-swagger`). That route is not yet restored in Rust: the
`utoipa-swagger-ui` crate downloads the Swagger UI bundle from GitHub in its build
script, which breaks offline/sandboxed builds (and the rule that the server compiles
offline). Restore it by vendoring the UI bundle (`SWAGGER_UI_OVERWRITE_FOLDER` or a
`file://` `SWAGGER_UI_DOWNLOAD_URL`) so the build stays network-free, then mount it at
`/swagger`. The OpenAPI JSON is unaffected.

---

## Research / open questions

These live in `docs/research/` because the design hasn't been chosen yet:

- **Collaborative E2EE editing** — `docs/research/01-cryptpad-collab-stack.md` through `08-office-cell-formatting-getlock.md`. CryptPad pattern proven; integration into kutup is a multi-PR effort and the design isn't finalized.
- **Version history** — `docs/research/03-version-history-design.md`. Two-tier checkpoint+delta model recommended; not yet specced.
- **WebDAV mount** — `docs/research/06-webdav-support.md`. Client-side proxy is the only viable path because server-side WebDAV breaks E2EE. Long-term work.
- **WebAuthn / passkey support** — not yet captured in `docs/research/`. Would supplement TOTP for second-factor. Useful research before adding.
- **Chat open questions** — `docs/research/11-federated-chat.md` §7: sealed sender across federation (certificate-root trust with N mutually-distrusting servers), mailbox retention under E2EE, group-blob placement, an MLS suite slot for very large rooms. The chat *track* itself is committed (see the post-v1 section above); these sub-designs aren't.

---

## Working with this file

- **When something lands**, delete its entry and update the appropriate `docs/*.md` to describe the now-shipped behavior.
- **When you discover a new gap**, add it here. Be specific: file paths, what endpoint, what the user-visible change is.
- **Don't add items that are pure ideas.** Those belong in `docs/research/` as exploratory notes. This file is for committed, scoped work.
- **The `Blockers for v1` section is the gate to the first `v*` tag.** If you're tempted to ship before everything there is done, push back — the user has explicitly asked for production-grade, not fast.
