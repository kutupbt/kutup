# Production-readiness roadmap

Kutup is **pre-production**: there is no public release yet (until the first `v*` / `desktop-v*` git tag — see CLAUDE.md). This document is the canonical list of everything between today and "ready to tag v1".

It is the bridge between `docs/` (current state, authoritative) and `docs/research/` (forward-looking design notes that may never ship). Items here are committed work — we know we want them; they're scoped, just not built yet.

**When a feature lands**, move it out of this file and update the appropriate `docs/*.md`. The roadmap should always describe the gap to v1, not the past.

---

## What "production-ready" means for kutup

The bar for the first `v*` tag:

1. **No silent stubs in admin-facing UI.** Every clickable action that exists in the UI must work end-to-end. No "wire-up pending" toasts in shipped builds.
2. **Deletion is recoverable.** ✅ Shipped: owner-scoped trash with restore + permanent delete, and an hourly retention sweeper (`TRASH_RETENTION_DAYS`, default 30). See `docs/api.md` → Trash.
3. **Self-hosters can recover broken users without SSH.** Lost TOTP device, forgotten password, accidental disable — the admin UI must cover these without touching the database.
4. **Builds are signed.** Unsigned binaries trigger macOS Gatekeeper and Windows SmartScreen warnings that look like malware to non-technical users.
5. **Admin actions leave an audit trail.** Self-hosting communities — especially compliance-driven ones — need to know who disabled an account, when, and why.
6. **Basic abuse protection.** Login + admin endpoints have rate-limiting; brute-force attempts surface in logs.
7. **Documentation tracks reality.** No "this works but..." caveats in user-facing docs.

Items below are organized by **whether they block v1** vs. whether they can ship in a subsequent release.

---

## Blockers for v1 (must-have)

### Admin · Password reset

kutup is E2EE. A user's password derives (via Argon2id over `kdf_salt`) the key-encryption-key that decrypts `encrypted_master_key`. **The server never sees the master key**, so an admin *cannot* reset a password while preserving the user's data — only the user can, with their current password or their recovery phrase (the existing `/auth/recover` flow).

This means there is **no simple "reset password" endpoint** — it's a design problem with two distinct flows:

- **Recoverable** — the user still has their recovery phrase. They don't need an admin: they self-serve via `/auth/recover`. The admin's only role is to point them there. If we want an admin-initiated nudge, the safe scope is *rotating the temp password of a user still in `is_first_login` state* (no keys generated yet) — anything more for an established user breaks their access to their own files.
- **Unrecoverable** — the user has lost both password and recovery phrase. Their data is cryptographically gone. The only "reset" is a **destructive account wipe** (destroy keys + files, keep email/username) so they can start fresh, behind an explicit data-loss confirmation.

| What's needed | Where |
|---|---|
| Design: write up both flows + UI copy + the `is_first_login` temp-password-rotation carve-out | `docs/research/` — new note |
| Backend: `POST /admin/users/:id/rotate-temp-password` — only valid while `is_first_login` | `crates/kutup-server/src/handlers/admin.rs` |
| Backend: `POST /admin/users/:id/wipe` — destructive reset for the unrecoverable path | same |
| Frontend: surface both as distinct, clearly-labelled actions (not one "Reset password") | `AdminUserMenu` / `MobileAdminUserDetailPage` |
| Email (optional, see SMTP below): deliver the rotated temp password if SMTP is configured | backend integration |

### Admin · Audit log

Admin actions today leave no record. Production self-hosters — especially in regulated contexts — need to know who disabled an account, when, with what reason.

| What's needed | Where |
|---|---|
| Backend: schema migration — `admin_audit_log(id, admin_user_id, action, target_user_id, payload_jsonb, occurred_at)` | `crates/kutup-server/migrations/` |
| Backend: write a log row from every admin handler (`CreateUser`, `UpdateUser`, `DeleteUser`, `UpdateAdminSettings`, future reset/2fa/promote) | `crates/kutup-server/src/handlers/admin.rs` |
| Backend: `GET /admin/activity?limit=50&before=cursor` | new handler |
| Frontend: unhide the Recent activity card on the desktop Admin Overview (today it's hidden with a footnote about the missing endpoint) | `frontend/src/components/admin/AdminOverviewTab.tsx` |
| Frontend: similar card on mobile Admin Overview | `frontend/src/pages/mobile/account/admin/MobileAdminOverviewTab.tsx` |

### Rate limiting + brute-force protection

Login + register + admin endpoints have no rate limit. A trivial script can hammer them.

| What's needed | Where |
|---|---|
| Backend: middleware — token-bucket per IP for `/auth/*` (10 req / 5 min default) | `crates/kutup-server/src/middleware.rs` + `ratelimit.rs` |
| Backend: per-account "5 failed logins → lockout for 15 min" | `crates/kutup-server/src/handlers/auth.rs` + DB column or in-memory `failed_logins` |
| Backend: separate stricter limit on admin endpoints | same middleware |
| Config: env-var overrides (`AUTH_RATE_LIMIT_PER_5MIN`, `LOGIN_LOCKOUT_THRESHOLD`, etc.) | `crates/kutup-server/src/config.rs` |
| Test: integration test that exceeding the limit returns 429 | `crates/kutup-server/src/handlers/auth.rs` (tests) |

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

### Documentation truthfulness pass

The mobile UI shipped over PRs 2 → 13 changed a lot of user-visible behavior (bottom-tab nav, Account → Admin sub-pages, mobile-specific routes like `/drive/account/admin`, TOTP setup as a page, etc.). `docs/architecture.md` and `docs/mobile-build.md` need a sweep to confirm they describe what shipped, not what the design originally proposed.

| What's needed | Where |
|---|---|
| Re-read each `docs/*.md` and confirm it describes the current shipped UI | every file under `docs/` |
| Update `docs/api.md` with the new `storageTotalBytes` field on `AdminStats` | `docs/api.md` |
| Update `docs/self-hosting.md` to document the new `STORAGE_TOTAL_BYTES` env var | `docs/self-hosting.md` |
| Add per-path `#[utoipa::path]` operation annotations + an interactive Swagger UI (the spec is already served at `GET /api-docs/openapi.json`) | `crates/kutup-server/src/openapi.rs` + handlers |

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

### Go→Rust CLI rewrite · whiteboard asset extraction/hydration

The Rust `kutup` CLI (branch `claude/go-rust-rewrite-G16zO`, `crates/kutup-cli`)
ports the core upload/download paths but **defers the `.excalidraw` whiteboard
asset steps** the Go CLI does:

- **upload** (`crates/kutup-cli` upload path) — encrypt each
  embedded image as an asset blob, upload it, flip the element to
  `status:"saved"`, and commit a fresh snapshot.
- **download** (`crates/kutup-cli` download path) — fetch separately
  stored asset blobs and re-inline their `dataURL`s.

Both are best-effort optimizations (regular files transfer correctly without
them; the web re-uploads/hydrates assets on first open). They need the asset +
snapshot API surface ported (`UploadAsset`, `DownloadAsset`, `UploadSnapshotBlob`,
`RecordSnapshot`), which lands with the CLI's collab/versions slice. Port these
before declaring CLI parity.

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

### Go→Rust server rewrite · per-path OpenAPI operations

The Rust `utoipa` `ApiDoc` currently carries the `info` block, the `BearerAuth` security
scheme, and the response/DTO **schemas**, but not the per-path **operations** (the Go
handlers had `// @Router`/`// @Summary` annotations consumed by `swaggo`; the Rust handlers
have no `#[utoipa::path(...)]` annotations yet). So `GET /api-docs/openapi.json` lists
schemas but an empty `paths`. Endpoint parity was instead verified **directly against the
router**: before the cutover, a method+path diff of `crates/kutup-server/src/main.rs`
against the Go `backend/main.go` matched exactly (72 method+path combinations; only
`GET /swagger/*` → `GET /api-docs/openapi.json` differed, per the entry above). To fully
restore the spec, add `#[utoipa::path]` to each handler and register them in
`ApiDoc::paths(...)`, then `GET /api-docs/openapi.json` lists every operation.

---

## Research / open questions

These live in `docs/research/` because the design hasn't been chosen yet:

- **Collaborative E2EE editing** — `docs/research/01-cryptpad-collab-stack.md` through `08-office-cell-formatting-getlock.md`. CryptPad pattern proven; integration into kutup is a multi-PR effort and the design isn't finalized.
- **Version history** — `docs/research/03-version-history-design.md`. Two-tier checkpoint+delta model recommended; not yet specced.
- **WebDAV mount** — `docs/research/06-webdav-support.md`. Client-side proxy is the only viable path because server-side WebDAV breaks E2EE. Long-term work.
- **WebAuthn / passkey support** — not yet captured in `docs/research/`. Would supplement TOTP for second-factor. Useful research before adding.

---

## Working with this file

- **When something lands**, delete its entry and update the appropriate `docs/*.md` to describe the now-shipped behavior.
- **When you discover a new gap**, add it here. Be specific: file paths, what endpoint, what the user-visible change is.
- **Don't add items that are pure ideas.** Those belong in `docs/research/` as exploratory notes. This file is for committed, scoped work.
- **The `Blockers for v1` section is the gate to the first `v*` tag.** If you're tempted to ship before everything there is done, push back — the user has explicitly asked for production-grade, not fast.
