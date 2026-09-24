# Multi-app web rewrite — account, drive, chat

Status: **proposed** (2026-09-23), branch `feat/frontend-rewrite`.
Replaces the single-SPA "Polar Workspace" frontend described in
`docs/frontend.md` and `docs/plans/polar-workspace-frontend-redesign.md`.

## Why

- The current web UI is one SPA where Chat is bolted into the Drive shell
  (Messages sits beside Files/Shared/Trash; `Chat.tsx` is 4.3k lines,
  `Drive.tsx` 1.5k, with a parallel `pages/mobile/**` tree).
- Drive splits folders (`CollectionGrid`) from files (`FileTable`). The
  product direction is one Dolphin / Google-Drive-style list.
- One origin carries everything, including the CSP relaxations OnlyOffice
  needs (`'unsafe-eval' 'unsafe-inline'`), so a bug anywhere reaches the keys
  of every feature.
- There are no server-side sessions: refresh tokens are stateless 7-day JWTs,
  logout never reaches the server, and a session cannot be revoked.

## Decisions

| Topic | Decision |
|---|---|
| App model | Proton model: **one account, separate apps**, app switcher. |
| Origins | `account.<domain>`, `drive.<domain>`, `chat.<domain>` (apps) + `office.<domain>` (keyless OnlyOffice sandbox). Each app calls `/api` on its own origin; one backend behind the reverse proxy. |
| Reverse proxy | **Traefik is the default** in the single `docker-compose.yml` (host routing + automatic TLS / ACME). Documented alternatives: nginx and Caddy example configs. |
| Desktop | `src-tauri/` removed on this branch; desktop returns after Android / iOS. |
| Single login | **Session forking** (Proton pattern): account creates a child session and hands keys over an encrypted, one-time payload whose key travels only in the URL fragment. |
| Repo layout | Monorepo: `frontend/` becomes a pnpm workspace (`apps/*`, `packages/*`), source-only packages. |
| Visual system | asec-next frontend system (tokens, Radix primitives, dark chrome, paper canvas, "spine", IBM Plex, next-themes, sonner) with Kutup's glacier/ice palette; three-diamond logo unchanged (`TRADEMARK.md`). |
| Drive list | One list for folders, files, notes, office docs, whiteboards. Sort / filter / view controls top-right. **Default: list, last modified, newest first.** "Folders first" toggle, **default off**. |
| Platforms | Web + CLI first → Android / iOS → desktop. The new frontend is **web-only** (no Tauri code paths). |
| Mobile (later) | Two native apps per platform, **Kutup Drive** and **Kutup Chat**, mirroring the web split and sharing the Rust core (`kutup-client-ffi`); one repo per platform with two app targets (`kutup-ios`, `kutup-android`). Cross-app sign-in later via iOS keychain access group / Android signature-protected provider — the Nextcloud Files + Talk model (Nextcloud Android-SingleSignOn). |

References (read-only checkouts in `../kutup-references/`, see its README):
Proton `WebClients` (fork protocol, app shell, Drive explorer), `cryptpad`
(sandbox origin, OnlyOffice checkpoints, drive UX), `Signal-Desktop` /
`Signal-Server` (Chat UX).

## Topology

```
                 ┌──────── Traefik (default; TLS via ACME) ────────┐
account.<d>  ──▶ │ /  → account static    /api → kutup-server      │
drive.<d>    ──▶ │ /  → drive static      /api → kutup-server      │  (+ collab WS)
chat.<d>     ──▶ │ /  → chat static       /api → kutup-server      │  (+ chat WS)
office.<d>   ──▶ │ /  → OnlyOffice bundle (no /api, no cookies)    │
                 └─────────────────────────────────────────────────┘
```

- **App origins come from server config**, not hostname guessing:
  `KUTUP_ACCOUNT_URL`, `KUTUP_DRIVE_URL`, `KUTUP_CHAT_URL`, `KUTUP_OFFICE_URL` (defaults derived
  from one `KUTUP_BASE_DOMAIN`). `GET /api/auth/settings` publishes them, so
  self-hosters can use any three hostnames. The fork redirect allowlist is the
  same config, enforced **server-side** (child client type → exact origin).
- Cookies are host-only per app origin (refresh cookie `Path=/api/auth/refresh`,
  `HttpOnly; Secure; SameSite=Lax`). No cross-origin API calls, so no CORS
  beyond today's defaults.
- `/.well-known/kutup/federation.json` and federation endpoints keep answering
  on the configured federation host (`CHAT_SERVER_NAME`), unchanged.
- Public Drive links move to `drive.<d>/s/<token>#key=…`.

### Where features live

| App | Owns |
|---|---|
| **account** | login (+2FA), register, first-login, recovery, the fork producer (`/authorize`), app switcher landing, settings (profile, security/2FA, recovery phrase, sessions, language, appearance, per-product sections `/drive/…`, `/chat/…`), admin (`/admin/…`). |
| **drive** | explorer (unified list), shared with me, trash, uploads, sharing dialogs, public-link page `/s/:token`, editors (`/file/:cid/:fid`: text/markdown collab, OnlyOffice, Excalidraw, viewers), version history. |
| **chat** | conversation list, thread, details panel, groups, requests, safety verification, chat devices, backup/recovery status. |

Cross-app bridges (send-to-chat, save-to-drive) are **not** built in this
rewrite; they go on `docs/roadmap.md` (no stub affordances).

## Sessions and forking (server)

### Data model

- `sessions`: `id`, `user_id`, `client_type` (`<platform>-<app>`:
  `web-account`, `web-drive`, `web-chat`, `cli`; reserved for later
  `android-drive`, `android-chat`, `ios-drive`, `ios-chat`, `desktop-*`),
  `parent_session_id`
  (null for directly authenticated sessions), `refresh_token_hash`
  (rotating, opaque 32 random bytes, SHA-256 at rest), `local_key`
  (nullable, see persistence), `created_at`, `last_used_at`, `expires_at`,
  `revoked_at`, user-agent label.
- `session_forks`: `selector_hash`, `parent_session_id`, `child_client_type`,
  `payload` (opaque ciphertext), `expires_at` (60 s), `consumed_at`.
- Access tokens stay short-lived JWTs and gain a `sid` claim. Refresh checks
  the session row (revoked / expired / rotated) — revocation takes effect at
  the next refresh (≤ access-token TTL, reduced to 10 min).

### Endpoints

| Method + path | Auth | Purpose |
|---|---|---|
| existing `POST /api/auth/login`, `/login/2fa`, `/register`, `/complete-setup`, `/recover` | — | Now create a `sessions` row. Body field `clientType` (`web-account` or `cli`; others rejected until those clients exist). |
| `POST /api/auth/refresh` | refresh cookie (web) or body (CLI) | Rotates the refresh token; rejects revoked sessions and reused (already rotated) tokens — reuse revokes the session. |
| `POST /api/auth/forks` | parent session (`web-account` only) | `{childClientType, payload}` → `{selector}`. |
| `POST /api/auth/forks/consume` | none | `{selector, clientType}` on the child origin → creates the child session, sets the refresh cookie **on this origin**, returns `{accessToken, payload, userId, …}`. Single use; `clientType` must match; request `Origin` must equal the configured origin for that client type. |
| `PUT` / `GET /api/auth/sessions/current/local-key` | session | Store / fetch the per-session key that unlocks the persisted blob (below). |
| `POST /api/auth/logout` | session | Revokes the current session. Revoking a `web-account` session also revokes its children. |
| `GET /api/auth/sessions`, `DELETE /api/auth/sessions/:id`, `DELETE /api/auth/sessions` (all others) | session | Settings → Sessions, and CLI `kutup sessions`. |

### Fork flow

1. drive/chat boots without a session → `location.replace(account/authorize?app=drive&state=<rand>)`;
   the return path is kept in `sessionStorage` under `state`.
2. account (login first if needed) builds the payload
   `{masterKey, privateKey, publicKey, userId}`, encrypts it with a fresh
   32-byte key, `POST /api/auth/forks`, and redirects to the **configured**
   drive origin: `…/login#selector=<s>&sk=<key>&state=<state>`.
3. drive reads and immediately clears the fragment
   (`history.replaceState`), `POST /api/auth/forks/consume`, decrypts the
   payload, persists it (below), and navigates to the saved return path.

The fork payload is a new persistent-ish wire format, so per `CLAUDE.md`
("Rust owns Kutup cryptographic formats") it is defined in `kutup-crypto`
(XChaCha20-Poly1305, AAD `"kutup-fork-v1"`, versioned header), exposed
through `kutup-crypto-wasm`, with checked-in vectors — not ad-hoc WebCrypto.

### Persistence per origin (replaces raw keys in `sessionStorage`)

- Keys are stored in `localStorage` as a blob encrypted with a random
  per-session **local key** that only the server holds
  (`PUT …/local-key` right after login or fork). Reload / new tab:
  refresh → `GET …/local-key` → decrypt. Revoking the session makes the local
  blob useless; nothing usable sits in browser storage on its own.
- This removes today's raw `masterKey`/`privateKey` in `sessionStorage` and
  the BroadcastChannel key hand-off (new tabs, e.g. editors, just resume).
- Logout in any app → `POST /logout`, wipe the local blob, go to
  `account/…/signed-out`. Other apps notice on their next refresh (401) and
  re-fork, which lands on account's login.

Deferred: multiple signed-in accounts per browser (Proton's `/u/<n>/`),
per-app least-privilege keys (drive and chat both receive the master key for
now), QR sign-in for devices.

## OnlyOffice isolation — sandbox origin (in scope)

OnlyOffice needs `'unsafe-eval' 'unsafe-inline'`. It moves to a fourth,
**keyless** origin, `office.<domain>` (CryptPad's `httpSafeOrigin` pattern):

- `office.<d>` serves only the OnlyOffice bundle, x2t and a small Kutup
  bootstrap. No cookies, no `/api`, no storage of secrets;
  `connect-src 'self'`, `frame-ancestors <drive origin>`.
- The drive editor page (strict CSP) embeds
  `office.<d>/editor.html` in an iframe, holds every key, does all
  encryption, the collab WebSocket, snapshot upload and version calls, and
  exchanges **plaintext only** with the sandbox over a typed postMessage RPC
  (`{q, txid, content}`, allow-listed commands, explicit target origin,
  `event.source` + `event.origin` checks both ways). Commands:
  `init(document bytes, user, presence)`, `remote-ops`, `local-ops`,
  `cursor`, `save-request` → `save-result(bin | ooxml)`, `convert` (x2t).
- The sandbox boot script refuses to run top-level and refuses to start if
  it is not framed by the configured drive origin.
- Checkpoints follow CryptPad: snapshot every N ops (single writer lock),
  upload as an encrypted blob, replay ops after the last checkpoint on load
  (the existing `snapshot-blob` / `versions` endpoints).
- All four origins (`account`, `drive`, `chat`, `office`) ship strict CSP
  except the office sandbox; no origin that can hold keys allows `unsafe-eval`.

## Frontend workspace

```
frontend/
  apps/account/  apps/drive/  apps/chat/     # Vite apps, one per origin
  packages/
    ui/          # tokens.css, fonts, primitives, AppShell, AppSwitcher, UserMenu
    session/     # axios client, auth store, fork produce/consume, persistence, apps registry
    crypto/      # today's src/crypto + wasm loaders (unchanged logic)
    collab/      # today's src/collab (WS URL from the app origin, not location hacks)
    drive-core/  # upload, download, mediaCache, mediaPreview, workers
    chat-core/   # today's chat service / MLS / backup / transport (non-UI)
    i18n/        # en/tr per app namespace + parity/usage tests
    config/      # tsconfig, eslint (asec rules), vitest presets
```

- Conventions from asec-next: feature folders with `api.ts` (types + query
  keys + hooks), mutations invalidate (no cache patching), forms are pages
  (dialogs only for confirm / pick / reveal / focused edit), one destructive
  confirm component, lint bans raw palette classes and native select /
  checkbox, meta-tests (locale parity + key existence, token parity, every
  write hook reachable). Existing Kutup rules stay: every string in `en` and
  `tr`, no stub affordances, no hard-coded English.
- Redux is removed; the session store is a small external store
  (`useSyncExternalStore`) in `packages/session`.
- One responsive layout per app; the `pages/mobile/**` tree is not carried
  over.

## Drive explorer

- One virtualised list of `Folder | File` rows. Kinds: folder, note (md/txt),
  code, document, spreadsheet, presentation, whiteboard, image, video, audio,
  pdf, archive, other.
- Toolbar right side: **Sort** (modified, name, size, type; asc/desc),
  **Filter** (kind chips), **Folders first** toggle (off), **List / Grid**.
  Choices live in the URL (`?sort=modified&dir=desc&kind=…`) and the last
  choice is remembered per origin.
- Sorting and filtering are client-side: names and MIME types are encrypted,
  so the server cannot sort by them. Natural name compare; ties by name.
- Server change: `CollectionRow` gains `createdAt` / `updatedAt` (columns
  already exist) so folders have a modified time.
- Left sidebar: New (folder, note, document, spreadsheet, presentation,
  whiteboard, upload files, upload folder), My files, Shared with me, Trash,
  storage meter. App switcher next to the logo; user menu top-right.

## Chat app

Rebuilt as its own shell (conversation list | thread | details panel),
using Signal-Desktop as the UX reference: header actions (devices, backup,
QR safety, group, block) move into the details panel. `chat-core` keeps the
existing protocol code; the 315 e2e test ids are preserved where the element
still exists.

## Phases

Each phase is committed with `tsc`, `vitest`, lint and build passing
(`cargo test` / `clippy` for server phases).

0. **Workspace + foundation** — pnpm workspace, `packages/{config,ui,i18n}`,
   move non-UI logic into `packages/*` with its tests green, delete the old UI.
1. **Sessions + forking (server, crypto, CLI)** — tables, endpoints,
   `kutup-crypto` fork blob + vectors, CLI `clientType`, `kutup sessions`,
   CLI logout revoking server-side.
2. **account app** — auth flows, fork producer, settings, sessions, admin.
3. **drive app** — fork consumer, shell, unified explorer, sharing, trash,
   public links, editors, versions.
4. **chat app** — shell, conversations, groups, devices, backup.
5. **Deployment + docs** — Traefik-based `docker-compose.yml` (four hosts,
   ACME TLS, self-signed for local), nginx and Caddy example configs,
   per-origin CSP, env, dev setup (`account.localhost` / `drive.localhost` /
   `chat.localhost` / `office.localhost`), Playwright suite ported, remove
   `src-tauri/` + its workflow, docs (`architecture`, `frontend`,
   `self-hosting`, `api`, `roadmap`, `onlyoffice`, `CLAUDE.md`) updated.

## Status (2026-09-23)

**Done** (committed on `feat/frontend-rewrite`, verified in a browser against
the local dev stack):

- Phases 0–2 complete: workspace and shared packages, server-side sessions
  with forking and immediate revocation (server, crypto, CLI `kutup
  sessions`), the account app (sign-in, registration, recovery, settings,
  sessions, devices, the whole admin area).
- Phase 3 (Drive) complete:
  - unified list (folders and files together, last modified first, sort and
    type filter top right, list/grid, folders-first toggle off by default);
  - uploads (files, folders, drag and drop), sharing (local and federated),
    public links and the anonymous `/s/:token` page, trash with undo,
    folder colours, rename, ZIP downloads;
  - the file page: notes and code (collaborative text editor), office
    documents (OnlyOffice), whiteboards (Excalidraw), image/PDF/media
    viewers, versions, restore;
  - downloads and copies take an edited file's latest version, not the
    original upload;
  - OnlyOffice on its own sandbox origin (`office.<domain>`), with the
    bridge bound to one parent origin;
  - right-click menus (item, selection, empty space), box selection,
    Copy to… with a folder picker, ZIP of a selection.
  - file-type colours as filled icons (tokens, 4.5:1 in both themes);
    folders neutral by default, colours stored as `#rrggbb` for web and CLI
    alike; grid cards with a preview area (the kind icon until thumbnails);
    the app switcher top right; search in the top bar (in the browser,
    accent- and Turkish-i-insensitive); Quick Look on Space.

- Versions v2 (docs/plans/drive-versions-v2.md): one-request versions
    charged by measured size, one object per version, real deletes,
    thinning retention with a per-account setting, unchanged saves skipped
    and named in place, the original retired as version zero; downloads,
    public links and federation serve the latest edited version.

**Next, in order**

1. Thumbnails: client-generated, encrypted with the file key, stored beside
   the file (Proton's model: 512 px ≤ 60 KB, plus an HD preview). Design
   note first — format in `kutup-crypto`, server endpoint, quota, backfill;
   then images, whiteboards and notes; video and PDF; office last.
2. Move (Drive): folder move needs a server endpoint (reparent, owner only,
   no cycles). File move needs a crypto decision — file content is sealed
   to its collection id, so today a move is a re-encrypting copy. The
   intended fix binds content to the file only and rewraps just the file key
   (a format change across Rust, WASM and CLI, with new vectors).
3. Phase 4 — the Chat app.
4. Phase 5 — Traefik compose with the four hosts (nginx and Caddy
   examples), per-origin CSP including the office sandbox, removing
   `src-tauri/`, the Playwright suite ported, docs.

**Known gaps (to go to `docs/roadmap.md` in phase 5)**

- Share listing and link revocation have no server endpoints yet, so there
  is no UI for them.
- The upload panel labels copies as uploads.

## Resolved questions (2026-09-23)

1. `src-tauri/` — removed on this branch.
2. OnlyOffice — sandbox origin `office.<domain>` now, as part of this rewrite.
3. Hosting — three app hostnames plus the office sandbox; Traefik default
   in one compose file, nginx and Caddy documented; no single-host mode.
