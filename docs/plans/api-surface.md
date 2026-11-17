# API pass: the API surface made once, before the wipe

Status: **approved** (main, 2026-11-17; decisions in §10). The build starts
after W7's group 1 (the renames) lands on `wipe/w7`.
Branch `wipe/api-pass` on `wipe/w7` 4f9ccdd9. It follows W7
(docs/plans/w7-schema.md): W7 renames the schema, this renames what clients
and peers see: paths, versions, JSON field names, client storage names, and
it adds a server instance id. The rule is the user's: change now whatever is
cheap only before real users, clients and peers exist.

## 0. Inventory

Taken from `build_router` (crates/kutup-server/src/main.rs, the only router)
and the clients on this branch.

| What | Count |
|---|---|
| Route paths (path + method pairs) | 432 (519) |
| … under `/api/` for clients | 373 (the sweep's ~382 counted differently) |
| … under `/api/fed/` (server to server) | 47 (17 chat, 28 drive, `policies/:feature`, plus 1 `/api/federation/policies/:feature` for clients) |
| … `/.well-known/` 7, `/api/health*` 2, `/api/csp-report`, `/internal/mail/rcpt`, `/api-docs/openapi.json` | 12 |
| Paths that only gain the version prefix | 270 |
| Paths renamed (prefix, segment or both) | 148 |
| Paths dropped | 3 (name-keyed federation routes) |
| Unchanged (unversioned) | 11 |
| Top-level prefixes for one thing (the account) | 3: `/api/user/` 18, `/api/users/` 4, `/api/account/` 9 (+ `/api/devices`, `/api/device-ticket`, `/api/device-session`) |
| `/api/admin/users/…` paths | 13 |
| Drive paths outside `/api/drive/` | 59 (`files` 23, `collections` 11, `share` 10, `albums` 6, `trash` 3, `uploads` 2, `shared-files`, `shared-by-me`, `file-shares`, `photos` 1 each) |
| Version headers today | none; `x-kutup-client` (client type, 9 web types + `cli`) and `x-kutup-session-version` (security-state digest) |
| Federation version today | `fedVersion: 2` in the signed discovery and in every request signature; feature capabilities `identity.v1`, `chat.v2`, `drive.v1`; no version in paths |
| Places that build the API base | 3: web `frontend/packages/session/src/apiBase.ts` (`/api`), CLI `crates/kutup-cli/src/api/mod.rs` `url()` (`{base}/api{path}`), FFI host `ChatHttpClient` (paths relative to a host base) |
| Hard-coded `/api/…` outside those | nginx (`nginx/nginx.conf`: collab ws regex, `/api/chat/ws`, `/api/chat/provisioning`, auth rate-limit regex), the frontend container (`frontend/docker/40-kutup-hosts.sh`: CSP `report-uri`, `Reporting-Endpoints`, `/api/` proxy), cookie paths (`/api/auth/refresh`, `/api/auth`), tus `Location`, 176 federation path strings in the server, `utoipa::path` attributes, docs/api.md, tests |
| Browser storage names | 8 IndexedDB, 37 localStorage (incl. 10 chat prefs, 5 legacy), 6 sessionStorage, 6 BroadcastChannels, 11 lock names, 2 server cookies; 5 naming styles; no Cache Storage |
| CLI local names | data dir `<data>/kutup/<profile>/kutup.redb` (tables `session`, `sync_state`, `collab_device`, `manifest_pin`, `resume`), keyring service `kutup-cli/<profile>` account `device-key`, unit `kutup-ssh-agent.service` |

Two things the sweep listed are already done on this branch:
`/api/fed/policies/mls-ordering` no longer exists (the feature enum is
`chat` | `drive`; only a test string names it), and federation already has a
protocol version (above). What federation lacks is a version in its paths
and a list of the versions a server speaks.

## 1. Versioning

### 1.1 What the references do

- **Proton:** the version is in the path, per service: `/api/core/v4/users`,
  `/api/mail/v4/messages`, `/api/drive/v2/…`. Every request carries
  `x-pm-appversion: <clientId>@<semver>` (for example `web-mail@5.0.12`).
  A client the server no longer accepts gets API error code `5003`
  (`APP_VERSION_BAD`); the web client latches it (`appVersionBad`), refuses
  every further call and shows "new version, reload"
  (`packages/shared/lib/api/helpers/withApiHandlers.ts`).
- **Signal:** the version is in the path, per endpoint (`/v1/messages`,
  `/v2/keys`). The client version is the `User-Agent`
  (`Signal-Desktop/7.x`); `RemoteDeprecationFilter` compares it with a
  per-platform minimum and blocked list (dynamic configuration) and answers
  HTTP `499`; the client then shows "this version expired".
- **Matrix:** path versions (`/_matrix/client/v3/…`,
  `/_matrix/federation/v1/…`) and an unversioned `GET /versions` that lists
  what the server speaks.

All three: the path carries the contract version; a separate client version
(header) is compared with a server-held minimum per client kind; one error
code that every client latches.

### 1.2 Decision: path version plus client version

- **Client API: `/api/v1/…`.** One version for the whole client API
  (Kutup is one server; per-service versions would be Proton's
  microservices showing through). It is bumped only for a break that can't
  be added beside the old shape; additions stay in v1.
- **Unversioned, on purpose:** `/api/health`, `/api/health/ready`,
  `/api/csp-report` (baked into served CSP headers), `/internal/mail/rcpt`
  (Stalwart), `/.well-known/…` (fixed by their standards or by peers'
  discovery). `GET /api/health` is the one place any client learns what the
  server speaks (Matrix's `/versions`).
- **OpenAPI** moves to `/api/v1/openapi.json` (it describes v1); `/api-docs/`
  and its nginx block go.
- **Client version header.** `x-kutup-client` becomes
  `<clientType>/<version>`: `web-drive/2026.1120.0`, `cli/0.0.14`. The
  client type keeps its W7 spelling (bound into local-state vectors);
  sessions read the part before `/`. One header, as Proton's
  `x-pm-appversion` and the `User-Agent` style the CLI already sends
  (`kutup-cli/<version>`). Browsers can't set headers on a WebSocket
  upgrade, so the three sockets take `?client=<clientType>/<version>`.
- **Versions.** CLI and FFI: their crate version (semver; the CLI stays on
  v0.0.x, and a move to 0.1 or higher is the user's call). The check
  compares by client type, so semver for `cli` and native types and CalVer
  for web types never meet; both parse as semver
  (`2026.1120.0` is a valid semver). Web apps: the
  release version, stamped at build into both server and frontend, replacing
  the `BUILD_VERSION = "dev"` constant: CalVer in semver shape,
  `YYYY.MDD.N`: the month without a leading zero, which semver forbids
  (`2026.1120.0`, `2027.105.2`); sortable, no meaning to maintain. A dev
  build is `0.0.0-dev`. A `-dev` client is exempt from the minimum only on a
  server that is itself a dev build. Pre-release identifiers compare as
  semver says: one by one, numeric ones as numbers (`-rc.10` > `-rc.2`).
  A malformed `KUTUP_RELEASE` fails the web build; a version the server
  can't parse leaves the request unchecked, and sign-in still reads the
  client type before the `/`.
- **No lockout.** An administrator can't set a web type's minimum above
  this server's release (the web apps ship with it: the admin page itself
  would be refused). A CLI minimum above the CLI built from the same tree
  saves with a warning.

### 1.3 What "too old" compares

`clientVersion < minimum(clientType)`, where
`minimum = max(compiled floor, site setting)`:
- **The compiled floor** (`MIN_CLIENT_VERSIONS` in the server, a table per
  client type) is raised by a developer in the same commit that stops the
  server accepting something an older client does. It is empty at the
  wipe.
- **The site setting** `server.min_client_version.<clientType>` (W7
  namespacing; admin-editable, per the standing rule) lets an operator
  raise it, never lower it below the floor. Signal's per-platform minimum.
- **Not checked:** a request without `x-kutup-client` (curl, `<img>`, map
  tiles through MapLibre, a public link opened by a crawler). Every Kutup
  client sends it on every fetch it makes itself; the check is for our
  clients, not a gate.
- **A retired path version** (`/api/v1/…` after v1 is dropped) and **the
  bare `/api/…` paths of today** answer the same `clientTooOld` from a
  fallback route. That is what beta tabs still open at the wipe deploy will
  hit.
- **A version the server doesn't know** (`/api/v2/…` on an older server)
  answers `404` with code `apiVersionUnsupported` and `supported: [1]`: the
  server is too old for the client.

### 1.4 The error

```
HTTP/1.1 426 Upgrade Required
x-kutup-min-client: cli/0.0.14
{"error": "client too old", "code": "clientTooOld",
 "clientType": "cli", "minimum": "0.0.14"}
```

- Status 426: the request is fine, the client must update; nothing caches it
  and generic HTTP code treats it as a client error. (Signal uses a
  non-standard 499; Proton a 4xx with code 5003. Apps act on `code`, as
  docs/api.md says, so the status matters only to tools.) RFC 9110 wants an
  `Upgrade` header with 426; we send none, as other APIs using 426 for
  "update the app" do.
- `clientTooOld` and `apiVersionUnsupported` join the code table in
  docs/api.md (its test enforces the list).
- `GET /api/health` gains `apiVersions: [1]`, `instanceId` (§5) and
  `minimumClients: {"cli": "0.0.14", …}` (only types with a minimum), so the
  CLI and native apps can check before they start work.

### 1.5 How clients react

- **Web** (`@kutup/session`'s axios client, and the raw `fetch` users:
  call links, tus, the block reader, the service worker):
  - one response interceptor latches `clientTooOld`: every later request
    fails at once without leaving the page (Proton's `appVersionBad`);
  - it dispatches the existing `RELOAD_NEEDED_EVENT`, so the page shows the
    "Kutup was updated, reload" screen from reloadGuard.ts;
  - a reload that still gets `clientTooOld` asks the service worker to
    update (`registration.update()`), then reloads once; the reload guard's
    per-build flag stops a loop;
  - `apiVersionUnsupported` shows "this server runs an older Kutup", with no
    reload.
- **CLI:**
  - `ApiError` maps `clientTooOld` to a new exit code 7 and the message
    "<server> needs kutup ≥ <minimum> (this is <version>); update: <url>";
  - `kutup login` and `kutup status` read `/api/health` first and say the
    same before asking for a password;
  - `apiVersionUnsupported`: "<server> runs an older Kutup than this CLI
    supports", exit 7.
- **FFI** (`crates/kutup-client-ffi`):
  - `ensure_success` reads the body's `code`;
  - `ChatError` gains `ClientTooOld { minimum }` and
    `ServerTooOld { supported }`;
  - the engine stops its network loops on either;
  - the host app shows its store's update prompt;
  - the host's `ChatHttpClient` sends `x-kutup-client: <type>/<version>`;
  - native client types come with the native apps (W7 dropped the
    `android-*` / `ios-*` values).
- **Chat engine in wasm:** the web transport already goes through the
  session client, so it gets the latch for free; the engine maps the
  failure to a stopped state, as for a signed-out session.

### 1.6 Federation

Federation is its own protocol with its own number, as Matrix keeps
`/client/v3` and `/federation/v1` apart.
- **Paths:** `/api/fed/v2/…`, the number being the existing
  `FEDERATION_VERSION = 2`. It is not renumbered to 1: it is bound into the
  signature profile (`HttpSignaturesV2`) and the
  `FEDERATION_DISCOVERY_V2` label, and changing those buys nothing.
- **Discovery** (`/.well-known/kutup/federation.json`, signed):
  - keeps `fedVersion` (the version the document itself is in);
  - gains `fedVersions: [2]`, every version this server serves. A newer
    server serves `/api/fed/v2/` and `/api/fed/v3/` side by side and lists
    both, as Matrix does;
  - the feature capabilities (`chat.v2`, `drive.v1`, `identity.v1`) keep
    versioning each feature inside it.
- **"Too old" compares** the sender's chosen version with `fedVersions`:
  - the sender picks the highest version both list, reading the peer's
    discovery (cached an hour, as now);
  - a request on a version this server doesn't serve gets a signed
    `426 {"code": "federationVersionUnsupported", "supported": [2]}`;
  - the sender re-reads discovery once. If still none is shared, it marks
    the peer `incompatible` on the admin federation page (a new peer state
    beside `quarantined`);
  - the outbox keeps the peer's messages until their normal expiry rather
    than dropping them.
- The transport's namespace check (`/api/fed/chat/`, `/api/fed/drive/`)
  takes the versioned prefix, and gains the account namespace of §3.

## 2. Path map

### 2.1 Rules

- **Prefix.** Every client path gains `/v1`: `/api/x` → `/api/v1/x`. Every
  federation path gains `/v2`: `/api/fed/x` → `/api/fed/v2/x`.
- **The account.** `account` (singular) is the signed-in account, `accounts`
  (plural) is lookup of others:
  - `/api/user/me` → `/api/v1/account`;
  - `/api/user/*` → `/api/v1/account/*`;
  - `/api/users/*` → `/api/v1/accounts/*`;
  - the device routes move under `account/devices`;
  - `/api/admin/users` → `/api/v1/admin/accounts`.
- **Apps own their paths.**
  - Drive is `/api/v1/drive/…`: files, collections, public links, trash,
    uploads, shared lists. `GET /api/drive/files` (list all) and
    `POST /api/files/upload` (whole-file upload) become `GET` and `POST`
    on `/api/v1/drive/files`.
  - Photos is `/api/v1/photos/…`: albums, preferences.
  - Chat takes `live-locations` (W7: `chat_live_location_streams`).
- **Names follow W7.**
  - Admin `wipe` → `reset-keys` (`account.resetKeys`).
  - Admin `limits` → `entitlements` (`account_entitlements`).
  - `share` (public) → `public-links`.
  - Sealed sender `domains/:domain` → `servers/:server` (W7: a server name
    is `<role>_server`). The federation admin `peers/:domain` keeps
    `domain`: peers are transport, as in W7.
- **Shape fixes** while every path moves anyway:
  - the public-link file routes take the private routes' shape
    (`…/files/:fileId/download`, `/state`, `/thumbnails/:variant`);
  - `chat/device` → `chat/devices`;
  - Drive's two federated share kinds are `folder-shares` and `file-shares`
    on both sides: client `/drive/federation/shares` and federation
    `/drive/invite|files|epochs|album` become `folder-shares`, federation
    `/drive/file-invite|file-content|file-state` become
    `file-shares/invite|content|state`.
  - Path parameters are camelCase (`:account_id`, `:room_id`, `:event_id`
    become `:accountId`, `:roomId`, `:eventId`), as OpenAPI shows them.
- **Not changed:**
  - the RPC-style verbs Proton also uses (`POST …/delete`,
    `…/items/remove`, `collab/versions/create`);
  - `collections` (folders and albums: one object, as Ente names it);
  - mail, calendar, contacts and pass beyond the prefix.

### 2.2 New routes

| Path | Methods | Replaces |
|---|---|---|
| `/api/fed/v2/accounts/lookup?name=<name>` | GET | `/api/fed/drive/users/:username`, `/api/fed/{chat,drive}/names/:username/renames` (§3) |
| `/api/{anything not v1}` fallback | any | answers `clientTooOld` (§1.3) |
| `/api/v{n}/…` fallback for n ≠ 1 | any | answers `apiVersionUnsupported` |

### 2.3 Old → new, by app

"(same)" means the path does not change. Methods are as built today.

#### Unversioned

| Old | New | Methods | Note |
|---|---|---|---|
| `/.well-known/kutup/federation.json` | (same) | GET | unversioned |
| `/.well-known/kutup/federation/identity/:sequence` | (same) | GET | unversioned |
| `/.well-known/openpgpkey/:domain/hu/:hash` | (same) | GET | unversioned |
| `/.well-known/openpgpkey/:domain/policy` | (same) | GET | unversioned |
| `/.well-known/openpgpkey/hu/:hash` | (same) | GET | unversioned |
| `/.well-known/openpgpkey/policy` | (same) | GET | unversioned |
| `/.well-known/security.txt` | (same) | GET | unversioned |
| `/api/csp-report` | (same) | POST | unversioned |
| `/api/health` | (same) | GET | unversioned |
| `/api/health/ready` | (same) | GET | unversioned |
| `/api-docs/openapi.json` | `/api/v1/openapi.json` | GET |  |
| `/internal/mail/rcpt` | (same) | POST | unversioned |

#### Auth

| Old | New | Methods | Note |
|---|---|---|---|
| `/api/auth/complete-setup` | `/api/v1/auth/complete-setup` | POST |  |
| `/api/auth/forks` | `/api/v1/auth/forks` | POST |  |
| `/api/auth/forks/consume` | `/api/v1/auth/forks/consume` | POST |  |
| `/api/auth/keep` | `/api/v1/auth/keep` | POST |  |
| `/api/auth/login/2fa` | `/api/v1/auth/login/2fa` | POST |  |
| `/api/auth/login/abort` | `/api/v1/auth/login/abort` | POST |  |
| `/api/auth/login/finish` | `/api/v1/auth/login/finish` | POST |  |
| `/api/auth/login/security-key/finish` | `/api/v1/auth/login/security-key/finish` | POST |  |
| `/api/auth/login/security-key/start` | `/api/v1/auth/login/security-key/start` | POST |  |
| `/api/auth/login/start` | `/api/v1/auth/login/start` | POST |  |
| `/api/auth/logout` | `/api/v1/auth/logout` | POST |  |
| `/api/auth/opaque/register/finish` | `/api/v1/auth/opaque/register/finish` | POST |  |
| `/api/auth/opaque/register/start` | `/api/v1/auth/opaque/register/start` | POST |  |
| `/api/auth/recover/grant` | `/api/v1/auth/recover/grant` | POST |  |
| `/api/auth/recover/preflight` | `/api/v1/auth/recover/preflight` | GET |  |
| `/api/auth/refresh` | `/api/v1/auth/refresh` | POST |  |
| `/api/auth/register` | `/api/v1/auth/register` | POST |  |
| `/api/auth/registration-code/check` | `/api/v1/auth/registration-code/check` | POST |  |
| `/api/auth/security-keys` | `/api/v1/auth/security-keys` | GET |  |
| `/api/auth/security-keys/:id` | `/api/v1/auth/security-keys/:id` | DELETE,PATCH |  |
| `/api/auth/security-keys/proof/start` | `/api/v1/auth/security-keys/proof/start` | POST |  |
| `/api/auth/security-keys/register/finish` | `/api/v1/auth/security-keys/register/finish` | POST |  |
| `/api/auth/security-keys/register/start` | `/api/v1/auth/security-keys/register/start` | POST |  |
| `/api/auth/security-keys/require-uv` | `/api/v1/auth/security-keys/require-uv` | PUT |  |
| `/api/auth/sessions` | `/api/v1/auth/sessions` | DELETE,GET |  |
| `/api/auth/sessions/:id` | `/api/v1/auth/sessions/:id` | DELETE |  |
| `/api/auth/sessions/current/local-key` | `/api/v1/auth/sessions/current/local-key` | GET,PUT |  |
| `/api/auth/settings` | `/api/v1/auth/settings` | GET |  |

#### Account

| Old | New | Methods | Note |
|---|---|---|---|
| `/api/user/me` | `/api/v1/account` | GET,PATCH |  |
| `/api/user/2fa` | `/api/v1/account/2fa` | DELETE |  |
| `/api/user/2fa/recovery-codes` | `/api/v1/account/2fa/recovery-codes` | GET,POST |  |
| `/api/user/2fa/setup` | `/api/v1/account/2fa/setup` | POST |  |
| `/api/user/2fa/verify` | `/api/v1/account/2fa/verify` | POST |  |
| `/api/user/close` | `/api/v1/account/close` | POST |  |
| `/api/user/consents` | `/api/v1/account/consents` | GET,PUT |  |
| `/api/devices` | `/api/v1/account/devices` | GET,POST |  |
| `/api/device-session` | `/api/v1/account/devices/session` | GET |  |
| `/api/device-ticket` | `/api/v1/account/devices/tickets` | POST |  |
| `/api/user/federation` | `/api/v1/account/federation` | PUT |  |
| `/api/account/head` | `/api/v1/account/head` | GET,POST |  |
| `/api/account/heads` | `/api/v1/account/heads` | GET |  |
| `/api/account/index/:scope` | `/api/v1/account/index/:scope` | GET |  |
| `/api/user/legal/acknowledge` | `/api/v1/account/legal/acknowledge` | POST |  |
| `/api/user/legal/pending` | `/api/v1/account/legal/pending` | GET |  |
| `/api/account/master-key/rotate` | `/api/v1/account/master-key/rotate` | POST |  |
| `/api/user/names` | `/api/v1/account/names` | GET |  |
| `/api/user/names/:name` | `/api/v1/account/names/:name` | DELETE |  |
| `/api/account/records` | `/api/v1/account/records` | POST |  |
| `/api/account/records/:scope` | `/api/v1/account/records/:scope` | GET |  |
| `/api/account/records/:scope/:id` | `/api/v1/account/records/:scope/:id` | GET |  |
| `/api/user/rename` | `/api/v1/account/rename` | POST |  |
| `/api/user/rename/check` | `/api/v1/account/rename/check` | GET |  |
| `/api/account/roots` | `/api/v1/account/roots` | GET |  |
| `/api/user/security-events` | `/api/v1/account/security-events` | GET |  |
| `/api/user/storage` | `/api/v1/account/storage` | GET |  |
| `/api/user/storage/versions` | `/api/v1/account/storage/versions` | GET |  |
| `/api/user/storage/versions/prune` | `/api/v1/account/storage/versions/prune` | POST |  |
| `/api/account/ui-preferences` | `/api/v1/account/ui-preferences` | GET,PUT |  |
| `/api/users/by-id/:accountId` | `/api/v1/accounts/:accountId` | GET |  |
| `/api/users/by-address/:address` | `/api/v1/accounts/by-address/:address` | GET |  |
| `/api/users/renames/:address` | `/api/v1/accounts/by-address/:address/renames` | GET |  |
| `/api/users/drive-identities` | `/api/v1/drive/identities` | POST |  |
| `/api/federation/policies/:feature` | `/api/v1/federation/policies/:feature` | GET |  |
| `/api/feedback` | `/api/v1/feedback` | POST |  |
| `/api/legal/documents` | `/api/v1/legal/documents` | GET |  |

#### Drive

| Old | New | Methods | Note |
|---|---|---|---|
| `/api/collections` | `/api/v1/drive/collections` | GET,POST |  |
| `/api/collections/:id` | `/api/v1/drive/collections/:id` | DELETE,GET,PUT |  |
| `/api/collections/:id/access` | `/api/v1/drive/collections/:id/access` | GET |  |
| `/api/collections/:id/available-hashes` | `/api/v1/drive/collections/:id/available-hashes` | POST |  |
| `/api/collections/:id/color` | `/api/v1/drive/collections/:id/color` | PATCH |  |
| `/api/collections/:id/epochs` | `/api/v1/drive/collections/:id/epochs` | GET |  |
| `/api/collections/:id/federated-shares` | `/api/v1/drive/collections/:id/federated-shares` | POST |  |
| `/api/collections/:id/files` | `/api/v1/drive/collections/:id/files` | GET |  |
| `/api/collections/:id/move` | `/api/v1/drive/collections/:id/move` | POST |  |
| `/api/collections/:id/rotate` | `/api/v1/drive/collections/:id/rotate` | POST |  |
| `/api/collections/:id/share` | `/api/v1/drive/collections/:id/share` | POST |  |
| `/api/drive/federation/file-shares` | `/api/v1/drive/federation/file-shares` | GET,POST |  |
| `/api/drive/federation/file-shares/:id` | `/api/v1/drive/federation/file-shares/:id` | DELETE,GET |  |
| `/api/drive/federation/file-shares/:id/assets/:assetId` | `/api/v1/drive/federation/file-shares/:id/assets/:assetId` | GET,PUT |  |
| `/api/drive/federation/file-shares/:id/claim-seed` | `/api/v1/drive/federation/file-shares/:id/claim-seed` | POST |  |
| `/api/drive/federation/file-shares/:id/collab/ws` | `/api/v1/drive/federation/file-shares/:id/collab/ws` | GET |  |
| `/api/drive/federation/file-shares/:id/content` | `/api/v1/drive/federation/file-shares/:id/content` | GET |  |
| `/api/drive/federation/file-shares/:id/state` | `/api/v1/drive/federation/file-shares/:id/state` | GET |  |
| `/api/drive/federation/file-shares/:id/versions` | `/api/v1/drive/federation/file-shares/:id/versions` | GET,POST |  |
| `/api/drive/federation/file-shares/:id/versions/:vid` | `/api/v1/drive/federation/file-shares/:id/versions/:vid` | PATCH |  |
| `/api/drive/federation/file-shares/:id/versions/:vid/download` | `/api/v1/drive/federation/file-shares/:id/versions/:vid/download` | GET |  |
| `/api/drive/federation/shares` | `/api/v1/drive/federation/folder-shares` | GET,POST |  |
| `/api/drive/federation/shares/:shareId` | `/api/v1/drive/federation/folder-shares/:shareId` | DELETE |  |
| `/api/drive/federation/shares/:shareId/album` | `/api/v1/drive/federation/folder-shares/:shareId/album` | GET |  |
| `/api/drive/federation/shares/:shareId/epochs` | `/api/v1/drive/federation/folder-shares/:shareId/epochs` | GET |  |
| `/api/drive/federation/shares/:shareId/files` | `/api/v1/drive/federation/folder-shares/:shareId/files` | GET,POST |  |
| `/api/drive/federation/shares/:shareId/files/:fileId` | `/api/v1/drive/federation/folder-shares/:shareId/files/:fileId` | DELETE |  |
| `/api/drive/federation/shares/:shareId/files/:fileId/assets/:assetId` | `/api/v1/drive/federation/folder-shares/:shareId/files/:fileId/assets/:assetId` | GET,PUT |  |
| `/api/drive/federation/shares/:shareId/files/:fileId/claim-seed` | `/api/v1/drive/federation/folder-shares/:shareId/files/:fileId/claim-seed` | POST |  |
| `/api/drive/federation/shares/:shareId/files/:fileId/collab/ws` | `/api/v1/drive/federation/folder-shares/:shareId/files/:fileId/collab/ws` | GET |  |
| `/api/drive/federation/shares/:shareId/files/:fileId/content` | `/api/v1/drive/federation/folder-shares/:shareId/files/:fileId/content` | GET |  |
| `/api/drive/federation/shares/:shareId/files/:fileId/state` | `/api/v1/drive/federation/folder-shares/:shareId/files/:fileId/state` | GET |  |
| `/api/drive/federation/shares/:shareId/files/:fileId/thumbnails/:variant` | `/api/v1/drive/federation/folder-shares/:shareId/files/:fileId/thumbnails/:variant` | GET |  |
| `/api/drive/federation/shares/:shareId/files/:fileId/versions` | `/api/v1/drive/federation/folder-shares/:shareId/files/:fileId/versions` | GET,POST |  |
| `/api/drive/federation/shares/:shareId/files/:fileId/versions/:vid` | `/api/v1/drive/federation/folder-shares/:shareId/files/:fileId/versions/:vid` | PATCH |  |
| `/api/drive/federation/shares/:shareId/files/:fileId/versions/:vid/download` | `/api/v1/drive/federation/folder-shares/:shareId/files/:fileId/versions/:vid/download` | GET |  |
| `/api/drive/federation/shares/:shareId/refresh` | `/api/v1/drive/federation/folder-shares/:shareId/refresh` | POST |  |
| `/api/drive/files` | `/api/v1/drive/files` | GET |  |
| `/api/files/upload` | `/api/v1/drive/files` | POST |  |
| `/api/files/:fileId/assets/:assetId` | `/api/v1/drive/files/:fileId/assets/:assetId` | GET,PUT |  |
| `/api/files/:fileId/claim-seed` | `/api/v1/drive/files/:fileId/claim-seed` | POST |  |
| `/api/files/:fileId/collab/frames` | `/api/v1/drive/files/:fileId/collab/frames` | GET,POST |  |
| `/api/files/:fileId/collab/ws` | `/api/v1/drive/files/:fileId/collab/ws` | GET |  |
| `/api/files/:fileId/thumbnails` | `/api/v1/drive/files/:fileId/thumbnails` | DELETE |  |
| `/api/files/:fileId/thumbnails/:variant` | `/api/v1/drive/files/:fileId/thumbnails/:variant` | GET,PUT |  |
| `/api/files/:fileId/versions` | `/api/v1/drive/files/:fileId/versions` | GET,POST |  |
| `/api/files/:fileId/versions/:vid` | `/api/v1/drive/files/:fileId/versions/:vid` | DELETE,PATCH |  |
| `/api/files/:fileId/versions/:vid/download` | `/api/v1/drive/files/:fileId/versions/:vid/download` | GET |  |
| `/api/files/:id` | `/api/v1/drive/files/:id` | DELETE,PUT |  |
| `/api/files/:id/access` | `/api/v1/drive/files/:id/access` | GET |  |
| `/api/files/:id/content-hash` | `/api/v1/drive/files/:id/content-hash` | PUT |  |
| `/api/files/:id/download` | `/api/v1/drive/files/:id/download` | GET |  |
| `/api/files/:id/federated-shares` | `/api/v1/drive/files/:id/federated-shares` | POST |  |
| `/api/files/:id/move` | `/api/v1/drive/files/:id/move` | POST |  |
| `/api/files/:id/original` | `/api/v1/drive/files/:id/original` | GET |  |
| `/api/files/:id/rekey` | `/api/v1/drive/files/:id/rekey` | POST |  |
| `/api/files/:id/revisions/:revisionId/commit` | `/api/v1/drive/files/:id/revisions/:revisionId/commit` | POST |  |
| `/api/files/:id/rotate` | `/api/v1/drive/files/:id/rotate` | POST |  |
| `/api/files/:id/share` | `/api/v1/drive/files/:id/share` | POST |  |
| `/api/files/:id/shares` | `/api/v1/drive/files/:id/shares` | PUT |  |
| `/api/files/:id/sharing` | `/api/v1/drive/files/:id/sharing` | PUT |  |
| `/api/drive/limits` | `/api/v1/drive/limits` | GET |  |
| `/api/drive/people` | `/api/v1/drive/people` | GET |  |
| `/api/drive/profile-keys` | `/api/v1/drive/profile-keys` | PUT |  |
| `/api/share` | `/api/v1/drive/public-links` | POST |  |
| `/api/share/:token` | `/api/v1/drive/public-links/:token` | GET |  |
| `/api/share/:token/album` | `/api/v1/drive/public-links/:token/album` | GET |  |
| `/api/share/:token/epochs` | `/api/v1/drive/public-links/:token/epochs` | GET |  |
| `/api/share/:token/files` | `/api/v1/drive/public-links/:token/files` | GET |  |
| `/api/share/:token/files/:fileId/assets/:assetId` | `/api/v1/drive/public-links/:token/files/:fileId/assets/:assetId` | GET |  |
| `/api/share/:token/download/:fileId` | `/api/v1/drive/public-links/:token/files/:fileId/download` | GET |  |
| `/api/share/:token/state/:fileId` | `/api/v1/drive/public-links/:token/files/:fileId/state` | GET |  |
| `/api/share/:token/thumbnails/:fileId/:variant` | `/api/v1/drive/public-links/:token/files/:fileId/thumbnails/:variant` | GET |  |
| `/api/share/:token/report` | `/api/v1/drive/public-links/:token/report` | POST |  |
| `/api/shared-by-me` | `/api/v1/drive/shared-by-me` | GET |  |
| `/api/shared-files` | `/api/v1/drive/shared-with-me` | GET |  |
| `/api/file-shares/pending` | `/api/v1/drive/shared-with-me/pending` | GET |  |
| `/api/drive/top-level-available-hashes` | `/api/v1/drive/top-level-available-hashes` | POST |  |
| `/api/trash` | `/api/v1/drive/trash` | DELETE,GET |  |
| `/api/trash/:id` | `/api/v1/drive/trash/:id` | DELETE |  |
| `/api/trash/:id/restore` | `/api/v1/drive/trash/:id/restore` | POST |  |
| `/api/uploads` | `/api/v1/drive/uploads` | POST |  |
| `/api/uploads/:id` | `/api/v1/drive/uploads/:id` | DELETE,HEAD,PATCH |  |

#### Photos

| Old | New | Methods | Note |
|---|---|---|---|
| `/api/albums` | `/api/v1/photos/albums` | GET,POST |  |
| `/api/albums/:id` | `/api/v1/photos/albums/:id` | DELETE |  |
| `/api/albums/:id/items` | `/api/v1/photos/albums/:id/items` | GET,POST |  |
| `/api/albums/:id/items/remove` | `/api/v1/photos/albums/:id/items/remove` | POST |  |
| `/api/albums/:id/keys` | `/api/v1/photos/albums/:id/keys` | GET |  |
| `/api/albums/:id/membership` | `/api/v1/photos/albums/:id/membership` | DELETE |  |
| `/api/photos/preferences` | `/api/v1/photos/preferences` | GET,PUT |  |

#### Chat

| Old | New | Methods | Note |
|---|---|---|---|
| `/api/chat/account-identity` | `/api/v1/chat/account-identity` | PUT |  |
| `/api/chat/accounts/:account_id/keys` | `/api/v1/chat/accounts/:accountId/keys` | GET |  |
| `/api/chat/accounts/:account_id/manifest` | `/api/v1/chat/accounts/:accountId/manifest` | GET |  |
| `/api/chat/accounts/:account_id/manifest-history` | `/api/v1/chat/accounts/:accountId/manifest-history` | GET |  |
| `/api/chat/accounts/:account_id/messages` | `/api/v1/chat/accounts/:accountId/messages` | POST |  |
| `/api/chat/accounts/:account_id/profile/:version` | `/api/v1/chat/accounts/:accountId/profile/:version` | GET |  |
| `/api/chat/anonymous/accounts/:account_id/keys` | `/api/v1/chat/anonymous/accounts/:accountId/keys` | POST |  |
| `/api/chat/anonymous/accounts/:account_id/messages` | `/api/v1/chat/anonymous/accounts/:accountId/messages` | POST |  |
| `/api/chat/anonymous/messages/batch` | `/api/v1/chat/anonymous/messages/batch` | POST |  |
| `/api/chat/anonymous/messages/multi` | `/api/v1/chat/anonymous/messages/multi` | POST |  |
| `/api/chat/backup` | `/api/v1/chat/backup` | GET,POST |  |
| `/api/chat/backup/bases` | `/api/v1/chat/backup/bases` | POST |  |
| `/api/chat/backup/bases/:objectId` | `/api/v1/chat/backup/bases/:objectId` | GET |  |
| `/api/chat/backup/manifest` | `/api/v1/chat/backup/manifest` | PUT |  |
| `/api/chat/backup/media` | `/api/v1/chat/backup/media` | POST |  |
| `/api/chat/backup/media/:mediaId` | `/api/v1/chat/backup/media/:mediaId` | GET |  |
| `/api/chat/backup/media/copy` | `/api/v1/chat/backup/media/copy` | POST |  |
| `/api/chat/backup/media/reconciliation` | `/api/v1/chat/backup/media/reconciliation` | POST |  |
| `/api/chat/backup/segments` | `/api/v1/chat/backup/segments` | GET,POST |  |
| `/api/chat/call-links` | `/api/v1/chat/call-links` | GET,POST |  |
| `/api/chat/call-links/:room_id` | `/api/v1/chat/call-links/:roomId` | DELETE |  |
| `/api/chat/call-links/:room_id/info` | `/api/v1/chat/call-links/:roomId/info` | PUT |  |
| `/api/chat/call-links/:room_id/waiting-room` | `/api/v1/chat/call-links/:roomId/waiting-room` | PUT |  |
| `/api/chat/call-links/co-hosts` | `/api/v1/chat/call-links/co-hosts` | POST |  |
| `/api/chat/call-links/end` | `/api/v1/chat/call-links/end` | POST |  |
| `/api/chat/call-links/info` | `/api/v1/chat/call-links/info` | POST |  |
| `/api/chat/call-links/knock` | `/api/v1/chat/call-links/knock` | POST |  |
| `/api/chat/call-links/knock/leave` | `/api/v1/chat/call-links/knock/leave` | POST |  |
| `/api/chat/call-links/knock/status` | `/api/v1/chat/call-links/knock/status` | POST |  |
| `/api/chat/call-links/knocks` | `/api/v1/chat/call-links/knocks` | POST |  |
| `/api/chat/call-links/knocks/decide` | `/api/v1/chat/call-links/knocks/decide` | POST |  |
| `/api/chat/call-links/lock` | `/api/v1/chat/call-links/lock` | POST |  |
| `/api/chat/call-links/participants/mute` | `/api/v1/chat/call-links/participants/mute` | POST |  |
| `/api/chat/call-links/participants/remove` | `/api/v1/chat/call-links/participants/remove` | POST |  |
| `/api/chat/call-links/participants/screen` | `/api/v1/chat/call-links/participants/screen` | POST |  |
| `/api/chat/call-links/roles` | `/api/v1/chat/call-links/roles` | POST |  |
| `/api/chat/call-links/token` | `/api/v1/chat/call-links/token` | POST |  |
| `/api/chat/call-servers` | `/api/v1/chat/call-servers` | GET |  |
| `/api/chat/device` | `/api/v1/chat/devices` | GET,POST |  |
| `/api/chat/device/:deviceId` | `/api/v1/chat/devices/:deviceId` | DELETE,PATCH |  |
| `/api/chat/group-calls/token` | `/api/v1/chat/group-calls/token` | POST |  |
| `/api/chat/group-send/endorsement` | `/api/v1/chat/group-send/endorsement` | GET |  |
| `/api/chat/group-send/params` | `/api/v1/chat/group-send/params` | GET |  |
| `/api/chat/groups/gateway-key` | `/api/v1/chat/groups/gateway-key` | GET |  |
| `/api/chat/groups/relay/:server` | `/api/v1/chat/groups/relay/:server` | POST |  |
| `/api/chat/keys` | `/api/v1/chat/keys` | PUT |  |
| `/api/chat/keys/check` | `/api/v1/chat/keys/check` | POST |  |
| `/api/chat/keys/count` | `/api/v1/chat/keys/count` | GET |  |
| `/api/chat/link-preview` | `/api/v1/chat/link-preview` | POST |  |
| `/api/chat/link-tokens` | `/api/v1/chat/link-tokens` | POST |  |
| `/api/live-locations` | `/api/v1/chat/live-locations` | POST |  |
| `/api/live-locations/:streamId` | `/api/v1/chat/live-locations/:streamId` | DELETE,GET,PUT |  |
| `/api/chat/manifest` | `/api/v1/chat/manifest` | POST |  |
| `/api/chat/media/deliveries` | `/api/v1/chat/media/deliveries` | POST |  |
| `/api/chat/media/objects/:attachmentId` | `/api/v1/chat/media/objects/:attachmentId` | DELETE,GET |  |
| `/api/chat/media/references/:attachmentId` | `/api/v1/chat/media/references/:attachmentId` | DELETE,GET |  |
| `/api/chat/media/storage` | `/api/v1/chat/media/storage` | GET |  |
| `/api/chat/media/uploads` | `/api/v1/chat/media/uploads` | POST |  |
| `/api/chat/media/uploads/:id` | `/api/v1/chat/media/uploads/:id` | DELETE,HEAD,PATCH |  |
| `/api/chat/messages` | `/api/v1/chat/messages` | GET |  |
| `/api/chat/messages/ack` | `/api/v1/chat/messages/ack` | POST |  |
| `/api/chat/profile` | `/api/v1/chat/profile` | GET,PUT |  |
| `/api/chat/provisioning` | `/api/v1/chat/provisioning` | GET |  |
| `/api/chat/provisioning/:address` | `/api/v1/chat/provisioning/:address` | PUT |  |
| `/api/chat/provisioning/ticket` | `/api/v1/chat/provisioning/ticket` | POST |  |
| `/api/chat/push-subscription` | `/api/v1/chat/push-subscription` | DELETE,PUT |  |
| `/api/chat/sealed-sender/certificate` | `/api/v1/chat/sealed-sender/certificate` | POST |  |
| `/api/chat/sealed-sender/domains/:domain/policy` | `/api/v1/chat/sealed-sender/servers/:server/policy` | GET |  |
| `/api/chat/sync/messages` | `/api/v1/chat/sync/messages` | POST |  |
| `/api/chat/ws` | `/api/v1/chat/ws` | GET |  |

#### Mail

| Old | New | Methods | Note |
|---|---|---|---|
| `/api/mail/accounts` | `/api/v1/mail/accounts` | GET |  |
| `/api/mail/addresses` | `/api/v1/mail/addresses` | GET |  |
| `/api/mail/addresses/:address/forwarding-keys/:key` | `/api/v1/mail/addresses/:address/forwarding-keys/:key` | DELETE |  |
| `/api/mail/addresses/:id/delete` | `/api/v1/mail/addresses/:id/delete` | PUT |  |
| `/api/mail/addresses/:id/disable` | `/api/v1/mail/addresses/:id/disable` | PUT |  |
| `/api/mail/addresses/:id/enable` | `/api/v1/mail/addresses/:id/enable` | PUT |  |
| `/api/mail/addresses/:id/key-list` | `/api/v1/mail/addresses/:id/key-list` | PUT |  |
| `/api/mail/addresses/:id/keys` | `/api/v1/mail/addresses/:id/keys` | POST |  |
| `/api/mail/addresses/order` | `/api/v1/mail/addresses/order` | PUT |  |
| `/api/mail/auto-reply` | `/api/v1/mail/auto-reply` | GET,PUT |  |
| `/api/mail/counts` | `/api/v1/mail/counts` | GET |  |
| `/api/mail/domains` | `/api/v1/mail/domains` | GET,POST |  |
| `/api/mail/domains/:id` | `/api/v1/mail/domains/:id` | DELETE,GET |  |
| `/api/mail/domains/:id/catch-all` | `/api/v1/mail/domains/:id/catch-all` | PUT |  |
| `/api/mail/domains/addresses` | `/api/v1/mail/domains/addresses` | POST |  |
| `/api/mail/drafts` | `/api/v1/mail/drafts` | POST |  |
| `/api/mail/drafts/:id` | `/api/v1/mail/drafts/:id` | PUT |  |
| `/api/mail/drafts/:id/attachments` | `/api/v1/mail/drafts/:id/attachments` | GET,POST |  |
| `/api/mail/drafts/:id/attachments/:attachment` | `/api/v1/mail/drafts/:id/attachments/:attachment` | DELETE,GET |  |
| `/api/mail/filters` | `/api/v1/mail/filters` | GET,POST |  |
| `/api/mail/filters/:id` | `/api/v1/mail/filters/:id` | DELETE,PATCH |  |
| `/api/mail/filters/apply` | `/api/v1/mail/filters/apply` | POST |  |
| `/api/mail/filters/order` | `/api/v1/mail/filters/order` | PUT |  |
| `/api/mail/filters/runs/:id` | `/api/v1/mail/filters/runs/:id` | GET |  |
| `/api/mail/folders` | `/api/v1/mail/folders` | POST |  |
| `/api/mail/folders/:id` | `/api/v1/mail/folders/:id` | DELETE,PATCH |  |
| `/api/mail/forwardings` | `/api/v1/mail/forwardings` | GET,POST |  |
| `/api/mail/forwardings/:id` | `/api/v1/mail/forwardings/:id` | DELETE,PUT |  |
| `/api/mail/forwardings/:id/accept` | `/api/v1/mail/forwardings/:id/accept` | POST |  |
| `/api/mail/forwardings/:id/activation` | `/api/v1/mail/forwardings/:id/activation` | GET |  |
| `/api/mail/forwardings/:id/code` | `/api/v1/mail/forwardings/:id/code` | POST |  |
| `/api/mail/forwardings/:id/conditions` | `/api/v1/mail/forwardings/:id/conditions` | PUT |  |
| `/api/mail/forwardings/:id/decline` | `/api/v1/mail/forwardings/:id/decline` | POST |  |
| `/api/mail/forwardings/:id/pause` | `/api/v1/mail/forwardings/:id/pause` | PUT |  |
| `/api/mail/forwardings/:id/reinvite` | `/api/v1/mail/forwardings/:id/reinvite` | PUT |  |
| `/api/mail/forwardings/:id/resume` | `/api/v1/mail/forwardings/:id/resume` | PUT |  |
| `/api/mail/forwardings/:id/verify` | `/api/v1/mail/forwardings/:id/verify` | POST |  |
| `/api/mail/forwardings/external` | `/api/v1/mail/forwardings/external` | POST |  |
| `/api/mail/forwardings/external/decline` | `/api/v1/mail/forwardings/external/decline` | POST |  |
| `/api/mail/groups` | `/api/v1/mail/groups` | GET |  |
| `/api/mail/groups/:id` | `/api/v1/mail/groups/:id` | GET,PATCH |  |
| `/api/mail/groups/:id/keys` | `/api/v1/mail/groups/:id/keys` | GET,POST |  |
| `/api/mail/groups/:id/members` | `/api/v1/mail/groups/:id/members` | PUT |  |
| `/api/mail/groups/directory` | `/api/v1/mail/groups/directory` | GET |  |
| `/api/mail/groups/recipients` | `/api/v1/mail/groups/recipients` | GET |  |
| `/api/mail/identity` | `/api/v1/mail/identity` | GET,PATCH |  |
| `/api/mail/image-senders` | `/api/v1/mail/image-senders` | GET,POST |  |
| `/api/mail/image-senders/delete` | `/api/v1/mail/image-senders/delete` | POST |  |
| `/api/mail/images` | `/api/v1/mail/images` | POST |  |
| `/api/mail/keys` | `/api/v1/mail/keys` | GET |  |
| `/api/mail/keys/outside` | `/api/v1/mail/keys/outside` | GET |  |
| `/api/mail/labels` | `/api/v1/mail/labels` | POST |  |
| `/api/mail/labels/:id` | `/api/v1/mail/labels/:id` | DELETE,PATCH |  |
| `/api/mail/messages` | `/api/v1/mail/messages` | GET,PATCH |  |
| `/api/mail/messages/:id/content` | `/api/v1/mail/messages/:id/content` | GET |  |
| `/api/mail/messages/:id/receipt` | `/api/v1/mail/messages/:id/receipt` | POST |  |
| `/api/mail/messages/:id/unsubscribe` | `/api/v1/mail/messages/:id/unsubscribe` | POST |  |
| `/api/mail/messages/batch` | `/api/v1/mail/messages/batch` | POST |  |
| `/api/mail/messages/delete` | `/api/v1/mail/messages/delete` | POST |  |
| `/api/mail/messages/empty` | `/api/v1/mail/messages/empty` | POST |  |
| `/api/mail/messages/snooze` | `/api/v1/mail/messages/snooze` | POST |  |
| `/api/mail/notifications` | `/api/v1/mail/notifications` | GET |  |
| `/api/mail/outbox/:id` | `/api/v1/mail/outbox/:id` | GET |  |
| `/api/mail/outbox/:id/cancel` | `/api/v1/mail/outbox/:id/cancel` | POST |  |
| `/api/mail/places` | `/api/v1/mail/places` | GET |  |
| `/api/mail/search-addresses` | `/api/v1/mail/search-addresses` | GET |  |
| `/api/mail/search-index` | `/api/v1/mail/search-index` | GET |  |
| `/api/mail/search-index/changes` | `/api/v1/mail/search-index/changes` | GET |  |
| `/api/mail/send` | `/api/v1/mail/send` | POST |  |
| `/api/mail/sender-rules` | `/api/v1/mail/sender-rules` | GET,POST |  |
| `/api/mail/sender-rules/:id` | `/api/v1/mail/sender-rules/:id` | PATCH |  |
| `/api/mail/sender-rules/delete` | `/api/v1/mail/sender-rules/delete` | POST |  |
| `/api/mail/sending` | `/api/v1/mail/sending` | GET |  |
| `/api/mail/settings` | `/api/v1/mail/settings` | GET,PATCH |  |
| `/api/mail/threads/:id` | `/api/v1/mail/threads/:id` | GET |  |

#### Calendar, Contacts, Pass, Maps

| Old | New | Methods | Note |
|---|---|---|---|
| `/api/calendar/alarms` | `/api/v1/calendar/alarms` | GET |  |
| `/api/calendar/calendars` | `/api/v1/calendar/calendars` | GET,POST |  |
| `/api/calendar/calendars/:id` | `/api/v1/calendar/calendars/:id` | DELETE,PUT |  |
| `/api/calendar/calendars/:id/events` | `/api/v1/calendar/calendars/:id/events` | GET |  |
| `/api/calendar/calendars/:id/events/:event_id` | `/api/v1/calendar/calendars/:id/events/:eventId` | GET |  |
| `/api/calendar/calendars/:id/events/sync` | `/api/v1/calendar/calendars/:id/events/sync` | POST |  |
| `/api/calendar/push-subscription` | `/api/v1/calendar/push-subscription` | DELETE,PUT |  |
| `/api/calendar/settings` | `/api/v1/calendar/settings` | GET,PUT |  |
| `/api/contacts` | `/api/v1/contacts` | GET,POST |  |
| `/api/contacts/:id` | `/api/v1/contacts/:id` | DELETE,PUT |  |
| `/api/contacts/delete` | `/api/v1/contacts/delete` | POST |  |
| `/api/contacts/emails` | `/api/v1/contacts/emails` | GET |  |
| `/api/contacts/import` | `/api/v1/contacts/import` | POST |  |
| `/api/maps` | `/api/v1/maps` | GET |  |
| `/api/maps/preferences` | `/api/v1/maps/preferences` | PUT |  |
| `/api/maps/proxy/:provider/*path` | `/api/v1/maps/proxy/:provider/*path` | GET |  |
| `/api/pass/icon` | `/api/v1/pass/icon` | POST |  |
| `/api/pass/pin` | `/api/v1/pass/pin` | DELETE,PUT |  |
| `/api/pass/pin` | `/api/v1/pass/pin` | GET |  |
| `/api/pass/pin/verify` | `/api/v1/pass/pin/verify` | POST |  |
| `/api/pass/settings` | `/api/v1/pass/settings` | GET,PUT |  |
| `/api/pass/vault-states` | `/api/v1/pass/vault-states` | GET |  |

#### Admin

| Old | New | Methods | Note |
|---|---|---|---|
| `/api/admin/users` | `/api/v1/admin/accounts` | GET,POST |  |
| `/api/admin/users/:id` | `/api/v1/admin/accounts/:id` | DELETE,PUT |  |
| `/api/admin/users/:id/2fa` | `/api/v1/admin/accounts/:id/2fa` | DELETE |  |
| `/api/admin/users/:id/close` | `/api/v1/admin/accounts/:id/close` | POST |  |
| `/api/admin/users/:id/limits` | `/api/v1/admin/accounts/:id/entitlements` | GET |  |
| `/api/admin/users/:id/limits/:key` | `/api/v1/admin/accounts/:id/entitlements/:key` | PUT |  |
| `/api/admin/users/:id/legal-hold` | `/api/v1/admin/accounts/:id/legal-hold` | DELETE,PUT |  |
| `/api/admin/users/:id/mail-domains` | `/api/v1/admin/accounts/:id/mail-domains` | GET,PUT |  |
| `/api/admin/users/:id/mail-sending` | `/api/v1/admin/accounts/:id/mail-sending` | GET,PUT |  |
| `/api/admin/users/:id/registration-code` | `/api/v1/admin/accounts/:id/registration-code` | GET |  |
| `/api/admin/users/:id/reset-grant` | `/api/v1/admin/accounts/:id/reset-grant` | POST |  |
| `/api/admin/users/:id/wipe` | `/api/v1/admin/accounts/:id/reset-keys` | POST |  |
| `/api/admin/users/:id/rotate-temp-password` | `/api/v1/admin/accounts/:id/rotate-temp-password` | POST |  |
| `/api/admin/activity` | `/api/v1/admin/activity` | GET |  |
| `/api/admin/activity/export` | `/api/v1/admin/activity/export` | GET |  |
| `/api/admin/activity/verify` | `/api/v1/admin/activity/verify` | GET |  |
| `/api/admin/federation` | `/api/v1/admin/federation` | GET,PUT |  |
| `/api/admin/federation/peers/:domain/evidence` | `/api/v1/admin/federation/peers/:domain/evidence` | GET |  |
| `/api/admin/federation/peers/:domain/repin` | `/api/v1/admin/federation/peers/:domain/repin` | POST |  |
| `/api/admin/federation/peers/:domain/retry` | `/api/v1/admin/federation/peers/:domain/retry` | POST |  |
| `/api/admin/federation/peers/:domain/verify` | `/api/v1/admin/federation/peers/:domain/verify` | POST |  |
| `/api/admin/federation/peers/retry` | `/api/v1/admin/federation/peers/retry` | POST |  |
| `/api/admin/federation/rules/:feature/:domain` | `/api/v1/admin/federation/rules/:feature/:domain` | DELETE,PUT |  |
| `/api/admin/feedback` | `/api/v1/admin/feedback` | GET |  |
| `/api/admin/feedback/:id` | `/api/v1/admin/feedback/:id` | DELETE |  |
| `/api/admin/feedback/:id/resolve` | `/api/v1/admin/feedback/:id/resolve` | POST |  |
| `/api/admin/legal/documents` | `/api/v1/admin/legal/documents` | GET,POST |  |
| `/api/admin/mail/domains` | `/api/v1/admin/mail/domains` | GET |  |
| `/api/admin/mail/domains/:id/approve` | `/api/v1/admin/mail/domains/:id/approve` | POST |  |
| `/api/admin/mail/domains/:id/deactivate` | `/api/v1/admin/mail/domains/:id/deactivate` | POST |  |
| `/api/admin/mail/domains/blocks` | `/api/v1/admin/mail/domains/blocks` | GET |  |
| `/api/admin/mail/domains/blocks/:name` | `/api/v1/admin/mail/domains/blocks/:name` | DELETE |  |
| `/api/admin/mail/domains/settings` | `/api/v1/admin/mail/domains/settings` | PUT |  |
| `/api/admin/mail/groups` | `/api/v1/admin/mail/groups` | GET,POST |  |
| `/api/admin/mail/groups/:id` | `/api/v1/admin/mail/groups/:id` | DELETE,PATCH |  |
| `/api/admin/mail/outside-sending` | `/api/v1/admin/mail/outside-sending` | GET,PUT |  |
| `/api/admin/mail/senders` | `/api/v1/admin/mail/senders` | GET |  |
| `/api/admin/maps` | `/api/v1/admin/maps` | GET,PUT |  |
| `/api/admin/names/:name/close` | `/api/v1/admin/names/:name/close` | POST |  |
| `/api/admin/names/:name/free` | `/api/v1/admin/names/:name/free` | POST |  |
| `/api/admin/shares/:id/block` | `/api/v1/admin/public-links/:id/block` | DELETE,POST |  |
| `/api/admin/rate-limits` | `/api/v1/admin/rate-limits` | GET |  |
| `/api/admin/rate-limits/:key` | `/api/v1/admin/rate-limits/:key` | PUT |  |
| `/api/admin/registration-codes` | `/api/v1/admin/registration-codes` | GET,POST |  |
| `/api/admin/registration-codes/:id/revoke` | `/api/v1/admin/registration-codes/:id/revoke` | POST |  |
| `/api/admin/registration-codes/:id/uses` | `/api/v1/admin/registration-codes/:id/uses` | GET |  |
| `/api/admin/reports` | `/api/v1/admin/reports` | GET |  |
| `/api/admin/reports/:id/dismiss` | `/api/v1/admin/reports/:id/dismiss` | POST |  |
| `/api/admin/reports/:id/remove-link` | `/api/v1/admin/reports/:id/remove-link` | POST |  |
| `/api/admin/settings` | `/api/v1/admin/settings` | GET,PUT |  |
| `/api/admin/settings/registry` | `/api/v1/admin/settings/registry` | GET |  |
| `/api/admin/stats` | `/api/v1/admin/stats` | GET |  |

#### Federation

| Old | New | Methods | Note |
|---|---|---|---|
| (new) | `/api/fed/v2/accounts/lookup?name=` | GET | §3: the one name → account lookup |
| `/api/fed/chat/names/:username/renames` | (dropped) | GET | folded into accounts/lookup |
| `/api/fed/drive/names/:username/renames` | (dropped) | GET | folded into accounts/lookup |
| `/api/fed/drive/users/:username` | (dropped) | GET | → /api/fed/v2/accounts/lookup?name= |
| `/api/fed/chat/accounts/renames` | `/api/fed/v2/accounts/renames` | POST | chat+drive copies become one |
| `/api/fed/drive/accounts/renames` | `/api/fed/v2/accounts/renames` | POST | chat+drive copies become one |
| `/api/fed/chat/accounts/:account_id/keys` | `/api/fed/v2/chat/accounts/:accountId/keys` | GET |  |
| `/api/fed/chat/accounts/:account_id/manifest` | `/api/fed/v2/chat/accounts/:accountId/manifest` | GET |  |
| `/api/fed/chat/accounts/:account_id/manifest-history` | `/api/fed/v2/chat/accounts/:accountId/manifest-history` | GET |  |
| `/api/fed/chat/accounts/:account_id/profile/:version` | `/api/fed/v2/chat/accounts/:accountId/profile/:version` | GET |  |
| `/api/fed/chat/group-calls/token` | `/api/fed/v2/chat/group-calls/token` | POST |  |
| `/api/fed/chat/groups/gateway` | `/api/fed/v2/chat/groups/gateway` | POST |  |
| `/api/fed/chat/groups/gateway-key` | `/api/fed/v2/chat/groups/gateway-key` | GET |  |
| `/api/fed/chat/live-locations/:streamId` | `/api/fed/v2/chat/live-locations/:streamId` | GET |  |
| `/api/fed/chat/media/objects` | `/api/fed/v2/chat/media/objects` | POST |  |
| `/api/fed/chat/media/offers` | `/api/fed/v2/chat/media/offers` | POST |  |
| `/api/fed/chat/messages` | `/api/fed/v2/chat/messages` | POST |  |
| `/api/fed/chat/sealed/accounts/:account_id/keys` | `/api/fed/v2/chat/sealed/accounts/:accountId/keys` | POST |  |
| `/api/fed/chat/sealed/batch` | `/api/fed/v2/chat/sealed/batch` | POST |  |
| `/api/fed/chat/sealed/messages` | `/api/fed/v2/chat/sealed/messages` | POST |  |
| `/api/fed/chat/sealed/multi` | `/api/fed/v2/chat/sealed/multi` | POST |  |
| `/api/fed/drive/accounts/:accountId` | `/api/fed/v2/drive/accounts/:accountId` | GET |  |
| `/api/fed/drive/collab/assets/create` | `/api/fed/v2/drive/collab/assets/create` | POST |  |
| `/api/fed/drive/collab/claim-seed` | `/api/fed/v2/drive/collab/claim-seed` | POST |  |
| `/api/fed/drive/collab/files/:fileId/assets/:assetId` | `/api/fed/v2/drive/collab/files/:fileId/assets/:assetId` | GET |  |
| `/api/fed/drive/collab/files/:fileId/versions/:vid` | `/api/fed/v2/drive/collab/files/:fileId/versions/:vid` | GET |  |
| `/api/fed/drive/collab/frames` | `/api/fed/v2/drive/collab/frames` | POST |  |
| `/api/fed/drive/collab/log` | `/api/fed/v2/drive/collab/log` | POST |  |
| `/api/fed/drive/collab/push` | `/api/fed/v2/drive/collab/push` | POST |  |
| `/api/fed/drive/collab/subscribe` | `/api/fed/v2/drive/collab/subscribe` | POST |  |
| `/api/fed/drive/collab/unsubscribe` | `/api/fed/v2/drive/collab/unsubscribe` | POST |  |
| `/api/fed/drive/collab/versions/create` | `/api/fed/v2/drive/collab/versions/create` | POST |  |
| `/api/fed/drive/collab/versions/list` | `/api/fed/v2/drive/collab/versions/list` | POST |  |
| `/api/fed/drive/collab/versions/patch` | `/api/fed/v2/drive/collab/versions/patch` | POST |  |
| `/api/fed/drive/file-content` | `/api/fed/v2/drive/file-shares/content` | GET |  |
| `/api/fed/drive/file-invite` | `/api/fed/v2/drive/file-shares/invite` | GET |  |
| `/api/fed/drive/file-state` | `/api/fed/v2/drive/file-shares/state` | GET |  |
| `/api/fed/drive/album` | `/api/fed/v2/drive/folder-shares/album` | GET |  |
| `/api/fed/drive/epochs` | `/api/fed/v2/drive/folder-shares/epochs` | GET |  |
| `/api/fed/drive/files` | `/api/fed/v2/drive/folder-shares/files` | GET,POST |  |
| `/api/fed/drive/files/:fileId` | `/api/fed/v2/drive/folder-shares/files/:fileId` | DELETE |  |
| `/api/fed/drive/files/:fileId/content` | `/api/fed/v2/drive/folder-shares/files/:fileId/content` | GET |  |
| `/api/fed/drive/files/:fileId/state` | `/api/fed/v2/drive/folder-shares/files/:fileId/state` | GET |  |
| `/api/fed/drive/files/:fileId/thumbnails/:variant` | `/api/fed/v2/drive/folder-shares/files/:fileId/thumbnails/:variant` | GET |  |
| `/api/fed/drive/invite` | `/api/fed/v2/drive/folder-shares/invite` | GET |  |
| `/api/fed/drive/profile-keys` | `/api/fed/v2/drive/profile-keys` | PUT |  |
| `/api/fed/policies/:feature` | `/api/fed/v2/policies/:feature` | GET |  |

## 3. Name-keyed federation routes

Today a name becomes a remote account in two route families. Both are
Drive's or Chat's, though the account is neither's:
- `GET /api/fed/drive/users/:username`: Drive's account lookup by name.
  The client's `GET /api/users/by-address/:address` reaches it for any
  remote address, so a Chat-only federation (Drive off) can't resolve
  addresses on that peer. A bug this fixes.
- `GET /api/fed/{chat,drive}/names/:username/renames`: the rename chains
  naming a held name. These are the same route under two features.
- Beside them, the announcement `POST /api/fed/{chat,drive}/accounts/renames`
  is also one route under two names.

**Decision:** one account namespace, admitted under either feature's
policy, as renames already are.

| Route | What |
|---|---|
| `GET /api/fed/v2/accounts/lookup?name=<name>` | The one name → account step: `{server, accountId, address, renames: [chain…]}`. A held or moved name answers its rename chains (today's `names/…/renames` answer, keyed by `(server, accountId)` after W7 §1.3); an unknown name `404`. The name is a query parameter: a lookup, not a resource. |
| `POST /api/fed/v2/accounts/renames` | The rename announcement, once. |
| `GET /api/fed/v2/drive/accounts/:accountId` | Drive's keys for an account, by id only (unchanged but for the prefix). |
| `GET /api/fed/v2/chat/accounts/:accountId/…` | Chat's keys, manifest and profile, by id only (unchanged). |

- The Drive caller (`remote_user_by_name`) now takes two steps: the lookup,
  then Drive's keys by id. The second step is cached per account like every
  id-keyed fetch, so a new address costs one extra signed request once.
- The `incarnationId` filter of the renames route becomes an `accountId`
  filter (W7 re-keys `remote_account_renames`).
- **Dropped:**
  - `/api/fed/drive/users/:username`;
  - both `names/:username/renames`;
  - the per-feature `accounts/renames` copies;
  - `mls-ordering`'s last test mention.

## 4. JSON field names

### 4.1 Rule

The API's names are W7's column names in camelCase, so the database, the
API and the clients say one thing:
- **A local account is `<role>AccountId`.**
  - The account a response is about, or the signed-in one, is `accountId`.
  - Roles: `ownerAccountId`, `uploaderAccountId`, `recipientAccountId`,
    `sharerAccountId`, `senderAccountId`, `authorAccountId`,
    `targetAccountId`, `adminAccountId`, `originAccountId`.
  - Actors are `<verb>ByAccountId` (`addedByAccountId`, `createdByAccountId`, …).
- **A remote account is `{<role>Server, <role>AccountId}`.**
  - A display address beside it is `<role>Address` (`user@server`): a label,
    never a key.
  - `username` stays only where it is the name itself (sign-in, rename,
    the names list) and in a display `address`.
- **`ownerId` names its kind.** `ownerAccountId`, or `mailboxOwner` for
  Mail's account-or-group (W7).
- **Enum values in JSON are camelCase** (already W7's rule for stored
  values; the API follows).
- Query parameters follow the same names (`?accountId=`, `?server=`).
- No aliases. The old names are refused, not accepted silently: every
  struct gets `#[serde(deny_unknown_fields)]` on requests where it is not
  already there, so a missed rename fails a test rather than dropping a
  field.

### 4.2 Changed fields

Counts are server structs (S), CLI declarations (C) and frontend type
declarations (F). Struct locations are in the inventory notes; a builder
greps the wire name.

| Old | New | S | C | F | Note |
|---|---|---|---|---|---|
| `userId` | `accountId` | 16 | 2 | 26 | login, complete-setup, fork consume, mail groups and sending, folder and file access, feedback, registration codes, the JWT claim, collab peers |
| `username` | `name` (own sign-in name); `address` where shown as `name@server` | 15 | 4 | 20 | `IceServer.username` (TURN credential, calls.rs:40) is **not** renamed |
| `ownerUserId` | `ownerAccountId` | 10 | 4 | 16 | collections, trash, public links, federated shares, link reports |
| `uploaderUserId` | `uploaderAccountId` | 2 | 0 | 3 | |
| `recipientUserId` | `recipientAccountId` | 2 | 1 | (literals) | |
| `sharerUserId` | `sharerAccountId` | 1 | 0 | 1 | |
| `collectionOwnerUserId` | `collectionOwnerAccountId` | 1 | 1 | 1 | |
| `authorUserId` | `authorAccountId` | 1 | 1 | 2 | |
| `targetUserId`, `targetUsername` | `targetAccountId`, `targetAddress` | 1 each | 0 | 1 each | the admin activity row; with W7 §3 the stored username snapshot may go (W7 question 2) |
| `adminUserId`, `adminUsername` | `adminAccountId`, `adminAddress` | 1 each | 0 | 1 each | |
| `ownerId` | `ownerAccountId` | 1 | 0 | 1 | calendars |
| `ownerUsername` | `ownerAddress` | 1 | 0 | 1 | link reports |
| `recipientUsername` | `recipientAddress` | 2 | 1 | 2 | |
| `userUsername` | `accountAddress` | 1 | 0 | 1 | feedback |
| `totalUsers`, `activeUsers` | `totalAccounts`, `activeAccounts` | 2 each | 0 | 1 each | admin stats |
| `owner` (mail domains admin), `owners` (mail groups) | `ownerAccountId`, `ownerAccountIds` | 1 each | 0 | | W7: local account = `<role>_account_id` |
| `"userId"` / `"username"` keys in `json!` details | `accountId` / dropped | 3 / 15 | | | error details in mail group keys; admin and link-report audit payloads (W7 §3 drops `username` from payloads) |
| enum value `user` (`ClosingBy`, destruction `Actor`) | `account` | 2 | | | W7 §3 lists `closing_by` values; the JSON follows |

Kept: `AccountAddress.username` in kutup-chat-proto (the local part of an
address is a username), the `owner*` fields that carry no `user`, and
`account` where it already means the `user@server` label (`ownerAccount`
→ `ownerAddress` for the same rule; 1 struct).

The Rust types follow too, so no `User` remains in names a builder greps:
`CreateUserRequest`, `UpdateUserRequest`, `WipeUserRequest` (admin.rs),
`UserRow` (alias `AdminUserRow`), `CreateAdminUserRequest`,
`UpdateAdminUserRequest`, `AuthUser`, `AdminUser`, `LocalUser`, CLI
`UserMe`; `MeResponse` becomes `AccountResponse`.

### 4.3 WebSocket messages

Already clean: no tag names `user` or `mls`, and all JSON frames tag by
`"type"`.
- **Chat:** `envelope`, `drainMailbox`, `devicesChanged`, `pong`, `ping`.
- **Provisioning:** `address`, `envelope`.
- **Collab:** `hello`, `peers`, `base`, `stored`, `replayed`, `resume`.

Changes:
- **The collab peer object** (`PeerSummary`, collab.rs:61; client
  `PeerInfo`, transport.ts:7): `userId` → `accountId`, `username` →
  `address`.
- **Sockets take the client version** in the query (`?client=`, §1.2).
- Collab's binary kinds (SCREAMING_SNAKE constants, u8 on the wire) are
  numbers, not names: unchanged.

### 4.4 OpenAPI

Nothing consumes the spec, so it changes freely:
- **Paths follow §2 automatically** where `#[utoipa::path(path = …)]`
  strings are edited with the routes. The registration test
  (`EXPECTED_OPERATIONS = 95`, stale) becomes equality: every route in
  `build_router` has an operation, and no operation lacks a route.
- **Tags are app names,** one word or dotted, no spaces. The 32 tags today
  mix `drive federation`, `chat-backup`, `user`… They become `account`,
  `auth`, `admin`, `drive`, `drive.federation`, `photos`, `chat`,
  `chat.backup`, `chat.federation`, `mail`, `calendar`, `contacts`,
  `pass`, `maps`, `federation`, `health`, declared in one `tags(...)`
  block. `files`, `collections`, `shares`, `trash`, `tus`, `versions`,
  `thumbnails`, `assets` and `collab` fold into `drive`; `user`,
  `devices`, `sessions`, `security` and `legal` into `account`.
- **Schema names:**
  - the `User` ones as §4.2;
  - the four duplicate `ToSchema` names (`LoginFinishRequest`,
    `RegisterFinishRequest`, `RenameRequest`, `RotateRequest`) get
    distinct names, since utoipa can silently pick one;
  - request bodies end in `Request`, responses in `Response`. Today the
    450-odd schemas use 9 suffixes (`Result`, `View`, `Row`, `Input`…).
- **Version suffixes stay where they are a wire format** (`AccountManifestV3`,
  `ChatBackup*V1`, `FederationDiscoveryV2`: they name signed or sealed
  shapes). The plain request/response pair `RegisterChatDeviceRequestV2` /
  `RegisterChatDeviceResponse` loses the stray `V2`.

## 5. Server instance id

### 5.1 Design

- **What:** 16 random bytes, minted the first time the server starts on an
  empty database, never changed by the server afterwards. It names this
  database's lifetime, not the host or the release.
- **Storage:** one row in a new account-free table
  `server_instance (singleton boolean PRIMARY KEY DEFAULT true
  CHECK (singleton), id bytea NOT NULL CHECK (octet_length(id) = 16),
  created_at timestamptz NOT NULL)`, so it holds at most one row. The row is added to the W7 baseline (coordinated with the second
  session: one table, no other change). Startup runs
  `INSERT … ON CONFLICT DO NOTHING` with a fresh id, then reads the row.
- **Restore keeps it.** A restore is the same instance (backups carry the
  row), so clients keep their state. This matters: anti-rollback guards
  then see the restore as a rollback and say so, which is right
  (docs/plans/restore-drill-and-alerting.md decides what an operator tells
  users).
- **A wipe changes it,** because it empties the database. An operator who
  wants a new instance on purpose drops the row (`kutup-server
  reset-instance-id`, refused while accounts exist; a server already running keeps answering with the old id until it is restarted, and the command says so).
- **Where clients see it:**
  - `GET /api/health` → `"instanceId": "<base64url, 22 chars>"`;
  - a response header `x-kutup-instance` on every `/api/v1` answer, exposed
    to CORS like `x-kutup-session-version`, so a running app notices without
    polling;
  - federation discovery is unaffected: peers are bound by the signed
    identity chain, which a wipe also restarts.

### 5.2 Client reaction

**The browser** (`@kutup/session`, on every app origin, since each origin
has its own storage):
1. Boot reads `localStorage['kutup.instance']` and asks `GET /api/health`
   for the server's id (one round trip, beside the app directory's;
   accepted). Every storage opener (every IndexedDB database, the chat
   engine's names) waits on one gate (`@kutup/crypto/storageGate`), which
   `configureClient` points at this check; `restoreSession` awaits it
   before reading the session.
2. **Match:** go on.
3. **Mismatch, or no marker while any `kutup` storage exists** (the beta
   browsers at this wipe):
   - first tell the origin's other tabs on the `kutup.session` channel
     (`instance-changed`): they reload, which closes their databases;
   - delete every IndexedDB database the origin has
     (`indexedDB.databases()`; where it is missing, the names in §6 and the
     legacy names). "Kutup storage exists" counts databases too;
   - delete every `kutup*` localStorage and sessionStorage key;
   - (web push is not unsubscribed: the server that held the
     subscription is the one that was reset);
   - store the new marker;
   - go to sign-in with a one-time notice: "This server was reset; local data
     was removed."

   Other tabs hear it on the `kutup.session` channel and reload.
4. **The exception: anti-rollback anchors** (§6, marked "anchor": the
   revision guard, manifest pins). A server that lies about its instance id
   must not be able to make clients forget what they pinned. They are keyed
   by account id, and a wiped server mints new account ids, so a real
   wipe's anchors never match again. They are kept across an instance
   change and across sign-out, and go only when the account is deleted
   (decision 5). The legacy `kutup_own_manifest_pin_v1:` keys count as
   anchors too.
5. A mismatch seen mid-session (the header changes) does the same after
   stopping the chat engine and pending uploads.

**The CLI:**
- the session gains `instance_id` from login;
- each command asks `GET /api/health` for the id before anything else (one
  request per command; accepted);
- on a mismatch it deletes the profile's `session`, `sync_state`,
  `resume` and `collab_device`, keeping `manifest_pin` (an anchor) and the
  keyring's device key, on purpose: that key encrypts the profile's store,
  which still holds the anchors;
- it exits 3 (no usable session): "<server> was reset; run `kutup login`
  again". A sync folder's local files are never touched; only the sync
  state is dropped, so the next sync treats both sides as new.

**FFI and native:** the host passes each answer's `X-Kutup-Instance` in
`ChatHttpResponse.instanceId`; the transport keeps the first one it sees
and answers `ServerReset` on another. The host stores the id beside its
account database too, and on `ServerReset` deletes the chat store (§6) and
signs in again. `ClientTooOld`, `ServerTooOld` and `ServerReset` stop the
engine's network work (`ChatError::stops_network`); its verification loops
count them as unreachable, never as a failed check.

### 5.3 Tests

- **Server live test:**
  - the id is minted once;
  - it is stable across a restart;
  - it is the same in health and in the header;
  - a truncated database gets a new one;
  - `reset-instance-id` is refused with accounts.
- **Web unit tests** (vitest with fake-indexeddb):
  - a mismatch deletes every store but the anchors;
  - a missing marker with legacy names present deletes them;
  - a match touches nothing;
  - openers wait for the check.
- **Browser spec** (added to the ci.yml browser job):
  - sign in, fill Drive and Chat state;
  - change the instance row (test-only admin hook in the test stack, or
    truncate and restart);
  - reload: sign-in page, the notice, IndexedDB empty except anchors.
- **CLI live test** (the backup gate's last step, as it restarts the
  server): log in, change the row, restart, run `kutup ls`: exit 3 and the
  message, then `whoami` finds no session. That `manifest_pin` stays is the
  CLI unit test's (`forget_server_state`).

## 6. Client storage names

### 6.1 Rule

`kutup.<app>.<thing>[:<key>]`:
- **`<app>`** is one of `session`, `account`, `ui`, `drive`, `photos`,
  `office`, `collab`, `chat`, `mail`, `calendar`, `pass`, `files` (the
  shared ciphertext cache) or `instance`.
- **`<thing>`** is camelCase (W7's casing).
- **`<key>`** is a variable part after one `:`.
- **The per-account key** is `<account>`: 32 hex of
  H(`"kutup.account-scope"` ‖ instanceId ‖ server ‖ accountId). It replaces
  raw `userId`s, addresses (mutable, so never a key) and chat's current
  scope hash. Because the instance id is in it, an old instance's data is
  unreachable even before the sweep deletes it.
- **No version in a name.** An IndexedDB format change bumps the IDB
  version and migrates in `onupgradeneeded`. A localStorage value that
  needs a format version carries `v` inside its JSON. Every new IDB starts
  at version 1.
- **Preferences are one JSON value per app** (`kutup.<app>.prefs`), as
  `kutup-calendar-prefs` already is. That is 10 chat keys, 4 mail keys and
  3 calendar keys fewer.
- **Sign-out clears** everything per-account that is not an anchor;
  anchors go too only when the account itself is being deleted
  (closing or deletion flows).
  Today it clears 4 of the 20-odd per-account names (inventory); the rest
  stay on the device after sign-out, which this fixes at the same time.
  Preferences are kept.

### 6.2 Map

IndexedDB:

| Old | New | Notes |
|---|---|---|
| `kutup-chat-v2:<scope>` (v16) | `kutup.chat.store:<account>` (v1) | Rust `indexed_db.rs`; name from `local-store.ts` |
| `kutup-chat-v2:<scope>:continuous-backup` (v2) | `kutup.chat.backup:<account>` (v1) | |
| `kutup-mail-search:<hmac>` | `kutup.mail.search:<hmac>` | the HMAC name stays (it hides the account from the origin's DB list) |
| `kutup-pass-<userId>` | `kutup.pass.outbox:<account>` | |
| `kutup-account-records` | `kutup.account.records` | per-account key inside, as now |
| `kutup-revisions-v2` | `kutup.drive.revisionsSeen` | **anchor** |
| `kutup-private-ciphertext-cache-v1` | `kutup.files.ciphertextCache` | its account purge gets a caller (sign-out) |
| `kutup-pending-uploads` | `kutup.drive.pendingUploads` | |

localStorage:

| Old | New | Notes |
|---|---|---|
| `kutup-session` | `kutup.session` | |
| (new) | `kutup.instance` | §5 |
| `kutup-manifest-pins:<userId>` | `kutup.account.manifestPins:<account>` | **anchor** |
| `kutup.sealed.v1:<scope>:drafts`, `…:read-marks` | `kutup.chat.drafts:<account>`, `kutup.chat.readMarks:<account>` | the sealed envelope carries its version |
| `kutup:chat:device-id:<userId>` | `kutup.chat.deviceId:<account>` | |
| `kutup:chat:replaced-device:<userId>` | `kutup.chat.replacedDevice:<account>` | |
| `kutup.chat.pending-default-timers.v2:<userId>` | `kutup.chat.pendingTimers:<account>` | |
| `kutup.chat.notInContactsDismissed:<userId>` | `kutup.chat.notInContactsDismissed:<account>` | |
| `kutup.mail.notInContactsDismissed:<userId>` | `kutup.mail.notInContactsDismissed:<account>` | |
| `kutup-meeting-hosts` | `kutup.chat.meetingHosts` | keyed by `<account>` inside |
| `kutup-meeting-history` | `kutup.chat.meetingHistory` | entries keyed by `<account>`, cleared at sign-out |
| `kutup-call-name`, `kutup-meeting-show-account` | `kutup.chat.prefs` (`callName`, `meetingShowAccount`) | |
| `kutup:chat:{read-receipts, link-previews, notifications, notification-sound, notification-content, notification-prompt-dismissed, web-push, always-relay-calls, typing-indicators, default-timer}` | `kutup.chat.prefs` | 10 keys into one |
| `kutup.mail.listSize.<layout>`, `kutup.mail.noReplyDontShowAgain`, `kutup.mail.notificationBanner.dismissed` | `kutup.mail.prefs` | |
| `kutup-calendar-prefs`, `kutup-calendar-push`, `kutup.calendar.notificationBanner.dismissed` | `kutup.calendar.prefs` | |
| `kutup-drive-view` | `kutup.drive.prefs` | |
| `kutup-photos-info` | `kutup.photos.prefs` | |
| `kutup-pass-lock` | `kutup.pass.lock` | |
| `kutup-pass-activity` | `kutup.pass.activity` | |
| `kutup-pass-auto-lock-minutes`, `kutup-pass-unlock-mode` | `kutup.pass.prefs` | |
| `kutup-md-mode-<fileId>`, `kutup.notes.sourceMode` | `kutup.office.prefs` (`markdownMode` by file id, capped at 500) | |
| `kutup_cursor_color_v1` | `kutup.collab.cursorColor` | |
| `kutup-theme` | `kutup.ui.theme` | next-themes `storageKey` in each `main.tsx` and the pre-paint script |
| `kutup-lang` | `kutup.ui.language` | i18next detector and the inline reload guard |
| legacy `kutup_own_manifest_pin_v1:*`, `kutup.chat.drafts.v1:*`, `kutup:chat:read:*`, `kutup.chat.pending-default-timers.v1:*`, unkeyed `*.notInContactsDismissed` | deleted | their migration code goes: the sweep (§5.2) deletes them |

sessionStorage:

| Old | New |
|---|---|
| `kutup-fork:<state>` | `kutup.session.fork:<state>` |
| `kutup-fork-attempts` | `kutup.session.forkAttempts` |
| `kutup-reload:<build>` | `kutup.ui.reload:<build>` |
| `kutup:chat:reset-device` | `kutup.chat.resetDevice` (value: `<account>`) |
| `kutup-meeting-seat:<roomId>` | `kutup.chat.meetingSeat:<roomId>` |
| `kutup.chat.liveShares.v1` | `kutup.chat.liveShares` |

BroadcastChannels and locks:

| Old | New |
|---|---|
| channel `kutup-session` | `kutup.session` |
| channel `kutup-pass-lock` | `kutup.pass.lock` |
| channel `kutup-chat-focus:<address>` | `kutup.chat.focus:<account>` |
| channel `kutup-chat-updates:<scope>` | `kutup.chat.updates:<account>` |
| channel `kutup-chat-engine:<scope>:alive` | `kutup.chat.engineAlive:<account>` |
| channel `kutup-mail-search:<hmac>` | `kutup.mail.search:<hmac>` |
| lock `kutup-refresh` | `kutup.session.refresh` |
| lock `kutup-account-head:<lsn>` | `kutup.account.head:<lsn>` |
| lock `kutup-revision:<entry>` | `kutup.drive.revision:<entry>` |
| lock `kutup-upload:<fileId>` | `kutup.drive.upload:<fileId>` |
| lock `kutup-chat-engine:<scope>` | `kutup.chat.engine:<account>` |
| lock `kutup-chat-engine:<scope>:attachment-ledger` | `kutup.chat.attachmentLedger:<account>` |
| locks `kutup-chat-notifier:<address>`, `kutup-chat-call-desk:<address>`, `kutup-chat-in-call:<address>` | `kutup.chat.notifier:<account>`, `kutup.chat.callDesk:<account>`, `kutup.chat.inCall:<account>` |
| locks `kutup-mail-search:<hmac>:write`, `:build` | `kutup.mail.searchWrite:<hmac>`, `kutup.mail.searchBuild:<hmac>` |

Cookies (server-set, HttpOnly):
- `refresh_token` → `kutup.refresh`, its path following the route to
  `/api/v1/auth/refresh`;
- `kutup_known` → `kutup.known`, path `/api/v1/auth`. The retired
  `Path=/api` clearing code goes.

Not storage, unchanged:
- window event names;
- notification tags;
- the worker name `kutup-block-reader`;
- the SFU topic `kutup-roles`;
- the service worker URL `/kutup-sw.js`.

The service worker keeps no state and uses no Cache Storage.

### 6.3 CLI and native

- **The CLI** keeps its layout and names:
  - `<data>/kutup/<profile>/kutup.redb`;
  - keyring service `kutup-cli/<profile>`, account `device-key`;
  - `kutup-ssh-agent.service`.

  They are already one style, and they are OS conventions rather than the
  web's. Changes:
  - the session JSON's `user_id` → `account_id`, `username` → `name`;
  - add `instance_id`;
  - `UserMe` → `AccountResponse`.

  The session is sealed and internal, and every CLI logs in again after the
  wipe anyway.
- **Native chat store files** (`kutup-chat-{}.db`, `kutup-chat-sqlcipher-{}.db`,
  `kutup-chat-no-sqlcipher-{}.db` in `kutup-chat-core/src/db/sqlite.rs`)
  become `chat-<account>.db` inside the host's app data directory. There
  is one name, since the cipher is a build choice and not a file kind.
  Nothing ships these yet.

## 7. Public link shapes

Links that can't be reissued once shared:

| Link | Shape today | Versioned? |
|---|---|---|
| Drive folder / file | `https://drive.<domain>/s/<token>#key=<std base64, %-encoded>` | no |
| Photos album | `https://photos.<domain>/s/<token>#key=…` | no |
| Office document in a public folder | `https://office.<domain>/s/<token>/<fileId>#key=…` | no |
| Meeting (call link) | `https://chat.<domain>/call#<44 base64url>` | yes (first byte) |
| Chat group link | `https://chat.<domain>/join#<base64url>` | yes (byte 1) |
| Chat contact | `kutup://contact/<name@server>` | no |
| Device link (QR, minutes) | `kutup://link?address=…&key=…` | n/a (short-lived) |
| Safety number QR | `kutup://verify/v3/…` (crypto), `kutup://verify/v4/…` (chat) | yes |

There are no calendar public links, and `/l/:placeId` is Mail's label route,
not a link anyone shares.

**Changes:**
1. **Drive, Photos and Office fragments get a format and a version:**
   `#v1.<base64url key, no padding>`, the call and group links' alphabet.
   Today's `key=` with %-encoded standard base64 can't say what a later
   format is, and a link can't be reissued.
   - The parser keeps the version and refuses an unknown one with "this link
     needs a newer Kutup".
   - A password-protected link later adds `v2` (Proton's
     `#<password>` model) without breaking `v1`.
2. **One entry point per link, whichever app shows it.**
   - Every app's `/s/:token` asks the server for the link's kind (the
     existing `GET …/public-links/:token`) and redirects within the domain
     to the app that shows it, keeping the fragment.
   - A folder link opened on `photos.` still works, and so does an album
     link after a later move of albums into or out of Photos.
   - Office's `/s/<token>/<fileId>` stays: it names a file inside the
     folder.
3. **The contact link becomes rename-proof:** `kutup://contact/<server>/<accountId>`.
   The current form names a username, which W7 and the identity rules call
   mutable; a renamed account's printed QR codes would break or, after the
   hold, point at someone else.
   - The app shows the current address after a lookup by id.
   - The name form is still accepted when pasted, as a lookup.
   - Signal's username links are encrypted for the same reason;
     `<server>/<accountId>` already reveals no more than an address.
4. Meeting, group, device and safety links are unchanged: already
   versioned, already rename-proof.
5. **The token** (`random_token(32)`, stored as its SHA-256 by W7 §2) is
   unchanged.

## 8. Order of work

Each slice builds and passes static, rust and web gates on its own; the
browser specs of the touched area run at the end of each slice touching the
web (ci.yml browser job list).

1. **Versioning plumbing.**
   - The release version replaces `BUILD_VERSION`.
   - `x-kutup-client: <type>/<version>` in web, CLI and FFI, with the server
     accepting both forms for this slice only.
   - `MIN_CLIENT_VERSIONS` and the setting; the `clientTooOld` error, the
     latch in web, CLI exit 7 and the FFI variant.
   - Health's `apiVersions`, `minimumClients`.
   - Tests: the code table, a server test per client type, web latch unit
     test, CLI test.

   No paths move yet.
2. **Instance id.**
   - The table in the W7 baseline (with the second session); startup
     minting; health and header; `reset-instance-id`.
   - Web check with the legacy sweep; CLI and FFI handling.
   - Tests as §5.3.

   Before the storage rename, so the sweep's legacy list is today's names.
3. **Storage names (web).**
   - The map in §6; `<account>` scopes; prefs merged.
   - The sweep extended to every old name; sign-out clears the per-account
     names.
   - Chat IDB names in Rust and TS together.
4. **Field names and Rust type names (§4).**
   - Server structs, `json!` details, CLI types, frontend types, the collab
     peer object.
   - One commit per app area (account and admin, Drive and Photos, Chat,
     Mail, Calendar) so each is reviewable; each builds because server and
     client types change in the same commit.
5. **Client paths (§2, client side).**
   - Router: everything under one `Router::nest("/api/v1", …)`, so the
     prefix is written once and the map's renames are the only edits.
   - Web `apiBase` → `/api/v1`, and every renamed path in the frontend.
   - CLI `url()` and its paths. FFI `account_path`.
   - nginx regexes, the frontend container's `/api/` block, cookie paths,
     tus `Location`, the service worker's URL matchers, map relay.
   - The `clientTooOld` fallback for bare `/api/…` and the
     `apiVersionUnsupported` one.
   - utoipa paths, tags and schema names (§4.4) with the equality test.
   - docs/api.md.
6. **Federation (§1.6, §3).**
   - `/api/fed/v2/` with `Router::nest`.
   - `fedVersions` in discovery (signed: kutup-federation-proto vectors
     regenerated).
   - The account namespace and lookup; drop the name routes.
   - The `incompatible` peer state; `federationVersionUnsupported`.
   - Tests: the two-server gate and the live backup gate (the rule for any
     change that reaches federation).
7. **Links (§7).**
   - The `v1.` fragment in Drive, Photos and Office; the `/s/` redirect.
   - The `kutup://contact/<server>/<accountId>` form.
   - The browser specs for public links and contacts.
8. **Final:**
   - the whole gate set;
   - a grep that no `/api/` path outside §2's unversioned list, no `userId`
     / `UserId` / `_user_id`, and no old storage name remains (kept as a
     static check in `gate.sh static`, so they can't come back);
   - then merge into the wipe stack.

## 9. Risks

- **Missed paths.** 176 federation path strings and the frontend's
  relative paths are plain strings, so the compiler checks none of them.
  - Mitigations: `Router::nest` for both prefixes; the static grep in
    slice 8; the equality test between routes and OpenAPI; and the live
    and browser suites, which call nearly every route.
  - The nginx and container configs are not covered by any test but the
    browser specs, so collab websockets (nginx regex) and CSP reports need
    an explicit spec run.
- **Signed federation paths.** The signature covers the path, and the
  transport checks it against the feature namespace. A half-renamed path
  fails as a signature or namespace error, not a 404. The two-server gate
  is the check.
- **The instance id as an attack.** A server can always lie about its
  instance id and so make clients forget local state. §5.2 keeps the
  anchors, so it can't erase pins; it can force a sign-in, which it could do
  anyway by revoking the session.
- **Old beta tabs at the deploy** keep calling bare `/api/…`. They get
  `clientTooOld`, which their code doesn't know, so they show an error
  rather than the reload screen until the person reloads. This happens
  once, at the wipe, and a reload fixes it. The service worker serves no
  cached app code (no Cache Storage), so a reload gets the new build.
- **`indexedDB.databases()`** is missing in older Firefox (before 126).
  The sweep falls back to the known names (§6 old and new, and the
  `kutup-chat-v2:` prefix needs the scope, so on those browsers an old
  chat IDB can stay behind). It is unreadable without the old keys, and
  only takes space.
- **Release versions.** CalVer stamping needs the deploy script and CI to
  agree; a build that forgets it reports `0.0.0-dev`, and a production
  server must refuse to start as `dev` (a check in `check-config`).
- **Size of slice 5:** about 400 path edits across server, web and CLI in
  one slice. It can't be split by app without a period where both prefixes
  are served. It could be (a nest at both prefixes), but the dual-serve code
  would be thrown away, so one slice, reviewed by the map.
- **Collision with W7.** Slices 2 (one table) and 4 (field names follow
  columns) depend on W7's names. This branch rebases on the final W7
  before slice 4.

## 10. Decisions (main, 2026-11-17)

1. `clientTooOld` answers **426**, the code in the body.
2. The client version goes **inside `x-kutup-client`** as `<type>/<version>`,
   as Proton's `x-pm-appversion`.
3. Server and web use **CalVer `YYYY.MDD.N`** (no leading zero: semver). The CLI keeps its own
   v0.0.x semver (0.1+ only with the user's OK); its semver is mapped into
   the minimum check per client type (§1.2).
4. Federation paths are **`/api/fed/v2/`**, the existing protocol number.
5. The **anti-rollback anchors are kept** across an instance change (§5.2).
6. **A restore keeps the instance id.** Clients then see the rollback through
   the anchors and show the existing rollback banner: a restore is a
   rollback.
7. Public link fragments are **`#v1.<base64url>`**, with the `/s/` redirect
   between apps (§7).
8. **Contact links by account id:** `kutup://contact/<server>/<accountId>`.
9. **All the shape fixes are taken** (§2.1): `public-links`,
   `shared-with-me`, `folder-shares` / `file-shares`, `chat/devices`,
   `admin/…/reset-keys` and `entitlements`, camelCase path parameters, the
   public-link file routes.
10. **Sign-out clears per-account local data**, in slice 3, keeping the
    anchors unless the account is being deleted.

The `server_instance` table goes into the W7 baseline; main has asked the
second session.
