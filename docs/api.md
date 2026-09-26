# API Reference

Base URL: `https://localhost:38443` for the bundled local Compose edge, or your
configured public `SERVER_URL`. Port `38080` redirects to HTTPS.

All authenticated endpoints require `Authorization: Bearer <accessToken>`.

> **Note:** File content and metadata are end-to-end encrypted by the client. Account secrets use one canonical, suite-bearing envelope per value; the server validates only its public framing and never sees the plaintext or key.

**Request bodies** are capped at 4 MiB unless a route says otherwise; the
upload routes raise it (whole-file upload 10 GiB, a version 2 GiB, a tus
chunk 64 MiB, a whiteboard asset one envelope, a federated Drive upload
10 GiB, streamed to disk). A larger body gets `413`.

---

## Authentication

Sign-ins are **server-side sessions** (`auth_sessions`). Every session has a
client type, sent by the client in the `X-Kutup-Client` header:

| Client type | Who | Signs in | Refresh token |
|---|---|---|---|
| `web-account` | the account web app (`account.<domain>`) | password (`/login`, `/login/2fa`, `/complete-setup`) | HttpOnly cookie on that origin |
| `web-drive`, `web-chat` | the Drive and Chat web apps | **forked** from a `web-account` session (`/api/auth/forks`) | HttpOnly cookie on their own origin |
| `cli` | the `kutup` CLI | password | JSON body |

Access tokens are 15-minute JWTs carrying the session id (`sid`); every
authenticated request (and each collab / chat WebSocket upgrade) checks that
the session is still live, so revoking a session takes effect immediately.
Refresh tokens are opaque 32-byte secrets that **rotate on every refresh**;
see `/api/auth/refresh`. Resetting the password (`/api/auth/recover`), an admin
disabling the account and an admin wipe end every session of the account.
Design: `docs/plans/multi-app-web-rewrite.md`.

### GET /api/auth/settings

Returns public server settings: whether registration is open, the Chat
capability advertisement, and where each web app lives (`apps`, from
`KUTUP_BASE_DOMAIN` / `KUTUP_{ACCOUNT,DRIVE,CHAT,OFFICE}_URL`).

**Auth:** None

**Response:**
```jsonc
{
  "registrationEnabled": true,
  "chat": {
    "enabled": true,
    "protocolVersion": 1,
    "suites": [1],
    "maximumActiveDevices": 10,
    "manifests": true,
    "profiles": true,
    "federation": true,
    "sealedSender": true,
    "mlsGroups": true
  },
  "apps": {
    "account": "https://account.example.org",
    "drive": "https://drive.example.org",
    "chat": "https://chat.example.org",
    "office": "https://office.example.org"
  }
}
```

The chat block also advertises size/retention limits, the canonical federation
server name when enabled, and the authenticated sealed-sender service-policy
history. `maximumActiveDevices` is operator-configurable from 1 through the V1
hard cap of 10. A capability is advertised only when its complete local and
federated path is enabled.

---

### POST /api/auth/register

Create a new account with an encrypted key bundle. Rate-limited (10/hr/IP, `RATE_LIMIT_REGISTER_PER_HOUR`).

**Auth:** None

**Request body:**
```json
{
  "email": "user@example.com",
  "username": "alice",
  "loginKey": "<base64>",
  "masterKeyEnvelope": "<canonical base64 AccountEnvelopeV1>",
  "recoveryKeyEnvelope": "<canonical base64 AccountEnvelopeV1>",
  "drivePrivateKeyEnvelope": "<canonical base64 AccountEnvelopeV1>",
  "publicKey": "<base64>",
  "accountAuthorityPublicKey": "<base64 32 bytes>",
  "accountAuthorityKeyId": "<lowercase SHA-256 hex>",
  "accountIncarnationId": "<lowercase SHA-256 hex>",
  "driveSigningPublicKey": "<base64 32 bytes>",
  "accountProtectionSuite": 1,
  "accountProtectionSalt": "<base64 16 bytes>",
  "argonMemoryKib": 65536,
  "argonIterations": 3,
  "argonParallelism": 1,
  "recoveryProof": "<base64>"
}
```

All key material is encrypted client-side before being sent. One parameterized
Argon2id invocation derives an account-protection root; HKDF purpose subkeys
produce the master-key KEK and `loginKey`. The server bcrypts only `loginKey`.
`recoveryProof` is a distinct HKDF output bound to the canonical login email;
the raw recovery entropy that opens `recoveryKeyEnvelope` is never sent. Each
envelope authenticates its suite, purpose, canonical login email, nonce and
exact ciphertext length as AEAD associated data. The three purposes cannot be
substituted for one another or relocated to another account.

The complete account identity is fixed at registration: the account authority,
incarnation, Drive X25519 key, and Drive Ed25519 share-signing key are persisted
as one binding. A later account manifest must match all of them exactly; a
self-signed first manifest cannot select a replacement authority.

**Response:** `201 Created`

**Errors:** `403` if registration is disabled, `409` if the email or username is already taken.

---

### GET /api/auth/login/preflight

Fetch the complete account-protection suite and parameters before submitting credentials. Rate-limited.

**Auth:** None
**Query:** `?email=user@example.com`

**Response:**
```json
{
  "accountProtectionSuite": 1,
  "accountProtectionSalt": "<base64 16 bytes>",
  "argonMemoryKib": 65536,
  "argonIterations": 3,
  "argonParallelism": 1
}
```

---

### POST /api/auth/login

Exchange the Argon2id-derived login key for tokens. Rate-limited (10/min/IP, `RATE_LIMIT_LOGIN_PER_MIN`). On top of the per-IP limit, repeated failed password attempts for one email lock that account out: after 5 failures (`LOGIN_LOCKOUT_THRESHOLD`) further attempts return `429` for 15 minutes (`LOGIN_LOCKOUT_MINUTES`). The lockout applies to unknown emails too, so a `429` does not reveal whether the account exists.

**Auth:** None · **Header:** `X-Kutup-Client: web-account` or `cli` (required; `400` otherwise)

**Request body:**
```json
{
  "email": "user@example.com",
  "loginKey": "<base64>"
}
```

**Response (no 2FA):**
```json
{
  "accessToken": "<jwt>",
  "sessionId": "<uuid>",
  "userId": "<uuid>",
  "username": "alice",
  "masterKeyEnvelope": "<canonical base64 AccountEnvelopeV1>",
  "drivePrivateKeyEnvelope": "<canonical base64 AccountEnvelopeV1>",
  "publicKey": "<base64>",
  "isAdmin": false,
  "storageQuotaBytes": 5368709120,
  "storageUsedBytes": 104857600
}
```

For `web-account` the refresh token is an HttpOnly, host-only cookie named `refresh_token` (`Path=/api/auth/refresh`, `SameSite=Lax`, 30-day sliding `Max-Age`, `Secure` outside development) and is **not** in the JSON body. For `cli` it is returned as `"refreshToken"` in the body and no cookie is set.

**Response (2FA enabled):** `200` with `{"requiresTotp": true, "preAuthToken": "<jwt>"}` — proceed to `/api/auth/login/2fa`.

**Response (first login, account created via `ADMIN_ACCOUNT` and not yet set up):** `200` with `{"requiresSetup": true, "setupToken": "<jwt>"}` — proceed to `/api/auth/complete-setup`.

---

### POST /api/auth/login/2fa

Complete login when 2FA is enabled. Locked after 5 failed attempts.

**Auth:** None (uses `preAuthToken` from the login response) · **Header:** `X-Kutup-Client` as for `/api/auth/login`

**Request body:**
```json
{
  "preAuthToken": "<jwt>",
  "code": "123456"
}
```

**Response:** Same full token response as `/api/auth/login` (no 2FA branch).

---

### GET /api/auth/recover/preflight

Fetch the encrypted recovery key bundle so the client can decrypt the master key with the mnemonic-derived recovery key. Rate-limited (5/hr/IP). Returns deterministic fake data for non-existent emails to prevent user enumeration.

**Auth:** None
**Query:** `?email=user@example.com`

**Response:**
```json
{
  "recoveryKeyEnvelope": "<canonical base64 AccountEnvelopeV1>"
}
```

---

### POST /api/auth/recover

Recover an account using a mnemonic-derived recovery key. The client proves possession of the mnemonic with `recoveryProof` and submits a fresh key bundle derived from a new password. Rate-limited (5/hr/IP).

**Auth:** None

**Request body:**
```json
{
  "email": "user@example.com",
  "recoveryProof": "<base64>",
  "newLoginKey": "<base64>",
  "newMasterKeyEnvelope": "<canonical base64 AccountEnvelopeV1>",
  "newAccountProtectionSuite": 1,
  "newAccountProtectionSalt": "<base64 16 bytes>",
  "newArgonMemoryKib": 65536,
  "newArgonIterations": 3,
  "newArgonParallelism": 1
}
```

`recoveryProof` is the 32-byte HKDF-derived authorization proof. The server
bcrypt-compares it to the verifier stored at registration; it never receives
the recovery entropy used for decryption. A successful recovery **ends every
session** of the account (web apps and CLIs alike).

---

### POST /api/auth/refresh

Rotate the session's refresh token and get a new access token. Web sessions
present the token in their `refresh_token` cookie and receive the next one the
same way; the CLI presents it in the body and receives the next one in the body.
A token presented the other way is refused (and does not rotate anything).

A just-rotated token is still honoured for 60 seconds (two tabs refreshing with
the same cookie): it yields an access token but no new refresh token. A rotated
token presented after that window is treated as stolen and **revokes the
session** and everything forked from it. A failed web refresh clears the cookie.

**Auth:** None (the refresh token itself is the credential)

**Request body (CLI only):**
```json
{
  "refreshToken": "<43-char base64url>"
}
```

**Response:**
```json
{
  "accessToken": "<jwt>",
  "sessionId": "<uuid>",
  "refreshToken": "<CLI only, absent within the grace window>"
}
```

---

### POST /api/auth/complete-setup

Called after first login by accounts created via `ADMIN_ACCOUNT` that haven't yet generated a recovery phrase. The client derives a full key bundle (mnemonic, master key, recovery entropy, account Drive keys and typed account envelopes) and submits it here.

**Auth:** Bearer `setupToken` (returned by `/api/auth/login` when `requiresSetup` is true) · **Header:** `X-Kutup-Client` as for `/api/auth/login`

**Request body:** Same shape as `POST /api/auth/register` (encrypted key bundle, salts, public key).

**Response:** creates a session and issues tokens exactly as `/api/auth/login` does (cookie for `web-account`, body for `cli`) — the encrypted key bundle just submitted is **not** echoed back.
```json
{
  "accessToken": "<jwt>",
  "sessionId": "<uuid>",
  "userId": "<uuid>",
  "username": "alice",
  "isAdmin": false,
  "storageQuotaBytes": 5368709120,
  "storageUsedBytes": 0
}
```

---

## Sessions

### POST /api/auth/logout

End the caller's sign-in: the `web-account` (or `cli`) session **and every
session forked from it**. Signing out of Drive or Chat therefore signs out of
all Kutup web apps on that browser; they notice on their next request.

**Auth:** Bearer · **Response:** `{"ok": true}` (web: also clears the cookie)

### GET /api/auth/sessions

The account's live sessions, most recently used first. `current` marks the
caller's own sign-in (its root and the sessions forked from it).

**Auth:** Bearer

```json
[
  {
    "id": "<uuid>",
    "clientType": "web-drive",
    "parentId": "<uuid of the web-account session>",
    "userAgent": "Mozilla/5.0 …",
    "createdAt": "2026-09-23T14:07:00Z",
    "lastUsedAt": "2026-09-23T14:12:00Z",
    "current": true
  }
]
```

### DELETE /api/auth/sessions/:id

End one session of the caller's account and anything forked from it. `404` for
an unknown or foreign id. **Auth:** Bearer

### DELETE /api/auth/sessions

Sign out everywhere else: end every session except the caller's own sign-in.
**Auth:** Bearer

### POST /api/auth/forks

The account app hands a child web app a session (the Proton pattern). The
payload is a `SessionFork` local-state envelope (`kutup-crypto::local_state`,
profile = the child client type) sealed under a fresh 32-byte key that travels
only in the child URL's fragment; the server stores the envelope once, for 60
seconds, and never sees the key.

**Auth:** Bearer, `web-account` sessions only (`403` otherwise)

**Request body:**
```json
{
  "childClientType": "web-drive",
  "payload": "<canonical base64, ≤ 16 KiB>"
}
```

**Response:**
```json
{
  "selector": "<43-char base64url, single use>",
  "childOrigin": "https://drive.example.org"
}
```

The account app then redirects to
`<childOrigin>/login#selector=<selector>&sk=<key>&state=<state>`.

### POST /api/auth/forks/consume

The child app, on its own origin, turns a fork into its own session. The
`X-Kutup-Client` header must be the client type the fork was minted for and the
request `Origin` must equal that app's configured origin (`403`); the selector
is single-use and expires after 60 s (`401`). Sets the child's refresh cookie
on its own origin. Rate-limited with login.

**Request body:** `{"selector": "<selector>"}`

**Response:**
```json
{
  "accessToken": "<jwt>",
  "sessionId": "<uuid>",
  "userId": "<uuid>",
  "payload": "<the SessionFork envelope, canonical base64>"
}
```

### PUT / GET /api/auth/sessions/current/local-key

A web session keeps its unlocked keys in the browser as a `WebSession`
local-state envelope (profile `<client type>:<session id>`); the 32-byte key
that opens it lives only here, released only to that live session. Neither the
browser blob nor this key is useful alone, and revoking the session makes the
blob useless. Web sessions only (`400` for the CLI).

**Auth:** Bearer · **Body / response:** `{"key": "<canonical base64, 32 bytes>"}`
(`404` from GET when none is stored)

---

## User

### GET /api/user/me

Return the current user's profile (public key + storage stats). The encrypted key bundle is **not** returned here — it is delivered as part of the `/api/auth/login` response.

**Auth:** Bearer JWT

**Response:**
```json
{
  "id": "<uuid>",
  "email": "user@example.com",
  "username": "alice",
  "publicKey": "<base64>",
  "totpEnabled": false,
  "storageQuotaBytes": 5368709120,
  "storageUsedBytes": 104857600,
  "isAdmin": false
}
```

---

### POST /api/user/2fa/setup

Generate a TOTP secret and return a QR code URI.

**Auth:** Bearer JWT

**Response:**
```json
{
  "secret": "BASE32SECRET",
  "qrUri": "otpauth://totp/Kutup:user@example.com?secret=BASE32SECRET&issuer=Kutup"
}
```

The secret is stored as *pending* and only becomes active after `POST /api/user/2fa/verify` succeeds.

---

### POST /api/user/2fa/verify

Confirm TOTP setup by providing the first valid code.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "code": "123456"
}
```

---

### DELETE /api/user/2fa

Disable TOTP for the current user. Requires a valid TOTP code to prevent a stolen session from silently removing 2FA.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "code": "123456"
}
```

---

### GET /api/users/by-email/:email

Look up another local user's registered Drive identity (used when sharing a collection).

**Auth:** Bearer JWT; 30 lookups per minute per IP (`RATE_LIMIT_USER_LOOKUP_PER_MIN`), then `429`
**Param:** `:email` — URL-encoded email address

**Response:**
```json
{
  "userId": "<uuid>",
  "account": "bob@example.com",
  "driveHpkePublicKey": "<canonical base64, 32 bytes>",
  "accountIncarnationId": "<lowercase SHA-256 hex>",
  "driveSigningPublicKey": "<canonical base64, 32 bytes>"
}
```

---

## Collections

### GET /api/collections/

List all collections accessible to the current user (owned and shared).

**Auth:** Bearer JWT

**Response:** Array of collection objects. Owned and shared collections use the
same authenticated record. An owned row contains `ownerKeyEnvelope`; a shared
row contains `namedShareEnvelope`, `isShared: true`, and the owner's registered
identity fields required for independent client verification. Neither key
envelope is returned in the other row type.

```json
[
  {
    "id": "<uuid>",
    "ownerUserId": "<uuid>",
    "nameEnvelope": "<DriveEnvelopeV1 base64>",
    "namedShareEnvelope": "<NamedShareEnvelopeV1 base64>",
    "keyEpoch": 1,
    "nameRevision": 1,
    "epochStatement": "<CollectionEpochStatementV1 base64>",
    "epochStatementHash": "<lowercase SHA-256 hex>",
    "ownerAccount": "alice@example.com",
    "ownerIncarnationId": "<lowercase SHA-256 hex>",
    "ownerDriveSigningPublicKey": "<canonical base64, 32 bytes>",
    "ownerAuthorityPublicKey": "<canonical base64, 32 bytes>",
    "parentCollectionId": null,
    "color": "blue",
    "canUpload": true,
    "canDelete": false,
    "uploadQuotaBytes": null,
    "uploadUsedBytes": null,
    "isShared": true,
    "createdAt": "2026-09-01T10:00:00Z",
    "updatedAt": "2026-09-23T12:30:00Z"
  }
]
```

`updatedAt` is the folder's "modified" time as a file manager shows it: the
latest of the folder's own change (rename, colour), its newest direct file
change (upload, rename, or a new saved version), and its newest direct
subfolder. `GET /api/collections/:id` returns the same fields.

`canUpload`, `canDelete`, `uploadQuotaBytes`, `uploadUsedBytes`, `isShared`, and
the owner identity fields are present only on shared collections (the owner has
full rights implicitly). Clients verify the named-share signature, recipient
incarnation, epoch statement, epoch hash, collection-key commitment and name
envelope before displaying or using a shared collection.

---

### POST /api/collections/

Create a new collection.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "id": "<client-generated canonical uuid>",
  "nameEnvelope": "<DriveEnvelopeV1 base64>",
  "ownerKeyEnvelope": "<DriveEnvelopeV1 base64>",
  "epochStatement": "<CollectionEpochStatementV1 base64>",
  "parentCollectionId": null
}
```

The name envelope is bound to `(collection ID, owner user ID, epoch 1,
revision 1)`. The owner-key envelope binds the same identifiers with the
collection-key purpose. The account authority signs the epoch-1 statement.
Creation writes the collection and its first immutable epoch-history row in one
database transaction.

**Response:** `201 Created`
```json
{
  "id": "<uuid>"
}
```

---

### GET /api/collections/:id

Get a single owned or shared collection by ID. The response has the same
owner-vs-recipient key-envelope separation as the list route.

**Auth:** Bearer JWT

**Response:**
```json
{
  "id": "<uuid>",
  "ownerUserId": "<uuid>",
  "nameEnvelope": "<DriveEnvelopeV1 base64>",
  "ownerKeyEnvelope": "<DriveEnvelopeV1 base64>",
  "keyEpoch": 1,
  "nameRevision": 1,
  "epochStatement": "<CollectionEpochStatementV1 base64>",
  "epochStatementHash": "<lowercase SHA-256 hex>",
  "parentCollectionId": null,
  "color": "blue"
}
```

---

### PUT /api/collections/:id

Rename a collection (client re-encrypts the name with the collection key).

**Auth:** Bearer JWT

**Request body:**
```json
{
  "nameEnvelope": "<DriveEnvelopeV1 base64>",
  "nameRevision": 2
}
```

The revision must be exactly one greater than the stored revision and the
envelope must authenticate that exact revision, current epoch, collection and
owner. Concurrent/stale renames fail instead of overwriting a newer name.

**Response:** `200 OK` `{"message": "updated"}`.

---

### DELETE /api/collections/:id

Move a collection — with its whole subtree (sub-folders + files) — to the trash. The folder becomes a single trash entry; restore or purge it via the Trash endpoints. Items already in the trash keep their own entry and deletion time. While trashed, the subtree is invisible to every other endpoint (listings, downloads, shares, federation, collab) and its public share links go dark. Trashed items keep counting against quota until purged.

**Auth:** Bearer JWT (owner only)

**Response:** `204 No Content`.

---

### PATCH /api/collections/:id/color

Set the display color of a folder.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "color": "blue"
}
```

**Response:** `204 No Content`.

---

### POST /api/collections/:id/share

Share a collection with another user on this server.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "recipientUserId": "<uuid>",
  "namedShareEnvelope": "<NamedShareEnvelopeV1 base64>",
  "canUpload": false,
  "canDelete": false,
  "uploadQuotaBytes": null
}
```

`namedShareEnvelope` HPKE-encrypts the collection key to the recipient's
registered Drive key and signs the collection, epoch, sender/recipient accounts
and both incarnation IDs with the sender's registered Drive signing key. All
recipients have read access; `canUpload` and `canDelete` are independent boolean
grants. `uploadQuotaBytes` optionally caps uploads; omit (or `null`) for no
per-share cap.

**Response:** `201 Created` `{"message": "shared"}`. Re-sharing with the same recipient updates the existing grant (upsert).

---

### GET /api/drive/federation/users/:username

Resolve a remote Drive user through authenticated v2 federation before sealing
the collection key.

**Auth:** Bearer JWT
**Query:** `?server=other.example.com` (canonical DNS identity, not a URL)

**Response:**
```json
{
  "username": "bob",
  "server": "other.example.com",
  "account": "bob@other.example.com",
  "driveHpkePublicKey": "<canonical base64, 32 bytes>",
  "accountIncarnationId": "<lowercase SHA-256 hex>",
  "driveSigningPublicKey": "<canonical base64, 32 bytes>",
  "accountAuthorityPublicKey": "<canonical base64, 32 bytes>"
}
```

The response is accepted only after signed discovery, peer pin/rotation policy,
admission, request authentication, and response authentication succeed.

---

### POST /api/collections/:id/federated-shares

Create a domain-bound share for a user on a remote Kutup instance.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "recipientUsername": "bob",
  "recipientServer": "other.example.com",
  "namedShareEnvelope": "<NamedShareEnvelopeV1 base64>",
  "canUpload": true,
  "canDelete": false,
  "uploadQuotaBytes": null
}
```

The named envelope is sealed to the exact `bob@other.example.com` identity
returned by the lookup above. The origin validates the sender signature and all
routing bindings before storing it. The destination repeats that validation
against Bob's current registered incarnation and verifies the owner-signed epoch
statement before accepting the invite. The origin stores the canonical
recipient domain and a SHA-256 capability verifier, not a remote URL or
plaintext capability.

**Response:** `201 Created`
```json
{
  "inviteUrl": "https://this.example.com/invite#server=this.example.com&capability=<base64url>"
}
```

The capability appears only in the fragment so browsers do not send it to the
sharer's web origin. It is shown once and cannot be recovered from the outgoing
share row.

---

## People you share with (profiles)

People who share a folder, either way round and across servers, hand each
other the key to their end-to-end encrypted profile so Drive can show names
and pictures (docs/plans/unified-profile.md). One key per pair, however many
folders they share.

### GET /api/drive/people

**Auth:** Bearer JWT

Everyone you share a folder with or who shares one with you:

```json
{
  "people": [{
    "account": "bob@example.org",
    "local": true,
    "accountIncarnationId": "<hex>",
    "drivePublicKey": "<base64>",
    "driveSigningPublicKey": "<base64>",
    "receivedEnvelope": "<ProfileKeyEnvelopeV1 base64> | null",
    "sentProfileVersion": "<hex> | null"
  }]
}
```

For someone on another server (`local: false`) the three key fields are null:
look them up with `GET /api/drive/federation/users/:username`. Open
`receivedEnvelope` with your Drive key and check it with theirs; the profile
key then fetches their profile through
`GET /api/chat/users/:account/profile/:version`. When `sentProfileVersion` is
not your current profile version, give them your key again.

### PUT /api/drive/profile-keys

**Auth:** Bearer JWT

```json
{
  "recipientAccount": "bob@example.org",
  "envelope": "<ProfileKeyEnvelopeV1 base64>",
  "profileVersion": "<hex, the version the key opens>"
}
```

The server checks that the envelope is from you (your account, incarnation
and Drive signing key), is for that account (and, here, its current
incarnation), and that a share exists between you. Someone on another server
gets it through `PUT /api/fed/drive/profile-keys`. `204`; `404` when there is
no share between you; `400` for an envelope that does not match.

---

## Maps

Kutup stores no map data (docs/plans/maps.md). The administrator chooses the
providers people may use and whether map traffic goes through this server;
each person turns maps on (off by default) and chooses within that. Places
themselves are end-to-end encrypted elsewhere and drawn in the browser.

### GET /api/maps

**Auth:** Bearer JWT

```json
{
  "enabled": true,
  "proxy": "off | available | enforced",
  "providers": [{
    "id": "openfreemap | openstreetmap | custom",
    "name": "OpenFreeMap",
    "kind": "vector | raster",
    "url": "https://tiles.openfreemap.org/styles/liberty",
    "proxyUrl": "/api/maps/proxy/openfreemap/styles/liberty",
    "attribution": "…"
  }],
  "preferences": { "enabled": false, "provider": null, "viaProxy": true }
}
```

`enabled: false` means the administrator turned maps off (no providers are
listed). `proxyUrl` is null when the relay is off. A vector provider's `url`
is a MapLibre style; a raster provider's is a `{z}/{x}/{y}` template.

### PUT /api/maps/preferences

**Auth:** Bearer JWT. Body: `{ enabled, provider, viaProxy }`; `provider` must
be one on offer (or null). Returns the same shape as `GET /api/maps`.

### GET /api/maps/proxy/:provider/*path

**Auth:** Bearer JWT. The resource at that path on the provider (style,
TileJSON, tile, glyphs, sprite), fetched by this server and kept in its
shared cache; JSON is rewritten so every URL on the provider points back
here. Only offered providers while the relay is on; plain path segments
only; images, JSON and vector tiles only, at most 4 MiB. `404` for a provider
not offered or a resource it does not have, `429` above 1,200 requests a
minute per person, `502` when the provider fails (an expired cached copy is
served instead when there is one).

---

## Files

**Write rights.** Reading a file needs the folder's owner or any share on it.
Changing it — uploading into the folder, saving a version, naming or keeping
one, storing a whiteboard asset or thumbnail, claiming a note's seed, or
sending edits over the collab socket — needs the owner or a share with
`canUpload` ("can add and edit"). Everything a recipient stores is charged to
them and counts against the share's `uploadQuotaBytes`.

**Quota.** Every writer checks the same headroom: quota − stored − the full
declared length of the user's open tus uploads (an upload reserves its whole
length until it is finalised).

### POST /api/files/upload

Upload an encrypted file to a collection. Multipart form.

**Auth:** Bearer JWT

**Form fields:**

| Field | Type | Description |
|-------|------|-------------|
| `fileId` | string (canonical UUID) | Client-generated before envelope construction |
| `collectionId` | string (UUID) | Target collection |
| `metadataEnvelope` | string (canonical base64) | `DriveEnvelopeV1` metadata record under the file key, bound to the file (object = parent = file), key generation 1 and revision 1 |
| `fileKeyEnvelope` | string (canonical base64) | `DriveEnvelopeV1` file-key record under the collection key, bound to file, collection, the collection's current epoch and key generation 1 (the revision slot) |
| `file` | binary | Complete typed Drive file blob (`application/octet-stream`) |

The server obtains the current collection epoch itself and rejects malformed,
noncanonical, relocated, stale-epoch, wrong-purpose, or wrong-revision
envelopes. It also validates that the blob's authenticated-format header binds
the same file and key generation 1 before storage (the blob names no folder:
docs/plans/drive-move.md). It never accepts a
server-generated replacement for `fileId`. A `fileId` already used by a
stored file or an open upload is refused with `409` and nothing is written —
a retry cannot overwrite what an earlier attempt stored.

**Response:** `201 Created`
```json
{
  "id": "<same client-generated uuid>"
}
```

---

### GET /api/collections/:id/files

List files in a collection.

**Auth:** Bearer JWT

**Response:** Array of file objects:
```json
[
  {
    "id": "<uuid>",
    "collectionId": "<uuid>",
    "uploaderUserId": "<uuid>",
    "metadataEnvelope": "<DriveEnvelopeV1 base64>",
    "fileKeyEnvelope": "<DriveEnvelopeV1 base64>",
    "keyEpoch": 1,
    "keyGeneration": 1,
    "metadataRevision": 1,
    "encryptedSizeBytes": 4096,
    "createdAt": "2026-03-14T12:00:00Z",
    "updatedAt": "2026-03-14T12:00:00Z",
    "thumbnails": { "sm": "2026-03-14T12:00:05Z", "smKeyGeneration": 1 },
    "thumbnailStale": false,
    "originalKeyGeneration": 1,
    "contentKeyGeneration": 1
  }
]
```

`keyEpoch` is the collection epoch the file key is wrapped at; `keyGeneration`
counts the file's own keys (see "Moving" and `rekey` below).

`thumbnails` has the store time of each thumbnail variant that exists (`sm`,
`lg`; absent keys mean none). `thumbnailStale` is true when a stored thumbnail
was drawn from something other than the file's latest version, so a client
with write access should redraw it (see "Thumbnails" below).

`encryptedSizeBytes` is the size of the ciphertext blob on disk: a 32-byte
typed Drive header, a 24-byte secretstream header, and at least one frame with
a 17-byte authentication/tag overhead.

---

### PUT /api/files/:id

Replace only the authenticated metadata envelope, sealed at the file's current
key generation. The request must advance the stored revision by exactly one;
gaps, rollback, replay, a wrong file binding, and a stale key generation
return `409` or `400` without changing the row.

```json
{
  "metadataEnvelope": "<DriveEnvelopeV1 base64>",
  "metadataRevision": 2
}
```

---

### GET /api/files/:id/download

Download the encrypted content of a file.

**Auth:** Bearer JWT

**Response:** Raw binary (`application/octet-stream`) — the encrypted file
bytes as the file is now: its latest `kind = file` version when it has one
(the same sealed format as the upload), otherwise the original upload.
Public links and federated reads serve the same.

---

### DELETE /api/files/:id

Move a file to the trash (soft delete). The file disappears from every normal endpoint but keeps counting against quota; restore or purge it via the Trash endpoints. Permanent deletion happens from the trash — explicitly, or automatically after `TRASH_RETENTION_DAYS` (default 30).

**Auth:** Bearer JWT (collection owner, or the uploader holding a `canDelete` share)

**Response:** `204 No Content`.

---

## Folder access and keys

Who can open a folder and taking that access away
(docs/plans/drive-share-revocation.md). A folder's keys form a chain of
epochs; every removal rotates to the next.

### GET /api/collections/:id/epochs

The folder's key history, oldest first:
`[{ epoch, epochStatement, epochStatementHash, previousKeyEnvelope? }]`.
`previousKeyEnvelope` (absent for epoch 1) is the previous epoch's key sealed
under this epoch's (purpose 8). Clients unlock older keys from the current one
with `collection_keyring::unlock`, which verifies the owner-signed chain and
every key commitment. **Auth:** owner (also for a trashed folder) or member.
Public links: `GET /api/share/:token/epochs` (anonymous); federated
recipients: `GET /api/drive/federation/shares/:shareId/epochs`.

### GET /api/collections/:id/access

Owner only. `{ keyEpoch, epochStatementHash, members: [{ userId, account,
accountIncarnationId, drivePublicKey, driveSigningPublicKey, canUpload, canDelete, uploadQuotaBytes,
createdAt }], publicLinks: [{ id, token, ownerLinkKeyEnvelope?, expiresAt?,
createdAt }], federatedShares: [{ id, recipientUsername, recipientServer,
recipientIncarnationId, canUpload, canDelete, uploadQuotaBytes, createdAt }] }`.
A link without `ownerLinkKeyEnvelope` predates owner copies and cannot be kept
through a rotation.

### POST /api/collections/:id/rotate

Owner only; all or nothing. **Body:** `{ fromEpoch, epochStatement,
ownerKeyEnvelope, previousKeyEnvelope, nameEnvelope, members: [{ userId,
namedShareEnvelope }], publicLinks: [{ id, collectionKeyEnvelope }],
federatedShares: [{ id, namedShareEnvelope }], removed: { members: [userId],
publicLinks: [id], federatedShares: [id] } }`. The statement must chain from
the current one under the owner's authority; the owner key, previous-key and
name (next name revision) envelopes must be at `fromEpoch + 1`; every kept
member's named share must be sealed at the new epoch to that exact account
(federated: the same account incarnation as before), every kept link
re-wrapped. Kept plus removed must be exactly the current access, else `409`
(also when `fromEpoch` is stale). **Response:** `{ keyEpoch,
epochStatementHash }`.

### POST /api/files/:id/rekey

Give a file a new key before writing to it (or moving it) when its folder has
rotated past it. **Body:** `{ fromGeneration, fileKeyEnvelope,
metadataEnvelope, previousKeyEnvelope }` — a new random file key of generation
`fromGeneration + 1` wrapped at the folder's current epoch, the metadata (same
revision) sealed under it, and the key being left sealed under it
(`PreviousFileKey`, purpose 10). **Response:** `{ keyEpoch, keyGeneration }`.
`409` if another editor re-keyed first or the file is already current.
**Auth:** write access. Open collaboration sockets on the file are closed so
peers reconnect under the new key.

**New content only under the current key.** Versions, assets, thumbnails,
renames and collaborative edits must be sealed at the file's current key
generation (`409 file key changed` otherwise), and are refused for a file
whose key is wrapped at an older epoch than its folder's (`409 file needs a
re-key`). An upload sealed at an older folder epoch gets `409 folder key
changed` (reload the folder and retry).

**Listing fields.** File rows carry `keyGeneration`, `originalKeyGeneration`
(the upload's), `contentKeyGeneration` (that of what `/download` serves),
`keyHistory` (`[{ generation, previousKeyEnvelope }]`, generations 2 to
`keyGeneration` in order, each sealing the one before) and
`thumbnails.{sm,lg}KeyGeneration`; version rows carry `keyGeneration`; an
asset download carries `X-Kutup-Key-Generation`. Each object opens with the
file key of its own generation, reached from the current key through
`keyHistory` wherever the file is.

### POST /api/files/:id/move

Move a file to another folder of the same owner (docs/plans/drive-move.md).
**Body:** `{ fromCollectionId, toCollectionId, toKeyEpoch, fileKeyEnvelope }`
— the file's current key sealed under the destination's key at its current
epoch `toKeyEpoch`, with the file's key generation. Nothing else changes: the
content, metadata, versions, thumbnails and assets are bound to the file, not
the folder. **Response:** `{ collectionId, keyEpoch }`. **Auth:** write access
to both folders. `400` same folder, another owner's folder (copy instead) or
an invalid envelope; `403` no write access; `409 the file moved`
(`fromCollectionId` is stale), `409 file needs a re-key` (re-key it in its
folder first, so no one removed from that folder can follow it), `409 folder
key changed` (the destination rotated; reload). Open collaboration sockets on
the file are closed.

### POST /api/collections/:id/move

Put a folder under another of the owner's folders, or at the top level.
**Body:** `{ parentCollectionId: string | null }`. A folder's key is sealed to
its owner, not its parent, so nothing encrypted changes. **Response:** `204`.
**Auth:** owner (`404` otherwise). `400` into itself or a folder inside it, or
under a folder the caller does not own.

---

## Trash

Trash is **owner-scoped**: an item lives in the trash of the user who owns the collection it belongs to (a share recipient's delete lands in the owner's trash — the Google Drive model). Every entry is a *trash root*: a deleted file, or a deleted folder carrying its whole subtree. A background sweeper purges roots older than `TRASH_RETENTION_DAYS` (default 30; `0` disables the sweeper). Federated Drive deletes (`DELETE /api/fed/drive/files/:fileId`) remain permanent — there is no cross-server trash.

### GET /api/trash

List the caller's trash roots, newest first. Folder rows carry the complete
authenticated owner collection record. File rows additionally carry the parent
collection's owner-key envelope and signed epoch record so the metadata chain
can be verified even when the collection is absent from the live listing.

**Auth:** Bearer JWT

**Response:** `200 OK`
```json
{
  "folders": [
    {
      "id": "<uuid>",
      "ownerUserId": "<uuid>",
      "nameEnvelope": "<DriveEnvelopeV1 base64>",
      "ownerKeyEnvelope": "<DriveEnvelopeV1 base64>",
      "keyEpoch": 1,
      "nameRevision": 1,
      "epochStatement": "<CollectionEpochStatementV1 base64>",
      "epochStatementHash": "<lowercase SHA-256 hex>",
      "color": "blue",
      "items": 12,
      "deletedAt": "2026-06-11T11:22:33Z"
    }
  ],
  "files": [
    {
      "id": "<uuid>",
      "collectionId": "<uuid>",
      "metadataEnvelope": "<DriveEnvelopeV1 base64>",
      "fileKeyEnvelope": "<DriveEnvelopeV1 base64>",
      "keyEpoch": 1,
      "metadataRevision": 1,
      "collectionOwnerUserId": "<uuid>",
      "collectionOwnerKeyEnvelope": "<DriveEnvelopeV1 base64>",
      "collectionKeyEpoch": 1,
      "collectionEpochStatement": "<CollectionEpochStatementV1 base64>",
      "collectionEpochStatementHash": "<lowercase SHA-256 hex>",
      "deletedAt": "2026-06-11T11:22:33Z"
    }
  ]
}
```

`items` is the number of files trashed together with the folder (its subtree).

### POST /api/trash/:id/restore

Put a trash root back where it was. Restoring a folder restores its whole subtree; if its original parent is gone or still trashed, it comes back at the top level. Restoring a file whose folder is still in the trash returns `409 Conflict` (restore the folder instead).

**Auth:** Bearer JWT (owner only)

**Response:** `200 OK` `{"message": "restored"}` · `409 Conflict` when the parent folder is still trashed.

### DELETE /api/trash/:id

Permanently purge one trash root: DB rows, S3 blobs (including version/asset children), and the held quota. Irreversible.

**Auth:** Bearer JWT (owner only)

**Response:** `204 No Content`.

### DELETE /api/trash

Empty the caller's whole trash. Irreversible.

**Auth:** Bearer JWT

**Response:** `204 No Content`.

---

## Public Shares

### POST /api/share/

Create a public share link for one collection. **Body** also carries the
link's client-chosen `id` (canonical UUID) and `ownerLinkKeyEnvelope`: the
link key sealed for the owner under their master key (`DriveEnvelopeV1`
purpose 9, object = link id, parent = owner, epoch 1), so the owner can list
and copy the link and keep it working across folder-key rotations. The link key used to open the
typed collection-key envelope lives only in the URL fragment; the server never
sees it.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "shareType": "collection",
  "targetId": "<uuid>",
  "collectionKeyEnvelope": "<DriveEnvelopeV1 base64>",
  "expiresInHours": 48
}
```

V1 accepts only `shareType: "collection"`. `expiresInHours` is optional; omit
or send `null` for no expiry; otherwise 1 to 87,840 (ten years), else `400`.
A link's folder in the trash makes the link answer `404` until it is
restored. `collectionKeyEnvelope` uses the public-link
purpose and binds the target collection, owner and current collection epoch.
Malformed, relocated, stale-epoch or wrong-purpose envelopes are rejected
before storage.

**Response:** `201 Created`
```json
{
  "id": "<uuid>",
  "token": "<random-token>"
}
```

The client builds the share URL as
`<SERVER_URL>/s/<token>#key=<base64-link-key>`; the server returns only the
token.

---

### GET /api/share/:token

Get metadata for a public share. The wrapped collection key is included; the link key needed to unwrap it lives only in the URL fragment held by the recipient.

**Auth:** None

**Response:**
```json
{
  "id": "<uuid>",
  "shareType": "collection",
  "targetId": "<uuid>",
  "collectionKeyEnvelope": "<DriveEnvelopeV1 base64>",
  "collectionKeyEpoch": 1,
  "ownerUserId": "<uuid>",
  "expiresAt": "2026-04-01T00:00:00Z"
}
```

`expiresAt` is `null` when the share has no expiry. Returns `410 Gone` if the share has expired.

---

### GET /api/share/:token/files

List files in a public share.

**Auth:** None

**Response:** Array of file objects. Note: shape is similar to `GET /api/collections/:id/files` but **omits** `uploaderUserId` and `updatedAt`, and `createdAt` is serialized as a string (matches the database `TIMESTAMP` text form).
```json
[
  {
    "id": "<uuid>",
    "collectionId": "<uuid>",
    "metadataEnvelope": "<DriveEnvelopeV1 base64>",
    "fileKeyEnvelope": "<DriveEnvelopeV1 base64>",
    "keyEpoch": 1,
    "keyGeneration": 1,
    "metadataRevision": 1,
    "encryptedSizeBytes": 4096,
    "createdAt": "2026-03-14T12:00:00Z",
    "originalKeyGeneration": 1,
    "contentKeyGeneration": 1
  }
]
```

Returns `400` if the share targets a single file (use `/download/:fileId` instead), `410` if the share has expired.

---

### GET /api/share/:token/download/:fileId

Download a file from a public share. Streams the encrypted blob (`application/octet-stream`) through the backend; the client decrypts it with the link key from the URL fragment.

**Auth:** None (the token is the capability)

**Response:** the raw encrypted bytes.

Returns `410 Gone` if the share has expired, `403` if the file does not belong to the shared target.

---

## Chat (E2EE messaging)

The current Chat protocol is described in `docs/chat-protocol.md`, media in
`docs/chat-media.md`, and continuous display-history recovery in
`docs/chat-backup.md`. Clients run libsignal Direct Chat and OpenMLS private
groups; servers retain public routing/identity material, operational metadata,
and opaque ciphertext rather than protected plaintext. All endpoints require a
Bearer JWT unless noted. Wire types live in `crates/kutup-chat-proto` and are
fully described by the OpenAPI document.

### POST /api/chat/device

Register the calling client as a chat device. The server assigns the lowest free device id and enforces its configured active-device limit, never exceeding the V1 hard cap of 10. Body: `suite` (`1`), `registrationId` (libsignal, `1..16383`), `identityKey`, `signedPreKey` (signature required), `lastResortKyberPreKey` (bundles are never non-PQ), optional `oneTimePreKeys[]` / `oneTimeKyberPreKeys[]` pools, optional `name`. All key material is canonical base64.

**Response:** `200 OK` → `{ "deviceId": 1 }` · `409` when the configured active-device limit is reached.

### GET /api/chat/device

The caller's chat devices: `{ "devices": [{ "deviceId", "suite", "name", "createdAt", "lastSeenAt" }] }`.

### PATCH /api/chat/device/{deviceId}

Rename one of the caller's registered Chat installations. The body is
`{ "name": "Work laptop" }`; names are trimmed, required, limited to 64 Unicode
characters, and cannot contain control characters. This changes only
account-private display metadata—the numeric device ID, encryption keys,
sessions, signed device manifest, and protected history remain unchanged.
`204`.

### DELETE /api/chat/device/{deviceId}

Revoke a chat device — hard delete; prekey pools and mailbox rows are removed,
and live sockets close. It does not delete account-level Chat history backup.
`204`.

### POST /api/chat/backup

Idempotently provision the always-on Chat archive after account recovery. The
body contains a typed account-master-key envelope for the random backup root
and an account-authority-signed manifest-signer authorization. The server
validates public bindings and signatures but never receives the root key.

### GET /api/chat/backup

Return provisioning state, current signed manifest/cursor, latest
server-acknowledged protected time, and dedicated Chat quota usage split into
message history, administrator-retained delivery media, and history media.

### POST /api/chat/backup/segments

Append one idempotent encrypted event segment. Requests bind a random operation
ID, active source device, contiguous per-device sequence and digest chain,
account-manifest sequence, ciphertext digest and length. The server assigns the
monotonic account cursor. `507` means the durable local outbox is not yet
protected; clients must show the latest acknowledged time and storage action.

### GET /api/chat/backup/segments?after=N&limit=N

Page the complete ordered encrypted event tail. Restoring it does not advance a
mailbox cursor or establish Direct/MLS protocol state.

### POST /api/chat/backup/bases

Stage a typed encrypted compacted base using multipart `metadata` and
`ciphertext` fields. Staging is bounded and expires after 24 hours. Temporary
overlap with the current archive is allowed only when the post-CAS footprint
fits the account's administrator-configured Chat quota.

### GET /api/chat/backup/bases/{objectId}

Stream only the currently committed encrypted base and its ciphertext digest.

### PUT /api/chat/backup/manifest

Verify and compare-and-swap a signed manifest against the exact current
generation, cursor and digest. Commit atomically activates the staged base and
reconciled media set, then releases superseded message/media quota.

### POST /api/chat/backup/media/copy

Copy an account-owned ordinary Chat-media ciphertext into a padded,
backup-specific outer encryption. The client supplies only the derived outer
key; the original attachment plaintext/key never reaches the server.

### POST /api/chat/backup/media

Multipart direct-upload fallback for a verified outer-encrypted media object
retained locally after its ordinary delivery object has expired.

### GET /api/chat/backup/media/{mediaId}

Lazily stream one opaque history-media object. Clients validate its typed
header, digest, secretstream final tag, source length and zero padding before
placing the inner Chat-media ciphertext in the private cache.

### POST /api/chat/backup/media/reconciliation

Page the exact, digest-bound media reference set for a target generation before
manifest CAS. Unreferenced history media is garbage-collected only at commit.

There is no Chat-backup DELETE route, ordinary disable action, or
device-transfer fallback. Account deletion and administrator loss-recovery wipe
invoke internal lifecycle cleanup that transactionally removes backup database
state/quota and deletes its object-storage prefix.

### PUT /api/chat/keys?deviceId=N

Rotate `signedPreKey` / `lastResortKyberPreKey` and/or upload more one-time prekeys (only fields present are changed; pool inserts are idempotent per `keyId`).

### GET /api/chat/keys/count?deviceId=N

Remaining one-time pool sizes: `{ "oneTimePreKeys": n, "oneTimeKyberPreKeys": n }` — clients replenish below a threshold.

### POST /api/chat/manifest

Publish one complete `AccountManifestV1`, signed by the account self-authority.
Sequences advance by exactly one and hash-link to the preceding signed record.
The authority and incarnation cannot change inside a chain. Every signed
device id, registration id, direct-chat identity key, MLS credential/delivery
key and suite must exactly match a registered server tuple. Registered rows
not selected by the authority-signed manifest are pruned atomically; this
recovers a crash between device registration and manifest publication without
allowing an unmanifested device to become trusted. The Drive HPKE and
share-signing keys are account-scoped fields in the same manifest. Publication
atomically updates the current head and immutable history; exact replay is
idempotent. Malformed signatures, gaps, forks, authority replacement, or a
declared device-key conflict return `409`.

### GET /api/chat/users/{username}/manifest

Return the current account-signed device manifest for a local user. This direct
manifest endpoint is authenticated. A client independently verifies its
signature, authority continuity, and hash chain rather than trusting a server
status label.

### GET /api/chat/users/{username}/manifest-history

Return complete, individually account-signed manifest records for an exact
inclusive range. Query parameters are `fromSequence`, `toSequence`, and an
optional `pageFromSequence`. Pages contain at most 64 records and carry the
next exact sequence, never an opaque server cursor. Missing, duplicated,
reordered, cross-incarnation, or partially verified history does not clear a
client gap and blocks new sends to that peer. A remote canonical address is
resolved only through the authenticated federation transport.

### GET /api/chat/profile

Owner-only recovery of the current opaque encrypted profile, including the
random profile key wrapped under the account master key for linked-device
recovery. Returns `404` until a profile has been published.
The response carries `suite: 1`, canonical `account`, version, revision,
source device, and canonical `ProfileEnvelopeV1` fields. The owner-only
response includes the wrapped profile-key envelope; peer responses omit it.

### PUT /api/chat/profile

Publish a new opaque encrypted profile: display name, optional avatar and
optional `about` (Signal's one-line "about", ≤ 140 characters, padded to
128/254/512 bytes before encryption). The server sees
only ciphertext, a profile-key-derived version, an access-key verifier, a
master-key-wrapped profile key, revision, and source device. Revision plus
source-device ordering resolves concurrent linked-device writes; exact replay
is idempotent and a stale/conflicting revision returns `409`.
Every encrypted field binds the exact profile suite, authenticated canonical
account, version, revision, source device and purpose. Unknown suites,
noncanonical base64, malformed headers, relocation and trailing bytes return
`400` before persistence.

### GET /api/chat/users/{username}/profile/{version}

Capability-gated encrypted profile lookup for a local or federated canonical
address. The caller supplies the profile access key in the dedicated request
header rather than the URL. A wrong version or capability is deliberately
indistinguishable from a missing profile and returns `404`.

### GET /api/chat/users/{username}/keys

Return PQXDH prekey bundles for **every** active Chat device of `username`
(a logical message encrypts to all of them), together with the exact complete
account-signed manifest. Each bundle carries `identityKey`, `signedPreKey`,
`kyberPreKey` (a consumed one-time ML-KEM-1024 prekey, or the reusable
last-resort key when the pool is empty), and optionally a consumed one-time EC
prekey. The client verifies manifest and bundle identity equality before
creating sessions. Fetches are limited to 30/min per authenticated account
(`RATE_LIMIT_CHAT_KEYS_PER_MIN`) with a coarse 120/min IP wall
(`RATE_LIMIT_CHAT_KEYS_IP_PER_MIN`).

### POST /api/chat/users/{username}/messages

Deliver one logical message as per-device ciphertexts: `{ "senderDeviceId": n, "envelopes": [{ "deviceId", "registrationId", "envelopeType": "preKey"|"message", "suite": 1, "content": "<base64>" }] }`. The device set must exactly match the recipient's current devices — ids **and** registration ids — or the send fails with `409 { "missingDevices": [], "staleDevices": [], "extraDevices": [] }` (Signal's contract: no device can be silently skipped, and reinstalled devices are detected). Stored envelopes are also pushed to the recipient's live chat sockets.

### POST /api/chat/sync/messages

Deliver an encrypted sent transcript to every other active device belonging to
the authenticated account. The sending device is excluded from the exact
device-set check; an empty destination set succeeds for a single-device
account. Note to Self and ordinary outgoing-message synchronization use this
same idempotent mailbox path.

### GET /api/chat/messages?deviceId=N&limit=100

Drain the device's mailbox, oldest first (max 500/page): `{ "envelopes": [{ "id", "sender", "senderDeviceId", "envelopeType", "suite", "content", "serverTimestamp" }], "more": bool }`. Envelopes stay stored until acked.

### POST /api/chat/messages/ack?deviceId=N

`{ "ids": ["<uuid>", …] }` → deletes processed envelopes; returns `{ "acked": n }`.

### POST /api/chat/link-preview

Fetch one public page or image for a link preview the caller is building
(`{ "url": "https://…", "kind": "page" | "image" }` → `{ finalUrl,
contentType, body }`, body standard base64). Only `https` on port 443 whose
every resolved address is public; the connection is pinned to the checked
address; at most three redirects, each checked again; pages are cut at
512 KiB and must be HTML, images must be JPEG/PNG/WebP/GIF of at most 2 MiB;
8 s total. 30 per minute per account. `404` when `CHAT_LINK_PREVIEWS=false`
(then `/api/auth/settings` → `chat.linkPreviews` is false), `400` for a
non-public or non-https URL, `422` when the site gives nothing usable. The
browser parses the page (`DOMParser`) and resizes the image; the preview then
travels end-to-end encrypted in the message.

### GET /api/chat/call-servers

ICE servers for a call ([`chat-calls.md`](chat-calls.md)):
`{ "iceServers": [{ "urls": [...], "username"?, "credential"? }], "relay": bool, "expiresAt"? }`.
With `CHAT_TURN_URLS` and `CHAT_TURN_SECRET` set, the TURN entry carries a
12-hour coturn shared-secret credential (username `<expiry>:<pseudonym>`,
password `base64(HMAC-SHA1(secret, username))`); `relay` is then true. 60
per minute per account.

### POST /api/chat/group-calls/token

`{ "host", "roomId", "participantId" }` (room and tag: 32 lowercase hex each)
→ `{ "url", "token" }`: the SFU's WebSocket URL and a 6-hour LiveKit token
for that room ([`chat-calls.md`](chat-calls.md) "Group calls"). The host
mints it; another host is asked over signed federation
(`POST /api/fed/chat/group-calls/token`). `404` when the host has no SFU,
`429` over 30 per minute per account (300 per origin server), `502` when
the host cannot be reached.

### PUT /api/chat/push-subscription

`{ "deviceId": N, "endpoint": "https://…" }` → `204`: wake this chat device
through the browser's push subscription while it has no live socket
([`chat-notifications.md`](chat-notifications.md)). Only endpoints of the
push services in `CHAT_WEB_PUSH_HOSTS` (https, port 443); `400` otherwise,
`404` when Web Push is off (`/api/auth/settings` → `chat.webPushPublicKey`
is then absent) or the device is not the caller's.

### DELETE /api/chat/push-subscription?deviceId=N

`204`: stop waking the device.

### POST /api/chat/invite-links

One operation on a group link's mailbox ([`chat-invite-links.md`](chat-invite-links.md)):
`{ "host": "<domain>", "operation": { "op": "put" | "delete" | "preview" |
"request" | "requests" | "decide" | "status" | "cancel", … } }` →
`{ "result": "done" | "preview" | "requested" | "requests" | "status", … }`.
The server carries it out when it is the host, and otherwise forwards it
over signed federation. `404` when groups are off here or the link or request
no longer exists, `403` for a token that does not match, `429` over the rate
or waiting-request limits, `502` when the host cannot be reached.

### POST /api/chat/ws-ticket?deviceId=N

Mint a random, one-time browser WebSocket ticket bound to the authenticated user and chat device. The ticket expires in 60 seconds and is returned as `{ "ticket", "expiresAt" }`.

### GET /api/chat/ws?ticket=…

WebSocket. Browsers use the one-time ticket; native clients instead send `Authorization: Bearer …` with `?deviceId=N`. Reusable JWT query parameters are rejected. Server → client JSON frames: `{ "type": "drainMailbox" }` once on connect (fetch the backlog over REST), then `{ "type": "envelope", "envelope": {…} }` per newly arrived message. Acks stay on REST — the mailbox is the source of truth. The only client → server frame is `{ "type": "ping" }`, answered by `{ "type": "pong" }`: browsers cannot send protocol pings, so the web client probes every 25 s and reconnects when no answer arrives within 10 s.

---

## Chat Federation — Server-to-Server Endpoints

Chat federation is present only when the administrator configures a persistent
v2 identity. Admission follows the global stop plus Chat's `disabled`,
`allowlist`, `blocklist`, or `open` mode, trust floor, and directional domain
rules. Policy is evaluated before DNS/discovery or delivery. Admitted traffic
must then pass signed discovery and complete identity-history verification,
persistent pin/rotation/quarantine policy, public-HTTPS and DNS/SSRF checks,
strict RFC 9421/9530 request and response signatures, replay reservation,
request/body bounds, protocol checks, and coarse rate limiting. The normative
common transport contract is in `docs/federation-protocol.md`.

The v2 Ed25519 signature binds method, authority, path/query, exact-body digest,
content type, federation version, feature, origin, destination, key ID, nonce,
and a maximum five-minute lifetime. Authenticated responses bind those request
components in reverse origin/destination order. A destination mismatch,
unknown pinned key, bad signature, nonce/content conflict, or invalid time
window is rejected.

### GET /.well-known/kutup/federation.json

Signed v2 discovery containing the canonical server, delegated `apiBase`,
typed capabilities, embedded current identity document and hash, validity
window, and signature. Returns `404` when the shared identity is absent, the
global stop is active, or both Chat and Drive are disabled. An individually
disabled feature is omitted from `capabilities` while the other remains
discoverable. Production discovery and delegated API targets require public
HTTPS.

### GET /.well-known/kutup/federation/identity/{sequence}.json

Return one immutable identity document from the locally verified, contiguous
history. Genesis is sequence zero. Every rotation hash-links its predecessor
and is signed by both old and new keys.

### GET /api/fed/chat/users/{username}/keys

Authenticated server-to-server directory lookup. Returns the remote user's
account-signed complete manifest and replay-safe last-resort PQ bundles. It
deliberately does not consume one-time prekeys, so a replayed signed read cannot
exhaust the remote recipient's pool.

### GET /api/fed/chat/users/{username}/manifest

Return the current complete account-signed manifest through an authenticated,
origin- and destination-bound federation response.

### GET /api/fed/chat/users/{username}/manifest-history

Return the same exact-sequence, maximum-64-entry history pages as the local
route. The signed request URI binds `fromSequence`, `toSequence`, and optional
`pageFromSequence`.

### GET /api/fed/chat/users/{username}/profile/{version}

Authenticated proxy lookup for an opaque encrypted profile. The server-to-
server signature authenticates and destination-binds the originating
homeserver; the separate profile access-key header remains the end-to-end
capability. Wrong capabilities return `404`.

### POST /api/fed/chat/messages

Receive one signed, ordered `FederatedChatTransaction`. The receiver enforces a
contiguous per-origin sequence, exact recipient device set, canonical
origin/sender and destination/recipient binding, and transaction-id replay
safety. Mailbox rows, the stored idempotent response, and the sequence
high-water mark commit atomically. Exact replay returns the stored response;
device mismatch or sequence gap returns typed `409` data so the origin can
refresh/re-encrypt or replay the missing retained transaction.

### POST /api/fed/chat/invite-links

One signed `InviteLinkOperationV1` for a group link this server hosts, from
an account of the origin server; answered like `POST /api/chat/invite-links`
in a signed response. The authenticated origin is recorded as a request's
server.

---

## Drive Federation — Local Authenticated Endpoints

These routes let a local browser interact with a remote encrypted share. The
local server performs all remote discovery, admission, identity pinning, and
message authentication; browsers never submit a remote API URL.

### POST /api/drive/federation/shares

Accept an invite after the browser parses its fragment.

**Auth:** Bearer JWT

```json
{
  "server": "sharer.example.com",
  "capability": "<base64url>"
}
```

The server fetches the signed invite and verifies that its source domain and
intended recipient username match the authenticated local account. Success is
`201 Created` with:

```json
{
  "id": "<uuid>",
  "remoteDomain": "sharer.example.com",
  "remoteCollectionId": "<uuid>",
  "namedShareEnvelope": "<NamedShareEnvelopeV1 base64>",
  "nameEnvelope": "<DriveEnvelopeV1 base64>",
  "keyEpoch": 1,
  "nameRevision": 1,
  "epochStatement": "<CollectionEpochStatementV1 base64>",
  "epochStatementHash": "<lowercase SHA-256 hex>",
  "ownerUserId": "<uuid>",
  "ownerAccount": "alice@sharer.example.com",
  "ownerIncarnationId": "<lowercase SHA-256 hex>",
  "ownerSigningPublicKey": "<canonical base64, 32 bytes>",
  "ownerAuthorityPublicKey": "<canonical base64, 32 bytes>",
  "canUpload": true,
  "canDelete": false,
  "uploadQuotaBytes": null,
  "createdAt": "<RFC3339>"
}
```

The retained remote capability is secret server-side state and is omitted from
all responses.

### GET /api/drive/federation/shares

List the authenticated user's accepted remote shares. Returns the same public
shape as acceptance, without any capability.

### DELETE /api/drive/federation/shares/:shareId

Remove one accepted remote share for the authenticated user. Returns `204`.

### GET /api/drive/federation/shares/:shareId/files

Return the signed and verified remote ciphertext metadata list.

### GET /api/drive/federation/shares/:shareId/files/:fileId/content

Stream remote ciphertext. The local server first spools and hashes the complete
remote response, verifies its signed RFC 9530 digest under the pinned peer key,
then releases the verified stream to the browser.

### POST /api/drive/federation/shares/:shareId/files

Upload encrypted multipart fields (`fileId`, `metadataEnvelope`,
`fileKeyEnvelope`, and `file`). Exact retries are idempotent
and return the same `201 { "id": "<uuid>" }` result. The body is spooled to
disk and streamed on to the owner's server with its signed content digest;
it is never held in memory.

### POST /api/drive/federation/shares/:shareId/refresh

Bring a share's stored copy up to the owner's current folder key after a
rotation. The recipient's server fetches the invite again and accepts it only
from the same owner, folder and authority, never at an older epoch, and only
if the owner's signed history (`GET /api/fed/drive/epochs`) descends from the
stored epoch. A revoked share fails from the owner's server. **Response:** the
refreshed share.

### DELETE /api/drive/federation/shares/:shareId/files/:fileId

Move a file this share uploaded to the owner's trash, when `canDelete`
permits it. Exact retries are idempotent and return `204`.

---

## Drive Federation — Server-to-Server Endpoints

All `/api/fed/drive/*` routes require the unified `drive.v1` RFC 9421/9530
request signature and return an authenticated response. Except for user lookup,
they also require `Kutup-Share-Capability`; the capability is checked only
after the request's canonical origin domain has authenticated, and the share
must be bound to that same domain.

### GET /api/fed/drive/users/:username

Return `{ "username", "server", "publicKey" }` for one active local user.

### PUT /api/fed/drive/profile-keys

Signed server-to-server delivery of a profile key
(`{ senderAccount, recipientAccount, envelope, profileVersion }`). The sender
must be on the calling server and the recipient here, the envelope must name
both (and the recipient's current incarnation), and a share must exist
between them. The recipient's client checks the sender's signature.

### GET /api/fed/drive/invite

Return the encrypted collection metadata, wrapped key, intended recipient, and
grants for the capability-authorized share.

### GET /api/fed/drive/files

List ciphertext file metadata for the capability-authorized collection.

### GET /api/fed/drive/epochs

The capability-authorized folder's key history, signed.

### GET /api/fed/drive/files/:fileId/content

Stream ciphertext with its precomputed signed content digest and exact length.

### POST /api/fed/drive/files

Store one encrypted multipart upload. The exact ciphertext is hashed while it
is spooled and the digest is persisted with the file row. A stable request ID
plus authenticated request hash provides persistent idempotency. The folder
owner pays: the upload must fit their quota (less their open uploads) and the
share's `uploadQuotaBytes`, measured from the files the share uploaded. A
`fileId` already in use is `409`. The request is signed over its content
digest: the server verifies the signature first, spools and hashes the body,
and parses nothing until the digest matches. Body cap 10 GiB.

### DELETE /api/fed/drive/files/:fileId

Move one file **this share uploaded** to the owner's trash (restorable, and
purged with its versions, assets, thumbnails and charges by the trash's own
path), under a persistent idempotent mutation result. Other files are `404`.

The removed `/api/fed/users`, `/api/fed/invites/*`, `/api/fed/shares/*`,
`/api/fed-proxy/*`, `/api/collections/:id/share-federated`, and
`/api/collections/fed-pubkey` routes have no compatibility handlers and return
`404`.

---

## Admin

All admin endpoints require the `isAdmin` flag on the JWT and share a stricter per-IP rate limit (120/min, `RATE_LIMIT_ADMIN_PER_MIN`; over-limit requests return `429`).

Every mutating admin endpoint (create / update / delete user, force-disable 2FA, settings update) writes a row to the **admin audit log** — who did what to whom, when. The log is readable via `GET /api/admin/activity` below. Audit rows have no foreign keys and outlive the accounts they reference; the human-readable identities (emails, usernames) are snapshotted into the row's `payload` at action time.

### GET /api/admin/users

List all registered users.

**Auth:** Bearer JWT (admin)

**Response:** Array of user objects:
```json
[
  {
    "id": "<uuid>",
    "email": "alice@example.com",
    "username": "alice",
    "storageQuotaBytes": 10737418240,
    "storageUsedBytes": 524288000,
    "isAdmin": false,
    "isActive": true,
    "totpEnabled": false,
    "createdAt": "2026-03-14T12:00:00Z",
    "isProtected": false
  }
]
```

`isProtected` is `true` for the break-glass admin (the account from the `ADMIN_ACCOUNT` env var). Protected users cannot be demoted, disabled, or deleted — the relevant mutations below return `403`.

---

### POST /api/admin/users

Create a user account (admin-initiated, bypasses registration settings). The user logs in with `tempPassword` and is then forced through the first-login setup flow to generate their own key bundle and recovery phrase.

**Auth:** Bearer JWT (admin)

**Request body:**
```json
{
  "email": "newuser@example.com",
  "username": "newuser",
  "tempPassword": "temporaryPassword",
  "storageQuotaBytes": 10737418240
}
```

`storageQuotaBytes` is optional and defaults to 10 GB. Returns `201 Created` `{"message": "user created"}`. `409` if the email or username is already taken.

---

### PUT /api/admin/users/:id

Update a user. All fields are optional; only the ones present in the request are applied.

**Auth:** Bearer JWT (admin)

**Request body:**
```json
{
  "storageQuotaBytes": 21474836480,
  "isActive": true,
  "isAdmin": false
}
```

`isAdmin` promotes/demotes the user. The change is reflected in JWT claims on the user's next token refresh.

**Response:** `200 OK` `{"message": "updated"}`. `403` if the request would demote or disable the break-glass admin; `400` if it would leave zero usable admins.

---

### DELETE /api/admin/users/:id

Delete a user and all their data.

**Auth:** Bearer JWT (admin)

**Response:** `204 No Content`. `403` if the target is the break-glass admin.

---

### DELETE /api/admin/users/:id/2fa

Force-disable a user's TOTP two-factor authentication — an admin override for users locked out of their authenticator. Clears `totp_secret` and `totp_enabled`; the account becomes password-only until the user re-enables 2FA from their Security page. Allowed on any user, including the break-glass admin.

**Auth:** Bearer JWT (admin)

**Response:** `200 OK` `{"message": "2fa disabled"}`. `404` if the user does not exist.

---

### POST /api/admin/users/:id/rotate-temp-password

Replace the temporary password of an account still in first-login state (`isFirstLogin: true`). Such an account has no E2EE key material yet, so nothing is destroyed. For an established account this returns `409` — under E2EE the server cannot reset a password without destroying the user's data; the user self-serves via `POST /api/auth/recover` (recovery phrase), or the admin wipes (below). Design: `docs/research/10-admin-password-reset.md`.

**Auth:** Bearer JWT (admin)

**Request body:** `{"tempPassword": "<new temp password>"}`

**Response:** `200 OK` `{"message": "temp password rotated"}` · `409` when the user has completed setup.

---

### POST /api/admin/users/:id/wipe

Destructive account reset for a user who lost both their password and their recovery phrase (their data is cryptographically unreachable anyway). Purges every collection the user owns — files, versions, assets, S3 blobs, share links, trash — erases the key bundle, disables TOTP, revokes collab device keys and received shares, then resets the account to first-login with the supplied temp password. Email, username, and quota survive. **Irreversible.** Refused (`403`) for the break-glass admin.

**Auth:** Bearer JWT (admin)

**Request body:** `{"tempPassword": "<new temp password>"}`

**Response:** `200 OK` `{"message": "account wiped"}`.

---

### GET /api/admin/stats

Return aggregate server statistics.

**Auth:** Bearer JWT (admin)

**Response:**
```json
{
  "totalUsers": 42,
  "activeUsers": 39,
  "totalFiles": 1234,
  "totalStorageUsedBytes": 107374182400,
  "totalCollections": 87,
  "storageTotalBytes": 536870912000,
  "storageBackendUsedBytes": 268435456000
}
```

`totalStorageUsedBytes` is the DB sum of per-account usage. `storageTotalBytes` and `storageBackendUsedBytes` are the storage backend's real total capacity and on-disk usage, probed live from the SeaweedFS master (`SEAWEEDFS_MASTER_URL`); `storageTotalBytes` falls back to the `STORAGE_TOTAL_BYTES` env var, and both are `0` when no probe or env var is configured.

---

### GET /api/admin/activity

The admin audit-log feed, newest first.

**Auth:** Bearer JWT (admin)

**Query parameters:** `limit` (1–100, default 50) · `before` (cursor: return
entries with `id` lower than this — pass the previous page's `nextBefore`) ·
`actionPrefix` (for example `federation.`) · `domain` (an exact canonical
federation domain in the structured event payload). Filters compose and the
cursor remains stable.

**Response:**
```json
{
  "entries": [
    {
      "id": 7,
      "action": "user.create",
      "adminUserId": "<uuid>",
      "adminEmail": "admin@example.com",
      "adminUsername": "admin",
      "targetUserId": "<uuid>",
      "targetEmail": "newuser@example.com",
      "payload": { "email": "newuser@example.com", "username": "newuser", "storageQuotaBytes": 10737418240 },
      "occurredAt": "2026-06-11T11:22:33Z"
    }
  ],
  "nextBefore": null
}
```

Actions include user/settings changes plus `federation.policy.*`,
`federation.rule.*`, `federation.peer.*`, and `federation.identity.*`. Identity
pin, authenticated rotation, quarantine, verification, and break-glass re-pin
events retain full fingerprints, sequences, and reasons but never private
signing keys or Drive capabilities. `adminEmail`/`targetEmail` are the live
identities and become `null` once the referenced account is deleted — the
`payload` snapshot keeps the trail readable. `nextBefore` is non-null while
older pages remain.

### GET /api/admin/activity/export

Export the same filtered audit stream as spreadsheet-safe UTF-8 CSV. It accepts
`before`, `actionPrefix`, and `domain`; `limit` is clamped to 1–5000 and defaults
to 1000. Cells beginning with spreadsheet formula markers are neutralized and
the response is downloaded as `kutup-admin-audit.csv`.

---

### GET /api/admin/maps · PUT /api/admin/maps

**Auth:** Bearer JWT (admin)

```json
{
  "enabled": true,
  "providers": ["openfreemap", "openstreetmap"],
  "custom": null,
  "proxy": "available",
  "cacheMegabytes": 2048
}
```

`custom` is the server's own tile server,
`{ name, kind: "vector" | "raster", url, attribution }`: a style URL, or a
tile template with `{z}`, `{x}` and `{y}`; it must also be listed in
`providers`. Maps on with no provider, a provider listed twice, or a cache
above 102,400 MB is `400`. Saving writes the `maps.settings.update` audit
entry.

---

### GET /api/admin/settings

Return current global server settings.

**Auth:** Bearer JWT (admin)

**Response:**
```json
{
  "registrationEnabled": true
}
```

---

### PUT /api/admin/settings

Update global server settings.

**Auth:** Bearer JWT (admin)

**Request body:**
```json
{
  "registrationEnabled": false
}
```

**Response:** Same shape as `GET /api/admin/settings`.

---

### GET /api/admin/federation

Return the unified federation identity, feature policies, domain rules, and
persisted peer trust/discovery state. Rules remain visible while inactive.

**Auth:** Bearer JWT (admin)

```json
{
  "configured": true,
  "serverName": "chat.example.com",
  "fingerprint": "64-lowercase-hex-characters",
  "fingerprintDisplay": "grouped full fingerprint",
  "identitySequence": 0,
  "capabilities": ["chat.v1", "drive.v1", "identity.v1"],
  "globalEnabled": true,
  "features": [
    { "feature": "chat", "mode": "allowlist", "minimumTrust": "verified" },
    { "feature": "drive", "mode": "allowlist", "minimumTrust": "verified" }
  ],
  "rules": [
    {
      "domain": "friend.example",
      "feature": "chat",
      "inbound": "allow",
      "outbound": "allow",
      "trustRequirement": "inherit",
      "createdAt": "2026-07-20T10:00:00Z",
      "updatedAt": "2026-07-20T10:00:00Z"
    }
  ],
  "peers": [
    {
      "domain": "friend.example",
      "trust": "tofu",
      "sequence": 0,
      "fingerprint": "64-lowercase-hex-characters",
      "fingerprintDisplay": "grouped full fingerprint",
      "apiBase": "https://friend.example",
      "capabilities": ["chat.v1", "drive.v1", "identity.v1"],
      "firstSeenAt": "2026-07-20T10:00:00Z",
      "lastSeenAt": "2026-07-20T10:00:00Z",
      "verifiedAt": null,
      "discoveryExpiresAt": "2026-07-20T11:00:00Z",
      "quarantineReason": null,
      "pendingFingerprint": null,
      "lastDiscoveryError": null,
      "diagnostics": {
        "chatPendingTransactions": 0,
        "chatMismatchTransactions": 0,
        "driveIncomingShares": 1,
        "driveOutgoingShares": 0
      }
    }
  ],
  "operational": {
    "peerTotal": 1,
    "tofuPeers": 1,
    "verifiedPeers": 0,
    "quarantinedPeers": 0,
    "chatPendingTransactions": 0,
    "chatMismatchTransactions": 0,
    "oldestChatPendingAt": null,
    "driveIncomingShares": 1,
    "driveOutgoingShares": 0,
    "activeReplayReservations": 0
  }
}
```

`configured` reports whether the persistent v2 identity exists. Fingerprints
are always returned in full; the grouped form is display-only.

### PUT /api/admin/federation

Update the emergency stop and one feature policy:

```json
{
  "globalEnabled": true,
  "feature": "chat",
  "mode": "disabled|allowlist|blocklist|open",
  "minimumTrust": "tofu|verified"
}
```

Returns the full control-plane response, wakes the Chat outbox, and audits
`federation.policy.update`. The global stop denies every feature. A disabled
Chat feature also hides public discovery. `allowlist` requires an explicit
directional allow, `blocklist` permits inherited directions except explicit
blocks, and `open` permits every admitted direction. Admission never bypasses
the effective trust requirement.

### PUT /api/admin/federation/rules/:feature/:domain

Create or replace a rule for `chat` or `drive` and a canonical lowercase DNS
domain. The local domain cannot be added.

```json
{
  "inbound": "inherit|allow|block",
  "outbound": "inherit|allow|block",
  "trustRequirement": "inherit|tofu|verified"
}
```

Returns the full response, wakes pending Chat delivery for the domain, and
audits `federation.rule.upsert`.

### DELETE /api/admin/federation/rules/:feature/:domain

Delete the feature-scoped rule. Returns the full response, or `404` when the
rule does not exist, wakes pending Chat delivery, and audits
`federation.rule.delete`.

### POST /api/admin/federation/peers/:domain/verify

Promote the current TOFU pin to verified trust after comparing its full
fingerprint through an independent channel. Body:

```json
{ "fingerprint": "64-lowercase-hex-characters" }
```

### POST /api/admin/federation/peers/:domain/retry

Evict positive and negative discovery caches, retry authenticated discovery
through either enabled Chat or Drive capability, and wake pending Chat
delivery. The returned control-plane state exposes the new discovery result or
`lastDiscoveryError`. The outcome is audited as `federation.peer.retry`.

### POST /api/admin/federation/peers/retry

Retry up to 100 selected canonical domains independently. One failed peer does
not abort the others.

```json
{ "domains": ["one.example", "two.example"] }
```

The response contains `{domain, refreshed, error}` per peer and the complete
batch result is retained in `federation.peer.retry-bulk` audit evidence.

### GET /api/admin/federation/peers/:domain/evidence

Return the immutable accepted, superseded, and quarantined signed identity
documents preserved by the generic trust store. Each entry includes sequence,
document hash, full fingerprint, acceptance state, recorded time, and the exact
public signed document. The response also identifies the current and pending
document hashes and quarantine reason. Results are newest-first and bounded to
200 documents with `truncated: true` when older history exists. This endpoint
does not expose federation private keys or Drive capabilities.

### POST /api/admin/federation/peers/:domain/repin

Break-glass replacement for a quarantined competing identity only. It requires
the exact old fingerprint, pending new fingerprint, and domain:

```json
{
  "oldFingerprint": "64-lowercase-hex-characters",
  "newFingerprint": "64-lowercase-hex-characters",
  "confirmDomain": "friend.example"
}
```

The re-pin is persisted with administrator identity and old/new evidence; it
is not an automatic fallback for failed rotation.

---

## Devices

Per-device Ed25519 signing keys for collaborative-edit frame signing. Each browser tab session creates one device row; CLI sessions persist across runs.

### POST /api/devices
Register a device signing key. Required before opening any collaborative-edit WebSocket.
**Auth:** Bearer JWT.
**Body:** `{publicSigning: <base64-32>, label?: string, authSig: <base64>, timestamp: <unix-seconds>}`. AuthSig is recorded but not validated in v1; the JWT is the trust anchor.
**Response 201:** `{deviceId, label, createdAt}`

### GET /api/devices
List the user's devices.
**Response:** array of `{deviceId, label, isActive, createdAt, lastSeenAt}`.

### DELETE /api/devices/:id
Revoke a device. Closes any open WebSocket connections from that device. Returns 404 if the device is already inactive (idempotent state-transition semantics).
**Response:** `204`.

---

## Collaborative Editing

### GET /api/files/:fileId/collab/ws
WebSocket upgrade. Auth via `Authorization: Bearer ...` header **or** `?token=...&deviceId=N` query (browsers can't set custom headers on the initial WS handshake).

PreUpgrade validates: JWT (rejects setup/pre-auth tokens), file access (owner OR collection-share recipient), device registration (must belong to user, must be active). Failures return HTTP 401/403/404 BEFORE the WS handshake completes.

A view-only recipient joins to follow edits: the server relays its presence
frames (awareness and cursors) and drops everything else it sends. Edits are
checked against the sender's rights frame by frame, and every open socket
re-checks its session and file access every 15 s, closing when either is
gone (share narrowed or removed, file or folder trashed, session signed out).
A message is at most one frame (1 MiB of plaintext plus framing); a client
sending edits faster than 50 frames/s or 1 MiB/s sustained (bursts of 500
frames / 16 MiB) is disconnected. Office edit frames stay in the log for a
day, as a buffer for peers resuming after a dropped connection.

On accept the server sends a JSON `hello` `{type, fileId, currentDocKeyId, headSeq, peers: [{deviceId, userId}]}`. Client replies with JSON `{type: "resume", lastSeenSeq: K}`. Server replays binary `CollabFrame`s from seq `K+1` to head, then enters bidirectional binary mode. `CollabFrameSuiteId = 1` is the canonical Rust-owned `KUTPCF1\0` format documented in `docs/v1-format-inventory.md`; the server rejects an unknown suite, malformed length, invalid device signature, or any file/collection/epoch/document-generation mismatch.

### PUT /api/files/:fileId/assets/:assetId

Upload one whiteboard image as multipart field `file`. The part must be a
complete `DriveEnvelopeV1` purpose-6 asset envelope for the exact live file,
collection, current collection-key epoch and path `assetId`. Asset IDs are
1–128 bytes and may not contain slash, backslash or `..`. Plaintext is capped
at 25 MiB; oversized or invalid public envelopes are rejected before quota or
object-storage mutation. **Auth:** Bearer JWT and write access. **Response:**
`204`. Assets are content-addressed and immutable: once an id is stored a
re-upload changes nothing (neither bytes nor charge) and returns `204`.

### GET /api/files/:fileId/assets/:assetId

Return the stored opaque asset envelope as `application/octet-stream`. The
client opens it with the current collection key and the same exact context;
key, file, collection, epoch, asset-ID relocation and tampering fail closed.
**Auth:** Bearer JWT and file access.

### PUT /api/files/:fileId/thumbnails/:variant

Store the file's `sm` (≤ 512 px) or `lg` (≤ 1920 px) thumbnail, replacing any
previous one of that variant. **Body:** the raw `DriveEnvelopeV1` purpose-7
thumbnail envelope (`application/octet-stream`), sealed under the file key
by the client; the server checks its public header against the exact file,
variant and current key epoch and its size against the variant cap
(64 KiB / 1 MiB plaintext) before any quota or storage change.
**Query:** `source` — the version id it was drawn from, or `original`
(default); a version of another file is refused. The size is charged to the
uploader; replacing your own thumbnail charges only the difference.
**Auth:** Bearer JWT and write access. **Response:** `204`; `400` invalid
envelope or source; `404` unknown variant; `413` too large or over quota.

### GET /api/files/:fileId/thumbnails/:variant

The stored envelope as `application/octet-stream`, with
`Cache-Control: private, max-age=31536000, immutable` — clients add
`?v={thumbnails.<variant>}` from the listing, so a URL never changes meaning
and caches hold only ciphertext. **Auth:** Bearer JWT and file access.
**Response:** `200`; `404` when there is none.

### DELETE /api/files/:fileId/thumbnails

Remove both variants and release their bytes to whoever was charged.
**Auth:** Bearer JWT and write access. **Response:** `204`.

---

## Version History

### GET /api/files/:fileId/versions
List all versions newest-first.
**Response:** array of `{id, s3VersionId, storagePath, seqAtSnapshot, docKeyId, authorUserId, sizeBytes, label, keepForever, createdAt}`.

### GET /api/files/:fileId/versions/:vid/download
Get the encrypted snapshot bytes for a specific version. Returns
`application/octet-stream`. Headers: `X-Kutup-Doc-Key-Id`, `X-Kutup-Seq`,
`X-Kutup-S3-Version`. The snapshot uses the same typed,
file/collection/epoch-bound Drive file-blob format as an original file. There
is no snapshot-specific legacy decoder.

### PATCH /api/files/:fileId/versions/:vid
**Body:** `{label?: string, keepForever?: boolean}` — set or unset; a label
is at most 200 characters. **Auth:** write access (it changes what retention
keeps). **Response:** updated version row.

### POST /api/files/:fileId/versions
Store a version in one request (docs/plans/drive-versions-v2.md). Multipart:
`file` — a complete typed Drive file blob, validated against the exact file,
collection and current epoch; `kind` — `file` (the whole file: office
documents, whiteboards, restored copies) or `yjs` (a note's collaboration
state); `seqAtSnapshot`, `docKeyId`; optional `label`, `keepForever`.

The server measures the body and charges **that** size to the author's
quota (a client's size claim is not read), stores it as an object of its own
(`files/{id}/versions/{versionId}`), records the row, truncates
`file_update_log` up to `seqAtSnapshot` and sets the file's `updatedAt` (and
so its folder's) — one transaction; the object is removed again if the
commit fails. Truncation takes the relay's per-file lock, never goes past the
log's head, and happens only when `docKeyId` is the file's current document
key. **Auth:** write access (`403` for a view-only recipient).

**Response 201:** the version row, including `kind`. `413` over quota.

Versions are kept by the file owner's `versionRetentionDays` (see
`PATCH /api/user/me`): the last day whole, the last week one per hour, then
one per day; the newest version and `keepForever` ones always.
