# API Reference

Base URL: `http://localhost` (through Nginx proxy) or your configured `SERVER_URL`.

All authenticated endpoints require `Authorization: Bearer <accessToken>`.

> **Note:** File content and metadata are end-to-end encrypted by the client. The API transports ciphertext and base64-encoded nonces — the server never interprets their contents.

---

## Authentication

### GET /api/auth/settings

Returns public server settings (e.g. registration enabled/disabled).

**Auth:** None

**Response:**
```json
{
  "registrationEnabled": true
}
```

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
  "encryptedMasterKey": "<base64>",
  "masterKeyNonce": "<base64>",
  "encryptedRecoveryKey": "<base64>",
  "recoveryKeyNonce": "<base64>",
  "encryptedPrivateKey": "<base64>",
  "privateKeyNonce": "<base64>",
  "publicKey": "<base64>",
  "kdfSalt": "<base64>",
  "loginKeySalt": "<base64>",
  "recoveryProof": "<base64>"
}
```

All key material is encrypted client-side before being sent. `loginKey` is the Argon2id-derived login key (base64); the server bcrypts it and stores only the bcrypt hash — the raw password is never transmitted. `recoveryProof` is the base64 of the recovery-key entropy; the server bcrypts it into a verifier so it can later prove mnemonic possession during account recovery.

**Response:** `201 Created`

**Errors:** `403` if registration is disabled, `409` if the email or username is already taken.

---

### GET /api/auth/login/preflight

Fetch the KDF salts needed to derive the login key before submitting credentials. Rate-limited.

**Auth:** None
**Query:** `?email=user@example.com`

**Response:**
```json
{
  "kdfSalt": "<base64>",
  "loginKeySalt": "<base64>"
}
```

---

### POST /api/auth/login

Exchange the Argon2id-derived login key for tokens. Rate-limited (10/min/IP, `RATE_LIMIT_LOGIN_PER_MIN`). On top of the per-IP limit, repeated failed password attempts for one email lock that account out: after 5 failures (`LOGIN_LOCKOUT_THRESHOLD`) further attempts return `429` for 15 minutes (`LOGIN_LOCKOUT_MINUTES`). The lockout applies to unknown emails too, so a `429` does not reveal whether the account exists.

**Auth:** None

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
  "userId": "<uuid>",
  "username": "alice",
  "encryptedMasterKey": "<base64>",
  "masterKeyNonce": "<base64>",
  "encryptedPrivateKey": "<base64>",
  "privateKeyNonce": "<base64>",
  "publicKey": "<base64>",
  "isAdmin": false,
  "storageQuotaBytes": 5368709120,
  "storageUsedBytes": 104857600
}
```

The refresh token is delivered via an HTTP-only cookie named `refresh_token` (scoped to `Path=/api/auth/refresh`) — it is not present in the JSON body.

**Response (2FA enabled):** `200` with `{"requiresTotp": true, "preAuthToken": "<jwt>"}` — proceed to `/api/auth/login/2fa`.

**Response (first login, account created via `ADMIN_ACCOUNT` and not yet set up):** `200` with `{"requiresSetup": true, "setupToken": "<jwt>"}` — proceed to `/api/auth/complete-setup`.

---

### POST /api/auth/login/2fa

Complete login when 2FA is enabled. Locked after 5 failed attempts.

**Auth:** None (uses `preAuthToken` from the login response)

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
  "encryptedRecoveryKey": "<base64>",
  "recoveryKeyNonce": "<base64>",
  "encryptedPrivateKey": "<base64>",
  "privateKeyNonce": "<base64>"
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
  "newEncryptedMasterKey": "<base64>",
  "newMasterKeyNonce": "<base64>",
  "newKdfSalt": "<base64>",
  "newLoginKeySalt": "<base64>"
}
```

`recoveryProof` is the base64 of the recovery-key entropy. The server bcrypt-compares it to the verifier stored at registration.

---

### POST /api/auth/refresh

Exchange a refresh token for a new access token. The refresh token is normally read from the HTTP-only `refresh_token` cookie set at login; for clients that cannot rely on cookies, it may instead be passed in the JSON body.

**Auth:** None (the refresh token itself is the credential)

**Request body (optional, only if no cookie is sent):**
```json
{
  "refreshToken": "<jwt>"
}
```

**Response:**
```json
{
  "accessToken": "<jwt>"
}
```

---

### POST /api/auth/complete-setup

Called after first login by accounts created via `ADMIN_ACCOUNT` that haven't yet generated a recovery phrase. The client derives a full key bundle (mnemonic, master key, recovery key, NaCl box keypair) and submits it here.

**Auth:** Bearer `setupToken` (returned by `/api/auth/login` when `requiresSetup` is true)

**Request body:** Same shape as `POST /api/auth/register` (encrypted key bundle, salts, public key).

**Response:** issues an access token (JSON) and the refresh token (cookie) — the encrypted key bundle just submitted is **not** echoed back.
```json
{
  "accessToken": "<jwt>",
  "userId": "<uuid>",
  "username": "alice",
  "isAdmin": false,
  "storageQuotaBytes": 5368709120,
  "storageUsedBytes": 0
}
```

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

Look up another user's public key (used when sharing a collection).

**Auth:** Bearer JWT
**Param:** `:email` — URL-encoded email address

**Response:**
```json
{
  "userId": "<uuid>",
  "publicKey": "<base64>"
}
```

---

## Collections

### GET /api/collections/

List all collections accessible to the current user (owned and shared).

**Auth:** Bearer JWT

**Response:** Array of collection objects. Owned and shared collections are returned in the same array; for shared collections `encryptedKey` is the recipient-specific copy and `isShared` is `true`.

```json
[
  {
    "id": "<uuid>",
    "ownerUserId": "<uuid>",
    "encryptedName": "<base64>",
    "nameNonce": "<base64>",
    "encryptedKey": "<base64>",
    "encryptedKeyNonce": "<base64>",
    "parentCollectionId": null,
    "color": "blue",
    "canUpload": true,
    "canDelete": false,
    "uploadQuotaBytes": null,
    "uploadUsedBytes": null,
    "isShared": true
  }
]
```

`canUpload`, `canDelete`, `uploadQuotaBytes`, `uploadUsedBytes`, and `isShared` are present only on shared collections (the owner has full rights implicitly).

---

### POST /api/collections/

Create a new collection.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "encryptedName": "<base64>",
  "nameNonce": "<base64>",
  "encryptedKey": "<base64>",
  "encryptedKeyNonce": "<base64>",
  "parentCollectionId": null
}
```

`encryptedKey` is the collection key encrypted with the owner's master key.

**Response:** `201 Created`
```json
{
  "id": "<uuid>"
}
```

---

### GET /api/collections/:id

Get a single collection by ID. Owner-only — returns `404` for collections owned by other users (even if shared with you; use `GET /api/collections/` for those).

**Auth:** Bearer JWT

**Response:**
```json
{
  "id": "<uuid>",
  "ownerUserId": "<uuid>",
  "encryptedName": "<base64>",
  "nameNonce": "<base64>",
  "encryptedKey": "<base64>",
  "encryptedKeyNonce": "<base64>",
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
  "encryptedName": "<base64>",
  "nameNonce": "<base64>"
}
```

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
  "encryptedCollectionKey": "<base64>",
  "canUpload": false,
  "canDelete": false,
  "uploadQuotaBytes": null
}
```

`encryptedCollectionKey` is the collection key encrypted with the recipient's public key (NaCl box, sealed). All recipients have read access; `canUpload` and `canDelete` are independent boolean grants. `uploadQuotaBytes` optionally caps how much the recipient may upload to this share — omit (or `null`) for no per-share cap.

**Response:** `201 Created` `{"message": "shared"}`. Re-sharing with the same recipient updates the existing grant (upsert).

---

### POST /api/collections/:id/share-federated

Share a collection with a user on a remote Kutup instance.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "recipientUsername": "bob",
  "recipientServer": "https://other.kutup.example.com",
  "encryptedCollectionKey": "<base64>",
  "canUpload": true,
  "canDelete": false,
  "uploadQuotaBytes": null
}
```

`encryptedCollectionKey` is the collection key sealed to the recipient's public key (fetched via `GET /api/collections/fed-pubkey`).

**Response:** `201 Created`
```json
{
  "inviteToken": "<hex32>",
  "inviteUrl": "https://this.kutup.example.com/invite/<hex32>"
}
```

`inviteUrl` is built from the **sharer's** `SERVER_URL` (this server). The recipient hands the `inviteToken` to their own server via `POST /api/fed-proxy/incoming` to accept.

---

### GET /api/collections/fed-pubkey

Fetch the public key of a remote user (used before federated sharing).

**Auth:** Bearer JWT
**Query:** `?username=bob&server=https://other.kutup.example.com`

**Response:**
```json
{
  "publicKey": "<base64>"
}
```

---

## Files

### POST /api/files/upload

Upload an encrypted file to a collection. Multipart form.

**Auth:** Bearer JWT

**Form fields:**

| Field | Type | Description |
|-------|------|-------------|
| `collectionId` | string (UUID) | Target collection |
| `encryptedMetadata` | string (base64) | Encrypted filename, size, MIME type |
| `metadataNonce` | string (base64) | Nonce for metadata ciphertext |
| `encryptedFileKey` | string (base64) | Per-file key encrypted with collection key |
| `fileKeyNonce` | string (base64) | Nonce for file key ciphertext |
| `file` | binary | Encrypted file content (`application/octet-stream`) |

**Response:** `201 Created`
```json
{
  "id": "<uuid>"
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
    "encryptedMetadata": "<base64>",
    "metadataNonce": "<base64>",
    "encryptedFileKey": "<base64>",
    "fileKeyNonce": "<base64>",
    "encryptedSizeBytes": 4096,
    "createdAt": "2026-03-14T12:00:00Z",
    "updatedAt": "2026-03-14T12:00:00Z"
  }
]
```

`encryptedSizeBytes` is the size of the ciphertext blob on disk (slightly larger than the plaintext due to per-chunk auth tags from the secretstream wrapping).

---

### GET /api/files/:id/download

Download the encrypted content of a file.

**Auth:** Bearer JWT

**Response:** Raw binary (`application/octet-stream`) — the encrypted file bytes.

---

### DELETE /api/files/:id

Move a file to the trash (soft delete). The file disappears from every normal endpoint but keeps counting against quota; restore or purge it via the Trash endpoints. Permanent deletion happens from the trash — explicitly, or automatically after `TRASH_RETENTION_DAYS` (default 30).

**Auth:** Bearer JWT (collection owner, or the uploader holding a `canDelete` share)

**Response:** `204 No Content`.

---

## Trash

Trash is **owner-scoped**: an item lives in the trash of the user who owns the collection it belongs to (a share recipient's delete lands in the owner's trash — the Google Drive model). Every entry is a *trash root*: a deleted file, or a deleted folder carrying its whole subtree. A background sweeper purges roots older than `TRASH_RETENTION_DAYS` (default 30; `0` disables the sweeper). Federated deletes (`DELETE /api/fed/shares/...`) remain permanent — there is no cross-server trash.

### GET /api/trash

List the caller's trash roots, newest first. Like everything else, names arrive encrypted: folder rows carry the folder's owner-wrapped key; file rows additionally carry the parent collection's owner-wrapped key (`collectionEncryptedKey`/`collectionEncryptedKeyNonce`) so the metadata chain decrypts even when the folder isn't in the live listing.

**Auth:** Bearer JWT

**Response:** `200 OK`
```json
{
  "folders": [
    {
      "id": "<uuid>",
      "encryptedName": "<base64>",
      "nameNonce": "<base64>",
      "encryptedKey": "<base64>",
      "encryptedKeyNonce": "<base64>",
      "color": "blue",
      "items": 12,
      "deletedAt": "2026-06-11T11:22:33Z"
    }
  ],
  "files": [
    {
      "id": "<uuid>",
      "collectionId": "<uuid>",
      "encryptedMetadata": "<base64>",
      "metadataNonce": "<base64>",
      "encryptedFileKey": "<base64>",
      "fileKeyNonce": "<base64>",
      "collectionEncryptedKey": "<base64>",
      "collectionEncryptedKeyNonce": "<base64>",
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

Create a public share link for a collection or file. The link key (used to decrypt the wrapped collection key) lives only in the URL fragment — the server never sees it.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "shareType": "collection",
  "targetId": "<uuid>",
  "encryptedCollectionKey": "<base64>",
  "encryptedCollectionKeyNonce": "<base64>",
  "expiresInHours": 48
}
```

`shareType` is `"collection"` or `"file"`. `expiresInHours` is optional — omit (or `null`) for no expiry. `encryptedCollectionKey` is the collection key wrapped under a randomly-generated link key that the client keeps in the URL fragment.

**Response:** `201 Created`
```json
{
  "id": "<uuid>",
  "token": "<random-token>"
}
```

The client builds the share URL as `<SERVER_URL>/s/<token>#<linkKey>` — the server returns only the token.

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
  "encryptedCollectionKey": "<base64>",
  "encryptedCollectionKeyNonce": "<base64>",
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
    "encryptedMetadata": "<base64>",
    "metadataNonce": "<base64>",
    "encryptedFileKey": "<base64>",
    "fileKeyNonce": "<base64>",
    "encryptedSizeBytes": 4096,
    "createdAt": "2026-03-14T12:00:00Z"
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

The local slice of the federated chat track ("ileti" — design: `docs/research/11-federated-chat.md`). Clients run the Signal protocol (PQXDH + Triple Ratchet, suite `1`); the server stores **public prekeys and opaque ciphertext only**. All endpoints require a Bearer JWT unless noted. Wire types live in `crates/kutup-chat-proto` and are fully described by the OpenAPI document.

### POST /api/chat/device

Register the calling client as a chat device. The server assigns the lowest free device id (`1..=127` per user). Body: `registrationId` (libsignal, `1..16380`), `identityKey`, `signedPreKey` (signature required), `lastResortKyberPreKey` (bundles are never non-PQ), optional `oneTimePreKeys[]` / `oneTimeKyberPreKeys[]` pools, optional `name`. All key material base64.

**Response:** `200 OK` → `{ "deviceId": 1 }` · `409` when all 127 ids are taken.

### GET /api/chat/device

The caller's chat devices: `{ "devices": [{ "deviceId", "suite", "name", "createdAt", "lastSeenAt" }] }`.

### DELETE /api/chat/device/{deviceId}

Revoke a chat device — hard delete; prekey pools and mailbox rows cascade, live sockets close. `204`.

### PUT /api/chat/keys?deviceId=N

Rotate `signedPreKey` / `lastResortKyberPreKey` and/or upload more one-time prekeys (only fields present are changed; pool inserts are idempotent per `keyId`).

### GET /api/chat/keys/count?deviceId=N

Remaining one-time pool sizes: `{ "oneTimePreKeys": n, "oneTimeKyberPreKeys": n }` — clients replenish below a threshold.

### GET /api/chat/users/{username}/keys

PQXDH prekey bundles for **every** chat device of `username` (a message must encrypt to all of them). Each bundle carries `identityKey`, `signedPreKey`, `kyberPreKey` (a one-time Kyber prekey, **consumed** by this fetch, or the reusable last-resort key when the pool is empty) and optionally a consumed one-time EC prekey. Rate-limited per IP (`RATE_LIMIT_CHAT_KEYS_PER_MIN`, default 30) because fetches consume pool keys.

### POST /api/chat/users/{username}/messages

Deliver one logical message as per-device ciphertexts: `{ "senderDeviceId": n, "envelopes": [{ "deviceId", "registrationId", "envelopeType": "preKey"|"message", "suite": 1, "content": "<base64>" }] }`. The device set must exactly match the recipient's current devices — ids **and** registration ids — or the send fails with `409 { "missingDevices": [], "staleDevices": [], "extraDevices": [] }` (Signal's contract: no device can be silently skipped, and reinstalled devices are detected). Stored envelopes are also pushed to the recipient's live chat sockets.

### GET /api/chat/messages?deviceId=N&limit=100

Drain the device's mailbox, oldest first (max 500/page): `{ "envelopes": [{ "id", "sender", "senderDeviceId", "envelopeType", "suite", "content", "serverTimestamp" }], "more": bool }`. Envelopes stay stored until acked.

### POST /api/chat/messages/ack?deviceId=N

`{ "ids": ["<uuid>", …] }` → deletes processed envelopes; returns `{ "acked": n }`.

### GET /api/chat/ws?deviceId=N&token=…

WebSocket. Auth like the collab WS (token via `Authorization` or `?token=`, validated before upgrade). Server → client JSON frames: `{ "type": "drainMailbox" }` once on connect (fetch the backlog over REST), then `{ "type": "envelope", "envelope": {…} }` per newly arrived message. Acks stay on REST — the mailbox is the source of truth.

---

## Federation — Public Endpoints

These endpoints are called by remote Kutup servers as part of the federation protocol.

### GET /api/fed/users

Look up a user on this server by username and return their public key. Rate-limited (60/min/IP).

**Auth:** None
**Query:** `?username=alice`

**Response:**
```json
{
  "publicKey": "<base64>"
}
```

Returns `404` for unknown or inactive users.

---

### GET /api/fed/invites/:token

Retrieve federated share invite metadata by token. The token itself is the credential — there is no auth header.

**Auth:** None

**Response:**
```json
{
  "wrappedKey": "<base64>",
  "encryptedName": "<base64>",
  "nameNonce": "<base64>",
  "canUpload": true,
  "canDelete": false,
  "uploadQuotaBytes": null
}
```

`wrappedKey` is the collection key sealed to the recipient's NaCl box public key by the original sharer. The recipient unseals it with their own private key.

---

### GET /api/fed/shares/:token/files

List files in a federated share. Called by remote server when proxying for its local user.

**Auth:** None (token provides access)

---

### GET /api/fed/shares/:token/files/:fileId/download

Download a file from a federated share.

**Auth:** None (token provides access)

---

### POST /api/fed/shares/:token/files

Upload a file to a federated share (if permission allows).

**Auth:** None (token provides access)
**Body:** Multipart (same fields as `POST /api/files/upload`)

---

### DELETE /api/fed/shares/:token/files/:fileId

Delete a file from a federated share (if permission allows).

**Auth:** None (token provides access)

---

## Federation Proxy — Authenticated Endpoints

These endpoints are called by the local Kutup client to interact with collections shared from remote servers.

### POST /api/fed-proxy/incoming

Accept a federated share invite. The client only needs to paste the invite URL — this server parses out the remote host + token, calls the remote `GET /api/fed/invites/{token}`, and persists the resulting wrapped key.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "inviteUrl": "https://other.kutup.example.com/invite/<token>"
}
```

**Response:** `201 Created`
```json
{
  "id": "<uuid>",
  "remoteServer": "https://other.kutup.example.com",
  "encryptedCollectionKey": "<base64>",
  "encryptedName": "<base64>",
  "nameNonce": "<base64>",
  "canUpload": true,
  "canDelete": false,
  "uploadQuotaBytes": null
}
```

`502` if the remote server is unreachable or returns invalid invite data.

---

### GET /api/fed-proxy/incoming

List all accepted incoming federated shares for the current user.

**Auth:** Bearer JWT

---

### DELETE /api/fed-proxy/incoming/:shareId

Remove an incoming federated share.

**Auth:** Bearer JWT

---

### GET /api/fed-proxy/:shareId/files

List files in an incoming federated share. Proxies the request to the remote server.

**Auth:** Bearer JWT

---

### GET /api/fed-proxy/:shareId/files/:fileId/download

Download a file from an incoming federated share. Proxied to the remote server.

**Auth:** Bearer JWT

---

### POST /api/fed-proxy/:shareId/upload

Upload a file to an incoming federated share (if permitted). Proxied to the remote server.

**Auth:** Bearer JWT

---

### DELETE /api/fed-proxy/:shareId/files/:fileId

Delete a file in an incoming federated share (if permitted). Proxied to the remote server.

**Auth:** Bearer JWT

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

**Query parameters:** `limit` (1–100, default 50) · `before` (cursor: return entries with `id` lower than this — pass the previous page's `nextBefore`).

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

Actions: `user.create`, `user.update` (payload carries a `changes` object with only the fields that were modified), `user.delete`, `user.2fa_disable`, `settings.update`. `adminEmail`/`targetEmail` are the live identities and become `null` once the referenced account is deleted — the `payload` snapshot keeps the trail readable. `nextBefore` is non-null while older pages remain.

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

On accept the server sends a JSON `hello` `{type, fileId, currentDocKeyId, headSeq, peers: [{deviceId, userId}]}`. Client replies with JSON `{type: "resume", lastSeenSeq: K}`. Server replays binary `CollabFrame`s from seq `K+1` to head, then enters bidirectional binary mode. See `docs/superpowers/specs/2026-05-04-collab-edit-design.md` §5 for the wire envelope.

---

## Version History

### GET /api/files/:fileId/versions
List all versions newest-first.
**Response:** array of `{id, s3VersionId, storagePath, seqAtSnapshot, docKeyId, authorUserId, sizeBytes, label, keepForever, createdAt}`.

### GET /api/files/:fileId/versions/:vid/download
Get the encrypted snapshot bytes for a specific version. Returns `application/octet-stream`. Headers: `X-Kutup-Doc-Key-Id`, `X-Kutup-Seq`, `X-Kutup-S3-Version`. The blob format is `nonce(24) || aead_ciphertext` encrypted under the per-file content key (HKDF-derived as documented above).

### PATCH /api/files/:fileId/versions/:vid
**Body:** `{label?: string, keepForever?: boolean}` — set or unset.
**Response:** updated version row.

### POST /api/files/:fileId/versions
Record a new snapshot. Server inserts the row and truncates `file_update_log` up to `seqAtSnapshot`.
**Body:** `{s3VersionId, storagePath, seqAtSnapshot, docKeyId, sizeBytes, label?, keepForever?}`
**Response 201:** `{id}` — the version row id.

### POST /api/files/:fileId/snapshot-blob
Multipart `file` upload of the encrypted snapshot bytes. Companion to POST /versions; uploads the actual blob to S3 (with versioning enabled), returns the S3 metadata for the client to hand to /versions.
**Response:** `{storagePath, s3VersionId}`.
