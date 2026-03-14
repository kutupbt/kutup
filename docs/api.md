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

Create a new account with an encrypted key bundle.

**Auth:** None

**Request body:**
```json
{
  "email": "user@example.com",
  "loginKeyHash": "<base64>",
  "encryptedMasterKey": "<base64>",
  "masterKeyNonce": "<base64>",
  "encryptedRecoveryKey": "<base64>",
  "recoveryKeyNonce": "<base64>",
  "encryptedPrivateKey": "<base64>",
  "privateKeyNonce": "<base64>",
  "publicKey": "<base64>",
  "kdfSalt": "<base64>",
  "loginKeySalt": "<base64>"
}
```

All key material is encrypted client-side before being sent. `loginKeyHash` is the result of hashing the Argon2id-derived login key — the raw password is never transmitted.

**Response:** `201 Created`

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

Exchange a login key hash for tokens. Rate-limited.

**Auth:** None

**Request body:**
```json
{
  "email": "user@example.com",
  "loginKeyHash": "<base64>"
}
```

**Response (no 2FA):**
```json
{
  "accessToken": "<jwt>",
  "refreshToken": "<jwt>",
  "encryptedMasterKey": "<base64>",
  "masterKeyNonce": "<base64>",
  "encryptedPrivateKey": "<base64>",
  "privateKeyNonce": "<base64>"
}
```

**Response (2FA enabled):** `200` with `{"twoFactorRequired": true, "partialToken": "<jwt>"}` — proceed to `/api/auth/login/2fa`.

---

### POST /api/auth/login/2fa

Complete login when 2FA is enabled.

**Auth:** None (uses `partialToken` from the login response)

**Request body:**
```json
{
  "partialToken": "<jwt>",
  "code": "123456"
}
```

**Response:** Same full token response as `/api/auth/login`.

---

### GET /api/auth/recover/preflight

Fetch KDF parameters for account recovery. Rate-limited.

**Auth:** None
**Query:** `?email=user@example.com`

**Response:**
```json
{
  "kdfSalt": "<base64>"
}
```

---

### POST /api/auth/recover

Recover an account using a mnemonic-derived recovery key. Rate-limited.

**Auth:** None

**Request body:**
```json
{
  "email": "user@example.com",
  "recoveryKeyHash": "<base64>",
  "newLoginKeyHash": "<base64>",
  "newLoginKeySalt": "<base64>",
  "encryptedMasterKey": "<base64>",
  "masterKeyNonce": "<base64>"
}
```

---

### POST /api/auth/refresh

Exchange a refresh token for a new access token.

**Auth:** None

**Request body:**
```json
{
  "refreshToken": "<jwt>"
}
```

**Response:**
```json
{
  "accessToken": "<jwt>",
  "refreshToken": "<jwt>"
}
```

---

### POST /api/auth/complete-setup

Called after first login to mark setup as complete (after saving the recovery phrase).

**Auth:** Bearer JWT

**Request body:** `{}` (empty)

---

## User

### GET /api/user/me

Return the current user's profile and key bundle.

**Auth:** Bearer JWT

**Response:**
```json
{
  "id": "<uuid>",
  "email": "user@example.com",
  "username": "alice",
  "publicKey": "<base64>",
  "encryptedMasterKey": "<base64>",
  "masterKeyNonce": "<base64>",
  "encryptedPrivateKey": "<base64>",
  "privateKeyNonce": "<base64>",
  "storageUsed": 104857600,
  "storageQuota": 5368709120,
  "twoFactorEnabled": false,
  "setupComplete": true,
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
  "totpUri": "otpauth://totp/Kutup:user@example.com?secret=BASE32&issuer=Kutup"
}
```

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

Disable TOTP for the current user.

**Auth:** Bearer JWT

---

### GET /api/users/by-email/:email

Look up another user's public key (used when sharing a collection).

**Auth:** Bearer JWT
**Param:** `:email` — URL-encoded email address

**Response:**
```json
{
  "id": "<uuid>",
  "username": "bob",
  "publicKey": "<base64>"
}
```

---

## Collections

### GET /api/collections/

List all collections accessible to the current user (owned and shared).

**Auth:** Bearer JWT

**Response:** Array of collection objects:
```json
[
  {
    "id": "<uuid>",
    "encryptedName": "<base64>",
    "nameNonce": "<base64>",
    "encryptedKey": "<base64>",
    "encryptedKeyNonce": "<base64>",
    "parentCollectionId": null,
    "color": "blue",
    "permission": "delete",
    "isOwner": true
  }
]
```

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

**Response:** `201 Created` with the created collection object.

---

### GET /api/collections/:id

Get a single collection by ID.

**Auth:** Bearer JWT

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

---

### DELETE /api/collections/:id

Delete a collection and all files within it.

**Auth:** Bearer JWT

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

---

### POST /api/collections/:id/share

Share a collection with another user on this server.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "recipientUserId": "<uuid>",
  "encryptedCollectionKey": "<base64>",
  "encryptedCollectionKeyNonce": "<base64>",
  "permission": "read"
}
```

`permission` is one of `read`, `upload`, `delete`.

`encryptedCollectionKey` is the collection key encrypted with the recipient's public key (NaCl box).

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
  "encryptedCollectionKeyNonce": "<base64>",
  "permission": "upload"
}
```

**Response:**
```json
{
  "inviteUrl": "https://other.kutup.example.com/accept?token=..."
}
```

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
    "encryptedMetadata": "<base64>",
    "metadataNonce": "<base64>",
    "encryptedFileKey": "<base64>",
    "fileKeyNonce": "<base64>",
    "size": 4096,
    "uploadedAt": "2026-03-14T12:00:00Z"
  }
]
```

---

### GET /api/files/:id/download

Download the encrypted content of a file.

**Auth:** Bearer JWT

**Response:** Raw binary (`application/octet-stream`) — the encrypted file bytes.

---

### DELETE /api/files/:id

Delete a file.

**Auth:** Bearer JWT

---

## Public Shares

### POST /api/share/

Create a public share link for a collection.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "collectionId": "<uuid>"
}
```

**Response:**
```json
{
  "token": "<random-token>",
  "shareUrl": "https://kutup.example.com/s/<token>"
}
```

---

### GET /api/share/:token

Get metadata for a public share (encrypted collection info).

**Auth:** None

**Response:** Collection metadata (ciphertext only — no decryption key is available without the owner's credentials).

---

### GET /api/share/:token/files

List files in a public share.

**Auth:** None

**Response:** Array of encrypted file objects (same shape as `GET /api/collections/:id/files`).

---

### GET /api/share/:token/download/:fileId

Download a file from a public share.

**Auth:** None

**Response:** Raw binary (`application/octet-stream`).

---

## Federation — Public Endpoints

These endpoints are called by remote Kutup servers as part of the federation protocol.

### GET /api/fed/users

Look up a user on this server by username. Rate-limited.

**Auth:** None
**Query:** `?username=alice`

**Response:**
```json
{
  "username": "alice",
  "publicKey": "<base64>"
}
```

---

### GET /api/fed/invites/:token

Retrieve federated share invite metadata by token.

**Auth:** None

**Response:** Invite details (sender server, encrypted collection key, permissions).

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

Register a federated share invite (accept an invite from a remote server).

**Auth:** Bearer JWT

**Request body:**
```json
{
  "inviteToken": "<token>",
  "remoteServer": "https://other.kutup.example.com",
  "encryptedCollectionKey": "<base64>",
  "encryptedCollectionKeyNonce": "<base64>"
}
```

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

All admin endpoints require the `isAdmin` flag on the JWT.

### GET /api/admin/users

List all registered users.

**Auth:** Bearer JWT (admin)

**Response:** Array of user objects with storage usage.

---

### POST /api/admin/users

Create a user account (admin-initiated, bypasses registration settings).

**Auth:** Bearer JWT (admin)

**Request body:**
```json
{
  "email": "newuser@example.com",
  "username": "newuser",
  "password": "temporaryPassword"
}
```

---

### PUT /api/admin/users/:id

Update a user (quota, admin flag, etc.).

**Auth:** Bearer JWT (admin)

**Request body:** Fields to update (e.g. `storageQuota`, `isAdmin`).

---

### DELETE /api/admin/users/:id

Delete a user and all their data.

**Auth:** Bearer JWT (admin)

---

### GET /api/admin/stats

Return aggregate storage statistics.

**Auth:** Bearer JWT (admin)

**Response:**
```json
{
  "totalUsers": 42,
  "totalStorageUsed": 107374182400,
  "totalFiles": 1234
}
```

---

### GET /api/admin/settings

Return current global server settings.

**Auth:** Bearer JWT (admin)

---

### PUT /api/admin/settings

Update global server settings.

**Auth:** Bearer JWT (admin)

**Request body:** Key-value settings map (e.g. `registrationEnabled`, `defaultStorageQuota`).
