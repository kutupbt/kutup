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
```jsonc
{
  "registrationEnabled": true,
  "chat": {
    "enabled": true,
    "protocolVersion": 1,
    "keyTransparency": true,
    "transparencyOperatorKeyId": "<64 lowercase hex>",
    "transparencyOperatorPublicKey": "<base64 Ed25519 public key>",
    "transparencyWitnesses": [
      { "witnessId": "audit.example", "keyId": "<hex>", "publicKey": "<base64>" }
    ],
    "transparencyWitnessQuorum": 1
  }
}
```

The chat block also advertises suites, size/retention limits, federation,
manifests, profiles, and sealed-sender support. Browser clients use the
operator/witness fields as their local transparency policy. Applications that
need an independent trust root must pin the same policy out of band rather than
treating this same-origin response as authoritative.

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
  "publicKey": "<base64>"
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
  "encryptedCollectionKey": "<base64>",
  "canUpload": true,
  "canDelete": false,
  "uploadQuotaBytes": null
}
```

`encryptedCollectionKey` is the collection key sealed to the exact
`bob@other.example.com` public key returned by the lookup above. The server
stores the canonical recipient domain and a SHA-256 capability verifier, not a
remote URL or plaintext capability.

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

Trash is **owner-scoped**: an item lives in the trash of the user who owns the collection it belongs to (a share recipient's delete lands in the owner's trash — the Google Drive model). Every entry is a *trash root*: a deleted file, or a deleted folder carrying its whole subtree. A background sweeper purges roots older than `TRASH_RETENTION_DAYS` (default 30; `0` disables the sweeper). Federated Drive deletes (`DELETE /api/fed/drive/files/:fileId`) remain permanent — there is no cross-server trash.

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

### POST /api/chat/manifest?transparencyTreeSize=N

Publish the account-authority-signed current device manifest. Versions must
advance by exactly one and hash-link to the preceding manifest; the authority
key cannot rotate silently. The signed device ids, registration ids, and
identity keys must exactly match the server's registered device set. Suite 1 is
currently server-bounded and mandatory; authenticated per-device suite lists
will be added to the next manifest format before another suite ships.
`transparencyTreeSize` is the client's highest verified local checkpoint. A
successful publish transactionally advances both the chronological log and
current-value sparse map and returns the manifest with its transparency proof.
Exact replay is idempotent; version, chain, authority, or device-set conflicts
return `409`.

### GET /api/chat/users/{username}/manifest

Return the current account-signed device manifest for a local user. This direct
manifest endpoint is authenticated, but new-session directory reads should use
the keys endpoint below because its response also binds the manifest to key
transparency and supplies the PQXDH bundles.

### GET /api/chat/profile

Owner-only recovery of the current opaque encrypted profile, including the
random profile key wrapped under the account master key for linked-device
recovery. Returns `404` until a profile has been published.

### PUT /api/chat/profile

Publish a new opaque encrypted display-name/avatar profile. The server sees
only ciphertext, a profile-key-derived version, an access-key verifier, a
master-key-wrapped profile key, revision, and source device. Revision plus
source-device ordering resolves concurrent linked-device writes; exact replay
is idempotent and a stale/conflicting revision returns `409`.

### GET /api/chat/users/{username}/profile/{version}

Capability-gated encrypted profile lookup for a local or federated canonical
address. The caller supplies the profile access key in the dedicated request
header rather than the URL. A wrong version or capability is deliberately
indistinguishable from a missing profile and returns `404`.

### GET /api/chat/transparency/checkpoint?fromTreeSize=N

Public monitor endpoint; it does not consume prekeys or require a user account.
Returns the current chronological checkpoint, sparse-map root, the persistent
operator signature, cached independent witness attestations, and an RFC 6962
consistency path from `N` (`0` for first observation). Returns `404` while the
log is empty and `409` when `N` is newer than the presented view. Clients and
witnesses verify the response before advancing durable state. The web client
polls this endpoint on open, online/foreground/reconnect transitions, and every
15 visible minutes. It preserves the last valid pin on network failure and
blocks new sends when authentication, consistency, policy, or witness quorum
verification fails.

### POST /api/chat/transparency/witness

Public, rate-limited submission endpoint for an administrator-allowlisted
independent witness. Body:

```json
{
  "treeSize": 42,
  "attestation": {
    "witnessId": "audit.example",
    "observedAt": 1784250000,
    "keyId": "<64 lowercase hex>",
    "publicKey": "<base64 Ed25519 public key>",
    "signature": "<base64 signature over the exact operator checkpoint>"
  }
}
```

The server verifies the configured identity/key and exact checkpoint.
Identical replay succeeds with `{ "accepted": true, "deduplicated": true }`;
an unknown key returns `401`, an unknown checkpoint `404`, and equivocation at
one tree size `409`.

### GET /api/chat/users/{username}/keys?transparencyTreeSize=N

PQXDH prekey bundles for **every** chat device of `username` (a message must encrypt to all of them), plus the account-signed device manifest and its transparency proof. `transparencyTreeSize` is the client's highest verified homeserver checkpoint (`0` initially); the response proves chronological inclusion of the exact manifest, sparse-map membership as the account's current value, inclusion of that map root as the checkpoint's final leaf, RFC 6962 consistency from the requested size, and the operator signature plus configured witness quorum for the exact checkpoint. Each bundle carries `identityKey`, `signedPreKey`, `kyberPreKey` (a one-time Kyber prekey, **consumed** by this fetch, or the reusable last-resort key when the pool is empty) and optionally a consumed one-time EC prekey. Fetches are limited to 30/min per authenticated account (`RATE_LIMIT_CHAT_KEYS_PER_MIN`) with a coarse 120/min IP wall (`RATE_LIMIT_CHAT_KEYS_IP_PER_MIN`).

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

### POST /api/chat/ws-ticket?deviceId=N

Mint a random, one-time browser WebSocket ticket bound to the authenticated user and chat device. The ticket expires in 60 seconds and is returned as `{ "ticket", "expiresAt" }`.

### GET /api/chat/ws?ticket=…

WebSocket. Browsers use the one-time ticket; native clients instead send `Authorization: Bearer …` with `?deviceId=N`. Reusable JWT query parameters are rejected. Server → client JSON frames: `{ "type": "drainMailbox" }` once on connect (fetch the backlog over REST), then `{ "type": "envelope", "envelope": {…} }` per newly arrived message. Acks stay on REST — the mailbox is the source of truth.

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

### GET /api/fed/chat/users/{username}/keys?transparencyTreeSize=N

Authenticated server-to-server directory lookup. Returns the remote user's
account-signed device manifest, remote transparency proof, and replay-safe
last-resort PQ bundles. It deliberately does not consume one-time prekeys, so a
replayed signed read cannot exhaust the remote recipient's pool. The signed URI
binds the caller's highest verified remote checkpoint.

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
  "encryptedCollectionKey": "<base64>",
  "encryptedName": "<base64>",
  "nameNonce": "<base64>",
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

Upload encrypted multipart fields (`encryptedMetadata`, `metadataNonce`,
`encryptedFileKey`, `fileKeyNonce`, and `file`). Exact retries are idempotent
and return the same `201 { "id": "<uuid>" }` result.

### DELETE /api/drive/federation/shares/:shareId/files/:fileId

Delete a remote ciphertext object when `canDelete` permits it. Exact retries
are idempotent and return `204`.

---

## Drive Federation — Server-to-Server Endpoints

All `/api/fed/drive/*` routes require the unified `drive.v1` RFC 9421/9530
request signature and return an authenticated response. Except for user lookup,
they also require `Kutup-Share-Capability`; the capability is checked only
after the request's canonical origin domain has authenticated, and the share
must be bound to that same domain.

### GET /api/fed/drive/users/:username

Return `{ "username", "server", "publicKey" }` for one active local user.

### GET /api/fed/drive/invite

Return the encrypted collection metadata, wrapped key, intended recipient, and
grants for the capability-authorized share.

### GET /api/fed/drive/files

List ciphertext file metadata for the capability-authorized collection.

### GET /api/fed/drive/files/:fileId/content

Stream ciphertext with its precomputed signed content digest and exact length.

### POST /api/fed/drive/files

Store one encrypted multipart upload. The exact ciphertext is hashed while it
is spooled and the digest is persisted with the file row. A stable request ID
plus authenticated request hash provides persistent idempotency.

### DELETE /api/fed/drive/files/:fileId

Delete one ciphertext file under a persistent idempotent mutation result.

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
