# Architecture

Kutup is a zero-knowledge file storage system. The server stores only ciphertext — it never sees plaintext file content, filenames, or cryptographic keys.

---

## Key Hierarchy

```
mnemonic (BIP39, 24 words)
    │
    └─► recovery key  (Argon2id KDF over mnemonic)
              │
              └─► encrypts ──► encryptedMasterKey  (stored server-side)
                                        │
                               decrypt (client-side)
                                        │
                                  master key
                                        │
                          ┌─────────────┴───────────────┐
                          │                             │
              per-collection key               NaCl keypair
              (XSalsa20-Poly1305 via      (asymmetric, for sharing)
               crypto_secretbox)                        │
                          │                  publicKey  encryptedPrivateKey
              per-file key (random)         (stored     (stored encrypted,
                          │                 plaintext)  nonce = privateKeyNonce)
                XChaCha20-Poly1305
              (crypto_secretstream,
                  5 MB chunks)
                          │
              encrypted file content
              (stored in SeaweedFS)
```

Every cryptographic primitive is from **libsodium** (`libsodium-wrappers-sumo`), running entirely in the browser. The backend is a pure ciphertext relay.

---

## Registration Flow

1. Client generates a random 32-byte **master key**.
2. Client derives a **login key** from the user's password using Argon2id (`loginKeySalt`). Only the base64-encoded `loginKey` is sent to the server, which then bcrypts it and stores `login_key_hash`. The raw password never leaves the browser.
3. Client generates a NaCl box **keypair** (`publicKey`, `privateKey`).
4. Client derives a **recovery key** from a freshly generated BIP39 mnemonic using Argon2id (`kdfSalt`).
5. Client encrypts:
   - `masterKey` with the recovery key → `encryptedRecoveryKey` + `recoveryKeyNonce`
   - `masterKey` with the login key → `encryptedMasterKey` + `masterKeyNonce`
   - `privateKey` with the master key → `encryptedPrivateKey` + `privateKeyNonce`
6. Client also sends a **recovery proof** — base64 of the recovery-key entropy. The server bcrypts it into `recovery_key_verifier` so it can later confirm the client really holds the mnemonic during account recovery (no plaintext recovery key is ever transmitted).
7. Client POSTs the encrypted bundle to `POST /api/auth/register`. The server stores all ciphertext, the public key, and the recovery verifier. The mnemonic is shown to the user once and never stored anywhere.

---

## Login Flow

1. Client fetches `GET /api/auth/login/preflight?email=...` to retrieve `loginKeySalt` and `kdfSalt`.
2. Client recomputes the login key from the password + `loginKeySalt` via Argon2id (in a Web Worker to avoid blocking the UI).
3. Client POSTs the base64 `loginKey` to `POST /api/auth/login`. Server bcrypt-compares it against the stored `login_key_hash`.
4. On success the server returns an **access token** (short-lived JWT) in the JSON body and sets the **refresh token** as an HTTP-only `refresh_token` cookie scoped to `/api/auth/refresh`.
5. The login response also carries `encryptedMasterKey` + `masterKeyNonce` (and the encrypted private key); the client decrypts the master key locally with the login key. The master key lives only in browser memory.
6. If 2FA is enabled, the server returns `{requiresTotp: true, preAuthToken: ...}` instead of full tokens. The client completes login at `POST /api/auth/login/2fa` with a TOTP code before receiving the full JWT.
7. For accounts created via `ADMIN_ACCOUNTS` that have not yet generated a recovery phrase, the server returns `{requiresSetup: true, setupToken: ...}`. The client derives a fresh key bundle and submits it to `POST /api/auth/complete-setup`.

---

## File Encryption

For each file upload:

1. Client generates a random **file key**.
2. Client encrypts the file bytes with the file key → `encryptedFileContent`.
3. Client encrypts file metadata (name, size, MIME type) with the file key → `encryptedMetadata` + `metadataNonce`.
4. Client encrypts the file key with the **collection key** → `encryptedFileKey` + `fileKeyNonce`.
5. Client uploads the ciphertext blob and encrypted metadata as a multipart POST.
6. Backend stores the blob in SeaweedFS and records the encrypted metadata in PostgreSQL.

On download, the client receives the blob and all encrypted fields, then reverses the process locally.

---

## Collection Sharing

Sharing a collection with another user:

1. Sharer fetches the recipient's `publicKey` from `GET /api/users/by-email/:email`.
2. Sharer seals the **collection key** to the recipient's public key using NaCl crypto_box (sender-anonymous via sealed-box; recipient decrypts with their own private key alone).
3. Sharer POSTs the sealed collection key to `POST /api/collections/:id/share` along with the recipient's user ID and two boolean grants — `canUpload` and `canDelete`. Read access is implicit; an optional `uploadQuotaBytes` caps how much the recipient may upload to this share.
4. Recipient sees the shared collection on next list. They unseal the collection key using their own private key (decrypted from `encryptedPrivateKey` using their master key).

The server stores the encrypted collection key — it cannot read it.

---

## Federation Model

Federation allows sharing a collection with a user on a **different Kutup server**.

```
Server A (sharer)                          Server B (recipient)
─────────────────                          ────────────────────
1. Look up recipient's pubkey
   GET /api/fed/users?username=...
   on Server B
                                           ← returns publicKey

2. Encrypt collection key to pubkey
   POST /api/collections/:id/share-federated
   (creates a federated share token)

3. Return invite link:
   Server B URL + /accept?token=...
   + inviteToken (for Server A's API)

                                           4. Recipient opens invite link
                                              POST /api/fed-proxy/incoming
                                              (registers the share on Server B)

                                           5. Recipient browses via proxy:
                                              GET /api/fed-proxy/:shareId/files
                                              → Server B proxies to Server A
                                              GET /api/fed/shares/:token/files

                                           6. File downloads proxied similarly.
```

**SSRF protection:** Before proxying requests to the remote server URL, the backend validates that the target hostname is not a private/loopback address.

**Cross-server upload/delete** is gated by the `canUpload` and `canDelete` boolean grants set at share time.

---

## Storage Layer

Files are stored in **SeaweedFS** accessed via its S3-compatible API. The backend uses the AWS SDK v2 (`aws-sdk-go-v2`) configured to point at the internal SeaweedFS S3 gateway.

- The backend acts as a **streaming proxy** — it pipes upload bytes directly to SeaweedFS without buffering the entire file in memory (Fiber's `StreamRequestBody` is enabled).
- Each file is stored under a UUID key; the human-readable name exists only in `encryptedMetadata` which the server cannot read.
- The SeaweedFS cluster (master + volume + filer + S3 gateway) runs as Docker services on the same network as the backend. No S3 ports are exposed externally.
- Storage quotas are enforced by the backend before accepting uploads; the current usage is tracked in PostgreSQL.

---

## Database

PostgreSQL 16 is used for all persistent metadata:

- User accounts, key bundles, public keys
- Collection records and sharing permissions
- File records (encrypted metadata, SeaweedFS object keys)
- Public share tokens
- Federation share tokens and incoming shares
- TOTP secrets (encrypted)
- Global settings and per-user quotas

Migrations are managed with **golang-migrate** and run automatically on server startup from `backend/db/migrations/`.

## Collaborative Editing

kutup supports real-time, end-to-end-encrypted collaborative editing of text/markdown/code files (`.txt`, `.md`, code formats). Office docs (`.docx`/`.xlsx`/`.pptx`/`.odt`/`.ods`/`.odp`) are deferred to a future release.

The architecture is summarised below; the design rationale and footguns live in `docs/superpowers/specs/2026-05-04-collab-edit-design.md`.

### Sync engine
Yjs CRDT (`Y.Text`) under CodeMirror 6 with `y-codemirror.next`. Clients exchange opaque binary update frames; the server never instantiates a `Y.Doc`.

### Wire envelope
Each frame is wrapped in an XChaCha20-Poly1305 AEAD with `(version, kind, doc_key_id, sender_device_id, sequence)` as additional authenticated data, then signed with the sender's Ed25519 device key. The server validates the signature and stores the opaque ciphertext.

### Per-file content key
Derived deterministically as `HKDF-SHA256(collection_master_key, "kutup/file-content/v1", utf8(fileId))`. No new key wrapping — the existing collection-key plumbing already distributes the master key to authorized members.

### Device keys
Each browser tab session and each CLI session generates a fresh Ed25519 keypair. The public key is registered to the user account; the private key never leaves the device. Revocation marks the device inactive and forces existing WebSocket connections to close.

### Versioning
Two-tier:
- **Live deltas** in Postgres `file_update_log` (truncated on snapshot).
- **Snapshots** as SeaweedFS S3 noncurrent versions, indexed in `file_versions`.

Snapshots fire on idle 30s + ≥1 update, every 200 updates, or on explicit "Save version".

Retention: 30 days OR last 50 versions, whichever yields more. Named/keep-forever versions are exempt forever.

### Federation, sharing
Existing collection-share + federation flows are unchanged. A live-edited file is still a regular `files` row with an encrypted blob; non-editing users continue to download it as today.

### Replay protection
Each frame carries a per-device monotonically-increasing sequence number. The `file_update_log` has a `UNIQUE (file_id, sender_device, sender_seq)` constraint that rejects replays at the database level. Combined with Ed25519 signature verification on every frame, this prevents both forgery and replay attacks.
