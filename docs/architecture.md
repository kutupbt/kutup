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
              (XSalsa20-Poly1305)         (asymmetric, for sharing)
                          │                             │
              per-file key (random)         publicKey  encryptedPrivateKey
                          │                (stored     (stored encrypted,
              XSalsa20-Poly1305             plaintext)  nonce = privateKeyNonce)
                          │
              encrypted file content
              (stored in SeaweedFS)
```

Every cryptographic primitive is from **libsodium** (`libsodium-wrappers-sumo`), running entirely in the browser. The backend is a pure ciphertext relay.

---

## Registration Flow

1. Client generates a random 32-byte **master key**.
2. Client derives a **login key** from the user's password using Argon2id (`kdfSalt`), then hashes it once more to produce `loginKeyHash`. Only `loginKeyHash` is sent to the server — the server stores this hash and uses it to verify login. The raw password never leaves the browser.
3. Client generates a NaCl box **keypair** (`publicKey`, `privateKey`).
4. Client derives a **recovery key** from a freshly generated BIP39 mnemonic using Argon2id.
5. Client encrypts:
   - `masterKey` with the recovery key → `encryptedRecoveryKey` + `recoveryKeyNonce`
   - `masterKey` with the login key → `encryptedMasterKey` + `masterKeyNonce`
   - `privateKey` with the master key → `encryptedPrivateKey` + `privateKeyNonce`
6. Client POSTs the encrypted bundle to `POST /api/auth/register`. The server stores all ciphertext and the public key. The mnemonic is shown to the user once and never stored anywhere.

---

## Login Flow

1. Client fetches `GET /api/auth/login/preflight?email=...` to retrieve `loginKeySalt` and `kdfSalt`.
2. Client recomputes the login key from the password + `loginKeySalt` via Argon2id (in a Web Worker to avoid blocking the UI), then hashes it to `loginKeyHash`.
3. Client POSTs `loginKeyHash` to `POST /api/auth/login`. Server verifies the hash.
4. On success the server returns an **access token** (short-lived JWT) and a **refresh token**.
5. Client uses the access token's payload to retrieve `encryptedMasterKey` + `masterKeyNonce` from the server response, then decrypts the master key locally. The master key lives only in browser memory.
6. If 2FA is enabled, the server returns a partial token; the client must complete login at `POST /api/auth/login/2fa` with a TOTP code before receiving the full JWT.

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
2. Sharer encrypts the **collection key** to the recipient's public key using NaCl box (`crypto_box_easy`). The sharer's private key is used as the sender key.
3. Sharer POSTs the encrypted collection key + nonce to `POST /api/collections/:id/share` along with the recipient's user ID and the desired permission level (`read`, `upload`, or `delete`).
4. Recipient sees the shared collection on next list. They decrypt the collection key using their own private key (decrypted from `encryptedPrivateKey` using their master key).

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

**Cross-server upload/delete** is gated by the permission level set at share time (`upload` or `delete` flags).

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
