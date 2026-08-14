CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                   TEXT NOT NULL UNIQUE,
    -- Canonical base64 AccountEnvelopeV1 values. Each envelope carries its
    -- suite, purpose, account context, nonce and exact ciphertext length.
    master_key_envelope       TEXT NOT NULL,
    recovery_key_envelope     TEXT NOT NULL,
    drive_private_key_envelope TEXT NOT NULL,
    public_key              TEXT NOT NULL,
    account_authority_public_key TEXT NOT NULL,
    account_authority_key_id CHAR(64) NOT NULL,
    account_incarnation_id CHAR(64) NOT NULL,
    drive_signing_public_key TEXT NOT NULL,
    -- Complete per-account password-protection suite. Suite zero plus an
    -- empty salt is reserved for an administrator-created first-login account.
    account_protection_suite SMALLINT NOT NULL CHECK (account_protection_suite IN (0, 1)),
    account_protection_salt  TEXT NOT NULL,
    argon_memory_kib         INTEGER NOT NULL CHECK (argon_memory_kib >= 0),
    argon_iterations         INTEGER NOT NULL CHECK (argon_iterations >= 0),
    argon_parallelism        INTEGER NOT NULL CHECK (argon_parallelism >= 0),
    -- Auth
    login_key_hash          TEXT NOT NULL,  -- bcrypt(HKDF(Argon2id(password), login-purpose))
    -- TOTP
    totp_secret             TEXT,
    totp_enabled            BOOLEAN NOT NULL DEFAULT false,
    -- Quota
    storage_quota_bytes     BIGINT NOT NULL DEFAULT 10737418240,  -- 10 GB
    storage_used_bytes      BIGINT NOT NULL DEFAULT 0,
    -- Admin / status
    is_admin                BOOLEAN NOT NULL DEFAULT false,
    is_active               BOOLEAN NOT NULL DEFAULT true,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
    ,CHECK (account_authority_key_id = '' OR account_authority_key_id ~ '^[0-9a-f]{64}$')
    ,CHECK (account_incarnation_id = '' OR account_incarnation_id ~ '^[0-9a-f]{64}$')
);

CREATE INDEX idx_users_email ON users(email);
