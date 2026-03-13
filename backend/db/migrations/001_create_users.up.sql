CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                   TEXT NOT NULL UNIQUE,
    -- Encrypted key material (base64-encoded ciphertext)
    encrypted_master_key    TEXT NOT NULL,
    master_key_nonce        TEXT NOT NULL,
    encrypted_recovery_key  TEXT NOT NULL,
    recovery_key_nonce      TEXT NOT NULL,
    encrypted_private_key   TEXT NOT NULL,
    private_key_nonce       TEXT NOT NULL,
    public_key              TEXT NOT NULL,
    -- KDF salts (base64-encoded)
    kdf_salt                TEXT NOT NULL,
    login_key_salt          TEXT NOT NULL,
    -- Auth
    login_key_hash          TEXT NOT NULL,  -- bcrypt(Argon2id(password, loginKeySalt))
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
);

CREATE INDEX idx_users_email ON users(email);
