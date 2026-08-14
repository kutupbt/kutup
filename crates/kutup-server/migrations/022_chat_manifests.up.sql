-- Account-signed chat device sets. The server is only a distributor: it verifies
-- the self-authority signature and continuity, but never possesses the signing key.
CREATE TABLE chat_device_manifests (
    user_id          UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    version          BIGINT      NOT NULL CHECK (version > 0),
    manifest_hash    TEXT        NOT NULL CHECK (length(manifest_hash) = 64),
    authority_key_id TEXT        NOT NULL CHECK (length(authority_key_id) = 64),
    manifest         JSONB       NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

