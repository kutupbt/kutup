CREATE TABLE collections (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_name        TEXT NOT NULL,
    name_nonce            TEXT NOT NULL,
    -- Collection key encrypted with owner's masterKey
    encrypted_key         TEXT NOT NULL,
    encrypted_key_nonce   TEXT NOT NULL,
    parent_collection_id  UUID REFERENCES collections(id) ON DELETE SET NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_collections_owner ON collections(owner_user_id);
CREATE INDEX idx_collections_parent ON collections(parent_collection_id);
