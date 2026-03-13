CREATE TABLE collection_shares (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id             UUID NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    sharer_user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Collection key encrypted with recipient's public key (crypto_box_seal)
    encrypted_collection_key  TEXT NOT NULL,
    can_write                 BOOLEAN NOT NULL DEFAULT false,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (collection_id, recipient_user_id)
);

CREATE INDEX idx_shares_collection ON collection_shares(collection_id);
CREATE INDEX idx_shares_recipient ON collection_shares(recipient_user_id);
