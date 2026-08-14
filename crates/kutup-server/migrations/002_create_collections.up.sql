CREATE TABLE collections (
    -- Client-generated before encryption so every envelope is bound to the
    -- final persistent identifier. The server never substitutes an id.
    id                    UUID PRIMARY KEY,
    owner_user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_envelope         TEXT NOT NULL,
    owner_key_envelope    TEXT NOT NULL,
    key_epoch             INTEGER NOT NULL CHECK (key_epoch > 0),
    name_revision         BIGINT NOT NULL CHECK (name_revision > 0),
    epoch_statement       TEXT NOT NULL,
    epoch_statement_hash  TEXT NOT NULL CHECK (epoch_statement_hash ~ '^[0-9a-f]{64}$'),
    parent_collection_id  UUID REFERENCES collections(id) ON DELETE SET NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Complete immutable key-epoch records. Current state and history are
-- inserted in the same transaction by the collection handler.
CREATE TABLE collection_key_epoch_history (
    collection_id          UUID NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    epoch                  INTEGER NOT NULL CHECK (epoch > 0),
    owner_key_envelope     TEXT NOT NULL,
    epoch_statement        TEXT NOT NULL,
    epoch_statement_hash   TEXT NOT NULL CHECK (epoch_statement_hash ~ '^[0-9a-f]{64}$'),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (collection_id, epoch),
    UNIQUE (collection_id, epoch_statement_hash)
);

CREATE INDEX idx_collections_owner ON collections(owner_user_id);
CREATE INDEX idx_collections_parent ON collections(parent_collection_id);
