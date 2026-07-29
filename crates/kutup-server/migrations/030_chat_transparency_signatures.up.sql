-- Stable operator-signed transparency heads. Signatures are persisted rather
-- than minted per response, so all clients compare the exact same
-- distinguished checkpoint object.
CREATE TABLE chat_transparency_signed_checkpoints (
    tree_size            BIGINT PRIMARY KEY CHECK (tree_size > 0),
    log_id               CHAR(64) NOT NULL,
    root_hash            BYTEA NOT NULL CHECK (octet_length(root_hash) = 32),
    map_root             BYTEA NOT NULL CHECK (octet_length(map_root) = 32),
    issued_at            BIGINT NOT NULL CHECK (issued_at > 0),
    operator_key_id      CHAR(64) NOT NULL,
    operator_public_key  TEXT NOT NULL,
    operator_signature   TEXT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
