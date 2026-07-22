-- Append-only RFC 6962-style log of every accepted device-manifest version.
-- The singleton row serializes appends and gives one stable identity to this
-- database even when public hostnames or federation routing change.
CREATE TABLE chat_transparency_log (
    singleton  BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    log_id     CHAR(64) NOT NULL UNIQUE,
    tree_size  BIGINT NOT NULL DEFAULT 0 CHECK (tree_size >= 0)
);

INSERT INTO chat_transparency_log (singleton, log_id, tree_size)
VALUES (true, encode(gen_random_bytes(32), 'hex'), 0);

CREATE TABLE chat_transparency_leaves (
    position          BIGINT PRIMARY KEY CHECK (position >= 0),
    -- Nullable only after account deletion: historical leaves remain auditable
    -- while no longer participating in current-account lookup.
    user_id           UUID REFERENCES users(id) ON DELETE SET NULL,
    username          TEXT NOT NULL,
    manifest_version  BIGINT NOT NULL CHECK (manifest_version > 0),
    manifest_hash     CHAR(64) NOT NULL,
    authority_key_id  CHAR(64) NOT NULL,
    leaf_hash         BYTEA NOT NULL CHECK (octet_length(leaf_hash) = 32),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, manifest_version)
);

CREATE INDEX chat_transparency_leaves_user_version
    ON chat_transparency_leaves (user_id, manifest_version DESC);

-- Complete aligned subtrees. Level zero contains leaf hashes; a node at level
-- L covers 2^L leaves. Incomplete right-edge roots are composed at read time.
CREATE TABLE chat_transparency_nodes (
    level       SMALLINT NOT NULL CHECK (level BETWEEN 0 AND 62),
    node_index  BIGINT NOT NULL CHECK (node_index >= 0),
    hash        BYTEA NOT NULL CHECK (octet_length(hash) = 32),
    PRIMARY KEY (level, node_index)
);
