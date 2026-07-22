-- Sparse authenticated map from canonical local usernames to their current
-- signed device manifests. Only non-empty nodes are stored. Every resulting
-- map root is committed as the final leaf of the existing chronological log,
-- binding current-value proofs to the same append-only checkpoint.
CREATE TABLE chat_transparency_map_nodes (
    depth  SMALLINT NOT NULL CHECK (depth BETWEEN 0 AND 256),
    path   BYTEA NOT NULL CHECK (octet_length(path) = 32),
    hash   BYTEA NOT NULL CHECK (octet_length(hash) = 32),
    PRIMARY KEY (depth, path)
);

CREATE TABLE chat_transparency_map_checkpoints (
    position   BIGINT PRIMARY KEY CHECK (position >= 0),
    map_root   BYTEA NOT NULL CHECK (octet_length(map_root) = 32),
    leaf_hash  BYTEA NOT NULL CHECK (octet_length(leaf_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
