CREATE TABLE files (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id         UUID NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    uploader_user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Encrypted metadata: {name, mimeType, size} as JSON, secretbox with fileKey
    encrypted_metadata    TEXT NOT NULL,
    metadata_nonce        TEXT NOT NULL,
    -- File key encrypted with collection key
    encrypted_file_key    TEXT NOT NULL,
    file_key_nonce        TEXT NOT NULL,
    -- Storage path in SeaweedFS: {userId}/{collectionId}/{fileId}
    storage_path          TEXT NOT NULL,
    -- Encrypted file size (actual bytes stored in SeaweedFS, for quota tracking)
    encrypted_size_bytes  BIGINT NOT NULL DEFAULT 0,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_files_collection ON files(collection_id);
CREATE INDEX idx_files_uploader ON files(uploader_user_id);
