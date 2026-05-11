-- Pending tus.io uploads.
--
-- An upload session is created with a known total_bytes and an associated
-- S3 multipart upload (s3_upload_id). Each PATCH appends one S3 part; the
-- ETags accumulate in s3_part_etags so the final PATCH can call
-- CompleteMultipartUpload with the full list. On completion we move the
-- temp object to the canonical {userId}/{collectionId}/{fileId} path and
-- INSERT into files, in the same transaction that commits the storage
-- quota. If the user abandons the upload the stale-sweeper aborts the
-- multipart, freeing SeaweedFS-side staging space.
--
-- We also reserve quota *soft*-ly: available quota for new uploads is
--     storage_quota_bytes - storage_used_bytes - SUM(uploads.total_bytes)
-- so a half-uploaded 50 GB file blocks a concurrent 50 GB attempt that
-- would push the user over their cap, without polluting storage_used_bytes
-- with bytes that haven't actually landed yet.

CREATE TABLE uploads (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    collection_id         UUID NOT NULL REFERENCES collections(id) ON DELETE CASCADE,

    -- Total bytes the client promised on POST /uploads. Immutable.
    total_bytes           BIGINT NOT NULL,
    -- Bytes successfully written so far. Bumped by each PATCH.
    received_bytes        BIGINT NOT NULL DEFAULT 0,

    -- Encrypted metadata fields, mirroring `files`. Carried from POST to
    -- the final INSERT — the client commits them up-front so we don't
    -- have to bargain about them mid-stream.
    encrypted_metadata    TEXT NOT NULL,
    metadata_nonce        TEXT NOT NULL,
    encrypted_file_key    TEXT NOT NULL,
    file_key_nonce        TEXT NOT NULL,

    -- Where the multipart upload accumulates on SeaweedFS, and the S3
    -- UploadId we hand back to CompleteMultipartUpload.
    storage_temp_key      TEXT NOT NULL,
    s3_upload_id          TEXT NOT NULL,
    -- JSON array of {PartNumber, ETag} pairs in order — required for the
    -- final Complete call.
    s3_part_etags         JSONB NOT NULL DEFAULT '[]'::jsonb,

    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_uploads_user_id     ON uploads(user_id);
CREATE INDEX idx_uploads_updated_at  ON uploads(updated_at);
