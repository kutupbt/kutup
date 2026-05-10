-- Per-file binary asset blobs (currently used by whiteboards for embedded
-- image binaries — Excalidraw's content-addressed `fileId` becomes our
-- `asset_id`). One row per (file_id, asset_id); content-addressed so
-- re-uploading the same blob is idempotent via ON CONFLICT DO NOTHING.
--
-- size_bytes is the source of truth for quota accounting. The cached
-- counter on users.storage_used_bytes is updated in the same transaction
-- as INSERT/DELETE, with a periodic reconciliation job (services/
-- quota_reconcile.go) re-deriving it from row sums.
--
-- ON DELETE CASCADE on file_id makes parent-file removal automatically
-- cascade; the FilesHandler.Delete handler queries the SUM(size_bytes)
-- before the cascade so it knows how much quota to release per uploader.
CREATE TABLE file_assets (
  file_id          UUID        NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  asset_id         TEXT        NOT NULL,
  size_bytes       BIGINT      NOT NULL CHECK (size_bytes >= 0),
  uploader_user_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (file_id, asset_id)
);
CREATE INDEX file_assets_uploader_idx ON file_assets (uploader_user_id);
