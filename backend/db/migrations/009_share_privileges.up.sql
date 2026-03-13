ALTER TABLE collection_shares
  ADD COLUMN can_upload BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN can_delete BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN upload_quota_bytes BIGINT;

-- Migrate existing write permissions
UPDATE collection_shares SET can_upload = true WHERE can_write = true;

ALTER TABLE collection_shares DROP COLUMN can_write;
