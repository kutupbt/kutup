ALTER TABLE collection_shares ADD COLUMN can_write BOOLEAN NOT NULL DEFAULT false;
UPDATE collection_shares SET can_write = true WHERE can_upload = true;
ALTER TABLE collection_shares
  DROP COLUMN can_upload,
  DROP COLUMN can_delete,
  DROP COLUMN upload_quota_bytes;
