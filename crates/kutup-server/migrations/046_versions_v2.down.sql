ALTER TABLE files DROP COLUMN IF EXISTS original_pruned;
ALTER TABLE file_versions DROP COLUMN IF EXISTS ciphertext_sha256;
ALTER TABLE users DROP COLUMN IF EXISTS version_retention_days;
ALTER TABLE file_versions DROP COLUMN IF EXISTS kind;
