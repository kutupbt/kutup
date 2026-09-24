-- Encrypted file previews (docs/plans/drive-thumbnails.md). Made and sealed
-- by clients under the file key; the server stores the envelope and checks
-- only its public header. One row per (file, variant); an upload replaces it.
--
-- size_bytes counts against the uploader's quota like file_assets. The S3
-- object lives at files/{file_id}/thumbnails/{variant}; s3_version_id is the
-- current object version, so a replacement deletes exactly the one it
-- superseded instead of leaving it to the bucket lifecycle.
CREATE TABLE file_thumbnails (
  file_id          UUID        NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  variant          TEXT        NOT NULL CHECK (variant IN ('sm', 'lg')),
  size_bytes       BIGINT      NOT NULL CHECK (size_bytes > 0),
  s3_version_id    TEXT        NOT NULL DEFAULT '',
  -- The content it was drawn from: a file_versions row, or NULL for the
  -- original upload. The listing compares it with the latest version.
  source_version   UUID        REFERENCES file_versions(id) ON DELETE SET NULL,
  uploader_user_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (file_id, variant)
);
CREATE INDEX file_thumbnails_uploader_idx ON file_thumbnails (uploader_user_id);
