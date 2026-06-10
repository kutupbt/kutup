-- Slice 1.5 polish on the tus uploads table.
--
-- Two changes:
--   1. Add `file_id` UUID. Generated server-side at Create, kept in the
--      uploads row so the final PATCH can INSERT into `files` with the
--      pre-known id. We allocate the S3 multipart upload directly at the
--      canonical {userId}/{collectionId}/{fileID} path and skip the
--      previous temp → final CopyObject dance entirely. CopyObject is
--      capped at 5 GiB on real AWS S3 and unreliable for multi-GB files;
--      the new flow has no such cap.
--   2. Rename `storage_temp_key` → `storage_path` to match the convention
--      in the `files` table and reflect that it's now the canonical
--      storage path, not a temp location.
--
-- Pre-production, no live tus uploads to migrate. If any uploads rows
-- exist they're test detritus — drop them rather than backfill.

DELETE FROM uploads;

ALTER TABLE uploads
    ADD COLUMN file_id UUID NOT NULL DEFAULT gen_random_uuid();
-- Drop the default — fileID must always be supplied by the application.
ALTER TABLE uploads
    ALTER COLUMN file_id DROP DEFAULT;

ALTER TABLE uploads
    RENAME COLUMN storage_temp_key TO storage_path;
