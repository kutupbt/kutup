-- Block-format uploads have no metadata the older schema can hold: they go
-- (their objects or multipart parts are left to the orphan sweep).
DELETE FROM uploads WHERE blob_suite = 2;

ALTER TABLE uploads
    DROP CONSTRAINT uploads_uploaded_check,
    DROP CONSTRAINT uploads_metadata_by_suite,
    DROP COLUMN uploaded_at,
    ALTER COLUMN metadata_revision SET NOT NULL,
    ALTER COLUMN metadata_envelope SET NOT NULL;
