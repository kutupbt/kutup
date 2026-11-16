-- Back to both suites: the constraints of 20261109130000 and
-- 20261109140000, and suite 1 as the default.
ALTER TABLE uploads
    DROP CONSTRAINT uploads_metadata_at_commit,
    DROP CONSTRAINT uploads_blob_suite_check,
    ALTER COLUMN blob_suite SET DEFAULT 1,
    ALTER COLUMN metadata_revision SET DEFAULT 1;
ALTER TABLE uploads
    ADD CONSTRAINT uploads_blob_suite_check CHECK (blob_suite IN (1, 2)),
    ADD CONSTRAINT uploads_metadata_by_suite CHECK (
        (blob_suite = 1 AND metadata_envelope IS NOT NULL AND metadata_revision IS NOT NULL)
        OR (blob_suite = 2 AND metadata_envelope IS NULL AND metadata_revision IS NULL));

ALTER TABLE file_versions
    DROP CONSTRAINT file_versions_revision_content_check,
    DROP CONSTRAINT file_versions_blob_suite_check,
    ALTER COLUMN blob_suite SET DEFAULT 1;
ALTER TABLE file_versions
    ADD CONSTRAINT file_versions_blob_suite_check CHECK (blob_suite IN (1, 2)),
    ADD CONSTRAINT file_versions_revision_content_by_suite CHECK (
        (blob_suite = 1 AND revision_content_envelope IS NULL)
        OR (blob_suite = 2 AND revision_content_envelope IS NOT NULL
            AND length(revision_content_envelope) = 476));

ALTER TABLE files
    DROP CONSTRAINT files_revision_content_check,
    DROP CONSTRAINT files_blob_suite_check,
    ALTER COLUMN blob_suite SET DEFAULT 1;
ALTER TABLE files
    ADD CONSTRAINT files_blob_suite_check CHECK (blob_suite IN (1, 2)),
    ADD CONSTRAINT files_revision_content_by_suite CHECK (
        (blob_suite = 1 AND revision_content_envelope IS NULL)
        OR (blob_suite = 2 AND revision_content_envelope IS NOT NULL
            AND length(revision_content_envelope) = 476));
