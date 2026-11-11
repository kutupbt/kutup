DROP INDEX uploads_revision_id_key;

ALTER TABLE file_versions
    DROP CONSTRAINT file_versions_revision_content_by_suite,
    DROP CONSTRAINT file_versions_blob_suite_check,
    DROP COLUMN revision_content_envelope,
    DROP COLUMN blob_suite;

ALTER TABLE files
    DROP CONSTRAINT files_revision_content_by_suite,
    DROP CONSTRAINT files_blob_suite_check,
    DROP COLUMN revision_content_envelope,
    DROP COLUMN blob_suite;
