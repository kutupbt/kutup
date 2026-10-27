ALTER TABLE uploads
    DROP CONSTRAINT uploads_blob_suite_check,
    DROP COLUMN blob_suite,
    DROP COLUMN revision_id;
DROP INDEX files_content_revision_id_key;
ALTER TABLE files DROP COLUMN content_revision_id;
