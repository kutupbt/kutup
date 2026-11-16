-- Suite 1 goes (docs/plans/drive-block-format.md §10 slice 7): every Drive
-- blob is in the block format (suite 2), so every stored revision carries
-- its sealed `RevisionContent` record and every upload's metadata comes
-- with its commit. `blob_suite` stays as the record of the suite, now only
-- 2. Rows of suite 1 go with the clean-slate wipe (§6); NOT VALID leaves
-- them be until then while every new row is checked.
ALTER TABLE files
    DROP CONSTRAINT files_revision_content_by_suite,
    DROP CONSTRAINT files_blob_suite_check,
    ALTER COLUMN blob_suite SET DEFAULT 2;
ALTER TABLE files
    ADD CONSTRAINT files_blob_suite_check CHECK (blob_suite = 2) NOT VALID,
    ADD CONSTRAINT files_revision_content_check CHECK (
        revision_content_envelope IS NOT NULL
        AND length(revision_content_envelope) = 476) NOT VALID;

ALTER TABLE file_versions
    DROP CONSTRAINT file_versions_revision_content_by_suite,
    DROP CONSTRAINT file_versions_blob_suite_check,
    ALTER COLUMN blob_suite SET DEFAULT 2;
ALTER TABLE file_versions
    ADD CONSTRAINT file_versions_blob_suite_check CHECK (blob_suite = 2) NOT VALID,
    ADD CONSTRAINT file_versions_revision_content_check CHECK (
        revision_content_envelope IS NOT NULL
        AND length(revision_content_envelope) = 476) NOT VALID;

ALTER TABLE uploads
    DROP CONSTRAINT uploads_metadata_by_suite,
    DROP CONSTRAINT uploads_blob_suite_check,
    ALTER COLUMN blob_suite SET DEFAULT 2,
    -- metadata arrives at the commit; no default may fill it in
    ALTER COLUMN metadata_revision DROP DEFAULT;
ALTER TABLE uploads
    ADD CONSTRAINT uploads_blob_suite_check CHECK (blob_suite = 2) NOT VALID,
    ADD CONSTRAINT uploads_metadata_at_commit CHECK (
        metadata_envelope IS NULL AND metadata_revision IS NULL) NOT VALID;
