-- Uploaded revisions (docs/plans/drive-block-format.md §10 slice 3, "The
-- commit, as Proton's"). A block-format (suite 2) upload carries no metadata:
-- the metadata commits to the content's manifest digest, known only after the
-- last block. Its upload row stays once the object is complete and checked
-- (`uploaded_at`), holding its quota reservation, the file id, the key
-- envelope and the name hash of a new file, until
-- `POST /api/files/{id}/revisions/{revisionId}/commit` brings the metadata
-- and makes the revision current, or the sweep of abandoned uploads deletes
-- the object and the row. A new file is therefore not a `files` row before
-- its commit: no listing, search, share, trash or count sees it.
ALTER TABLE uploads
    ALTER COLUMN metadata_envelope DROP NOT NULL,
    ALTER COLUMN metadata_revision DROP NOT NULL,
    ADD COLUMN uploaded_at timestamp with time zone;

-- An open block-format upload: its metadata now comes with the commit.
UPDATE uploads SET metadata_envelope = NULL, metadata_revision = NULL
WHERE blob_suite = 2;

ALTER TABLE uploads
    ADD CONSTRAINT uploads_metadata_by_suite CHECK (
        (blob_suite = 1 AND metadata_envelope IS NOT NULL AND metadata_revision IS NOT NULL)
        OR (blob_suite = 2 AND metadata_envelope IS NULL AND metadata_revision IS NULL)),
    ADD CONSTRAINT uploads_uploaded_check CHECK (
        uploaded_at IS NULL OR (blob_suite = 2 AND received_bytes = total_bytes));
