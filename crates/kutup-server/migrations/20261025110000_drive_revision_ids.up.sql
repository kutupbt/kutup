-- Revision ids (docs/plans/drive-block-format.md §3, slice 2): each content
-- object of a file is a revision with its own id. A block-format (suite 2)
-- blob names its revision in its header, chosen by the client before it
-- seals; the server checks the two agree. A version's revision id is its
-- `file_versions.id`; the original upload's is `files.content_revision_id`.
-- Rows before this, and streaming-format (suite 1) uploads, get a random one.
-- The id is the content's ETag, so ranged reads resume only on the same
-- bytes.
ALTER TABLE files
    ADD COLUMN content_revision_id uuid NOT NULL DEFAULT gen_random_uuid();
CREATE UNIQUE INDEX files_content_revision_id_key ON files (content_revision_id);

-- An open upload's revision (the file's original or the version it lands
-- as) and its blob's Drive object suite: the block format's structure is
-- checked when the upload completes.
ALTER TABLE uploads
    ADD COLUMN revision_id uuid NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN blob_suite smallint NOT NULL DEFAULT 1,
    ADD CONSTRAINT uploads_blob_suite_check CHECK (blob_suite IN (1, 2));
