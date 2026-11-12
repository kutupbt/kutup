-- What each content revision is (docs/plans/drive-block-format.md §2 and §10
-- slice 3, "History versions"): a block-format revision carries its sealed
-- `RevisionContent` envelope ({revisionId, manifestSha256, size} under the
-- file key, bound to the file, the revision and the key generation that
-- sealed the object). The file's metadata commits to the current content
-- only; readers of the original upload, a history version or a note's
-- snapshot open this record first and then the object against it, so no
-- reader opens a manifest without a committed digest.
--
-- It arrives with the revision's commit (the tus commit, a multipart upload
-- or save, a federated upload or save), once the manifest's digest is
-- known, and is stored on the row the revision becomes: `files` for the
-- original upload, `file_versions` for every version. An upload row never
-- holds it: the commit that brings it deletes that row. Both tables now
-- record their object's suite (`blob_suite`, as `uploads` does), so a
-- block-format (suite 2) row without its envelope is refused; a
-- streaming-format (suite 1) row has none. The envelope's length is fixed
-- (the purpose pads to one size): 356 bytes, 476 in base64.
--
-- Requires a fresh database (the clean-slate wipe that ships the block
-- format, docs/plans/drive-block-format.md §6): `blob_suite` defaults to 1
-- and nothing is backfilled, so a block-format row stored before this
-- migration would be marked as the streaming format and lack its record.
ALTER TABLE files
    ADD COLUMN blob_suite smallint NOT NULL DEFAULT 1,
    ADD COLUMN revision_content_envelope text,
    ADD CONSTRAINT files_blob_suite_check CHECK (blob_suite IN (1, 2)),
    ADD CONSTRAINT files_revision_content_by_suite CHECK (
        (blob_suite = 1 AND revision_content_envelope IS NULL)
        OR (blob_suite = 2 AND revision_content_envelope IS NOT NULL
            AND length(revision_content_envelope) = 476));

ALTER TABLE file_versions
    ADD COLUMN blob_suite smallint NOT NULL DEFAULT 1,
    ADD COLUMN revision_content_envelope text,
    ADD CONSTRAINT file_versions_blob_suite_check CHECK (blob_suite IN (1, 2)),
    ADD CONSTRAINT file_versions_revision_content_by_suite CHECK (
        (blob_suite = 1 AND revision_content_envelope IS NULL)
        OR (blob_suite = 2 AND revision_content_envelope IS NOT NULL
            AND length(revision_content_envelope) = 476));

-- A revision id names one content everywhere: `files.content_revision_id`
-- and `file_versions.id` are unique already, and an open upload's must be
-- too. Across the three tables every claim of an id takes that id's
-- advisory lock first (`drive_blob::ensure_revision_free`).
CREATE UNIQUE INDEX uploads_revision_id_key ON uploads (revision_id);
