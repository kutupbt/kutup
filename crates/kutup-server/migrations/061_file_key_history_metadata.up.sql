-- The file's metadata (name, type, size) as it was under the key a new
-- generation replaced, still sealed under that older key. Someone whose
-- single-file share waits at an older generation (docs/plans/drive-file-sharing.md)
-- can then still tell what the file is. Null for generations recorded before.
ALTER TABLE file_key_history
    ADD COLUMN previous_metadata_envelope TEXT,
    ADD COLUMN previous_metadata_revision BIGINT;
