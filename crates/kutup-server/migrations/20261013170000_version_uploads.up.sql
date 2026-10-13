-- A tus upload is a new file or a new version of one (docs/plans/drive-unique-names.md,
-- "Replace"): a version keeps its file's name, so it has no name hash or file key
-- envelope, and records the key generation it is sealed under, the content hash
-- and the version it was based on.
ALTER TABLE uploads
    ADD COLUMN kind text NOT NULL DEFAULT 'file',
    ADD COLUMN key_generation integer,
    ADD COLUMN content_hash text,
    ADD COLUMN based_on text,
    ALTER COLUMN file_key_envelope DROP NOT NULL,
    ALTER COLUMN name_hash DROP NOT NULL,
    ADD CONSTRAINT uploads_kind_check CHECK (kind IN ('file', 'version')),
    ADD CONSTRAINT uploads_kind_fields CHECK (
        (kind = 'file' AND name_hash IS NOT NULL AND file_key_envelope IS NOT NULL
            AND key_generation IS NULL AND content_hash IS NULL AND based_on IS NULL)
        OR (kind = 'version' AND name_hash IS NULL AND file_key_envelope IS NULL
            AND key_generation IS NOT NULL AND key_generation > 0
            AND (content_hash IS NULL OR content_hash ~ '^[0-9a-f]{64}$'))
    );
