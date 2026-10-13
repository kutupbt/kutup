DELETE FROM uploads WHERE kind = 'version';
ALTER TABLE uploads
    DROP CONSTRAINT uploads_kind_fields,
    DROP CONSTRAINT uploads_kind_check,
    ALTER COLUMN name_hash SET NOT NULL,
    ALTER COLUMN file_key_envelope SET NOT NULL,
    DROP COLUMN based_on,
    DROP COLUMN content_hash,
    DROP COLUMN key_generation,
    DROP COLUMN kind;
