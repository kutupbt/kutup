-- Versioned Signal-style opaque encrypted profiles. Older versions remain
-- readable with their old capability while a newly rotated key is distributed;
-- only one row is the owner-visible current revision.
CREATE TABLE chat_profiles (
    user_id              UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    version              CHAR(64) NOT NULL,
    revision             BIGINT NOT NULL CHECK (revision > 0),
    source_device_id     INTEGER NOT NULL CHECK (source_device_id BETWEEN 1 AND 127),
    name_ciphertext      TEXT NOT NULL,
    avatar_ciphertext    TEXT,
    wrapped_key          TEXT NOT NULL,
    access_key_verifier  BYTEA NOT NULL CHECK (octet_length(access_key_verifier) = 32),
    is_current           BOOLEAN NOT NULL DEFAULT true,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, version)
);

CREATE UNIQUE INDEX chat_profiles_one_current
    ON chat_profiles (user_id) WHERE is_current;
