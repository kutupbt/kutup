DROP TABLE IF EXISTS chat_group_avatars;

CREATE TABLE chat_group_avatars (
    group_id bytea PRIMARY KEY REFERENCES chat_groups (group_id) ON DELETE CASCADE,
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) <= 40960),
    updated_at timestamptz NOT NULL DEFAULT now()
);
