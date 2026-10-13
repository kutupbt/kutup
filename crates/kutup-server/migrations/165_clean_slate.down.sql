ALTER TABLE chat_call_links ALTER COLUMN host_token_hash DROP NOT NULL;
ALTER TABLE chat_call_links ADD CONSTRAINT chat_call_links_waiting_room_needs_host
    CHECK (NOT waiting_room OR host_token_hash IS NOT NULL);

ALTER TABLE users ADD COLUMN email TEXT UNIQUE;
CREATE INDEX idx_users_email ON users(email);

ALTER TABLE public_shares ALTER COLUMN owner_link_key_envelope DROP NOT NULL;

ALTER TABLE file_versions ADD COLUMN s3_version_id TEXT NOT NULL DEFAULT '';
