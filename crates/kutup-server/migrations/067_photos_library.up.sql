-- An account's own marks on photos (favourites, archived, hidden) as one
-- account-private envelope (kutup-crypto photos_library). The server keeps
-- the latest and accepts only its successor: compare-and-swap on the
-- revision and the previous envelope's digest, never reading the marks.
CREATE TABLE photos_library (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    revision BIGINT NOT NULL CHECK (revision > 0),
    envelope_digest TEXT NOT NULL,
    envelope BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
