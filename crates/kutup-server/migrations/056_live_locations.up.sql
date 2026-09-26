-- Live-location streams (docs/plans/maps.md "Live location"). Each holds
-- only the latest sealed 88-byte update of one share and is deleted when the
-- share ends. No account, conversation or position is stored: only hashes of
-- the write secret and read capability, which the sharer's app makes.
CREATE TABLE live_location_streams (
    stream_id       BYTEA PRIMARY KEY CHECK (octet_length(stream_id) = 16),
    write_verifier  BYTEA NOT NULL CHECK (octet_length(write_verifier) = 32),
    read_verifier   BYTEA NOT NULL CHECK (octet_length(read_verifier) = 32),
    update_bytes    BYTEA CHECK (update_bytes IS NULL OR octet_length(update_bytes) = 88),
    counter         BIGINT NOT NULL DEFAULT 0 CHECK (counter >= 0),
    updated_at      TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX live_location_streams_expires_idx ON live_location_streams (expires_at);
