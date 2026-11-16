-- One store for the account's synced private records (docs/plans/
-- account-records.md, W3): Signal's Storage Service, under the account head.
-- The records are opaque. Each scope's id form, purpose and limits live in
-- kutup_crypto::account_records.
CREATE TABLE account_records (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- RecordScope::info().number.
    scope smallint NOT NULL CHECK (scope BETWEEN 1 AND 255),
    -- The id the head's index names, in the scope's form (43-character
    -- base64url, a file id, or a single record's fixed id).
    record_id text NOT NULL CHECK (octet_length(record_id) BETWEEN 1 AND 64),
    -- The revision in the envelope's authenticated header, never a body's.
    revision bigint NOT NULL CHECK (revision >= 1),
    envelope bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 1 AND 65536),
    -- The account's change counter when the record was last written.
    change_seq bigint NOT NULL CHECK (change_seq >= 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, scope, record_id)
);
CREATE INDEX account_records_feed ON account_records (user_id, scope, change_seq);

CREATE TABLE account_record_tombstones (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope smallint NOT NULL CHECK (scope BETWEEN 1 AND 255),
    record_id text NOT NULL CHECK (octet_length(record_id) BETWEEN 1 AND 64),
    change_seq bigint NOT NULL CHECK (change_seq >= 1),
    deleted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, change_seq)
);
CREATE INDEX account_record_tombstones_feed
    ON account_record_tombstones (user_id, scope, change_seq);
CREATE INDEX account_record_tombstones_age ON account_record_tombstones (deleted_at);

-- The account's change counter, bumped under the account lock so writes
-- commit in counter order (any snapshot sees an exact prefix), and the
-- floor: tombstones at or below it are forgotten, so an older cursor starts
-- over.
CREATE TABLE account_record_feeds (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    change_seq bigint NOT NULL DEFAULT 0 CHECK (change_seq >= 0),
    floor_seq bigint NOT NULL DEFAULT 0 CHECK (floor_seq >= 0 AND floor_seq <= change_seq)
);
