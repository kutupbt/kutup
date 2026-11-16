CREATE TABLE identity_pins (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    envelope bytea NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);
