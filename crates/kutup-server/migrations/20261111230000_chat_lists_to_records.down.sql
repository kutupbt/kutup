CREATE TABLE chat_group_list (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id text NOT NULL CHECK (id ~ '^[A-Za-z0-9_-]{43}$'),
    revision bigint NOT NULL CHECK (revision > 0),
    envelope bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, id),
    CONSTRAINT chat_group_list_envelope_check CHECK (octet_length(envelope) = 4144)
);
CREATE TABLE chat_contact_list (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id text NOT NULL CHECK (id ~ '^[A-Za-z0-9_-]{43}$'),
    revision bigint NOT NULL CHECK (revision > 0),
    envelope bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, id),
    CONSTRAINT chat_contact_list_envelope_check CHECK (octet_length(envelope) = 2160)
);
