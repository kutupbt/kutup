-- An account's Chat contacts (docs/plans/chat-contacts-sync.md): one sealed
-- entry per person the account accepted, rejected, blocked or asked, keyed
-- by a hash of their account under a key of the account's own. Listed under
-- the account head's `chatContacts` scope.
CREATE TABLE chat_contact_list (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id text NOT NULL CHECK (id ~ '^[A-Za-z0-9_-]{43}$'),
    revision bigint NOT NULL CHECK (revision > 0),
    -- Every sealed entry is one size (kutup-crypto chat_contact_list).
    envelope bytea NOT NULL CHECK (octet_length(envelope) = 2048),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, id)
);
