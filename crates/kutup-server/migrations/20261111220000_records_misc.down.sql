-- Back to the old tables and columns, empty (the records are not moved
-- back: the store's rows go with their scopes).
DELETE FROM account_records WHERE scope IN (7, 8, 9);
DELETE FROM account_record_tombstones WHERE scope IN (7, 8, 9);

CREATE TABLE chat_joined_meetings (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id text NOT NULL CHECK (id ~ '^[0-9a-f]{32}$'),
    entry bytea NOT NULL CONSTRAINT chat_joined_meetings_entry_check
        CHECK (octet_length(entry) = 1171),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, id)
);
CREATE INDEX idx_chat_joined_meetings_user ON chat_joined_meetings (user_id, created_at DESC);

ALTER TABLE calendar_members
    ADD COLUMN color char(7) NOT NULL DEFAULT '#8080ff' CHECK (color ~ '^#[0-9a-f]{6}$'),
    ADD COLUMN display boolean NOT NULL DEFAULT true,
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1);

CREATE TABLE contact_groups (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    color text NOT NULL CHECK (color ~ '^#[0-9a-f]{6}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_contact_groups_user ON contact_groups (user_id);

CREATE TABLE contact_group_members (
    contact_id uuid NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    group_id uuid NOT NULL REFERENCES contact_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (contact_id, group_id)
);
CREATE INDEX idx_contact_group_members_group ON contact_group_members (group_id);
