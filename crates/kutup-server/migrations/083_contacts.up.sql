-- Contacts (docs/plans/contacts.md): one encrypted address book per account,
-- Proton's split. The summary (uid, name, emails, groups, pinned keys) is
-- canonical JSON signed by the account authority and readable by the server,
-- which indexes it; the card (the full vCard) is sealed under a key only the
-- account holds. Both count against the account's storage pool.

CREATE TABLE contacts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    uid         TEXT NOT NULL CHECK (length(uid) BETWEEN 1 AND 800),
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 800),
    summary     TEXT NOT NULL CHECK (octet_length(summary) BETWEEN 1 AND 32768),
    signature   BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    card        BYTEA NOT NULL CHECK (octet_length(card) BETWEEN 1 AND 600000),
    revision    BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, uid)
);
CREATE INDEX idx_contacts_user_name ON contacts(user_id, lower(name), id);

-- Proton's ContactEmails: the readable index autocomplete runs on.
CREATE TABLE contact_emails (
    contact_id  UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    address     TEXT NOT NULL CHECK (address = lower(address) AND length(address) BETWEEN 3 AND 320),
    label       TEXT,
    position    INTEGER NOT NULL CHECK (position >= 0),
    last_used_at TIMESTAMPTZ,
    PRIMARY KEY (contact_id, address)
);
CREATE INDEX idx_contact_emails_user_address ON contact_emails(user_id, address text_pattern_ops);

CREATE TABLE contact_groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    color       TEXT NOT NULL CHECK (color ~ '^#[0-9a-f]{6}$'),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_contact_groups_user ON contact_groups(user_id);

-- Written from each contact's signed summary.
CREATE TABLE contact_group_members (
    contact_id  UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    group_id    UUID NOT NULL REFERENCES contact_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (contact_id, group_id)
);
CREATE INDEX idx_contact_group_members_group ON contact_group_members(group_id);
