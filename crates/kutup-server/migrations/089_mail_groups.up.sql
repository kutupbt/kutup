-- Mail groups (docs/plans/mail-groups.md, G1a): addresses that belong to a
-- team. A distribution list stores each message once (one data packet in the
-- group's storage, one small key packet per member in the member's row);
-- shared mailboxes come in G1b. Group mail is charged to the group's own
-- quota, never to its members.

CREATE TABLE mail_groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- name@<server name>, in the same namespace as usernames.
    address         TEXT NOT NULL UNIQUE CHECK (address = lower(address) AND length(address) BETWEEN 3 AND 320),
    display_name    TEXT NOT NULL DEFAULT '' CHECK (length(display_name) <= 200),
    description     TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
    kind            TEXT NOT NULL CHECK (kind IN ('list', 'shared')),
    -- Who may send to the group: anyone (outside too), Kutup users of this
    -- server, members, or owners and managers.
    post_policy     TEXT NOT NULL DEFAULT 'members' CHECK (post_policy IN ('anyone', 'local', 'members', 'managers')),
    -- The RFC 2142 role this system group answers for; system groups take
    -- mail from anyone and cannot be deleted or renamed.
    system_role     TEXT UNIQUE CHECK (system_role IN ('postmaster', 'abuse', 'security', 'hostmaster')),
    storage_quota_bytes BIGINT NOT NULL CHECK (storage_quota_bytes > 0),
    storage_used_bytes  BIGINT NOT NULL DEFAULT 0 CHECK (storage_used_bytes >= 0),
    -- Whose storage funds the group: the server (an administrator's quota)
    -- until organisations exist.
    storage_owner   TEXT NOT NULL DEFAULT 'server' CHECK (storage_owner IN ('server')),
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (system_role IS NULL OR post_policy = 'anyone')
);

CREATE TABLE mail_group_members (
    group_id    UUID NOT NULL REFERENCES mail_groups(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL CHECK (role IN ('owner', 'manager', 'member')),
    -- Shared mailboxes (G1b): may write as the group.
    can_send_as BOOLEAN NOT NULL DEFAULT false,
    added_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX idx_mail_group_members_user ON mail_group_members(user_id);

-- A group's address takes its place among the addresses, so no account can
-- take it and it cannot take an account's.
ALTER TABLE mail_addresses ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE mail_addresses ADD COLUMN group_id UUID UNIQUE REFERENCES mail_groups(id) ON DELETE CASCADE;
ALTER TABLE mail_addresses ADD CONSTRAINT mail_addresses_owner CHECK ((user_id IS NULL) <> (group_id IS NULL));

-- A distribution list's stored data packet, shared by its members' rows and
-- charged once to the group. Removed (and the group refunded) when no row
-- points at it any more.
CREATE TABLE mail_group_objects (
    object_key      TEXT PRIMARY KEY,
    object_version  TEXT NOT NULL DEFAULT '',
    group_id        UUID NOT NULL REFERENCES mail_groups(id) ON DELETE CASCADE,
    size_bytes      BIGINT NOT NULL CHECK (size_bytes > 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_mail_group_objects_group ON mail_group_objects(group_id);

-- A member's copy of list mail: the group it came through, and the member's
-- own key packet (the object holds the shared data packet alone). Such rows
-- share their object, so object keys are unique only for rows of one's own.
ALTER TABLE mail_messages ADD COLUMN group_id UUID REFERENCES mail_groups(id) ON DELETE SET NULL;
ALTER TABLE mail_messages ADD COLUMN key_packet BYTEA CHECK (octet_length(key_packet) BETWEEN 1 AND 4096);
ALTER TABLE mail_messages DROP CONSTRAINT mail_messages_object_key_key;
CREATE UNIQUE INDEX idx_mail_messages_object_once ON mail_messages(object_key) WHERE key_packet IS NULL;
CREATE INDEX idx_mail_messages_shared_object ON mail_messages(object_key) WHERE key_packet IS NOT NULL;
