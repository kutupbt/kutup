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

-- Shared mailboxes (G1b): one mailbox the members work in together, with its
-- own address key. Each member holds a share: the group key's secret
-- encrypted to the member's address key. The group's key lists are signed
-- by the server (a group has no account authority), with a key of its own.
CREATE TABLE mail_group_keys (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id            UUID NOT NULL REFERENCES mail_groups(id) ON DELETE CASCADE,
    fingerprint         CHAR(40) NOT NULL UNIQUE CHECK (fingerprint ~ '^[0-9a-f]{40}$'),
    sha256_fingerprint  CHAR(64) NOT NULL CHECK (sha256_fingerprint ~ '^[0-9a-f]{64}$'),
    public_key          BYTEA NOT NULL CHECK (octet_length(public_key) BETWEEN 1 AND 16384),
    is_primary          BOOLEAN NOT NULL DEFAULT false,
    flags               INTEGER NOT NULL DEFAULT 3 CHECK (flags BETWEEN 0 AND 15),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_mail_group_keys_primary ON mail_group_keys(group_id) WHERE is_primary;

CREATE TABLE mail_group_key_shares (
    group_key_id        UUID NOT NULL REFERENCES mail_group_keys(id) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    share               BYTEA NOT NULL CHECK (octet_length(share) BETWEEN 1 AND 16384),
    -- The member's address key the share is encrypted to.
    member_fingerprint  CHAR(40) NOT NULL CHECK (member_fingerprint ~ '^[0-9a-f]{40}$'),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_key_id, user_id)
);
CREATE INDEX idx_mail_group_key_shares_user ON mail_group_key_shares(user_id);

CREATE TABLE mail_group_key_lists (
    group_id    UUID NOT NULL REFERENCES mail_groups(id) ON DELETE CASCADE,
    sequence    BIGINT NOT NULL CHECK (sequence >= 1),
    data        BYTEA NOT NULL,
    signature   BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, sequence)
);

ALTER TABLE server_generated_keys DROP CONSTRAINT server_generated_keys_purpose_check;
ALTER TABLE server_generated_keys ADD CONSTRAINT server_generated_keys_purpose_check
    CHECK (purpose IN ('federation-identity', 'mls-control', 'mail-group-authority'));

-- A shared mailbox's message belongs to the group (no user); a list copy and
-- personal mail to their account. `owner` is whose mailbox a row is in.
ALTER TABLE mail_messages ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE mail_messages ADD CONSTRAINT mail_messages_owner CHECK (user_id IS NOT NULL OR group_id IS NOT NULL);
ALTER TABLE mail_messages ADD COLUMN owner UUID GENERATED ALWAYS AS (COALESCE(user_id, group_id)) STORED;
CREATE INDEX idx_mail_messages_owner_folder ON mail_messages(owner, folder, received_at DESC, id);
CREATE INDEX idx_mail_messages_owner_thread ON mail_messages(owner, thread_id, received_at);

-- Mail a member sent as a shared mailbox: who sent it, shown to the other
-- members and counted against that member's sending limits.
ALTER TABLE mail_messages ADD COLUMN sent_by UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE mail_messages ADD COLUMN sender_account UUID GENERATED ALWAYS AS (COALESCE(sent_by, user_id)) STORED;
CREATE INDEX idx_mail_messages_sender_recently ON mail_messages(sender_account, received_at)
    WHERE external_recipients > 0;
