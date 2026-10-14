-- Username renames (docs/plans/username-renames.md, v2): folded names, the
-- rename chain, holds, and old addresses that only receive.

-- kutup_crypto::names::fold, in SQL, byte for byte: ASCII letters lowercase,
-- `.`, `_` and `-` removed, anything else kept.
CREATE FUNCTION kutup_fold(name text) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN translate(name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ._-', 'abcdefghijklmnopqrstuvwxyz');

-- Every name in use or held, by its folded form (kutup_crypto::names::fold):
-- one account per folded name. The stored name keeps its owner's spelling.
CREATE TABLE account_names (
    folded         text PRIMARY KEY CHECK (folded ~ '^[a-z0-9]{1,32}$'),
    name           text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9_-]{3,32}$'),
    user_id        uuid REFERENCES users(id) ON DELETE SET NULL,
    -- Set in the transaction that finishes setup (register, complete-setup);
    -- null for an admin-made account not set up yet.
    incarnation_id text CHECK (incarnation_id ~ '^[0-9a-f]{64}$'),
    state          text NOT NULL CHECK (state IN ('current', 'held')),
    receive_until  timestamptz,
    free_at        timestamptz,
    CHECK ((state = 'held') = (free_at IS NOT NULL)),
    CHECK (state = 'held' OR user_id IS NOT NULL)
);
CREATE UNIQUE INDEX account_names_one_current ON account_names (user_id)
    WHERE state = 'current';
CREATE INDEX account_names_user ON account_names (user_id);
CREATE INDEX account_names_free ON account_names (free_at) WHERE state = 'held';
INSERT INTO account_names (folded, name, user_id, incarnation_id, state)
    SELECT kutup_fold(username), username, id,
           NULLIF(account_incarnation_id, ''), 'current'
      FROM users WHERE username IS NOT NULL;

-- The rename chain of each incarnation: AccountRenameV1 statements as signed.
CREATE TABLE account_renames (
    incarnation_id       text NOT NULL CHECK (incarnation_id ~ '^[0-9a-f]{64}$'),
    sequence             integer NOT NULL CHECK (sequence BETWEEN 1 AND 1000),
    user_id              uuid REFERENCES users(id) ON DELETE SET NULL,
    authority_public_key text NOT NULL,
    previous             text NOT NULL,
    current              text NOT NULL,
    -- false for the free undo (back to the name just left, within 7 days).
    counted              boolean NOT NULL,
    statement            jsonb NOT NULL,
    -- The chain's digest through this statement (hex), as a verified chain
    -- gives it: what /user/me tells the account's own devices to anchor.
    digest               text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    accepted_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (incarnation_id, sequence)
);
CREATE INDEX account_renames_previous ON account_renames (previous);
CREATE INDEX account_renames_current ON account_renames (current);
CREATE INDEX account_renames_user ON account_renames (user_id, accepted_at DESC);

-- An address row outlives its name: never deleted (mail, keys, identities and
-- key lists cascade from it). Only live rows hold the (folded) address.
ALTER TABLE mail_addresses
    ADD COLUMN state text NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'receiving', 'closed', 'freed')),
    -- The address folded, always derived from it (no write can disagree).
    ADD COLUMN folded text NOT NULL GENERATED ALWAYS AS (
        kutup_fold(split_part(address, '@', 1)) || '@' || lower(split_part(address, '@', 2))
    ) STORED,
    ADD COLUMN receive_until timestamptz,
    DROP CONSTRAINT mail_addresses_address_key;
CREATE UNIQUE INDEX mail_addresses_live ON mail_addresses (folded)
    WHERE state <> 'freed';
CREATE INDEX mail_addresses_address ON mail_addresses (address);

-- Whose profile key share a row holds, by incarnation: an announced rename
-- moves only rows of that incarnation (a reused name must not move a
-- previous owner's).
ALTER TABLE drive_profile_keys ADD COLUMN peer_incarnation_id text
    CHECK (peer_incarnation_id ~ '^[0-9a-f]{64}$');

-- The new grant purpose, in both lists (docs/plans/opaque.md "Grants").
ALTER TABLE auth_grants DROP CONSTRAINT auth_grants_purpose_check,
    ADD CONSTRAINT auth_grants_purpose_check CHECK (purpose IN (
        'pass', 'passwordChange', 'totp', 'adminReset', 'recovery', 'rotate', 'rename'));
ALTER TABLE opaque_login_states DROP CONSTRAINT opaque_login_states_grant_for_check,
    ADD CONSTRAINT opaque_login_states_grant_for_check CHECK (grant_for IN (
        'pass', 'passwordChange', 'totp', 'adminReset', 'verify', 'rename'));

-- Security events: a rename and a dropped name, with the names.
ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_kind_check,
    ADD CONSTRAINT account_security_events_kind_check CHECK (kind IN (
        'passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset',
        'rename', 'nameDropped', 'nameClosed', 'nameFreed')),
    DROP CONSTRAINT account_security_events_check,
    ADD CONSTRAINT account_security_events_check CHECK (
        kind IN ('adminReset', 'accountReset', 'nameClosed', 'nameFreed')
        OR admin_user_id IS NULL),
    ADD COLUMN old_name text,
    ADD COLUMN new_name text,
    ADD CONSTRAINT account_security_events_names_check CHECK (
        (kind IN ('rename', 'nameDropped', 'nameClosed', 'nameFreed')) = (old_name IS NOT NULL)
        AND (kind = 'rename') = (new_name IS NOT NULL));
