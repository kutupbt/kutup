-- Account states, legal hold and the destruction log
-- (docs/plans/server-personal-data.md, A5 and A7; slice L4).

-- A state replaces the is_active flag: `suspended` is what "not active" was,
-- with why; `closing` waits out its grace period, then the account is
-- deleted. `is_active` stays as what it always meant to every query that
-- routes, delivers or signs in (the state is `active`), derived, never set.
ALTER TABLE users
    ADD COLUMN state text NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'suspended', 'closing')),
    ADD COLUMN suspended_reason text
        CHECK (suspended_reason IN ('admin', 'operator_order', 'security')),
    ADD COLUMN state_changed_at timestamptz NOT NULL DEFAULT now(),
    -- Who asked for the account to be closed (`restore`: a restore found it
    -- destroyed after its dump), and when it goes.
    ADD COLUMN closing_by text CHECK (closing_by IN ('user', 'admin', 'restore')),
    ADD COLUMN closes_at timestamptz,
    -- When the account's purpose ended (it was asked to close): the start of
    -- every retention clock that runs on after an account ends.
    ADD COLUMN purpose_ended_at timestamptz,
    -- A legal hold: nothing of the account is deleted while it is set.
    ADD COLUMN legal_hold_reference text
        CHECK (char_length(legal_hold_reference) BETWEEN 1 AND 200),
    ADD COLUMN legal_hold_at timestamptz,
    ADD COLUMN legal_hold_by uuid REFERENCES users(id) ON DELETE SET NULL;
UPDATE users SET state = 'suspended', suspended_reason = 'admin' WHERE NOT is_active;
ALTER TABLE users DROP COLUMN is_active;
ALTER TABLE users
    ADD COLUMN is_active boolean GENERATED ALWAYS AS (state = 'active') STORED,
    ADD CONSTRAINT users_suspended_reason
        CHECK ((state = 'suspended') = (suspended_reason IS NOT NULL)),
    ADD CONSTRAINT users_closing
        CHECK ((state = 'closing') = (closing_by IS NOT NULL)
           AND (state = 'closing') = (closes_at IS NOT NULL)),
    ADD CONSTRAINT users_legal_hold
        CHECK ((legal_hold_reference IS NULL) = (legal_hold_at IS NULL)
           AND (legal_hold_reference IS NOT NULL OR legal_hold_by IS NULL));
CREATE INDEX users_closing_due ON users (closes_at) WHERE state = 'closing';

-- Closing and keeping an account are the owner's events; keeping it needs a
-- one-time grant (the sign-in that found it closing), and closing a reauth.
ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_kind_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_kind_check CHECK (kind = ANY (ARRAY[
    'passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset', 'rename',
    'nameDropped', 'nameClosed', 'nameFreed', 'domainLost',
    'twoFactorOn', 'twoFactorOff', 'recoveryCodeUsed', 'recoveryCodesRenewed',
    'securityKeyAdded', 'securityKeyRemoved', 'securityKeyCompromised',
    'authenticatorOn', 'authenticatorOff',
    'orgJoined', 'orgLeft', 'orgRemoved', 'orgAccessGranted', 'orgAccessRevoked',
    'orgReset', 'orgSignIn',
    'signIn', 'signInFailedPassword', 'signInFailed2fa', 'signOut',
    'sessionRevoked', 'allSessionsRevoked', 'adminAccess',
    'accountClosing', 'accountKept']));
ALTER TABLE auth_grants DROP CONSTRAINT auth_grants_purpose_check;
ALTER TABLE auth_grants ADD CONSTRAINT auth_grants_purpose_check CHECK (purpose = ANY (ARRAY[
    'pass', 'passwordChange', 'totp', 'adminReset', 'recovery', 'rotate', 'rename',
    'close', 'keep']));
ALTER TABLE auth_grants DROP CONSTRAINT auth_grants_check1;
ALTER TABLE auth_grants ADD CONSTRAINT auth_grants_check1
    CHECK ((purpose IN ('recovery', 'keep')) = (session_id IS NULL));

-- What was destroyed, when, how and by whom, naming nobody: an account is its
-- subject as a keyed hash of its id, one under each entry of the server key
-- list at the time (`subject_key_ids`), so a restore can find the accounts
-- the log destroyed after its dump. Append-only for the app role (the server
-- sets the grants at start, as for the security log).
--
-- It lives beside the account data keys, in the schema the database dump
-- leaves out and the key dump holds: a restore takes the newest key dump, so
-- the log it replays is as new as the keys, whatever database dump it
-- restores (A2).
CREATE TABLE account_keys.destruction_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    at timestamptz NOT NULL DEFAULT now(),
    category text NOT NULL CHECK (category IN (
        'account', 'security_events', 'admin_audit', 'sessions', 'destruction_events')),
    subject_key_ids integer[],
    subjects bytea[],
    method text NOT NULL CHECK (method IN ('crypto_shred', 'delete', 'anonymise')),
    actor text NOT NULL CHECK (actor IN ('user', 'admin', 'job')),
    reference text NOT NULL CHECK (char_length(reference) BETWEEN 1 AND 100),
    count integer NOT NULL DEFAULT 1 CHECK (count >= 1),
    CHECK ((subjects IS NULL) = (subject_key_ids IS NULL)),
    CHECK (subjects IS NULL OR (cardinality(subjects) >= 1
        AND cardinality(subjects) = cardinality(subject_key_ids)))
);
CREATE INDEX destruction_events_at ON account_keys.destruction_events (at);
CREATE INDEX destruction_events_accounts ON account_keys.destruction_events (category)
    WHERE subjects IS NOT NULL;
