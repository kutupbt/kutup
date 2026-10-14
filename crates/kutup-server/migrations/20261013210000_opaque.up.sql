-- OPAQUE sign-in (docs/plans/opaque.md): the server keeps a record that is
-- useless without an online exchange, instead of a hash of a login key that a
-- database reader could attack offline. The salt, the Argon2 parameters and
-- the login-key hash go; the suite's KSF replaces them.
ALTER TABLE users
    DROP COLUMN login_key_hash,
    DROP COLUMN account_protection_salt,
    DROP COLUMN account_protection_suite,
    DROP COLUMN argon_memory_kib,
    DROP COLUMN argon_iterations,
    DROP COLUMN argon_parallelism,
    -- The registration record, its suite, and the server setup that answers
    -- it: all three or none (an account never registered cannot sign in).
    ADD COLUMN opaque_record bytea,
    ADD COLUMN opaque_suite smallint,
    ADD COLUMN opaque_server_key_id smallint,
    ADD CONSTRAINT users_opaque_check CHECK (
        (opaque_record IS NULL) = (opaque_suite IS NULL)
        AND (opaque_record IS NULL) = (opaque_server_key_id IS NULL)),
    ADD CONSTRAINT users_opaque_suite_check CHECK (opaque_suite = 1),
    ADD CONSTRAINT users_opaque_server_key_id_check CHECK (opaque_server_key_id > 0),
    ADD CONSTRAINT users_opaque_record_check CHECK (octet_length(opaque_record) BETWEEN 1 AND 1024);

-- The server's OPAQUE setups (OPRF seed and keys), each sealed under the
-- OPAQUE_SETUP_KEYS key of the same id, which is never in the database.
CREATE TABLE opaque_server_setups (
    key_id smallint PRIMARY KEY CHECK (key_id > 0),
    sealed_setup bytea NOT NULL CHECK (octet_length(sealed_setup) BETWEEN 1 AND 4096),
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz
);

-- A sign-in between its start and its finish: single use, two minutes. The
-- server's state is sealed under the setup key (AAD: the login id), so a
-- database read never holds it in the clear. The attempt's lockout and
-- ceiling slots were taken at start; a right finish gives back these.
CREATE TABLE opaque_login_states (
    login_id uuid PRIMARY KEY,
    canonical_name text NOT NULL,
    user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    purpose text NOT NULL CHECK (purpose IN ('session', 'reauth')),
    -- Reauth only: the signed-in session asking, and what its grant is for.
    session_id uuid REFERENCES auth_sessions(id) ON DELETE CASCADE,
    grant_for text CHECK (grant_for IN ('pass', 'passwordChange', 'totp', 'adminReset', 'verify')),
    source text NOT NULL,
    -- The lockout key as auth_check makes it (it holds a NUL: bytes, not text).
    lockout_key bytea NOT NULL,
    ceiling_account text,
    ceiling_source text,
    server_key_id smallint NOT NULL,
    sealed_state bytea NOT NULL,
    -- The account's credential epoch at the start (auth_check::credential_epoch,
    -- the first 16 bytes of SHA-256 of its record): the session or grant is
    -- made only while the record is still that one. None for a name that is
    -- no account.
    credential_epoch bytea CHECK (credential_epoch IS NULL OR length(credential_epoch) = 16),
    expires_at timestamptz NOT NULL,
    CHECK ((purpose = 'reauth') = (session_id IS NOT NULL AND grant_for IS NOT NULL AND user_id IS NOT NULL)),
    CHECK ((ceiling_account IS NULL) = (ceiling_source IS NULL))
);
CREATE INDEX opaque_login_states_name ON opaque_login_states (canonical_name, expires_at);
CREATE INDEX opaque_login_states_source ON opaque_login_states (source, expires_at);
CREATE INDEX opaque_login_states_expiry ON opaque_login_states (expires_at);

-- One-time grants (`kg1_…`, kept as their SHA-256): proof of a fresh
-- password (or recovery phrase) for one action of one account, used once,
-- within minutes. Never a session.
CREATE TABLE auth_grants (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose text NOT NULL CHECK (purpose IN (
        'pass', 'passwordChange', 'totp', 'adminReset', 'recovery', 'rotate')),
    -- The session it was issued to (none for recovery, which has no session).
    session_id uuid REFERENCES auth_sessions(id) ON DELETE CASCADE,
    -- adminReset: the account the admin may reset (none on the admin's own
    -- reauth grant, which reset-grant exchanges for one with a target).
    target_user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    CHECK (target_user_id IS NULL OR purpose = 'adminReset'),
    CHECK ((purpose = 'recovery') = (session_id IS NULL))
);
CREATE INDEX auth_grants_user ON auth_grants (user_id);
CREATE INDEX auth_grants_expiry ON auth_grants (expires_at);

-- What changed an account's sign-in, for its owner to see (GET
-- /api/user/security-events). No IP addresses. Kept a year, or the newest
-- 500 per account, pruned on write; gone with the account. An account reset
-- (a new incarnation) keeps them: the owner sees that it happened.
CREATE TABLE account_security_events (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN
        ('passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset')),
    at timestamptz NOT NULL DEFAULT now(),
    -- The session that made the change (none for a recovery or an admin's),
    -- and what it was, copied: sessions do not last as long as events.
    acting_session_id uuid,
    acting_client text,
    acting_user_agent text,
    -- The administrator, for adminReset and accountReset.
    admin_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    CHECK ((kind IN ('adminReset', 'accountReset')) OR admin_user_id IS NULL)
);
CREATE INDEX account_security_events_user ON account_security_events (user_id, at DESC, id DESC);
