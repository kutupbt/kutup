-- Security keys as a second factor (docs/plans/security-keys.md, §3): WebAuthn
-- credentials, non-discoverable, several per account, each named. The key's
-- public key and its changing state (counter, flags) are kept as the
-- server's WebAuthn adapter encodes them (kutup_crypto::webauthn).
CREATE TABLE user_security_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id bytea NOT NULL CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
    transports bytea NOT NULL CHECK (octet_length(transports) = 1),
    static_state bytea NOT NULL,
    dynamic_state bytea NOT NULL,
    sign_count bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    -- The authenticator model; shown nowhere, kept to flag a known-bad one.
    aaguid bytea NOT NULL CHECK (octet_length(aaguid) = 16),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    -- Its counter went back: it may have been cloned. Shown, never used.
    compromised boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    UNIQUE (user_id, credential_id)
);
CREATE INDEX user_security_keys_user ON user_security_keys (user_id);

-- Proton's "Require PIN": user verification for adding and signing in.
ALTER TABLE users ADD COLUMN security_keys_require_uv boolean NOT NULL DEFAULT false;

-- A WebAuthn ceremony in flight: the adapter's state, found by its challenge
-- (the browser's answer names it), single use, bound to the session or the
-- sign-in's first step that started it (their SHA-256), until it expires.
CREATE TABLE webauthn_ceremonies (
    challenge bytea PRIMARY KEY CHECK (octet_length(challenge) = 16),
    kind text NOT NULL CHECK (kind IN ('register', 'signIn', 'proof')),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bound_to bytea NOT NULL CHECK (octet_length(bound_to) = 32),
    state bytea NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX webauthn_ceremonies_expiry ON webauthn_ceremonies (expires_at);

ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_kind_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_kind_check CHECK (kind = ANY (ARRAY[
    'passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset', 'rename',
    'nameDropped', 'nameClosed', 'nameFreed', 'domainLost',
    'twoFactorOn', 'twoFactorOff', 'recoveryCodeUsed', 'recoveryCodesRenewed',
    'securityKeyAdded', 'securityKeyRemoved', 'securityKeyCompromised',
    'authenticatorOn', 'authenticatorOff']));
-- Each key event names its key.
ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_names_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_names_check CHECK (
    (kind = ANY (ARRAY['rename', 'nameDropped', 'nameClosed', 'nameFreed', 'domainLost',
                       'securityKeyAdded', 'securityKeyRemoved', 'securityKeyCompromised']))
        = (old_name IS NOT NULL)
    AND (kind = 'rename') = (new_name IS NOT NULL));
