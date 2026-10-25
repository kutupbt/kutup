-- Two-factor recovery codes (docs/plans/security-keys.md, D2; Proton's): one-
-- time codes made when two-factor sign-in is turned on, each taking the
-- second factor's place once. Only a MAC of each is kept, under a key the
-- server makes for itself (server_generated_keys) and bound to the account.
CREATE TABLE two_factor_recovery_codes (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_mac bytea NOT NULL CHECK (octet_length(code_mac) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, code_mac)
);

-- The key the codes' MACs are made under.
ALTER TABLE server_generated_keys
    DROP CONSTRAINT server_generated_keys_purpose_check,
    ADD CONSTRAINT server_generated_keys_purpose_check
        CHECK (purpose = ANY (ARRAY['federation-identity', 'fake-accounts', 'registration-codes',
            'two-factor-recovery-codes']));

-- Two-factor changes in the account's security log; an administrator's 2FA
-- reset is recorded as its `twoFactorOff`.
ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_kind_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_kind_check CHECK (kind = ANY (ARRAY[
    'passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset', 'rename',
    'nameDropped', 'nameClosed', 'nameFreed', 'domainLost',
    'twoFactorOn', 'twoFactorOff', 'recoveryCodeUsed', 'recoveryCodesRenewed']));
ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_check CHECK (
    kind = ANY (ARRAY['adminReset', 'accountReset', 'nameClosed', 'nameFreed', 'twoFactorOff'])
    OR admin_user_id IS NULL);
