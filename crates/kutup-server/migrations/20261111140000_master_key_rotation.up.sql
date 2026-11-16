-- The master-key rotation (docs/plans/mk-rotation-exercise.md). The account's
-- current master-key generation (every record a client writes from now on
-- is sealed under it); the keyring (purpose 27: the previous master key
-- sealed under the current one, its object the previous generation) kept
-- beside the roots; the grant a rotation is made under; and its security
-- event.
ALTER TABLE users
    ADD COLUMN master_key_generation integer NOT NULL DEFAULT 1
        CHECK (master_key_generation > 0);

ALTER TABLE account_roots DROP CONSTRAINT account_roots_purpose_check;
ALTER TABLE account_roots ADD CONSTRAINT account_roots_purpose_check
    CHECK (purpose BETWEEN 22 AND 27);

ALTER TABLE auth_grants DROP CONSTRAINT auth_grants_purpose_check;
ALTER TABLE auth_grants ADD CONSTRAINT auth_grants_purpose_check CHECK (purpose = ANY (ARRAY[
    'pass', 'passwordChange', 'totp', 'adminReset', 'recovery', 'rotate', 'rename',
    'masterKeyRotation']));

ALTER TABLE opaque_login_states DROP CONSTRAINT opaque_login_states_grant_for_check;
ALTER TABLE opaque_login_states ADD CONSTRAINT opaque_login_states_grant_for_check CHECK (grant_for = ANY (ARRAY[
    'pass', 'passwordChange', 'totp', 'adminReset', 'verify', 'rename',
    'masterKeyRotation']));

ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_kind_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_kind_check CHECK (kind = ANY (ARRAY[
    'passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset', 'rename',
    'nameDropped', 'nameClosed', 'nameFreed', 'domainLost',
    'twoFactorOn', 'twoFactorOff', 'recoveryCodeUsed', 'recoveryCodesRenewed',
    'securityKeyAdded', 'securityKeyRemoved', 'securityKeyCompromised',
    'authenticatorOn', 'authenticatorOff', 'masterKeyRotated']));
