DROP TABLE account_keys.destruction_events;
DELETE FROM auth_grants WHERE purpose IN ('close', 'keep');
ALTER TABLE auth_grants DROP CONSTRAINT auth_grants_check1;
ALTER TABLE auth_grants ADD CONSTRAINT auth_grants_check1
    CHECK ((purpose = 'recovery') = (session_id IS NULL));
ALTER TABLE auth_grants DROP CONSTRAINT auth_grants_purpose_check;
ALTER TABLE auth_grants ADD CONSTRAINT auth_grants_purpose_check CHECK (purpose = ANY (ARRAY[
    'pass', 'passwordChange', 'totp', 'adminReset', 'recovery', 'rotate', 'rename']));
DELETE FROM account_security_events WHERE kind IN ('accountClosing', 'accountKept');
ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_check CHECK (
    kind = ANY (ARRAY['adminReset', 'accountReset', 'nameClosed', 'nameFreed', 'twoFactorOff'])
    OR admin_user_id IS NULL);
DELETE FROM opaque_login_states WHERE grant_for = 'close';
ALTER TABLE opaque_login_states DROP CONSTRAINT opaque_login_states_grant_for_check;
ALTER TABLE opaque_login_states ADD CONSTRAINT opaque_login_states_grant_for_check
    CHECK (grant_for = ANY (ARRAY['pass', 'passwordChange', 'totp', 'adminReset', 'verify',
        'rename']));
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
    'sessionRevoked', 'allSessionsRevoked', 'adminAccess']));
DROP FUNCTION kutup_account_held(uuid);
DROP INDEX users_closing_due;
ALTER TABLE users DROP COLUMN is_active;
ALTER TABLE users ADD COLUMN is_active boolean NOT NULL DEFAULT true;
UPDATE users SET is_active = (state = 'active');
ALTER TABLE users
    DROP COLUMN state, DROP COLUMN suspended_reason, DROP COLUMN state_changed_at,
    DROP COLUMN closing_by, DROP COLUMN closes_at, DROP COLUMN purpose_ended_at,
    DROP COLUMN legal_hold_reference, DROP COLUMN legal_hold_at, DROP COLUMN legal_hold_by,
    DROP COLUMN suspended_before_close, DROP COLUMN deleting_at, DROP COLUMN deleting_for, DROP COLUMN deletion_attempts,
    DROP COLUMN deletion_next_try_at;
