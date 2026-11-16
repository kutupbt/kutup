-- Rows only this migration's values allow go first, or the narrower checks
-- below would refuse the table.
DELETE FROM account_security_events WHERE kind = 'masterKeyRotated';
DELETE FROM opaque_login_states WHERE grant_for = 'masterKeyRotation';
DELETE FROM auth_grants WHERE purpose = 'masterKeyRotation';

ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_kind_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_kind_check CHECK (kind = ANY (ARRAY[
    'passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset', 'rename',
    'nameDropped', 'nameClosed', 'nameFreed', 'domainLost',
    'twoFactorOn', 'twoFactorOff', 'recoveryCodeUsed', 'recoveryCodesRenewed',
    'securityKeyAdded', 'securityKeyRemoved', 'securityKeyCompromised',
    'authenticatorOn', 'authenticatorOff']));

ALTER TABLE opaque_login_states DROP CONSTRAINT opaque_login_states_grant_for_check;
ALTER TABLE opaque_login_states ADD CONSTRAINT opaque_login_states_grant_for_check CHECK (grant_for = ANY (ARRAY[
    'pass', 'passwordChange', 'totp', 'adminReset', 'verify', 'rename']));

ALTER TABLE auth_grants DROP CONSTRAINT auth_grants_purpose_check;
ALTER TABLE auth_grants ADD CONSTRAINT auth_grants_purpose_check CHECK (purpose = ANY (ARRAY[
    'pass', 'passwordChange', 'totp', 'adminReset', 'recovery', 'rotate', 'rename']));

DELETE FROM account_roots WHERE purpose = 27;
ALTER TABLE account_roots DROP CONSTRAINT account_roots_purpose_check;
ALTER TABLE account_roots ADD CONSTRAINT account_roots_purpose_check
    CHECK (purpose BETWEEN 22 AND 26);

ALTER TABLE users DROP COLUMN master_key_generation;
