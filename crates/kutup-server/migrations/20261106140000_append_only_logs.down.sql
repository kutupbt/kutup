ALTER TABLE admin_audit_log DROP COLUMN row_hash, DROP COLUMN previous_hash;
ALTER TABLE account_security_events DROP COLUMN count;
ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_kind_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_kind_check CHECK (kind = ANY (ARRAY[
    'passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset', 'rename',
    'nameDropped', 'nameClosed', 'nameFreed', 'domainLost',
    'twoFactorOn', 'twoFactorOff', 'recoveryCodeUsed', 'recoveryCodesRenewed',
    'securityKeyAdded', 'securityKeyRemoved', 'securityKeyCompromised',
    'authenticatorOn', 'authenticatorOff',
    'orgJoined', 'orgLeft', 'orgRemoved', 'orgAccessGranted', 'orgAccessRevoked',
    'orgReset', 'orgSignIn']));
