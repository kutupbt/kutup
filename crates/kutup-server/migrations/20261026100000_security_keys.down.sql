DELETE FROM account_security_events
    WHERE kind IN ('securityKeyAdded', 'securityKeyRemoved', 'securityKeyCompromised',
                   'authenticatorOn', 'authenticatorOff');
ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_names_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_names_check CHECK (
    (kind = ANY (ARRAY['rename', 'nameDropped', 'nameClosed', 'nameFreed', 'domainLost'])) = (old_name IS NOT NULL)
    AND (kind = 'rename') = (new_name IS NOT NULL));
ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_kind_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_kind_check CHECK (kind = ANY (ARRAY[
    'passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset', 'rename',
    'nameDropped', 'nameClosed', 'nameFreed', 'domainLost',
    'twoFactorOn', 'twoFactorOff', 'recoveryCodeUsed', 'recoveryCodesRenewed']));
DROP TABLE webauthn_ceremonies;
ALTER TABLE users DROP COLUMN security_keys_require_uv;
DROP TABLE user_security_keys;
