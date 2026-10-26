DELETE FROM account_security_events
    WHERE kind IN ('twoFactorOn', 'twoFactorOff', 'recoveryCodeUsed', 'recoveryCodesRenewed');
ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_check CHECK (
    kind = ANY (ARRAY['adminReset', 'accountReset', 'nameClosed', 'nameFreed'])
    OR admin_user_id IS NULL);
ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_kind_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_kind_check CHECK (kind = ANY (ARRAY[
    'passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset', 'rename',
    'nameDropped', 'nameClosed', 'nameFreed', 'domainLost']));
DELETE FROM server_generated_keys WHERE purpose = 'two-factor-recovery-codes';
ALTER TABLE server_generated_keys
    DROP CONSTRAINT server_generated_keys_purpose_check,
    ADD CONSTRAINT server_generated_keys_purpose_check
        CHECK (purpose = ANY (ARRAY['federation-identity', 'fake-accounts', 'registration-codes']));
DROP TABLE IF EXISTS two_factor_recovery_codes;
