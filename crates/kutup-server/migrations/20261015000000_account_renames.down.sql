ALTER TABLE account_security_events
    DROP CONSTRAINT account_security_events_names_check,
    DROP COLUMN new_name,
    DROP COLUMN old_name,
    DROP CONSTRAINT account_security_events_check,
    ADD CONSTRAINT account_security_events_check CHECK (
        kind IN ('adminReset', 'accountReset') OR admin_user_id IS NULL),
    DROP CONSTRAINT account_security_events_kind_check,
    ADD CONSTRAINT account_security_events_kind_check CHECK (kind IN (
        'passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset'));
DELETE FROM opaque_login_states WHERE grant_for = 'rename';
ALTER TABLE opaque_login_states DROP CONSTRAINT opaque_login_states_grant_for_check,
    ADD CONSTRAINT opaque_login_states_grant_for_check CHECK (grant_for IN (
        'pass', 'passwordChange', 'totp', 'adminReset', 'verify'));
DELETE FROM auth_grants WHERE purpose = 'rename';
ALTER TABLE auth_grants DROP CONSTRAINT auth_grants_purpose_check,
    ADD CONSTRAINT auth_grants_purpose_check CHECK (purpose IN (
        'pass', 'passwordChange', 'totp', 'adminReset', 'recovery', 'rotate'));
ALTER TABLE drive_profile_keys DROP COLUMN peer_incarnation_id;
DELETE FROM mail_addresses WHERE state = 'freed';
DROP INDEX mail_addresses_address;
DROP INDEX mail_addresses_live;
ALTER TABLE mail_addresses
    ADD CONSTRAINT mail_addresses_address_key UNIQUE (address),
    DROP COLUMN receive_until,
    DROP COLUMN folded,
    DROP COLUMN state;
DROP TABLE account_renames;
DROP TABLE account_names;
DROP FUNCTION kutup_fold(text);
