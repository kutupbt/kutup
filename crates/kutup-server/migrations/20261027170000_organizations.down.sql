-- Back to domains held by an account: each domain goes to its
-- organization's first owner (by join time), and the organization-wide
-- limits back to that owner's per-account ones.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM account_security_events
                WHERE kind IN ('orgJoined', 'orgLeft', 'orgRemoved', 'orgAccessGranted',
                               'orgAccessRevoked', 'orgReset', 'orgSignIn')) THEN
        RAISE EXCEPTION 'organization security events exist: the older CHECK cannot hold them';
    END IF;
END $$;

ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_kind_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_kind_check CHECK (kind = ANY (ARRAY[
    'passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset', 'rename',
    'nameDropped', 'nameClosed', 'nameFreed', 'domainLost',
    'twoFactorOn', 'twoFactorOff', 'recoveryCodeUsed', 'recoveryCodesRenewed',
    'securityKeyAdded', 'securityKeyRemoved', 'securityKeyCompromised',
    'authenticatorOn', 'authenticatorOff']));

CREATE TEMPORARY TABLE owner_of_organization ON COMMIT DROP AS
    SELECT DISTINCT ON (organization_id) organization_id, account_id
      FROM organization_members
     WHERE role = 'owner'
     ORDER BY organization_id, joined_at NULLS LAST, account_id;

ALTER TABLE mail_domains ADD COLUMN user_id uuid REFERENCES users(id) ON DELETE CASCADE;
UPDATE mail_domains d SET user_id = o.account_id
  FROM owner_of_organization o WHERE o.organization_id = d.organization_id;
-- A domain whose organization has no owner left has no account to go to.
DELETE FROM mail_domains WHERE user_id IS NULL;
ALTER TABLE mail_domains ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE mail_domains DROP CONSTRAINT mail_domains_organization_name;
-- Two organizations of one owner can't happen (one per account), so names
-- stay unique per account.
ALTER TABLE mail_domains ADD CONSTRAINT mail_domains_user_id_name_key UNIQUE (user_id, name);

CREATE TABLE mail_domain_overrides (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    max_domains integer CHECK (max_domains BETWEEN 0 AND 100),
    max_addresses integer CHECK (max_addresses BETWEEN 1 AND 1000),
    catch_all boolean
);
INSERT INTO mail_domain_overrides (user_id, max_domains, max_addresses, catch_all)
    SELECT u.user_id,
           (SELECT least(greatest(s.value, 0), 100)::integer FROM organization_setting_overrides s
              JOIN owner_of_organization o ON o.organization_id = s.organization_id
             WHERE o.account_id = u.user_id AND s.key = 'mail_domains.per_organization'),
           (SELECT least(greatest(s.value, 1), 1000)::integer FROM user_setting_overrides s
             WHERE s.user_id = u.user_id AND s.key = 'mail_domains.addresses_per_account'),
           (SELECT s.value <> 0 FROM organization_setting_overrides s
              JOIN owner_of_organization o ON o.organization_id = s.organization_id
             WHERE o.account_id = u.user_id AND s.key = 'mail_domains.catch_all')
      FROM (SELECT account_id AS user_id FROM owner_of_organization
            UNION
            SELECT user_id FROM user_setting_overrides
             WHERE key = 'mail_domains.addresses_per_account') u;
DELETE FROM mail_domain_overrides
 WHERE max_domains IS NULL AND max_addresses IS NULL AND catch_all IS NULL;
DELETE FROM user_setting_overrides WHERE key = 'mail_domains.addresses_per_account';

ALTER TABLE mail_domains DROP COLUMN organization_id;

DROP TABLE organization_setting_overrides;
DROP TABLE organization_access_requests;
DROP TABLE organization_member_escrows;
DROP TABLE organization_key_shares;
DROP TABLE organization_keys;
DROP TABLE organization_members;
DROP TABLE organizations;
