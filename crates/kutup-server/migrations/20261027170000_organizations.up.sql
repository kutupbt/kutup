-- Organizations, following Proton (docs/plans/organizations.md, O1). An
-- organization is a permanent random id with members and roles; it holds
-- custom domains, which until now belonged to one account. The key, share,
-- escrow and request tables are here too, so the schema is complete before
-- the wipe; their formats come with O2 and their routes with O4.

CREATE TABLE organizations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- A changeable attribute, shown to members only; never bound into crypto.
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    -- Proton's: 0 disabled, 1 active.
    state smallint NOT NULL DEFAULT 1 CHECK (state IN (0, 1)),
    created_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    CHECK ((state = 0) = (disabled_at IS NOT NULL))
);

CREATE TABLE organization_members (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    account_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    -- MEMBER_STATE: 0 disabled, 1 enabled, 2 invited.
    state smallint NOT NULL CHECK (state IN (0, 1, 2)),
    -- MEMBER_TYPE: made by the organization (Proton's MANAGED), or invited.
    created_by_org boolean NOT NULL DEFAULT false,
    -- MEMBER_PRIVATE: admins hold no escrow of a private member's keys.
    private boolean NOT NULL DEFAULT true,
    -- MEMBER_ORG_KEY_STATE (owners and admins): 0 none, 1 active, 2 missing, 3 pending.
    org_key_state smallint NOT NULL DEFAULT 0 CHECK (org_key_state IN (0, 1, 2, 3)),
    invited_by uuid REFERENCES users(id) ON DELETE SET NULL,
    invited_at timestamptz,
    joined_at timestamptz,
    PRIMARY KEY (organization_id, account_id),
    CHECK ((state = 2) = (invited_at IS NOT NULL AND joined_at IS NULL))
);
-- One organization per account (Proton's screens enforce it), counting a
-- pending invitation's.
CREATE UNIQUE INDEX organization_members_one_per_account
    ON organization_members (account_id) WHERE state IN (1, 2);

-- The organization key: an X-Wing public key, its id a hash of it
-- (kutup/org/key-id/v1), certified by the admin who made it.
CREATE TABLE organization_keys (
    id bytea PRIMARY KEY CHECK (length(id) = 32),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    public_key bytea NOT NULL,
    certificate bytea NOT NULL,
    state text NOT NULL CHECK (state IN ('active', 'retired')),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX organization_keys_one_active
    ON organization_keys (organization_id) WHERE state = 'active';

-- An admin's hold on a key: sealed to them while pending, then their own
-- account envelope once they activated it.
CREATE TABLE organization_key_shares (
    key_id bytea NOT NULL REFERENCES organization_keys(id) ON DELETE CASCADE,
    account_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sealed_share bytea,
    envelope bytea,
    granted_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (key_id, account_id),
    CHECK ((sealed_share IS NULL) <> (envelope IS NULL))
);

-- A managed member's master key, sealed to the organization key, under the
-- master-key generation it belongs to.
CREATE TABLE organization_member_escrows (
    organization_id uuid NOT NULL,
    account_id uuid NOT NULL,
    key_id bytea NOT NULL REFERENCES organization_keys(id) ON DELETE CASCADE,
    mk_generation integer NOT NULL CHECK (mk_generation > 0),
    sealed bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, account_id),
    FOREIGN KEY (organization_id, account_id)
        REFERENCES organization_members (organization_id, account_id) ON DELETE CASCADE
);

-- An admin's signed request that a private member become managed.
CREATE TABLE organization_access_requests (
    organization_id uuid NOT NULL,
    account_id uuid NOT NULL,
    request bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, account_id),
    FOREIGN KEY (organization_id, account_id)
        REFERENCES organization_members (organization_id, account_id) ON DELETE CASCADE
);

-- An administrator's value for one organization over the site's, for the
-- registry settings that limit an organization (as user_setting_overrides
-- for an account's).
CREATE TABLE organization_setting_overrides (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    key text NOT NULL CHECK (key ~ '^[a-z0-9_.]{1,80}$'),
    value bigint NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, key)
);

-- Every account that holds domains today becomes the owner of an
-- organization of one, named after its username.
CREATE TEMPORARY TABLE organization_of_holder ON COMMIT DROP AS
    SELECT h.account_id, gen_random_uuid() AS organization_id
      FROM (SELECT DISTINCT user_id AS account_id FROM mail_domains) h;
-- A holder already in an organization would need its domains moved, not a
-- second organization: that can't happen before this migration (the table
-- is new), so it fails loudly rather than merging silently.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM organization_of_holder h
                 JOIN organization_members m ON m.account_id = h.account_id
                WHERE m.state IN (1, 2)) THEN
        RAISE EXCEPTION 'a domain holder is already in an organization: move its domains by hand';
    END IF;
END $$;
INSERT INTO organizations (id, name)
    SELECT h.organization_id, coalesce(nullif(u.username, ''), 'organization')
      FROM organization_of_holder h JOIN users u ON u.id = h.account_id;
INSERT INTO organization_members (organization_id, account_id, role, state, joined_at)
    SELECT h.organization_id, h.account_id, 'owner', 1, now() FROM organization_of_holder h;

-- Domains belong to the organization.
ALTER TABLE mail_domains ADD COLUMN organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE;
UPDATE mail_domains d SET organization_id = h.organization_id
  FROM organization_of_holder h WHERE h.account_id = d.user_id;
ALTER TABLE mail_domains ALTER COLUMN organization_id SET NOT NULL;

-- The per-account domain limits move: domains and the catch-all to the
-- holder's organization, the account's own address count to the account.
INSERT INTO organization_setting_overrides (organization_id, key, value)
    SELECT h.organization_id, 'mail_domains.per_organization', o.max_domains
      FROM mail_domain_overrides o JOIN organization_of_holder h ON h.account_id = o.user_id
     WHERE o.max_domains IS NOT NULL;
INSERT INTO organization_setting_overrides (organization_id, key, value)
    SELECT h.organization_id, 'mail_domains.catch_all', CASE WHEN o.catch_all THEN 1 ELSE 0 END
      FROM mail_domain_overrides o JOIN organization_of_holder h ON h.account_id = o.user_id
     WHERE o.catch_all IS NOT NULL;
INSERT INTO user_setting_overrides (user_id, key, value)
    SELECT o.user_id, 'mail_domains.addresses_per_account', o.max_addresses
      FROM mail_domain_overrides o WHERE o.max_addresses IS NOT NULL
    ON CONFLICT (user_id, key) DO NOTHING;
DROP TABLE mail_domain_overrides;

ALTER TABLE mail_domains DROP CONSTRAINT mail_domains_user_id_name_key;
ALTER TABLE mail_domains DROP COLUMN user_id;
ALTER TABLE mail_domains ADD CONSTRAINT mail_domains_organization_name UNIQUE (organization_id, name);

-- What happens to a member is a security event they see.
ALTER TABLE account_security_events DROP CONSTRAINT account_security_events_kind_check;
ALTER TABLE account_security_events ADD CONSTRAINT account_security_events_kind_check CHECK (kind = ANY (ARRAY[
    'passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset', 'rename',
    'nameDropped', 'nameClosed', 'nameFreed', 'domainLost',
    'twoFactorOn', 'twoFactorOff', 'recoveryCodeUsed', 'recoveryCodesRenewed',
    'securityKeyAdded', 'securityKeyRemoved', 'securityKeyCompromised',
    'authenticatorOn', 'authenticatorOff',
    'orgJoined', 'orgLeft', 'orgRemoved', 'orgAccessGranted', 'orgAccessRevoked',
    'orgReset', 'orgSignIn']));
