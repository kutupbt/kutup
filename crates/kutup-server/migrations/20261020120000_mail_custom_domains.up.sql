-- Custom mail domains (docs/plans/mail-custom-domains.md). A domain belongs
-- to an account's permanent id; its states are Proton's numbers (WebClients
-- Domain.ts), so the web UI shows Proton's badges one to one.
CREATE TABLE mail_domains (
    -- Permanent: its base32 is the domain's DKIM target label.
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Lowercase, IDNA A-labels, no trailing dot.
    name text NOT NULL CHECK (name = lower(name) AND length(name) BETWEEN 1 AND 253),
    -- kutup-verification=<26 base32>, kept when the same account adds the
    -- name again.
    verify_code text NOT NULL CHECK (verify_code ~ '^kutup-verification=[a-z2-7]{26}$'),
    -- DOMAIN_STATE: 0 not (or no longer) verified, 1 verified, 2 warn.
    state smallint NOT NULL DEFAULT 0 CHECK (state IN (0, 1, 2)),
    verify_state smallint NOT NULL DEFAULT 0,
    mx_state smallint NOT NULL DEFAULT 0,
    spf_state smallint NOT NULL DEFAULT 0,
    dkim_state smallint NOT NULL DEFAULT 0,
    dmarc_state smallint NOT NULL DEFAULT 0,
    -- DKIM was GOOD once: a broken record is then a WARNING, and Stalwart
    -- signs for the domain.
    dkim_good_once boolean NOT NULL DEFAULT false,
    dkim_warning_since timestamptz,
    -- In "admins approve" mode, when an administrator approved it.
    approved_at timestamptz,
    -- Removed by its owner: kept for the code and the addresses' history.
    removed_at timestamptz,
    catch_all_address_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    checked_at timestamptz,
    verified_at timestamptz,
    failing_since timestamptz,
    warned_at timestamptz,
    stopped_at timestamptz,
    UNIQUE (user_id, name)
);
-- One holder of a name at a time.
CREATE UNIQUE INDEX mail_domains_held ON mail_domains (name) WHERE state IN (1, 2);
CREATE INDEX mail_domains_checked ON mail_domains (checked_at) WHERE removed_at IS NULL;

-- Which domain an address is on; null is the server's own domain.
ALTER TABLE mail_addresses ADD COLUMN domain_id uuid REFERENCES mail_domains(id);
ALTER TABLE mail_domains
    ADD CONSTRAINT mail_domains_catch_all
    FOREIGN KEY (catch_all_address_id) REFERENCES mail_addresses(id) ON DELETE SET NULL;

-- Folding (. _ -) is for the server's own names only: an address on a
-- custom domain is compared lowercased, as Proton compares them.
DROP INDEX mail_addresses_live;
ALTER TABLE mail_addresses DROP COLUMN folded;
ALTER TABLE mail_addresses ADD COLUMN folded text GENERATED ALWAYS AS (
    CASE WHEN domain_id IS NULL
        THEN kutup_fold(split_part(address, '@', 1)) || '@' || lower(split_part(address, '@', 2))
        ELSE lower(address)
    END
) STORED NOT NULL;
CREATE UNIQUE INDEX mail_addresses_live ON mail_addresses (folded) WHERE state <> 'freed';
