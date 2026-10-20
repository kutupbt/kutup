DROP INDEX mail_addresses_live;
ALTER TABLE mail_addresses DROP COLUMN folded;
ALTER TABLE mail_addresses ADD COLUMN folded text GENERATED ALWAYS AS (
    kutup_fold(split_part(address, '@', 1)) || '@' || lower(split_part(address, '@', 2))
) STORED NOT NULL;
CREATE UNIQUE INDEX mail_addresses_live ON mail_addresses (folded) WHERE state <> 'freed';
ALTER TABLE mail_domains DROP CONSTRAINT mail_domains_catch_all;
ALTER TABLE mail_addresses DROP COLUMN domain_id;
DROP TABLE mail_domain_overrides;
DROP TABLE mail_domains;
