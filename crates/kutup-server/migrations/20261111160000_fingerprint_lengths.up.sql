-- Format evolution (docs/plans/format-evolution.md, mail key list row): an
-- OpenPGP fingerprint is 20 bytes for a v4 key and 32 for a v6 key, so the
-- columns that hold one take either length in lowercase hex instead of
-- exactly 40 characters. Which lengths a writer may use stays the Rust
-- format's rule (kutup-crypto mail_key); the database only refuses what no
-- version can be.

ALTER TABLE mail_address_keys DROP CONSTRAINT mail_address_keys_fingerprint_check;
ALTER TABLE mail_address_keys ALTER COLUMN fingerprint TYPE text;
ALTER TABLE mail_address_keys ADD CONSTRAINT mail_address_keys_fingerprint_check
    CHECK (fingerprint ~ '^([0-9a-f]{40}|[0-9a-f]{64})$');

ALTER TABLE mail_group_keys DROP CONSTRAINT mail_group_keys_fingerprint_check;
ALTER TABLE mail_group_keys ALTER COLUMN fingerprint TYPE text;
ALTER TABLE mail_group_keys ADD CONSTRAINT mail_group_keys_fingerprint_check
    CHECK (fingerprint ~ '^([0-9a-f]{40}|[0-9a-f]{64})$');

ALTER TABLE mail_forwarding_keys DROP CONSTRAINT mail_forwarding_keys_forwarder_fingerprint_check;
ALTER TABLE mail_forwarding_keys DROP CONSTRAINT mail_forwarding_keys_forwardee_fingerprint_check;
ALTER TABLE mail_forwarding_keys ALTER COLUMN forwarder_fingerprint TYPE text;
ALTER TABLE mail_forwarding_keys ALTER COLUMN forwardee_fingerprint TYPE text;
ALTER TABLE mail_forwarding_keys ADD CONSTRAINT mail_forwarding_keys_forwarder_fingerprint_check
    CHECK (forwarder_fingerprint ~ '^([0-9a-f]{40}|[0-9a-f]{64})$');
ALTER TABLE mail_forwarding_keys ADD CONSTRAINT mail_forwarding_keys_forwardee_fingerprint_check
    CHECK (forwardee_fingerprint ~ '^([0-9a-f]{40}|[0-9a-f]{64})$');

ALTER TABLE calendars DROP CONSTRAINT calendars_fingerprint_check;
ALTER TABLE calendars ALTER COLUMN fingerprint TYPE text;
ALTER TABLE calendars ADD CONSTRAINT calendars_fingerprint_check
    CHECK (fingerprint ~ '^([0-9a-f]{40}|[0-9a-f]{64})$');
