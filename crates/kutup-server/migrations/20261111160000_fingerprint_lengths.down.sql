-- Back to v4 fingerprints only: fails while a 64-character fingerprint is stored.

ALTER TABLE calendars DROP CONSTRAINT calendars_fingerprint_check;
ALTER TABLE calendars ALTER COLUMN fingerprint TYPE character(40);
ALTER TABLE calendars ADD CONSTRAINT calendars_fingerprint_check
    CHECK (fingerprint ~ '^[0-9a-f]{40}$');

ALTER TABLE mail_forwarding_keys DROP CONSTRAINT mail_forwarding_keys_forwarder_fingerprint_check;
ALTER TABLE mail_forwarding_keys DROP CONSTRAINT mail_forwarding_keys_forwardee_fingerprint_check;
ALTER TABLE mail_forwarding_keys ALTER COLUMN forwarder_fingerprint TYPE character(40);
ALTER TABLE mail_forwarding_keys ALTER COLUMN forwardee_fingerprint TYPE character(40);
ALTER TABLE mail_forwarding_keys ADD CONSTRAINT mail_forwarding_keys_forwarder_fingerprint_check
    CHECK (forwarder_fingerprint ~ '^[0-9a-f]{40}$');
ALTER TABLE mail_forwarding_keys ADD CONSTRAINT mail_forwarding_keys_forwardee_fingerprint_check
    CHECK (forwardee_fingerprint ~ '^[0-9a-f]{40}$');

ALTER TABLE mail_group_keys DROP CONSTRAINT mail_group_keys_fingerprint_check;
ALTER TABLE mail_group_keys ALTER COLUMN fingerprint TYPE character(40);
ALTER TABLE mail_group_keys ADD CONSTRAINT mail_group_keys_fingerprint_check
    CHECK (fingerprint ~ '^[0-9a-f]{40}$');

ALTER TABLE mail_address_keys DROP CONSTRAINT mail_address_keys_fingerprint_check;
ALTER TABLE mail_address_keys ALTER COLUMN fingerprint TYPE character(40);
ALTER TABLE mail_address_keys ADD CONSTRAINT mail_address_keys_fingerprint_check
    CHECK (fingerprint ~ '^[0-9a-f]{40}$');
