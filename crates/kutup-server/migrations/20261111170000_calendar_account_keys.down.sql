-- Back to passphrases on address keys: the shares can't be turned back into
-- key packets, so the calendars go (the quota reconciler gives the storage
-- back).
DELETE FROM calendars;

ALTER TABLE calendar_members
    DROP COLUMN passphrase_share,
    ADD COLUMN address_id uuid NOT NULL REFERENCES mail_addresses(id) ON DELETE CASCADE,
    ADD COLUMN passphrase_key_packet bytea NOT NULL
        CHECK (octet_length(passphrase_key_packet) BETWEEN 1 AND 1024);

ALTER TABLE calendars
    DROP COLUMN key_generation,
    ADD COLUMN passphrase_data_packet bytea NOT NULL
        CHECK (octet_length(passphrase_data_packet) BETWEEN 1 AND 1024),
    ADD COLUMN passphrase_signature text NOT NULL
        CHECK (octet_length(passphrase_signature) BETWEEN 1 AND 4096);
