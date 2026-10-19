ALTER TABLE mail_addresses DROP COLUMN key_list_owed;
ALTER TABLE mail_messages DROP COLUMN forwarded_from;
ALTER TABLE mail_address_keys
    DROP CONSTRAINT mail_address_keys_forwarding_id_check,
    DROP CONSTRAINT mail_address_keys_forwarding_check,
    DROP COLUMN forwarding_id,
    DROP COLUMN is_forwarding;
DROP TABLE mail_forwarding_keys;
DROP TABLE mail_forwardings;
