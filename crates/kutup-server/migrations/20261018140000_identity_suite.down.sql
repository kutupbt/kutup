ALTER TABLE mail_group_signing_shares DROP CONSTRAINT mail_group_signing_shares_share_check,
    ADD CONSTRAINT mail_group_signing_shares_share_check
        CHECK (octet_length(share) >= 1 AND octet_length(share) <= 1024);
ALTER TABLE federated_incoming_shares
    DROP CONSTRAINT federated_incoming_shares_named_share_envelope_check;
ALTER TABLE federated_outgoing_shares
    DROP CONSTRAINT federated_outgoing_shares_named_share_envelope_check;
ALTER TABLE collection_shares DROP CONSTRAINT collection_shares_named_share_envelope_check;
ALTER TABLE drive_profile_keys DROP CONSTRAINT drive_profile_keys_envelope_check,
    ADD CONSTRAINT drive_profile_keys_envelope_check CHECK (length(envelope) <= 2048);
ALTER TABLE federated_outgoing_file_shares
    DROP CONSTRAINT federated_outgoing_file_shares_share_envelope_check,
    ADD CONSTRAINT federated_outgoing_file_shares_share_envelope_check
        CHECK (length(share_envelope) <= 2048);
ALTER TABLE file_shares DROP CONSTRAINT file_shares_share_envelope_check,
    ADD CONSTRAINT file_shares_share_envelope_check CHECK (length(share_envelope) <= 2048);
ALTER TABLE users DROP COLUMN drive_key_binding_epoch, DROP COLUMN identity_suite;
