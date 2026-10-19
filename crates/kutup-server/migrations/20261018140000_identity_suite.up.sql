-- Post-quantum shares (docs/plans/pq-shares.md). Accounts' Drive keys move
-- from X25519 (identity suite 1) to X-Wing (suite 2) by a one-way upgrade at
-- each account's next sign-in; until then an account is on suite 1, and
-- nothing is shared to it. The binding carries an epoch from suite 2 on.
ALTER TABLE users
    ADD COLUMN identity_suite smallint NOT NULL DEFAULT 1
        CHECK (identity_suite IN (1, 2)),
    ADD COLUMN drive_key_binding_epoch integer NOT NULL DEFAULT 1
        CHECK (drive_key_binding_epoch > 0);

-- X-Wing envelopes are larger: a share is about 1.4 KB (an X-Wing
-- encapsulated key is 1120 bytes), about 1,900 base64 characters.
ALTER TABLE file_shares DROP CONSTRAINT file_shares_share_envelope_check,
    ADD CONSTRAINT file_shares_share_envelope_check CHECK (length(share_envelope) <= 4096);
ALTER TABLE federated_outgoing_file_shares
    DROP CONSTRAINT federated_outgoing_file_shares_share_envelope_check,
    ADD CONSTRAINT federated_outgoing_file_shares_share_envelope_check
        CHECK (length(share_envelope) <= 4096);
ALTER TABLE drive_profile_keys DROP CONSTRAINT drive_profile_keys_envelope_check,
    ADD CONSTRAINT drive_profile_keys_envelope_check CHECK (length(envelope) <= 4096);
ALTER TABLE collection_shares
    ADD CONSTRAINT collection_shares_named_share_envelope_check
        CHECK (length(named_share_envelope) <= 4096);
ALTER TABLE federated_outgoing_shares
    ADD CONSTRAINT federated_outgoing_shares_named_share_envelope_check
        CHECK (length(named_share_envelope) <= 4096);
ALTER TABLE federated_incoming_shares
    ADD CONSTRAINT federated_incoming_shares_named_share_envelope_check
        CHECK (length(named_share_envelope) <= 4096);
-- A signer share is now 1 + 32 + 1120 + 48 bytes.
ALTER TABLE mail_group_signing_shares DROP CONSTRAINT mail_group_signing_shares_share_check,
    ADD CONSTRAINT mail_group_signing_shares_share_check
        CHECK (octet_length(share) >= 1 AND octet_length(share) <= 2048);
