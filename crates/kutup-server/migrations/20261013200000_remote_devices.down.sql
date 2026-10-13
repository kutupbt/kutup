DROP TABLE collab_revocation_marks;
DROP TABLE remote_revocation_marks;
DROP TABLE remote_revoked_device_keys;
DROP TABLE remote_collab_devices;
ALTER TABLE federated_outgoing_shares
    DROP CONSTRAINT federated_outgoing_shares_recipient_incarnation_check,
    DROP COLUMN recipient_incarnation_id;
