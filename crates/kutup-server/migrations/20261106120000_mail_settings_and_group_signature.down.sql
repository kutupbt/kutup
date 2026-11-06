ALTER TABLE mail_groups
    DROP CONSTRAINT mail_groups_signature_check,
    DROP COLUMN signature;
ALTER TABLE mail_settings
    DROP COLUMN keep_moved_sent,
    DROP COLUMN unread_favicon;
