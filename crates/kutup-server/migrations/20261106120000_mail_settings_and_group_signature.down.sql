ALTER TABLE mail_groups
    DROP COLUMN signature_sealed;
ALTER TABLE mail_settings
    DROP COLUMN keep_moved_sent,
    DROP COLUMN unread_favicon;
