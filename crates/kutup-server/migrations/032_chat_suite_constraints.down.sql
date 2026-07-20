ALTER TABLE chat_mailbox
    DROP CONSTRAINT IF EXISTS chat_mailbox_suite_known,
    ALTER COLUMN suite SET DEFAULT 1;

ALTER TABLE chat_devices
    DROP CONSTRAINT IF EXISTS chat_devices_suite_known,
    ALTER COLUMN suite SET DEFAULT 1;
