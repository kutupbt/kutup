-- Direct Chat suite selection must always be explicit and use a code point the
-- deployed server understands. Defaults would turn an omitted/unknown choice
-- into suite 1 and create a downgrade path.

ALTER TABLE chat_devices
    ALTER COLUMN suite DROP DEFAULT,
    ADD CONSTRAINT chat_devices_suite_known CHECK (suite IN (1));

ALTER TABLE chat_mailbox
    ALTER COLUMN suite DROP DEFAULT,
    ADD CONSTRAINT chat_mailbox_suite_known CHECK (suite IN (1));
