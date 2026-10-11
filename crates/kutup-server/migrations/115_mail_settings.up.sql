-- Mail settings (docs/plans/mail-parity.md, P1), as Proton's: auto-delete of
-- Trash and Spam after 30 days (off by default, AutoDeleteSpamAndTrashDays)
-- and whether All mail leaves out Spam and Trash (AlmostAllMail, off).

CREATE TABLE mail_settings (
    user_id          UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    auto_delete_days INTEGER NOT NULL DEFAULT 0 CHECK (auto_delete_days IN (0, 30)),
    almost_all_mail  BOOLEAN NOT NULL DEFAULT false,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- When a message came into the folder it is in: auto-delete counts from
-- it. Mail already in Trash or Spam counts from now, as Proton's "a deletion
-- date based on the date they were moved there" cannot be known for it.
ALTER TABLE mail_messages ADD COLUMN folder_changed_at TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE FUNCTION mail_messages_folder_changed() RETURNS trigger AS $$
BEGIN
    IF NEW.folder IS DISTINCT FROM OLD.folder THEN
        NEW.folder_changed_at := now();
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;
CREATE TRIGGER mail_messages_folder_changed BEFORE UPDATE OF folder ON mail_messages
    FOR EACH ROW EXECUTE FUNCTION mail_messages_folder_changed();
CREATE INDEX idx_mail_messages_unwanted ON mail_messages (owner, folder_changed_at)
    WHERE folder IN ('trash', 'spam');
