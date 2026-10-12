-- Attachments in the list (docs/plans/mail-parity.md, P3), Proton's
-- AttachmentsMetadata: each file's name, type and size, readable metadata as
-- the subject is (Proton's uploads name them in the clear too).
ALTER TABLE mail_messages ADD COLUMN attachments JSONB NOT NULL DEFAULT '[]'::jsonb;
