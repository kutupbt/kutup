-- Image settings (docs/plans/mail-parity.md, P5): Proton's "Auto show
-- embedded images" (a message's own images, shown at once unless turned
-- off) and the account-wide "Remove image metadata" (where the insert
-- question starts; on by default in Kutup, off in Proton).
ALTER TABLE mail_settings ADD COLUMN embedded_images BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE mail_settings ADD COLUMN remove_image_metadata BOOLEAN NOT NULL DEFAULT true;
