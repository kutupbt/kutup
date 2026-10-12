-- Remote images (docs/plans/mail-parity.md, P5): Proton's "Auto show remote
-- images" for every sender (`ask` until loaded, or `always`), and senders
-- whose images always load, chosen when loading them (Kutup's own; Proton
-- asks each time). Readable, as the block and allow lists are.
ALTER TABLE mail_settings ADD COLUMN remote_images TEXT NOT NULL DEFAULT 'ask'
    CHECK (remote_images IN ('ask', 'always'));

CREATE TABLE mail_image_senders (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- A lowercase address.
    address    TEXT NOT NULL CHECK (length(address) BETWEEN 3 AND 320 AND address = lower(address)),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, address)
);
