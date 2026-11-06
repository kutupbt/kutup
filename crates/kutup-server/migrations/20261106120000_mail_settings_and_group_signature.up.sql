-- Proton's "Show unread count in favicon" (UnreadFavicon, off by default)
-- and "Keep messages in Sent" (ShowMoved: sent mail moved elsewhere still
-- shows in Sent; off by default).
ALTER TABLE mail_settings
    ADD COLUMN unread_favicon boolean DEFAULT false NOT NULL,
    ADD COLUMN keep_moved_sent boolean DEFAULT false NOT NULL;

-- A shared mailbox's signature, for whoever writes as it (Kutup's own:
-- Proton has no shared mailboxes); owners and managers set it, as an
-- address's own in mail_identities (10 KB at most).
ALTER TABLE mail_groups
    ADD COLUMN signature text DEFAULT '' NOT NULL,
    ADD CONSTRAINT mail_groups_signature_check CHECK (length(signature) <= 10000);
