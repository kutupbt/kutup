-- Proton's "Show unread count in favicon" (UnreadFavicon, off by default)
-- and "Keep messages in Sent" (ShowMoved: sent mail moved elsewhere still
-- shows in Sent; off by default).
ALTER TABLE mail_settings
    ADD COLUMN unread_favicon boolean DEFAULT false NOT NULL,
    ADD COLUMN keep_moved_sent boolean DEFAULT false NOT NULL;
