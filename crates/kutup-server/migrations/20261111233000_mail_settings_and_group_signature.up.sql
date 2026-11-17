-- Proton's "Show unread count in favicon" (UnreadFavicon, off by default)
-- and "Keep messages in Sent" (ShowMoved: sent mail moved elsewhere still
-- shows in Sent; off by default).
ALTER TABLE mail_settings
    ADD COLUMN unread_favicon boolean DEFAULT false NOT NULL,
    ADD COLUMN keep_moved_sent boolean DEFAULT false NOT NULL;

-- A shared mailbox's signature, for whoever writes as it (Kutup's own:
-- Proton has no shared mailboxes); owners and managers set it, 10 KB at
-- most, as an address's own in mail_identities. Sealed under the group's
-- data key (account_keys.mail_group_data_keys, from
-- 20261109120000_mail_sealed_headers), as an address's signature is under
-- its account's (docs/plans/server-personal-data.md, A2); none: no signature.
ALTER TABLE mail_groups
    ADD COLUMN signature_sealed bytea;
