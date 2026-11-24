-- Calendar invitations over Mail (docs/plans/calendar-e4.md, as built).
-- The shared-event split, the attendee and invitee tables are in the
-- baseline; this adds what building E4 showed they lack. Nothing wrote
-- these tables before (E4 was not released), so the new NOT NULL column
-- needs no data.
--
-- - An invitee row names the token of the attendee it is: the server lets
--   a Kutup attendee write that one answer row and no other attendee's.
--   It goes with the attendee row.
-- - An attendee's own calendar row (an adopted invitation) is signed by
--   the attendee, its shared parts by the organizer: the row names its own
--   author (none: the shared parts' author, as every other event).
-- - The account's invitation settings (Proton's calendar user settings
--   `InviteLocale` and `AutoImportInvite`): the language invitations and
--   replies are sent in (none: the app's), and whether received
--   invitations go into the calendar at once, marked as pending.
ALTER TABLE calendar_event_invitees ADD COLUMN token bytea NOT NULL;
ALTER TABLE calendar_event_invitees
    ADD CONSTRAINT calendar_event_invitees_token_check CHECK (octet_length(token) = 32);
ALTER TABLE calendar_event_invitees
    ADD CONSTRAINT calendar_event_invitees_attendee_fkey
    FOREIGN KEY (shared_event_id, token)
    REFERENCES calendar_event_attendees (shared_event_id, token) ON DELETE CASCADE;

ALTER TABLE calendar_events ADD COLUMN author_address_id uuid
    REFERENCES mail_addresses (id) ON DELETE SET NULL;

CREATE TABLE calendar_invite_settings (
    account_id uuid PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    invite_locale text CHECK (invite_locale IN ('en', 'tr')),
    auto_add boolean NOT NULL DEFAULT true,
    updated_at timestamp with time zone NOT NULL DEFAULT now()
);
