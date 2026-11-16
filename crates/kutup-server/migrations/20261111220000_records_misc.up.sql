-- W3 slice 7 (docs/plans/account-records.md): contact groups, the
-- account's own calendar settings and its joined meetings move onto the
-- account-records store (scopes contactGroups, calendarSettings and
-- joinedMeetings), sealed under the master key and covered by the head. No
-- data moves: kutup.dev is wiped with this release.
--
-- Contact groups: the plaintext name and colour go. A contact's signed
-- summary names its groups by record id, which the server checks against
-- the account's records; the membership index served only the old group
-- list's counts, which the apps now count themselves.
DROP TABLE contact_group_members;
DROP TABLE contact_groups;

-- A member's colour, display flag and the row revision the old head scope
-- `calendars` listed. The member row keeps what the server needs: the
-- permissions, the passphrase share, and the default reminders it fires
-- alarms from.
ALTER TABLE calendar_members
    DROP COLUMN color,
    DROP COLUMN display,
    DROP COLUMN revision;

-- Joined meetings: the same records (purpose JoinedMeeting), now in the
-- store, their cap the scope's site setting.
DROP TABLE chat_joined_meetings;
