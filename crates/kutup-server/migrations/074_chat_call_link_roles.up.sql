-- Who may run a meeting while it is on (docs/chat-calls.md, "Hosts").
--
-- The owner proves themselves with the host token. Each time they join, the
-- participant identity they joined under is recorded here as the owner's,
-- so the others can be shown who the host is and a co-host cannot remove
-- them. The owner can make any participant a co-host: that participant,
-- proving who they are with their own SFU token, may then let people in,
-- turn them away and remove participants who are not hosts.
--
-- A role belongs to one stay in the meeting: a participant who leaves and
-- joins again has a new identity and no role.
CREATE TABLE chat_call_link_roles (
    room_id         TEXT NOT NULL REFERENCES chat_call_links(room_id) ON DELETE CASCADE,
    participant_id  TEXT NOT NULL CHECK (participant_id ~ '^[0-9a-f]{32}$'),
    -- 1 owner, 2 co-host
    role            SMALLINT NOT NULL CHECK (role IN (1, 2)),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (room_id, participant_id)
);
