-- Calendars (docs/plans/calendar.md, E1): Proton Calendar's model. The
-- server keeps each calendar's key (public, and the secret locked with the
-- calendar's passphrase), the passphrase sealed per member, the sealed name
-- and description, and events as their parts; it reads only the times it
-- derives from an event's signed part.
CREATE TABLE calendars (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- The key's suite: 1 is a v4 OpenPGP key (Curve25519) with v3 key
    -- packets. A post-quantum suite comes with Mail's (rPGP v6 and ML-KEM;
    -- docs/plans/calendar.md), alongside, so no calendar needs a wipe.
    suite SMALLINT NOT NULL DEFAULT 1 CHECK (suite = 1),
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) BETWEEN 1 AND 8192),
    fingerprint CHAR(40) NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{40}$'),
    locked_secret_key BYTEA NOT NULL CHECK (octet_length(locked_secret_key) BETWEEN 1 AND 8192),
    -- The passphrase's data packet and the owner's signature over it.
    passphrase_data_packet BYTEA NOT NULL CHECK (octet_length(passphrase_data_packet) BETWEEN 1 AND 1024),
    passphrase_signature TEXT NOT NULL CHECK (octet_length(passphrase_signature) BETWEEN 1 AND 4096),
    -- The name and description, sealed to the calendar key (D-1).
    metadata_key_packet BYTEA NOT NULL CHECK (octet_length(metadata_key_packet) BETWEEN 1 AND 1024),
    metadata_data_packet BYTEA NOT NULL CHECK (octet_length(metadata_data_packet) BETWEEN 1 AND 4096),
    metadata_signature TEXT NOT NULL CHECK (octet_length(metadata_signature) BETWEEN 1 AND 4096),
    -- What the owner's storage pool is charged for the calendar itself (its
    -- events are charged on their rows).
    bytes BIGINT NOT NULL CHECK (bytes >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (fingerprint)
);
CREATE INDEX calendars_owner ON calendars (owner_id);

-- A member's place in a calendar: the passphrase's key packet to the
-- member's address key, Proton's permission bits, and what the member sets
-- for itself. `revision` counts the member's own writes to its row: the
-- account head's `calendars` scope lists (calendar, revision).
CREATE TABLE calendar_members (
    calendar_id UUID NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    address_id UUID NOT NULL REFERENCES mail_addresses(id) ON DELETE CASCADE,
    permissions INTEGER NOT NULL CHECK (permissions BETWEEN 0 AND 255),
    passphrase_key_packet BYTEA NOT NULL CHECK (octet_length(passphrase_key_packet) BETWEEN 1 AND 1024),
    color CHAR(7) NOT NULL CHECK (color ~ '^#[0-9a-f]{6}$'),
    display BOOLEAN NOT NULL DEFAULT true,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (calendar_id, user_id)
);
CREATE INDEX calendar_members_user ON calendar_members (user_id);

-- An event: its parts as the author sealed them, and the columns the server
-- reads from the shared signed part (never from the request).
CREATE TABLE calendar_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    calendar_id UUID NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
    uid TEXT NOT NULL CHECK (char_length(uid) BETWEEN 1 AND 255),
    author_address_id UUID REFERENCES mail_addresses(id) ON DELETE SET NULL,
    author_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    shared_key_packet BYTEA NOT NULL CHECK (octet_length(shared_key_packet) BETWEEN 1 AND 1024),
    calendar_key_packet BYTEA NOT NULL CHECK (octet_length(calendar_key_packet) BETWEEN 1 AND 1024),
    shared_signed TEXT NOT NULL CHECK (octet_length(shared_signed) BETWEEN 1 AND 65536),
    shared_signed_signature TEXT NOT NULL CHECK (octet_length(shared_signed_signature) BETWEEN 1 AND 4096),
    shared_encrypted BYTEA NOT NULL CHECK (octet_length(shared_encrypted) BETWEEN 1 AND 262144),
    shared_encrypted_signature TEXT NOT NULL CHECK (octet_length(shared_encrypted_signature) BETWEEN 1 AND 4096),
    calendar_signed TEXT NOT NULL CHECK (octet_length(calendar_signed) BETWEEN 1 AND 65536),
    calendar_signed_signature TEXT NOT NULL CHECK (octet_length(calendar_signed_signature) BETWEEN 1 AND 4096),
    calendar_encrypted BYTEA CHECK (octet_length(calendar_encrypted) BETWEEN 1 AND 262144),
    calendar_encrypted_signature TEXT CHECK (octet_length(calendar_encrypted_signature) BETWEEN 1 AND 4096),
    -- Read from the shared signed part.
    start_utc TIMESTAMPTZ NOT NULL,
    end_utc TIMESTAMPTZ NOT NULL,
    start_tz TEXT,
    end_tz TEXT,
    full_day BOOLEAN NOT NULL,
    rrule TEXT,
    recurrence_id TIMESTAMPTZ,
    -- The last instant any occurrence can reach; NULL for an endless rule.
    range_end_utc TIMESTAMPTZ,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    -- Counts the event's stored versions: a change names the one it was
    -- made from (`baseRevision`), so a replay or another device's newer
    -- save is a conflict, never overwritten.
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    bytes BIGINT NOT NULL CHECK (bytes >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (end_utc >= start_utc),
    CHECK ((calendar_encrypted IS NULL) = (calendar_encrypted_signature IS NULL))
);
-- One event (or one occurrence's change) per UID in a calendar.
CREATE UNIQUE INDEX calendar_events_uid
    ON calendar_events (calendar_id, uid, COALESCE(recurrence_id, '-infinity'::timestamptz));
CREATE INDEX calendar_events_window ON calendar_events (calendar_id, start_utc, range_end_utc);
-- For ON DELETE SET NULL when an address or account goes.
CREATE INDEX calendar_events_author_address ON calendar_events (author_address_id);
CREATE INDEX calendar_events_author_user ON calendar_events (author_user_id);
