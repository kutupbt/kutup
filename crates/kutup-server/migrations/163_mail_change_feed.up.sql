-- Body search's change feed (docs/plans/mail-body-search.md), as Proton's
-- event loop keeps its local search current: the browser keeps each indexed
-- message's list row in its index and filters there, so it must learn of
-- every move, flag, label and deletion.
--
-- Each change of a message records the transaction that made it
-- (`change_xid`); deletions leave a tombstone. The feed answers the changes
-- made by transactions that have all finished (below the snapshot's xmin),
-- so a change committed late is never skipped. Tombstones are kept 30 days;
-- an index older than that builds again (`mail_change_floors`).
ALTER TABLE mail_messages ADD COLUMN change_xid BIGINT NOT NULL DEFAULT 0;
CREATE INDEX idx_mail_messages_changes ON mail_messages(owner, change_xid, id);

CREATE FUNCTION mail_messages_mark_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.change_xid := pg_current_xact_id()::text::bigint;
    RETURN NEW;
END
$$;

CREATE TRIGGER mail_messages_inserted BEFORE INSERT ON mail_messages
    FOR EACH ROW EXECUTE FUNCTION mail_messages_mark_change();
-- Every update counts (a WHEN clause cannot read the generated columns);
-- one that changed nothing only sends the same row again.
CREATE TRIGGER mail_messages_updated BEFORE UPDATE ON mail_messages
    FOR EACH ROW EXECUTE FUNCTION mail_messages_mark_change();

CREATE TABLE mail_message_tombstones (
    owner       UUID NOT NULL,
    id          UUID NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    change_xid  BIGINT NOT NULL,
    deleted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (owner, change_xid, id)
);
CREATE INDEX idx_mail_message_tombstones_age ON mail_message_tombstones(deleted_at);

-- Per mailbox: tombstones up to this transaction were forgotten.
CREATE TABLE mail_change_floors (
    owner     UUID PRIMARY KEY,
    floor_xid BIGINT NOT NULL
);

-- Body search indexes only an account's own mail (owner = user_id).
CREATE FUNCTION mail_messages_tombstone() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.owner = OLD.user_id THEN
        INSERT INTO mail_message_tombstones (owner, id, received_at, change_xid)
        VALUES (OLD.owner, OLD.id, OLD.received_at, pg_current_xact_id()::text::bigint)
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER mail_messages_deleted AFTER DELETE ON mail_messages
    FOR EACH ROW EXECUTE FUNCTION mail_messages_tombstone();

-- A label put on or taken off changes the message's row (the update
-- trigger records the transaction).
CREATE FUNCTION mail_message_labels_mark_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE mail_messages SET change_xid = -1
     WHERE id = CASE WHEN TG_OP = 'DELETE' THEN OLD.message_id ELSE NEW.message_id END;
    RETURN NULL;
END
$$;

CREATE TRIGGER mail_message_labels_changed AFTER INSERT OR DELETE ON mail_message_labels
    FOR EACH ROW EXECUTE FUNCTION mail_message_labels_mark_change();
