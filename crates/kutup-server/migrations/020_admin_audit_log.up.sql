-- Admin audit log: who did what to whom, when (v1 production-readiness criterion #5).
--
-- Deliberately NO foreign keys: an audit row must outlive the admin and the target
-- user it references. The payload snapshots the human-readable identities (emails,
-- usernames) at action time so the trail stays meaningful after deletions.
CREATE TABLE admin_audit_log (
    id            BIGSERIAL PRIMARY KEY,
    admin_user_id UUID        NOT NULL,
    action        TEXT        NOT NULL,
    target_user_id UUID,
    payload       JSONB       NOT NULL DEFAULT '{}',
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The activity feed reads newest-first with a before-id cursor.
CREATE INDEX idx_admin_audit_log_id_desc ON admin_audit_log (id DESC);
