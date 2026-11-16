-- Restore drill and alerting (docs/plans/restore-drill-and-alerting.md).
--
-- Deleted blobs wait here before they leave the object store, for at least
-- the site setting storage_deleted_blob_retention_seconds, so a database dump
-- restored from before the delete never names a purged blob. `kind`:
--   object  every stored version of `key` (cancelled by a new write to it)
--   stored  the version `version_id` of `key` where the store deletes by
--           version, else `key` (cancelled by a new write to it)
--   version exactly the version `version_id` of `key`
--   prefix  every object under `key` (prefixes are never reused)
CREATE TABLE storage_pending_deletions (
    id BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('object', 'stored', 'version', 'prefix')),
    key TEXT NOT NULL CHECK (key <> ''),
    version_id TEXT NOT NULL DEFAULT '',
    queued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    UNIQUE (kind, key, version_id)
);
CREATE INDEX storage_pending_deletions_due ON storage_pending_deletions (queued_at, id);
CREATE INDEX storage_pending_deletions_key ON storage_pending_deletions (key);

-- The last successful pass of each background job, for /api/health/ready.
CREATE TABLE job_heartbeats (
    job TEXT PRIMARY KEY,
    last_success_at TIMESTAMPTZ NOT NULL
);

-- The newest finished backup of each kind, written by scripts/backup-*.sh
-- after the upload succeeded, for /api/health/ready.
CREATE TABLE backup_runs (
    kind TEXT PRIMARY KEY CHECK (kind IN ('database', 'mail')),
    name TEXT NOT NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    finished_at TIMESTAMPTZ NOT NULL
);
