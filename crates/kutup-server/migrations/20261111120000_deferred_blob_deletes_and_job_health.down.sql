-- Blobs still waiting are left in the store (orphans for the orphan sweep).
DROP TABLE backup_runs;
DROP TABLE job_heartbeats;
DROP TABLE storage_pending_deletions;
