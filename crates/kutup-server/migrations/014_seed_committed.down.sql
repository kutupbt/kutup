-- backend/db/migrations/014_seed_committed.down.sql
ALTER TABLE files DROP COLUMN IF EXISTS seed_committed;
