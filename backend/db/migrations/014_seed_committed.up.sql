-- backend/db/migrations/014_seed_committed.up.sql
-- Atomic first-seeder arbitration for collaborative files.
--
-- When two browser tabs of the same file race to open simultaneously
-- (the user-reported bug from 2026-05-06), both tabs would compute
-- headSeq=0 in their hello handshake and both would insert the cold-
-- start initialContent into Yjs. Yjs merges the two concurrent inserts
-- as separate operations, producing duplicated content.
--
-- Fix: serialise the seed step at the database level. Exactly one tab's
-- POST /api/files/:fid/claim-seed flips the column from false to true;
-- subsequent claims observe true and skip seeding (waiting for WS
-- replay to populate their local doc).

ALTER TABLE files ADD COLUMN seed_committed BOOLEAN NOT NULL DEFAULT false;
