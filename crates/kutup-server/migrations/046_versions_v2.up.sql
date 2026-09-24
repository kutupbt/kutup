-- Drive versions v2 (docs/plans/drive-versions-v2.md).

-- What a version holds: the whole file (office documents, whiteboards,
-- restored copies — the same sealed format as an upload, so downloads can
-- serve it) or a note's Yjs state. Older rows are unknown; 'yjs' is the safe
-- reading (never served as the file, never used to retire the original).
ALTER TABLE file_versions
  ADD COLUMN kind TEXT NOT NULL DEFAULT 'yjs' CHECK (kind IN ('file', 'yjs'));
ALTER TABLE file_versions ALTER COLUMN kind DROP DEFAULT;

-- How long versions are kept (the file owner's setting), thinned by age.
ALTER TABLE users
  ADD COLUMN version_retention_days INT NOT NULL DEFAULT 30
  CHECK (version_retention_days IN (7, 30, 90, 180, 365, 3650));

-- The original upload was superseded by a newer whole-file version and has
-- aged out of retention: its blob is gone and its bytes released.
ALTER TABLE files ADD COLUMN original_pruned BOOLEAN NOT NULL DEFAULT false;

-- Federated reads serve a file's current content with its ciphertext digest;
-- when that is a version, its digest is cached here (as files.ciphertext_sha256).
ALTER TABLE file_versions ADD COLUMN ciphertext_sha256 TEXT;
