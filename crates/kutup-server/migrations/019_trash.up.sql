-- Trash / soft-delete (30-day retention).
--
-- deleted_at      — when the row was moved to trash (NULL = live).
-- trash_root_id   — the id of the *trash entry* whose deletion trashed this row:
--                   the row's own id when it was deleted directly (it IS a trash entry),
--                   or the root collection's id when it was cascade-trashed with a folder.
--                   Restore/purge operate on a root and everything tagged with it.
ALTER TABLE files
    ADD COLUMN deleted_at    TIMESTAMPTZ,
    ADD COLUMN trash_root_id UUID;
ALTER TABLE collections
    ADD COLUMN deleted_at    TIMESTAMPTZ,
    ADD COLUMN trash_root_id UUID;

-- Live-row queries filter on deleted_at IS NULL; partial indexes keep the trash
-- bookkeeping off the hot path.
CREATE INDEX idx_files_trash_root ON files(trash_root_id) WHERE trash_root_id IS NOT NULL;
CREATE INDEX idx_collections_trash_root ON collections(trash_root_id) WHERE trash_root_id IS NOT NULL;
CREATE INDEX idx_files_deleted_at ON files(deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX idx_collections_deleted_at ON collections(deleted_at) WHERE deleted_at IS NOT NULL;
