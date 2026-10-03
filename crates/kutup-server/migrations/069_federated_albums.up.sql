-- Albums shared with people on other servers (docs/plans/photos.md): the
-- recipient's server keeps what kind of collection an invite is for, so
-- Drive lists shared folders and Photos lists shared albums.
ALTER TABLE federated_incoming_shares
    ADD COLUMN collection_kind TEXT NOT NULL DEFAULT 'folder' CHECK (collection_kind IN ('folder', 'album'));
