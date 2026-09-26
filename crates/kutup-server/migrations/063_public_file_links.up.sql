-- A public link to one file (docs/plans/drive-file-sharing.md, slice 3). For
-- share_type 'file', target_id is the file, collection_key_envelope holds the
-- file's key sealed under the link key (Drive envelope purpose 11), and
-- collection_key_epoch the file key generation it wraps.
ALTER TABLE public_shares DROP CONSTRAINT public_shares_share_type_check;
ALTER TABLE public_shares ADD CONSTRAINT public_shares_share_type_check
    CHECK (share_type IN ('collection', 'file'));
CREATE INDEX public_shares_file_target_idx ON public_shares (target_id) WHERE share_type = 'file';
