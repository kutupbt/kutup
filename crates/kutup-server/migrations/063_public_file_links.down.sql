DROP INDEX IF EXISTS public_shares_file_target_idx;
DELETE FROM public_shares WHERE share_type = 'file';
ALTER TABLE public_shares DROP CONSTRAINT public_shares_share_type_check;
ALTER TABLE public_shares ADD CONSTRAINT public_shares_share_type_check CHECK (share_type = 'collection');
