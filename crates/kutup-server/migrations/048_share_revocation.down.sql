ALTER TABLE public_shares DROP COLUMN owner_link_key_envelope;
ALTER TABLE file_thumbnails DROP COLUMN key_epoch;
ALTER TABLE file_assets DROP COLUMN key_epoch;
ALTER TABLE file_versions DROP COLUMN key_epoch;
ALTER TABLE files DROP CONSTRAINT files_original_key_epoch, DROP COLUMN original_key_epoch;
DROP TABLE file_key_history;
ALTER TABLE collection_key_epoch_history
    DROP CONSTRAINT collection_key_epoch_history_previous_key,
    DROP COLUMN previous_key_envelope;
