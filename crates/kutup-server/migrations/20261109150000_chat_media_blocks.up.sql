-- Chat attachments move to the block format (docs/plans/drive-block-format.md
-- §5, slice 6): every new upload and stored object is Chat-media suite 2
-- (KUTPCM2). Rows of suite 1 go with the clean-slate wipe; NOT VALID leaves
-- them be until then while every new row is checked.
ALTER TABLE chat_media_objects DROP CONSTRAINT chat_media_objects_suite_check;
ALTER TABLE chat_media_objects
    ADD CONSTRAINT chat_media_objects_suite_check CHECK (suite = 2) NOT VALID;
ALTER TABLE chat_media_uploads DROP CONSTRAINT chat_media_uploads_suite_check;
ALTER TABLE chat_media_uploads
    ADD CONSTRAINT chat_media_uploads_suite_check CHECK (suite = 2) NOT VALID;
