ALTER TABLE chat_media_uploads DROP CONSTRAINT chat_media_uploads_suite_check;
ALTER TABLE chat_media_uploads
    ADD CONSTRAINT chat_media_uploads_suite_check CHECK (suite = 1) NOT VALID;
ALTER TABLE chat_media_objects DROP CONSTRAINT chat_media_objects_suite_check;
ALTER TABLE chat_media_objects
    ADD CONSTRAINT chat_media_objects_suite_check CHECK (suite = 1) NOT VALID;
