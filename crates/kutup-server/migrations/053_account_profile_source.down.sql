DELETE FROM chat_profiles WHERE source_device_id = 128;
ALTER TABLE chat_profiles DROP CONSTRAINT chat_profiles_source_device_id_check;
ALTER TABLE chat_profiles ADD CONSTRAINT chat_profiles_source_device_id_check
    CHECK (source_device_id BETWEEN 1 AND 127);
