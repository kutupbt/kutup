-- The account app writes the profile too, as source 128: not a chat device
-- (those are 1-127). See docs/plans/unified-profile.md.
ALTER TABLE chat_profiles DROP CONSTRAINT chat_profiles_source_device_id_check;
ALTER TABLE chat_profiles ADD CONSTRAINT chat_profiles_source_device_id_check
    CHECK (source_device_id BETWEEN 1 AND 127 OR source_device_id = 128);
