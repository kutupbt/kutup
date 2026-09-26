-- Where lists made in the Maps app go (docs/plans/maps.md, step 4): one of
-- the person's own folders; null means My files. A folder deleted for good
-- clears it; one in the trash is ignored by the app (new maps go to My
-- files and the setting says so).
ALTER TABLE user_map_preferences
    ADD COLUMN save_folder_id UUID REFERENCES collections(id) ON DELETE SET NULL;
