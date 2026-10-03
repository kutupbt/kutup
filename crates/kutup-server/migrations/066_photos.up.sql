-- The Photos app on photos. (docs/plans/photos.md) is a sixth web app: its
-- sessions are forked from the account app like the others', and the native
-- Photos apps reserve their client types.
ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_client_type_check;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_client_type_check CHECK (client_type IN (
    'web-account', 'web-drive', 'web-chat', 'web-maps', 'web-photos', 'cli',
    'android-drive', 'android-chat', 'android-maps', 'android-photos',
    'ios-drive', 'ios-chat', 'ios-maps', 'ios-photos'));
ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_check;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_check
    CHECK (parent_session_id IS NULL OR client_type IN ('web-drive', 'web-chat', 'web-maps', 'web-photos'));
ALTER TABLE auth_session_forks DROP CONSTRAINT auth_session_forks_child_client_type_check;
ALTER TABLE auth_session_forks ADD CONSTRAINT auth_session_forks_child_client_type_check
    CHECK (child_client_type IN ('web-drive', 'web-chat', 'web-maps', 'web-photos'));

-- Which folders make up a person's photo library, and where uploads go.
-- Folder ids only: the server already knows the folders; it learns which
-- ones Photos shows. A folder that goes away drops out of the library.
CREATE TABLE photos_preferences (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    upload_folder_id UUID REFERENCES collections(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE photos_library_folders (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    collection_id UUID NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, collection_id)
);
