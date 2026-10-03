DELETE FROM auth_session_forks WHERE child_client_type = 'web-maps';
DELETE FROM auth_sessions WHERE client_type IN ('web-maps', 'android-maps', 'ios-maps');
ALTER TABLE auth_session_forks DROP CONSTRAINT auth_session_forks_child_client_type_check;
ALTER TABLE auth_session_forks ADD CONSTRAINT auth_session_forks_child_client_type_check
    CHECK (child_client_type IN ('web-drive', 'web-chat'));
ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_check;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_check
    CHECK (parent_session_id IS NULL OR client_type IN ('web-drive', 'web-chat'));
ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_client_type_check;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_client_type_check CHECK (client_type IN (
    'web-account', 'web-drive', 'web-chat', 'cli',
    'android-drive', 'android-chat', 'ios-drive', 'ios-chat'));
