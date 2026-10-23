-- The Calendar app at calendar.<domain> (docs/plans/calendar.md, E1): its
-- sessions are forked from the account app like every other web app's.
ALTER TABLE auth_session_forks DROP CONSTRAINT auth_session_forks_child_client_type_check;
ALTER TABLE auth_session_forks ADD CONSTRAINT auth_session_forks_child_client_type_check
    CHECK (child_client_type IN ('web-drive', 'web-chat', 'web-maps', 'web-photos', 'web-office', 'web-contacts', 'web-mail', 'web-pass', 'web-calendar'));
ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_check;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_check
    CHECK (parent_session_id IS NULL OR client_type IN ('web-drive', 'web-chat', 'web-maps', 'web-photos', 'web-office', 'web-contacts', 'web-mail', 'web-pass', 'web-calendar'));
ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_client_type_check;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_client_type_check
    CHECK (client_type IN ('web-account', 'web-drive', 'web-chat', 'web-maps', 'web-photos', 'web-office', 'web-contacts', 'web-mail', 'web-pass', 'web-calendar', 'cli', 'android-drive', 'android-chat', 'android-maps', 'android-photos', 'ios-drive', 'ios-chat', 'ios-maps', 'ios-photos'));
