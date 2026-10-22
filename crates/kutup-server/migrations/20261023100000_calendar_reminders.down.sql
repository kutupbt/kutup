DROP TABLE calendar_push_subscriptions;
DROP TABLE calendar_alarms;
DROP TABLE calendar_user_settings;
ALTER TABLE calendar_members
    DROP COLUMN default_reminders_all_day,
    DROP COLUMN default_reminders_timed;
DROP TABLE calendar_event_reminders;
