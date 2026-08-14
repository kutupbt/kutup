DROP TRIGGER IF EXISTS chat_mls_incarnation_recoveries_append_only
    ON chat_mls_incarnation_recoveries;
DROP TABLE IF EXISTS chat_mls_recovery_outbox;
DROP TABLE IF EXISTS chat_mls_incarnation_recoveries;
