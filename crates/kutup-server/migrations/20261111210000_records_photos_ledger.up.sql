-- W3 slice 6 (docs/plans/account-records.md): the Photos library and the Chat
-- attachment ledger move to the account-records store (scopes 5 and 6).
-- Their private chains, the ledger's history, operations and cursor go; the
-- account head and the records feed replace them. Pre-wipe: no data moves.
DROP TABLE photos_library;
DROP TABLE chat_attachment_ledger_operations;
DROP TABLE chat_attachment_ledger_history;
DROP TABLE chat_attachment_ledger_entities;
DROP SEQUENCE chat_attachment_ledger_cursor_seq;

-- The largest record a scope holds is the Photos library (4 MiB of marks,
-- padded, with its header). Each envelope is still checked against its own
-- purpose's bound when written.
ALTER TABLE account_records DROP CONSTRAINT account_records_envelope_check;
ALTER TABLE account_records ADD CONSTRAINT account_records_envelope_check
    CHECK (octet_length(envelope) BETWEEN 1 AND 4325376);
