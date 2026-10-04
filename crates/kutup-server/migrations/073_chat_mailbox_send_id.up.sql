-- The sender's logical send id travels with each delivered envelope, so a
-- device that cannot decrypt one can ask its sender for exactly that message
-- again (docs/chat-protocol.md, "Unreadable messages and session repair").
-- The server already holds it for send idempotency; rows stored before this
-- column have none.
ALTER TABLE chat_mailbox ADD COLUMN send_id TEXT;
