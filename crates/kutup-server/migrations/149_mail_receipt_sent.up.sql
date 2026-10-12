-- Read receipts (docs/plans/mail-parity.md, P3), Proton's FLAG_RECEIPT_SENT:
-- the reader sent one for this message (sent by the client, RFC 8098).
ALTER TABLE mail_messages ADD COLUMN receipt_sent BOOLEAN NOT NULL DEFAULT false;
