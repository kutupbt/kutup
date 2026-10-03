-- Resumable uploads are stored as equal-sized multipart parts whatever sizes
-- the client sends (some S3 stores, Cloudflare R2 among them, refuse parts
-- of different lengths). The bytes received but not yet part of a full part
-- wait here, in the same transaction as received_bytes and the part list.
ALTER TABLE uploads ADD COLUMN pending_bytes BYTEA NOT NULL DEFAULT ''::bytea;
ALTER TABLE chat_media_uploads ADD COLUMN pending_bytes BYTEA NOT NULL DEFAULT ''::bytea;
