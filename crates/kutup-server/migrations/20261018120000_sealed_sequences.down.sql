-- Lossy, as a down migration of this change must be: the old schema keeps
-- one answer per sendId, so where a sendId has several (a mismatch, then its
-- corrected resend) only one survives, and the outbox's stored answers go.
-- Origins that resend after a downgrade meet the old head-of-line rules.
ALTER TABLE chat_sealed_federation_outbox DROP COLUMN answer;
-- A recorded mismatch and its delivered resend share a sendId: keep the
-- delivery, which is what the old constraint stood for.
DELETE FROM chat_sealed_federation_inbound i
 WHERE response_status <> 200
   AND EXISTS (SELECT 1 FROM chat_sealed_federation_inbound d
                WHERE d.origin = i.origin AND d.send_id = i.send_id
                  AND d.response_status = 200);
DELETE FROM chat_sealed_federation_inbound i
 WHERE EXISTS (SELECT 1 FROM chat_sealed_federation_inbound o
                WHERE o.origin = i.origin AND o.send_id = i.send_id
                  AND o.sequence < i.sequence);
ALTER TABLE chat_sealed_federation_inbound
    ADD CONSTRAINT chat_sealed_federation_inbound_origin_send_id_key UNIQUE (origin, send_id);
