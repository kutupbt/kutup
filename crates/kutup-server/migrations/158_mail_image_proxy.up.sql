-- Image proxy (docs/plans/mail-parity.md, P5): Proton's "Protect against
-- email tracking". On by default: remote images load through the Kutup
-- server (it fetches them when the reader loads them and keeps nothing),
-- known tracking pixels never load, and tracking parameters leave links.
ALTER TABLE mail_settings ADD COLUMN image_proxy BOOLEAN NOT NULL DEFAULT true;
