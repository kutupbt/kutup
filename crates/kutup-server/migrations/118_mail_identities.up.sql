-- An address's display name and signature (docs/plans/mail-parity.md, P2),
-- as Proton's Identity settings: readable on the server, as there.
CREATE TABLE mail_identities (
    address_id   UUID PRIMARY KEY REFERENCES mail_addresses(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL DEFAULT '' CHECK (length(display_name) <= 100),
    -- HTML from the signature editor; sanitised again in every browser.
    signature    TEXT NOT NULL DEFAULT '' CHECK (length(signature) <= 10000),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
