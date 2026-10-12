-- Kutup Pass account settings (docs/plans/pass.md, "Site icons").
--
-- One row per account that changed a default; the same on every device.
-- `site_icons` is whether entries show their website's icon: `kutup`
-- (fetched by the Kutup server, which then sees the domain; the default, as
-- Proton Pass's) or `off`. As Proton, the browser never asks websites
-- itself, so the Pass page loads no outside images.
CREATE TABLE pass_settings (
    user_id    UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    site_icons TEXT        NOT NULL DEFAULT 'kutup'
        CHECK (site_icons IN ('kutup', 'off')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
