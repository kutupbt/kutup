-- Kutup Pass account settings (docs/plans/pass.md, "Site icons").
--
-- One row per account that changed a default; the same on every device.
-- `site_icons` is how entries show their website's icon: `kutup` (fetched by
-- the Kutup server, which then sees the domain; the default, as Proton
-- Pass's), `direct` (the browser asks the website itself) or `off`.
CREATE TABLE pass_settings (
    user_id    UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    site_icons TEXT        NOT NULL DEFAULT 'kutup'
        CHECK (site_icons IN ('kutup', 'direct', 'off')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
