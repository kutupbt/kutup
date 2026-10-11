-- Appearance (docs/plans/mail-parity.md, P2), as Proton's Layouts section:
-- the reading pane beside the list or below it (ViewLayout), how tight the
-- list is (Density), and whether the composer opens as a window or
-- maximised (ComposerMode).
ALTER TABLE mail_settings
    ADD COLUMN view_layout   TEXT NOT NULL DEFAULT 'column' CHECK (view_layout IN ('column', 'row')),
    ADD COLUMN density       TEXT NOT NULL DEFAULT 'comfortable' CHECK (density IN ('comfortable', 'compact')),
    ADD COLUMN composer_mode TEXT NOT NULL DEFAULT 'popup' CHECK (composer_mode IN ('popup', 'maximized'));
