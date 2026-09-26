-- Each person's map choices (docs/plans/maps.md): maps stay off until they
-- turn them on, and they choose among the providers the administrator
-- offers. The administrator's side is the `maps` row in site_settings.
CREATE TABLE user_map_preferences (
    user_id     UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    enabled     BOOLEAN NOT NULL DEFAULT false,
    provider    TEXT CHECK (provider IN ('openfreemap', 'openstreetmap', 'custom')),
    via_proxy   BOOLEAN NOT NULL DEFAULT true,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
