-- How the web apps look for an account: theme and language, shared by every
-- app and device (docs/roadmap.md, "Web · theme and language follow the
-- account"). Not secret, so not end-to-end encrypted. A null value means the
-- account never chose; each app then keeps its own (the system theme, the
-- browser's language).
CREATE TABLE user_ui_preferences (
    user_id     UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    theme       TEXT CHECK (theme IN ('light', 'dark', 'system')),
    language    TEXT CHECK (language IN ('en', 'tr')),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
