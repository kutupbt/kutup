-- Feedback from signed-in people: bugs, feature requests and anything else,
-- sent from the sidebar of any app to this server's administrators
-- (docs/api.md, "Feedback"). An administrator marks it done, dismisses it,
-- or forwards it to the public tracker (GitHub) after reading it, so nothing
-- private reaches a public page by itself. `details` holds only what the form
-- showed before sending (app version, browser, language, screen size).
CREATE TABLE feedback (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('bug', 'feature', 'other')),
    app         TEXT NOT NULL CHECK (char_length(app) <= 32),
    message     TEXT NOT NULL CHECK (char_length(message) BETWEEN 1 AND 5000),
    details     JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolution  TEXT CHECK (resolution IN ('done', 'dismissed', 'forwarded')),
    github_url  TEXT CHECK (github_url IS NULL OR char_length(github_url) <= 512),
    CHECK ((resolved_at IS NULL) = (resolution IS NULL)),
    CHECK (github_url IS NULL OR resolution = 'forwarded')
);

CREATE INDEX feedback_open ON feedback (created_at) WHERE resolved_at IS NULL;
CREATE INDEX feedback_resolved ON feedback (resolved_at DESC) WHERE resolved_at IS NOT NULL;
