-- Mail filters (docs/plans/mail-filters.md, F2). The server runs them as
-- mail arrives, so their conditions and actions are readable, as Proton's
-- Sieve is; their names are sealed in the browser (kutup-crypto mail_names).

CREATE TABLE mail_filters (
    -- Chosen by the browser, which binds the sealed name to it.
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_sealed TEXT NOT NULL CHECK (length(name_sealed) BETWEEN 1 AND 1000),
    enabled     BOOLEAN NOT NULL DEFAULT true,
    position    INTEGER NOT NULL DEFAULT 0,
    match       TEXT NOT NULL CHECK (match IN ('all', 'any')),
    -- [{"field", "op", "negate", "value"}]; checked by the server on write.
    conditions  JSONB NOT NULL CHECK (jsonb_typeof(conditions) = 'array'),
    -- {"folder", "labels", "markRead", "star"}
    actions     JSONB NOT NULL CHECK (jsonb_typeof(actions) = 'object'),
    -- Made by hand, or by "Always move/label sender's emails".
    source      TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'sender')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_mail_filters_user ON mail_filters (user_id, position) WHERE enabled;

-- "Apply to existing messages": one run at a time per account, in the
-- background, with its progress for the app.
CREATE TABLE mail_filter_runs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filter_ids  UUID[] NOT NULL,
    total       INTEGER NOT NULL DEFAULT 0,
    done        INTEGER NOT NULL DEFAULT 0,
    changed     INTEGER NOT NULL DEFAULT 0,
    failed      BOOLEAN NOT NULL DEFAULT false,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX idx_mail_filter_runs_one ON mail_filter_runs (user_id) WHERE finished_at IS NULL;
