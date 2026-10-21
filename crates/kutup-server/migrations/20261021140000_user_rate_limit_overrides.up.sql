-- One account's own value of a rate limit counted per account, set by
-- administrators on the account's page (docs/plans/admin-rate-limits.md §4).
-- `key` is a registry key (crate::ratelimit); the server checks it and the
-- bounds, and ignores a row whose limit no longer takes overrides.
CREATE TABLE user_rate_limit_overrides (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key TEXT NOT NULL CHECK (key ~ '^[a-z_]{1,64}$'),
    value BIGINT NOT NULL CHECK (value >= 1),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, key)
);
