-- One account's own value of a setting that limits one account, set by
-- administrators on the account's page (docs/plans/settings-registry.md):
-- a whole-number site setting's key (crate::site_settings), or a rate
-- limit's as `rate_limit.<key>` (crate::ratelimit). The server checks the key
-- and the bounds when it is set, and passes over a row whose setting no
-- longer takes one or whose bounds have moved.
CREATE TABLE user_setting_overrides (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key TEXT NOT NULL CHECK (key ~ '^[a-z0-9_.]{1,80}$'),
    value BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, key)
);

INSERT INTO user_setting_overrides (user_id, key, value, updated_at)
    SELECT user_id, 'rate_limit.' || key, value, updated_at FROM user_rate_limit_overrides;
DROP TABLE user_rate_limit_overrides;
