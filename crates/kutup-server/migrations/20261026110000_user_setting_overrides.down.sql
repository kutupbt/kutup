CREATE TABLE user_rate_limit_overrides (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key TEXT NOT NULL CHECK (key ~ '^[a-z_]{1,64}$'),
    value BIGINT NOT NULL CHECK (value >= 1),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, key)
);
INSERT INTO user_rate_limit_overrides (user_id, key, value, updated_at)
    SELECT user_id, substr(key, length('rate_limit.') + 1), value, updated_at
    FROM user_setting_overrides
    WHERE starts_with(key, 'rate_limit.') AND value >= 1;
DROP TABLE user_setting_overrides;
