-- The MLS invite links' rate limits went with them (20261023120000_remove_mls
-- dropped the per-account overrides); their site-wide values stayed behind
-- as rows no limit reads.
DELETE FROM site_settings
 WHERE key IN ('rate_limit.invite_link_account_calls',
               'rate_limit.invite_link_account_requests',
               'rate_limit.invite_link_origin_calls');
