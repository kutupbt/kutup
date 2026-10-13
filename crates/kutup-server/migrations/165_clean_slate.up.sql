-- The clean slate (the private beta starts again from an empty database and
-- bucket; migration 162 refuses a server with accounts). What only data from
-- before needed goes:
--
-- * file versions stored as S3 object versions of one key (before
--   docs/plans/drive-versions-v2.md): every version is an object of its own;
ALTER TABLE file_versions DROP COLUMN s3_version_id;

-- * public links without the owner's copy of their key: every link has one,
--   so a folder-key rotation re-wraps every link;
ALTER TABLE public_shares ALTER COLUMN owner_link_key_envelope SET NOT NULL;

-- * the sign-in email: an account is its username and Kutup address
--   (docs/plans/account-identity.md); a recovery email gets a table of its own;
ALTER TABLE users DROP COLUMN email;

-- * meeting links without a host token: every link has one, so removing
--   someone turns the waiting room on (docs/chat-calls.md).
ALTER TABLE chat_call_links DROP CONSTRAINT chat_call_links_waiting_room_needs_host;
ALTER TABLE chat_call_links ALTER COLUMN host_token_hash SET NOT NULL;
