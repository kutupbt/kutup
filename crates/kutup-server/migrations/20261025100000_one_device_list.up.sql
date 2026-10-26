-- One device list per account (docs/plans/one-device-list.md, wipe W5,
-- slice 1): the account manifest becomes V3, with one entry per device of
-- every kind, and Chat's device table becomes the account's `devices`.
--
-- No migration of the V2 manifests: a V2 chain can't continue as V3, and the
-- wipe this lands with clears every account. Every Chat device and manifest
-- goes (mailboxes, prekeys, push subscriptions and socket tickets cascade),
-- and each account's next Chat device registers by re-registration. Run on a
-- live server only after the user's confirmation right before the deploy.

DELETE FROM chat_link_tokens;
DELETE FROM chat_devices;
DELETE FROM chat_device_manifest_history;
DELETE FROM chat_device_manifests;
DELETE FROM chat_account_identities;

ALTER TABLE chat_devices RENAME TO devices;
ALTER TABLE devices RENAME CONSTRAINT chat_devices_pkey TO devices_pkey;
ALTER TABLE devices RENAME CONSTRAINT chat_devices_user_id_fkey TO devices_user_id_fkey;
ALTER TABLE devices RENAME CONSTRAINT chat_devices_device_id_check TO devices_device_id_check;
ALTER TABLE devices RENAME CONSTRAINT chat_devices_suite_known TO devices_suite_known;

ALTER TABLE devices
    -- What the device is, as its manifest entry says.
    ADD COLUMN kind text NOT NULL CHECK (kind IN ('chat', 'editor', 'cli')),
    -- The device's root sign-in (an app session's parent, or the session
    -- itself): its manifest entry carries a hash of it, and ending the
    -- sign-in ends the device.
    ADD COLUMN session_id uuid NOT NULL,
    -- The Ed25519 key its collab frames are signed with.
    ADD COLUMN frame_key bytea CHECK (octet_length(frame_key) = 32),
    ALTER COLUMN suite DROP NOT NULL,
    ALTER COLUMN registration_id DROP NOT NULL,
    ALTER COLUMN identity_key DROP NOT NULL,
    ALTER COLUMN signed_pre_key_id DROP NOT NULL,
    ALTER COLUMN signed_pre_key DROP NOT NULL,
    ALTER COLUMN signed_pre_key_signature DROP NOT NULL,
    ALTER COLUMN last_resort_kyber_pre_key_id DROP NOT NULL,
    ALTER COLUMN last_resort_kyber_pre_key DROP NOT NULL,
    ALTER COLUMN last_resort_kyber_pre_key_signature DROP NOT NULL,
    -- The Chat columns are all set (a device that takes Chat) or all empty;
    -- a chat device takes Chat, an editor never does, and editors and the
    -- CLI sign frames (as the manifest's entries).
    ADD CONSTRAINT devices_kind_keys CHECK (
        num_nulls(suite, registration_id, identity_key, signed_pre_key_id, signed_pre_key,
                  signed_pre_key_signature, last_resort_kyber_pre_key_id,
                  last_resort_kyber_pre_key, last_resort_kyber_pre_key_signature) IN (0, 9)
        AND (kind <> 'chat' OR suite IS NOT NULL)
        AND (kind <> 'editor' OR suite IS NULL)
        AND (kind = 'chat' OR frame_key IS NOT NULL)
    );

CREATE INDEX devices_session ON devices (session_id);
