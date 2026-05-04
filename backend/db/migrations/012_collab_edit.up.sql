-- backend/db/migrations/012_collab_edit.up.sql
-- Adds tables for collaborative E2EE file editing.
-- See docs/superpowers/specs/2026-05-04-collab-edit-design.md §7 for rationale.

CREATE TABLE user_devices (
  id              BIGSERIAL   PRIMARY KEY,
  user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_signing  BYTEA       NOT NULL,        -- Ed25519 32-byte pubkey
  label           TEXT,
  is_active       BOOLEAN     NOT NULL DEFAULT true,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at    TIMESTAMPTZ
);
CREATE INDEX user_devices_active ON user_devices (user_id) WHERE is_active;

CREATE TABLE file_update_log (
  file_id        UUID        NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  seq            BIGINT      NOT NULL,
  sender_device  BIGINT      NOT NULL REFERENCES user_devices(id),
  doc_key_id     BIGINT      NOT NULL,
  kind           SMALLINT    NOT NULL,
  frame          BYTEA       NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (file_id, seq)
);

CREATE TABLE file_versions (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  file_id         UUID        NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  s3_version_id   TEXT        NOT NULL,
  storage_path    TEXT        NOT NULL,
  seq_at_snapshot BIGINT      NOT NULL,
  doc_key_id      BIGINT      NOT NULL,
  author_user_id  UUID        NOT NULL REFERENCES users(id),
  size_bytes      BIGINT      NOT NULL,
  label           TEXT,
  keep_forever    BOOLEAN     NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX file_versions_timeline ON file_versions (file_id, created_at DESC);

ALTER TABLE files ADD COLUMN current_doc_key_id BIGINT NOT NULL DEFAULT 1;
