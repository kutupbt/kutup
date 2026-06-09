-- Per-user stable color for collab presence (cursors in notes, cell-edit
-- highlights in office docs). Stored as a hex string like '#ef4444'.
-- Nullable; clients fall back to a deterministic palette pick when absent.
ALTER TABLE users ADD COLUMN color TEXT;
ALTER TABLE users ADD CONSTRAINT users_color_format
  CHECK (color IS NULL OR color ~ '^#[0-9a-fA-F]{6}$');
