-- Saves that know what they replace (docs/plans/pass.md, "Saving without
-- overwriting").
--
-- A whole-file version records the content it replaced: the version that was
-- current when it was stored, or NULL for the original upload (and for
-- versions stored before this column, and notes' states). Two versions
-- with the same parent are a divergence, and the parent is the base a client
-- merges them against. Not a foreign key: retention may prune the parent,
-- and the id still names the base a client may hold itself.
ALTER TABLE file_versions ADD COLUMN parent_version_id UUID;
