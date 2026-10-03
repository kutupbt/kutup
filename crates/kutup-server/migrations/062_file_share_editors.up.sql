-- Whether people a file is shared with for editing may share it on
-- (docs/plans/drive-file-sharing.md). Off unless the owner turns it on.
ALTER TABLE files ADD COLUMN editors_can_share BOOLEAN NOT NULL DEFAULT false;
