-- The old device registry can't come back with its keys: forward only.
DO $$ BEGIN
    RAISE EXCEPTION 'collab_onto_the_manifest cannot be reverted: restore from a backup';
END $$;
