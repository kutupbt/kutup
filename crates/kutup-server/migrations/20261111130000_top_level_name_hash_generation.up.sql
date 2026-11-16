-- A top-level folder's name hash is an HMAC under a key from the owner's
-- Drive root (docs/plans/identity-rotation.md §3), so the folder records
-- which generation of the root made it: a reader knows which key to check
-- it under, and a Drive-root rotation rehashes the top level under the new
-- root (the rotation flow). Set with every top-level name hash; null for a
-- folder's name in a folder (under that folder's key) and for albums.
ALTER TABLE collections ADD COLUMN name_hash_generation integer;
UPDATE collections SET name_hash_generation = 1
 WHERE kind = 'folder' AND parent_collection_id IS NULL;
ALTER TABLE collections ADD CONSTRAINT collections_name_hash_generation_check
  CHECK (name_hash_generation IS NULL OR (name_hash_generation > 0 AND kind = 'folder'));
