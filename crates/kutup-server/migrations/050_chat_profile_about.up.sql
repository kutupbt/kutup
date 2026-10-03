-- Signal's profile "about": a separately encrypted, padded envelope beside the
-- name and avatar. The server stores it opaquely, like them.
ALTER TABLE chat_profiles ADD COLUMN about_ciphertext TEXT;
