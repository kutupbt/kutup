-- Mail folders and labels (docs/plans/mail-filters.md, F1). Their names are
-- sealed in the browser (kutup-crypto mail_names) and bound to the account
-- and the id, so the server keeps only ids, colours, order and the tree.

CREATE TABLE mail_folders (
    -- Chosen by the browser, which binds the sealed name to it.
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_id   UUID,
    name_sealed TEXT NOT NULL CHECK (length(name_sealed) BETWEEN 1 AND 1000),
    color       TEXT NOT NULL CHECK (color ~ '^#[0-9a-f]{6}$'),
    position    INTEGER NOT NULL DEFAULT 0,
    expanded    BOOLEAN NOT NULL DEFAULT true,
    notify      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, id),
    -- A parent is one of the same account's folders; the server keeps the
    -- tree three deep and free of cycles.
    FOREIGN KEY (user_id, parent_id) REFERENCES mail_folders (user_id, id) ON DELETE CASCADE,
    CHECK (parent_id IS NULL OR parent_id <> id)
);
CREATE INDEX idx_mail_folders_user ON mail_folders (user_id, parent_id, position);

CREATE TABLE mail_labels (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_sealed TEXT NOT NULL CHECK (length(name_sealed) BETWEEN 1 AND 1000),
    color       TEXT NOT NULL CHECK (color ~ '^#[0-9a-f]{6}$'),
    position    INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, id)
);
CREATE INDEX idx_mail_labels_user ON mail_labels (user_id, position);

-- A message is in one place: a fixed folder, or `custom` with the folder.
ALTER TABLE mail_messages DROP CONSTRAINT mail_messages_folder_check;
ALTER TABLE mail_messages ADD CONSTRAINT mail_messages_folder_check
    CHECK (folder IN ('inbox', 'drafts', 'sent', 'archive', 'spam', 'trash', 'custom'));
ALTER TABLE mail_messages ADD COLUMN custom_folder UUID;
ALTER TABLE mail_messages ADD CONSTRAINT mail_messages_custom_folder_fk
    FOREIGN KEY (user_id, custom_folder) REFERENCES mail_folders (user_id, id);
ALTER TABLE mail_messages ADD CONSTRAINT mail_messages_custom_folder_check
    CHECK ((folder = 'custom') = (custom_folder IS NOT NULL));
CREATE INDEX idx_mail_messages_custom_folder
    ON mail_messages (user_id, custom_folder, received_at DESC, id) WHERE custom_folder IS NOT NULL;

-- Labels on messages: any number, kept wherever the message is filed.
CREATE TABLE mail_message_labels (
    message_id UUID NOT NULL REFERENCES mail_messages(id) ON DELETE CASCADE,
    label_id   UUID NOT NULL REFERENCES mail_labels(id) ON DELETE CASCADE,
    PRIMARY KEY (message_id, label_id)
);
CREATE INDEX idx_mail_message_labels_label ON mail_message_labels (label_id);
