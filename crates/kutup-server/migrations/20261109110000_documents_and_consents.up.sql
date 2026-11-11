-- Notices and consents (docs/plans/server-personal-data.md, A3 and A4; slice
-- L6), as separate records. The documents' texts live elsewhere (the
-- operator's site, or a fork): the server keeps where each version is and the
-- SHA-256 of the exact text shown.

-- A published version of a document. `kind` is the operator's (`terms`,
-- `privacy_notice`, …; a consent purpose's text has the purpose's name), not
-- a list the core fixes. Never edited once published: a change is a new
-- version.
CREATE TABLE legal_documents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]{0,39}$'),
    version text NOT NULL CHECK (char_length(version) BETWEEN 1 AND 40),
    language text NOT NULL CHECK (language ~ '^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$'),
    url text NOT NULL CHECK (char_length(url) BETWEEN 1 AND 2048),
    sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
    required_at_signup boolean NOT NULL DEFAULT false,
    published_at timestamptz NOT NULL DEFAULT now(),
    published_by uuid REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (kind, version, language)
);
CREATE INDEX legal_documents_current ON legal_documents (kind, published_at DESC);

-- A notice shown and confirmed (not a consent): at sign-up, or when a new
-- required version was shown at a later sign-in. Append-only for the server.
CREATE TABLE document_acknowledgements (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    document_id uuid NOT NULL REFERENCES legal_documents(id),
    at timestamptz NOT NULL DEFAULT now(),
    context text NOT NULL CHECK (context IN ('signup', 'update')),
    PRIMARY KEY (user_id, document_id)
);

-- A consent, per purpose, given or withdrawn: each change is a row, the
-- latest is the state. Append-only for the server.
CREATE TABLE consents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The order of the changes: the latest is the state, even for two in one
    -- transaction (which share a time).
    seq bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose text NOT NULL CHECK (purpose IN ('federation_abroad', 'marketing')),
    given boolean NOT NULL,
    document_id uuid REFERENCES legal_documents(id),
    at timestamptz NOT NULL DEFAULT now(),
    channel text NOT NULL CHECK (channel IN ('settings', 'signup', 'admin'))
);
CREATE INDEX consents_latest ON consents (user_id, purpose, seq DESC);
