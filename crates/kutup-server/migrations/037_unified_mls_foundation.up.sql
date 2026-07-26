-- Unified MLS foundation for self-sync, direct conversations, and private
-- groups. This migration is additive: the legacy libsignal path remains
-- unadvertised for MLS until the complete client and federation cutover lands.

ALTER TABLE federation_feature_policy_documents
    DROP CONSTRAINT federation_feature_policy_documents_feature_type_check;
ALTER TABLE federation_feature_policy_documents
    ADD CONSTRAINT federation_feature_policy_documents_feature_type_check
    CHECK (feature_type IN (1, 2, 3));

-- A chat-capable device has a distinct P-256 MLS credential and a distinct
-- P-256 anonymous-delivery HPKE key. Both are bound into the accepted signed
-- manifest; the server cannot replace either key independently.
CREATE TABLE chat_mls_devices (
    user_id                       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id                     INTEGER     NOT NULL CHECK (device_id BETWEEN 1 AND 127),
    manifest_version              BIGINT      NOT NULL CHECK (manifest_version > 0),
    suite                         SMALLINT    NOT NULL CHECK (suite = 2),
    credential_public_key         BYTEA       NOT NULL CHECK (octet_length(credential_public_key) = 65),
    anonymous_delivery_public_key BYTEA       NOT NULL CHECK (octet_length(anonymous_delivery_public_key) = 65),
    name                          TEXT        NOT NULL DEFAULT '',
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at                  TIMESTAMPTZ,
    PRIMARY KEY (user_id, device_id)
);

-- KeyPackages are claimed once under row locking. The exact bytes and
-- KeyPackageRef remain available for audit after a claim.
CREATE TABLE chat_mls_key_packages (
    user_id             UUID        NOT NULL,
    device_id           INTEGER     NOT NULL,
    key_package_ref     CHAR(64)    NOT NULL,
    manifest_version    BIGINT      NOT NULL CHECK (manifest_version > 0),
    suite               SMALLINT    NOT NULL CHECK (suite = 2),
    key_package          BYTEA       NOT NULL CHECK (octet_length(key_package) BETWEEN 1 AND 65536),
    expires_at           TIMESTAMPTZ NOT NULL,
    claimed_at           TIMESTAMPTZ,
    claimed_conversation UUID,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id, key_package_ref),
    FOREIGN KEY (user_id, device_id) REFERENCES chat_mls_devices ON DELETE CASCADE,
    CHECK (key_package_ref ~ '^[0-9a-f]{64}$'),
    CHECK ((claimed_at IS NULL) = (claimed_conversation IS NULL))
);

CREATE INDEX chat_mls_key_packages_available_idx
    ON chat_mls_key_packages (user_id, device_id, expires_at, created_at)
    WHERE claimed_at IS NULL;

CREATE TABLE chat_mls_conversations (
    conversation_id     UUID        PRIMARY KEY,
    kind                SMALLINT    NOT NULL CHECK (kind IN (1, 2, 3)),
    current_incarnation BIGINT      NOT NULL CHECK (current_incarnation > 0),
    status              TEXT        NOT NULL DEFAULT 'active'
        CHECK (status IN ('pending', 'active', 'blocked', 'closed')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE chat_mls_incarnations (
    conversation_id       UUID        NOT NULL REFERENCES chat_mls_conversations ON DELETE CASCADE,
    incarnation           BIGINT      NOT NULL CHECK (incarnation > 0),
    mls_group_id           BYTEA       NOT NULL CHECK (octet_length(mls_group_id) BETWEEN 16 AND 255),
    suite                  SMALLINT    NOT NULL CHECK (suite = 2),
    roster_commitment      CHAR(64)    NOT NULL,
    member_count           INTEGER     NOT NULL CHECK (member_count BETWEEN 1 AND 1000),
    genesis_participant_domains JSONB  NOT NULL CHECK (jsonb_typeof(genesis_participant_domains) = 'array'),
    participant_domains    JSONB       NOT NULL CHECK (jsonb_typeof(participant_domains) = 'array'),
    authority_set_sequence BIGINT      NOT NULL CHECK (authority_set_sequence > 0),
    authority_set          JSONB       NOT NULL CHECK (jsonb_typeof(authority_set) = 'object'),
    owner_set_sequence     BIGINT,
    owner_set              JSONB,
    genesis                JSONB       NOT NULL CHECK (jsonb_typeof(genesis) = 'object'),
    genesis_hash           CHAR(64)    NOT NULL,
    last_finalized_height  BIGINT      NOT NULL DEFAULT 0 CHECK (last_finalized_height >= 0),
    last_finalized_epoch   BIGINT      NOT NULL DEFAULT 0 CHECK (last_finalized_epoch >= 0),
    last_block_hash        CHAR(64),
    status                 TEXT        NOT NULL DEFAULT 'active'
        CHECK (status IN ('pending', 'active', 'read_only', 'closed')),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, incarnation),
    UNIQUE (mls_group_id),
    CHECK (roster_commitment ~ '^[0-9a-f]{64}$'),
    CHECK (genesis_hash ~ '^[0-9a-f]{64}$'),
    CHECK (last_block_hash IS NULL OR last_block_hash ~ '^[0-9a-f]{64}$'),
    CHECK ((owner_set_sequence IS NULL) = (owner_set IS NULL)),
    CHECK (owner_set IS NULL OR jsonb_typeof(owner_set) = 'object')
);

ALTER TABLE chat_mls_conversations
    ADD CONSTRAINT chat_mls_conversations_current_incarnation_fk
    FOREIGN KEY (conversation_id, current_incarnation)
    REFERENCES chat_mls_incarnations (conversation_id, incarnation)
    DEFERRABLE INITIALLY DEFERRED;

-- Canonical usernames remain local membership data. Ordering authorities see
-- only the pseudonymous control structures stored with each incarnation.
CREATE TABLE chat_mls_local_members (
    conversation_id UUID        NOT NULL,
    incarnation     BIGINT      NOT NULL,
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_admin        BOOLEAN     NOT NULL DEFAULT false,
    is_owner        BOOLEAN     NOT NULL DEFAULT false,
    owner_id        CHAR(64),
    membership_status TEXT      NOT NULL DEFAULT 'active'
        CHECK (membership_status IN ('pending', 'active', 'rejected')),
    invitation_expires_at TIMESTAMPTZ,
    joined_epoch    BIGINT      NOT NULL CHECK (joined_epoch >= 0),
    removed_epoch   BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, incarnation, user_id, joined_epoch),
    FOREIGN KEY (conversation_id, incarnation)
        REFERENCES chat_mls_incarnations ON DELETE CASCADE,
    CHECK (owner_id IS NULL OR owner_id ~ '^[0-9a-f]{64}$'),
    CHECK (is_owner = (owner_id IS NOT NULL)),
    CHECK (
        (membership_status = 'pending' AND invitation_expires_at IS NOT NULL)
        OR (membership_status != 'pending' AND invitation_expires_at IS NULL)
    ),
    CHECK (removed_epoch IS NULL OR removed_epoch > joined_epoch)
);

CREATE UNIQUE INDEX chat_mls_one_active_local_membership_idx
    ON chat_mls_local_members (conversation_id, incarnation, user_id)
    WHERE removed_epoch IS NULL;

-- An administrator stages one destination-private snapshot for every server
-- affected by a membership transition. Finalization verifies the public
-- delivery commitments, applies the local snapshot, and promotes every staged
-- row in the same transaction as the public control block and retry outbox.
CREATE TABLE chat_mls_membership_deliveries (
    conversation_id UUID        NOT NULL,
    incarnation     BIGINT      NOT NULL CHECK (incarnation > 0),
    proposal_id     UUID        NOT NULL,
    destination     TEXT        NOT NULL,
    delivery_digest CHAR(64)    NOT NULL,
    delivery        JSONB       NOT NULL CHECK (jsonb_typeof(delivery) = 'object'),
    submitted_by    UUID        REFERENCES users(id) ON DELETE SET NULL,
    state           TEXT        NOT NULL DEFAULT 'staged'
        CHECK (state IN ('staged', 'finalized')),
    block_height    BIGINT,
    block_hash      CHAR(64),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '24 hours'),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finalized_at    TIMESTAMPTZ,
    PRIMARY KEY (conversation_id, incarnation, proposal_id, destination),
    FOREIGN KEY (conversation_id, incarnation)
        REFERENCES chat_mls_incarnations ON DELETE CASCADE,
    CHECK (destination = lower(destination)),
    CHECK (delivery_digest ~ '^[0-9a-f]{64}$'),
    CHECK (block_hash IS NULL OR block_hash ~ '^[0-9a-f]{64}$'),
    CHECK (
        (state = 'staged' AND block_height IS NULL AND block_hash IS NULL AND finalized_at IS NULL)
        OR
        (state = 'finalized' AND block_height > 0 AND block_hash IS NOT NULL AND finalized_at IS NOT NULL)
    )
);

CREATE INDEX chat_mls_membership_deliveries_expiry_idx
    ON chat_mls_membership_deliveries (state, expires_at);

-- Append-only finalized control log and the original signed statements used
-- to construct its quorum certificates.
CREATE TABLE chat_mls_control_blocks (
    conversation_id UUID        NOT NULL,
    incarnation     BIGINT      NOT NULL,
    height          BIGINT      NOT NULL CHECK (height > 0),
    block_hash      CHAR(64)    NOT NULL,
    previous_hash   CHAR(64),
    epoch_before    BIGINT      NOT NULL CHECK (epoch_before >= 0),
    epoch_after     BIGINT      NOT NULL CHECK (epoch_after > epoch_before),
    block           JSONB       NOT NULL CHECK (jsonb_typeof(block) = 'object'),
    quorum_certificate JSONB    NOT NULL CHECK (jsonb_typeof(quorum_certificate) = 'object'),
    commit_request   JSONB       NOT NULL CHECK (jsonb_typeof(commit_request) = 'object'),
    finalized_at    TIMESTAMPTZ NOT NULL,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, incarnation, height),
    UNIQUE (conversation_id, incarnation, block_hash),
    FOREIGN KEY (conversation_id, incarnation)
        REFERENCES chat_mls_incarnations ON DELETE CASCADE,
    CHECK (block_hash ~ '^[0-9a-f]{64}$'),
    CHECK (previous_hash IS NULL OR previous_hash ~ '^[0-9a-f]{64}$'),
    CHECK ((height = 1 AND previous_hash IS NULL) OR (height > 1 AND previous_hash IS NOT NULL))
);

CREATE TABLE chat_mls_ordering_votes (
    conversation_id       UUID        NOT NULL,
    incarnation           BIGINT      NOT NULL,
    authority_set_sequence BIGINT     NOT NULL CHECK (authority_set_sequence > 0),
    height                BIGINT      NOT NULL CHECK (height > 0),
    round                 INTEGER     NOT NULL CHECK (round >= 0),
    vote_type             SMALLINT    NOT NULL CHECK (vote_type IN (1, 2)),
    block_hash            CHAR(64)    NOT NULL,
    authority_domain      TEXT        NOT NULL,
    authority_key_id      CHAR(64)    NOT NULL,
    vote                  JSONB       NOT NULL CHECK (jsonb_typeof(vote) = 'object'),
    received_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (
        conversation_id, incarnation, authority_set_sequence,
        height, round, vote_type, authority_domain
    ),
    FOREIGN KEY (conversation_id, incarnation)
        REFERENCES chat_mls_incarnations ON DELETE CASCADE,
    CHECK (authority_domain = lower(authority_domain)),
    CHECK (block_hash ~ '^[0-9a-f]{64}$'),
    CHECK (authority_key_id ~ '^[0-9a-f]{64}$')
);

CREATE TABLE chat_mls_owner_approvals (
    conversation_id   UUID        NOT NULL,
    incarnation       BIGINT      NOT NULL,
    owner_set_sequence BIGINT     NOT NULL CHECK (owner_set_sequence > 0),
    proposal_hash     CHAR(64)    NOT NULL,
    owner_id          CHAR(64)    NOT NULL,
    approval          JSONB       NOT NULL CHECK (jsonb_typeof(approval) = 'object'),
    received_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (
        conversation_id, incarnation, owner_set_sequence,
        proposal_hash, owner_id
    ),
    FOREIGN KEY (conversation_id, incarnation)
        REFERENCES chat_mls_incarnations ON DELETE CASCADE,
    CHECK (proposal_hash ~ '^[0-9a-f]{64}$'),
    CHECK (owner_id ~ '^[0-9a-f]{64}$')
);

CREATE TABLE chat_mls_consensus_evidence (
    evidence_digest CHAR(64)    PRIMARY KEY,
    conversation_id UUID        NOT NULL REFERENCES chat_mls_conversations ON DELETE CASCADE,
    incarnation     BIGINT      NOT NULL CHECK (incarnation > 0),
    failure_class   TEXT        NOT NULL
        CHECK (failure_class IN (
            'authority_equivocation', 'invalid_vote', 'invalid_quorum',
            'control_fork', 'owner_equivocation', 'invalid_owner_approval',
            'authority_set_regression', 'epoch_regression'
        )),
    evidence        JSONB       NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
    detected_at     TIMESTAMPTZ NOT NULL,
    acknowledged_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (evidence_digest ~ '^[0-9a-f]{64}$')
);

-- An identified first contact is a bounded request queue. Acceptance switches
-- future traffic to capability-authenticated anonymous delivery; rejection,
-- block, expiry, or an incompatible policy reduction deletes the request as a
-- unit instead of leaving a partially verifiable MLS queue.
CREATE TABLE chat_mls_pending_requests (
    request_id               UUID        PRIMARY KEY,
    conversation_id          UUID        NOT NULL REFERENCES chat_mls_conversations ON DELETE CASCADE,
    incarnation              BIGINT      NOT NULL CHECK (incarnation > 0),
    sender_address           TEXT        NOT NULL,
    sender_origin            TEXT        NOT NULL,
    recipient_user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status                   TEXT        NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'accepted', 'rejected', 'blocked', 'expired')),
    maximum_messages         INTEGER     NOT NULL CHECK (maximum_messages BETWEEN 1 AND 128),
    maximum_ciphertext_bytes BIGINT      NOT NULL
        CHECK (maximum_ciphertext_bytes BETWEEN 65536 AND 16777216),
    message_count            INTEGER     NOT NULL DEFAULT 0 CHECK (message_count >= 0),
    ciphertext_bytes         BIGINT      NOT NULL DEFAULT 0 CHECK (ciphertext_bytes >= 0),
    genesis                  JSONB       NOT NULL CHECK (jsonb_typeof(genesis) = 'object'),
    expires_at               TIMESTAMPTZ NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (conversation_id, incarnation)
        REFERENCES chat_mls_incarnations ON DELETE CASCADE,
    CHECK (sender_origin = lower(sender_origin)),
    CHECK (message_count <= maximum_messages),
    CHECK (ciphertext_bytes <= maximum_ciphertext_bytes)
);

CREATE INDEX chat_mls_pending_requests_recipient_idx
    ON chat_mls_pending_requests (recipient_user_id, status, created_at);
CREATE UNIQUE INDEX chat_mls_one_pending_request_per_sender_idx
    ON chat_mls_pending_requests (recipient_user_id, sender_address)
    WHERE status = 'pending';

-- Mailbox rows for anonymous delivery structurally cannot contain sender,
-- conversation, group, or epoch metadata. Identified request rows carry only a
-- request id; the bounded request table owns the visible sender identity.
CREATE TABLE chat_mls_mailbox (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cursor              BIGINT      GENERATED ALWAYS AS IDENTITY,
    recipient_user_id   UUID        NOT NULL,
    recipient_device_id INTEGER     NOT NULL,
    delivery_kind       TEXT        NOT NULL
        CHECK (delivery_kind IN (
            'identified_request', 'anonymous', 'self_sync', 'membership_control'
        )),
    request_id          UUID        REFERENCES chat_mls_pending_requests ON DELETE CASCADE,
    conversation_id     UUID        REFERENCES chat_mls_conversations ON DELETE CASCADE,
    incarnation         BIGINT,
    send_id             UUID        NOT NULL,
    opaque_envelope     BYTEA       NOT NULL
        CHECK (octet_length(opaque_envelope) BETWEEN 1 AND 1048576),
    server_ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (recipient_user_id, recipient_device_id)
        REFERENCES chat_mls_devices ON DELETE CASCADE,
    FOREIGN KEY (conversation_id, incarnation)
        REFERENCES chat_mls_incarnations (conversation_id, incarnation)
        ON DELETE CASCADE,
    UNIQUE (recipient_user_id, recipient_device_id, send_id),
    CHECK (
        (delivery_kind = 'identified_request' AND request_id IS NOT NULL
            AND conversation_id IS NOT NULL AND incarnation IS NULL)
        OR (delivery_kind = 'anonymous' AND request_id IS NULL
            AND conversation_id IS NULL AND incarnation IS NULL)
        OR (delivery_kind = 'self_sync' AND request_id IS NULL
            AND conversation_id IS NOT NULL AND incarnation IS NULL)
        OR (delivery_kind = 'membership_control' AND request_id IS NULL
            AND conversation_id IS NOT NULL AND incarnation > 0)
    )
);

CREATE INDEX chat_mls_mailbox_recipient_idx
    ON chat_mls_mailbox (recipient_user_id, recipient_device_id, cursor);

-- Raw 16-byte capabilities are never persisted. Publication is keyed by epoch
-- so an accepted epoch and its verifier can be committed atomically.
CREATE TABLE chat_mls_delivery_capabilities (
    recipient_user_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    conversation_id   UUID        NOT NULL REFERENCES chat_mls_conversations ON DELETE CASCADE,
    incarnation       BIGINT      NOT NULL CHECK (incarnation > 0),
    epoch             BIGINT      NOT NULL CHECK (epoch >= 0),
    capability_kind   TEXT        NOT NULL CHECK (capability_kind IN ('direct', 'group')),
    capability_hash   BYTEA       NOT NULL CHECK (octet_length(capability_hash) = 32),
    policy_sequence   BIGINT      NOT NULL CHECK (policy_sequence > 0),
    published_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (recipient_user_id, conversation_id, incarnation, epoch),
    FOREIGN KEY (conversation_id, incarnation)
        REFERENCES chat_mls_incarnations ON DELETE CASCADE
);

CREATE UNIQUE INDEX chat_mls_delivery_capability_current_idx
    ON chat_mls_delivery_capabilities (
        recipient_user_id, conversation_id, incarnation, capability_hash
    );

CREATE TABLE chat_mls_anonymous_send_ids (
    recipient_user_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    capability_hash   BYTEA       NOT NULL CHECK (octet_length(capability_hash) = 32),
    send_id           UUID        NOT NULL,
    stored_count      INTEGER     NOT NULL CHECK (stored_count BETWEEN 1 AND 32),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (recipient_user_id, capability_hash, send_id)
);

CREATE TABLE chat_mls_rate_counters (
    scope_type   TEXT        NOT NULL CHECK (scope_type IN (
        'capability_bundle', 'identified_bundle', 'capability_minute',
        'capability_day', 'recipient', 'federation_origin'
    )),
    scope_digest BYTEA       NOT NULL CHECK (octet_length(scope_digest) = 32),
    window_start TIMESTAMPTZ NOT NULL,
    count        BIGINT      NOT NULL CHECK (count >= 0),
    expires_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope_type, scope_digest, window_start)
);

CREATE INDEX chat_mls_rate_counters_expiry_idx
    ON chat_mls_rate_counters (expires_at);

-- The origin may retain its authenticated local sender for retries. The
-- serialized destination transaction is constrained to omit sender and MLS
-- conversation metadata.
CREATE TABLE chat_mls_federation_sequences (
    destination   TEXT PRIMARY KEY,
    next_sequence BIGINT NOT NULL CHECK (next_sequence > 0),
    CHECK (destination = lower(destination))
);

CREATE TABLE chat_mls_federation_outbox (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    destination      TEXT        NOT NULL,
    sequence         BIGINT      NOT NULL CHECK (sequence > 0),
    sender_user_id   UUID        REFERENCES users(id) ON DELETE SET NULL,
    sender_device_id INTEGER     CHECK (sender_device_id IS NULL OR sender_device_id BETWEEN 1 AND 127),
    recipient        TEXT        NOT NULL,
    send_id          UUID        NOT NULL,
    transaction      JSONB       NOT NULL CHECK (jsonb_typeof(transaction) = 'object'),
    state            TEXT        NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'delivered', 'rejected')),
    attempts         INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error_class TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (destination, sequence),
    UNIQUE (destination, recipient, send_id),
    CHECK (destination = lower(destination)),
    CHECK (
        NOT transaction ?| ARRAY[
            'sender', 'senderDeviceId', 'conversationId', 'groupId', 'epoch'
        ]
    )
);

CREATE INDEX chat_mls_federation_outbox_due_idx
    ON chat_mls_federation_outbox (state, next_attempt_at, destination, sequence);

-- A locally finalized control block and every required federation delivery are
-- committed together. Retry rows contain only the already-pseudonymous public
-- control statement and never an authenticated local submitter.
CREATE TABLE chat_mls_control_outbox (
    destination      TEXT        NOT NULL,
    conversation_id  UUID        NOT NULL,
    incarnation      BIGINT      NOT NULL CHECK (incarnation > 0),
    height           BIGINT      NOT NULL CHECK (height > 0),
    block_hash       CHAR(64)    NOT NULL,
    commit_request   JSONB       NOT NULL CHECK (jsonb_typeof(commit_request) = 'object'),
    state            TEXT        NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'delivered')),
    attempts         INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error_class TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (destination, conversation_id, incarnation, height),
    FOREIGN KEY (conversation_id, incarnation)
        REFERENCES chat_mls_incarnations ON DELETE CASCADE,
    CHECK (destination = lower(destination)),
    CHECK (block_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX chat_mls_control_outbox_due_idx
    ON chat_mls_control_outbox (
        state, next_attempt_at, destination,
        conversation_id, incarnation, height
    );

CREATE TABLE chat_mls_federation_inbound_state (
    origin        TEXT PRIMARY KEY,
    last_sequence BIGINT      NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (origin = lower(origin))
);

CREATE TABLE chat_mls_federation_inbound_transactions (
    origin          TEXT        NOT NULL REFERENCES chat_mls_federation_inbound_state ON DELETE CASCADE,
    sequence        BIGINT      NOT NULL CHECK (sequence > 0),
    send_id         UUID        NOT NULL,
    response_status SMALLINT    NOT NULL CHECK (response_status BETWEEN 200 AND 599),
    response        JSONB       NOT NULL CHECK (jsonb_typeof(response) = 'object'),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (origin, sequence),
    UNIQUE (origin, send_id)
);

-- A newly added ordering authority stages a bounded, hash-chained copy of the
-- complete finalized control history. It becomes eligible to vote only after
-- the history digest, every old quorum certificate, owner authorization, and
-- the old-set certificate for the transition have all verified.
CREATE TABLE chat_mls_authority_bootstraps (
    bootstrap_id       CHAR(64)    PRIMARY KEY,
    origin_domain      TEXT        NOT NULL,
    conversation_id    UUID        NOT NULL,
    incarnation        BIGINT      NOT NULL CHECK (incarnation > 0),
    descriptor         JSONB       NOT NULL CHECK (jsonb_typeof(descriptor) = 'object'),
    page_count         INTEGER     NOT NULL CHECK (page_count > 0),
    next_page          INTEGER     NOT NULL DEFAULT 0 CHECK (next_page >= 0),
    last_page_hash     CHAR(64),
    state              TEXT        NOT NULL DEFAULT 'receiving'
        CHECK (state IN ('receiving', 'verified', 'materialized', 'rejected')),
    failure_class      TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (bootstrap_id ~ '^[0-9a-f]{64}$'),
    CHECK (origin_domain = lower(origin_domain)),
    CHECK (last_page_hash IS NULL OR last_page_hash ~ '^[0-9a-f]{64}$'),
    CHECK (next_page <= page_count),
    CHECK ((next_page = 0) = (last_page_hash IS NULL))
);

CREATE TABLE chat_mls_authority_bootstrap_pages (
    bootstrap_id CHAR(64)    NOT NULL REFERENCES chat_mls_authority_bootstraps ON DELETE CASCADE,
    page_index   INTEGER     NOT NULL CHECK (page_index >= 0),
    start_height BIGINT      NOT NULL CHECK (start_height > 0),
    page_hash    CHAR(64)    NOT NULL,
    page         JSONB       NOT NULL CHECK (jsonb_typeof(page) = 'object'),
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (bootstrap_id, page_index),
    CHECK (page_hash ~ '^[0-9a-f]{64}$')
);

-- A newly added participant stages the exact public history and receives only
-- its destination-private membership snapshot on the final page.
CREATE TABLE chat_mls_participant_bootstraps (
    bootstrap_id       CHAR(64)    PRIMARY KEY,
    origin_domain      TEXT        NOT NULL,
    conversation_id    UUID        NOT NULL,
    incarnation        BIGINT      NOT NULL CHECK (incarnation > 0),
    descriptor         JSONB       NOT NULL CHECK (jsonb_typeof(descriptor) = 'object'),
    page_count         INTEGER     NOT NULL CHECK (page_count > 0),
    next_page          INTEGER     NOT NULL DEFAULT 0 CHECK (next_page >= 0),
    last_page_hash     CHAR(64),
    state              TEXT        NOT NULL DEFAULT 'receiving'
        CHECK (state IN ('receiving', 'verified', 'materialized', 'rejected')),
    failure_class      TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (bootstrap_id ~ '^[0-9a-f]{64}$'),
    CHECK (origin_domain = lower(origin_domain)),
    CHECK (last_page_hash IS NULL OR last_page_hash ~ '^[0-9a-f]{64}$'),
    CHECK (next_page <= page_count),
    CHECK ((next_page = 0) = (last_page_hash IS NULL))
);

CREATE TABLE chat_mls_participant_bootstrap_pages (
    bootstrap_id CHAR(64)    NOT NULL REFERENCES chat_mls_participant_bootstraps ON DELETE CASCADE,
    page_index   INTEGER     NOT NULL CHECK (page_index >= 0),
    start_height BIGINT      NOT NULL CHECK (start_height > 0),
    page_hash    CHAR(64)    NOT NULL,
    page         JSONB       NOT NULL CHECK (jsonb_typeof(page) = 'object'),
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (bootstrap_id, page_index),
    CHECK (page_hash ~ '^[0-9a-f]{64}$')
);

CREATE TABLE chat_mls_admin_audit_events (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type      TEXT        NOT NULL CHECK (event_type IN (
        'genesis', 'owner_change', 'authority_change', 'policy_change',
        'incarnation_recovery', 'conversation_close', 'quarantine',
        'cryptographic_failure', 'invitation_accept', 'invitation_reject'
    )),
    conversation_id UUID        REFERENCES chat_mls_conversations ON DELETE SET NULL,
    incarnation     BIGINT,
    evidence_digest CHAR(64),
    details         JSONB       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (incarnation IS NULL OR incarnation > 0),
    CHECK (evidence_digest IS NULL OR evidence_digest ~ '^[0-9a-f]{64}$')
);

-- Security statements and finalized control blocks are immutable. Recovery
-- appends a new incarnation instead of rewriting history.
CREATE FUNCTION reject_chat_mls_append_only_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'MLS security history is append-only';
END
$$;

CREATE TRIGGER chat_mls_control_blocks_append_only
    BEFORE UPDATE OR DELETE ON chat_mls_control_blocks
    FOR EACH ROW EXECUTE FUNCTION reject_chat_mls_append_only_mutation();
CREATE TRIGGER chat_mls_ordering_votes_append_only
    BEFORE UPDATE OR DELETE ON chat_mls_ordering_votes
    FOR EACH ROW EXECUTE FUNCTION reject_chat_mls_append_only_mutation();
CREATE TRIGGER chat_mls_owner_approvals_append_only
    BEFORE UPDATE OR DELETE ON chat_mls_owner_approvals
    FOR EACH ROW EXECUTE FUNCTION reject_chat_mls_append_only_mutation();
CREATE TRIGGER chat_mls_consensus_evidence_append_only
    BEFORE UPDATE OR DELETE ON chat_mls_consensus_evidence
    FOR EACH ROW EXECUTE FUNCTION reject_chat_mls_append_only_mutation();
CREATE TRIGGER chat_mls_authority_bootstrap_pages_append_only
    BEFORE UPDATE OR DELETE ON chat_mls_authority_bootstrap_pages
    FOR EACH ROW EXECUTE FUNCTION reject_chat_mls_append_only_mutation();
CREATE TRIGGER chat_mls_participant_bootstrap_pages_append_only
    BEFORE UPDATE OR DELETE ON chat_mls_participant_bootstrap_pages
    FOR EACH ROW EXECUTE FUNCTION reject_chat_mls_append_only_mutation();
