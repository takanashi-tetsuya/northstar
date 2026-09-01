-- Durable XEP-0016 privacy lists.  List names are owner scoped and item
-- ordering is exact: duplicate order values would make first-match policy
-- evaluation ambiguous, so the database rejects them as well as the parser.
CREATE TABLE privacy_lists (
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (owner_id, name),
    CHECK (name <> ''),
    UNIQUE (owner_id, name)
);

CREATE TABLE privacy_list_items (
    owner_id UUID NOT NULL,
    list_name VARCHAR(128) NOT NULL,
    item_order BIGINT NOT NULL CHECK (item_order BETWEEN 0 AND 4294967295),
    action VARCHAR(5) NOT NULL CHECK (action IN ('allow', 'deny')),
    match_type VARCHAR(12) CHECK (match_type IN ('jid', 'group', 'subscription')),
    match_value VARCHAR(3071),
    filter_message BOOLEAN NOT NULL DEFAULT FALSE,
    filter_iq BOOLEAN NOT NULL DEFAULT FALSE,
    filter_presence_in BOOLEAN NOT NULL DEFAULT FALSE,
    filter_presence_out BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (owner_id, list_name, item_order),
    FOREIGN KEY (owner_id, list_name)
        REFERENCES privacy_lists(owner_id, name) ON DELETE CASCADE,
    CHECK ((match_type IS NULL) = (match_value IS NULL)),
    CHECK (match_type <> 'subscription' OR match_value IN ('none', 'to', 'from', 'both'))
);
CREATE INDEX privacy_list_items_evaluation_idx
    ON privacy_list_items(owner_id, list_name, item_order);

CREATE TABLE privacy_default_lists (
    owner_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    list_name VARCHAR(128) NOT NULL,
    FOREIGN KEY (owner_id, list_name)
        REFERENCES privacy_lists(owner_id, name) ON DELETE RESTRICT
);

-- Non-SM and live SM resources publish their session-local selection here so
-- list deletion and active selection serialize through the same owner lock.
CREATE TABLE privacy_active_sessions (
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL,
    list_name VARCHAR(128) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    PRIMARY KEY (owner_id, connection_id),
    FOREIGN KEY (owner_id, list_name)
        REFERENCES privacy_lists(owner_id, name)
        DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX privacy_active_sessions_list_idx
    ON privacy_active_sessions(owner_id, list_name, expires_at);

-- XEP-0198 resumes the same logical session, so its active privacy-list
-- selection must resume with it. The deferred FK both prevents deleting a
-- list used by a suspended session and still lets account deletion cascade
-- through both dependency trees in one transaction.
ALTER TABLE sm_resume_sessions
    ADD COLUMN active_privacy_list VARCHAR(128),
    ADD COLUMN privacy_requested BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT sm_resume_active_privacy_fk
        FOREIGN KEY (user_id, active_privacy_list)
        REFERENCES privacy_lists(owner_id, name)
        DEFERRABLE INITIALLY DEFERRED;
