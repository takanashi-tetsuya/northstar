CREATE TABLE invitation_tokens (
    id UUID PRIMARY KEY,
    token_hash BYTEA NOT NULL UNIQUE,
    label VARCHAR(128) NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    max_uses INTEGER NOT NULL CHECK (max_uses BETWEEN 1 AND 100000),
    use_count INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX invitation_tokens_active_idx ON invitation_tokens(expires_at, revoked_at);

CREATE TABLE abuse_reports (
    id UUID PRIMARY KEY,
    reporter_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reported_jid VARCHAR(3071) NOT NULL,
    category VARCHAR(32) NOT NULL CHECK (category IN ('spam', 'harassment', 'threat', 'impersonation', 'illegal', 'other')),
    description TEXT NOT NULL DEFAULT '',
    status VARCHAR(24) NOT NULL DEFAULT 'submitted' CHECK (status IN ('submitted', 'reviewing', 'actioned', 'rejected', 'closed')),
    resolution TEXT,
    assigned_admin_id UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX abuse_reports_queue_idx ON abuse_reports(status, created_at);
CREATE INDEX abuse_reports_reporter_idx ON abuse_reports(reporter_id, created_at DESC);

CREATE TABLE abuse_report_evidence (
    id UUID PRIMARY KEY,
    report_id UUID NOT NULL REFERENCES abuse_reports(id) ON DELETE CASCADE,
    client_message_id VARCHAR(128),
    sender_jid VARCHAR(3071) NOT NULL,
    sent_at TIMESTAMPTZ,
    body_text TEXT NOT NULL,
    encrypted BOOLEAN NOT NULL DEFAULT TRUE,
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 19),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX abuse_report_evidence_report_idx ON abuse_report_evidence(report_id, position);

CREATE TABLE abuse_appeals (
    id UUID PRIMARY KEY,
    report_id UUID NOT NULL UNIQUE REFERENCES abuse_reports(id) ON DELETE CASCADE,
    appellant_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'submitted' CHECK (status IN ('submitted', 'reviewing', 'upheld', 'denied')),
    resolution TEXT,
    assigned_admin_id UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX abuse_appeals_queue_idx ON abuse_appeals(status, created_at);
