CREATE TABLE mam_preferences (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    default_policy VARCHAR(16) NOT NULL DEFAULT 'always'
        CHECK (default_policy IN ('always', 'never', 'roster')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE mam_preference_jids (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    jid VARCHAR(3071) NOT NULL,
    policy VARCHAR(8) NOT NULL CHECK (policy IN ('always', 'never')),
    PRIMARY KEY (user_id, jid)
);

CREATE INDEX mam_preference_jids_user_policy_idx
    ON mam_preference_jids(user_id, policy);
