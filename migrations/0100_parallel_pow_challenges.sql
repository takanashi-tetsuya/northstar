-- A client may prepare several independently bound message stanzas before the
-- server has consumed the first proof.  The former action/subject uniqueness
-- constraint made the second issuance replace the first challenge, turning a
-- normal short burst into a deterministic authentication failure.
--
-- Challenge IDs remain the one-use authority.  Global, actor and source-IP
-- capacity accounting in the application bounds the number of live rows, and
-- expiry cleanup remains indexed separately.
ALTER TABLE abuse_pow_challenges
    DROP CONSTRAINT IF EXISTS abuse_pow_challenges_action_subject_hash_key;

-- Preserve an efficient operator/forensics lookup without restoring
-- single-active-challenge semantics.
CREATE INDEX abuse_pow_challenges_action_subject_expiry_idx
    ON abuse_pow_challenges (action, subject_hash, expires_at);
