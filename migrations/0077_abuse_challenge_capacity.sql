-- Bound active proof-of-work challenge storage by opaque actor keys. Existing
-- rows remain globally bounded and expire within their original short TTL;
-- newly issued rows participate in both per-actor and per-source ceilings.
ALTER TABLE abuse_pow_challenges
    ADD COLUMN capacity_actor_keys TEXT[] NOT NULL DEFAULT '{}'
    CHECK (cardinality(capacity_actor_keys) <= 16);

CREATE INDEX abuse_pow_challenges_capacity_actor_keys_idx
    ON abuse_pow_challenges USING GIN (capacity_actor_keys);

CREATE INDEX abuse_challenge_issue_windows_updated_idx
    ON abuse_challenge_issue_windows (updated_at);
