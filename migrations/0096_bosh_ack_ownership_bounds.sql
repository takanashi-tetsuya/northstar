-- A BOSH client may keep a response recoverably owned only for a bounded
-- acknowledgement window. Renewal never moves this immutable origin time.
ALTER TABLE bosh_delivery_fences
 ADD COLUMN first_owned_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();

CREATE INDEX bosh_delivery_fence_session_age
 ON bosh_delivery_fences(session_id,first_owned_at,response_rid);

UPDATE bosh_delivery_fences
 SET expires_at=LEAST(expires_at,first_owned_at+INTERVAL '5 minutes');

ALTER TABLE bosh_delivery_fences ADD CONSTRAINT bosh_delivery_fence_ack_age_shape
 CHECK(expires_at<=first_owned_at+INTERVAL '5 minutes');
