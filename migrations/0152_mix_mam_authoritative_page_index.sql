-- MAM pages use the public stanza ID as the tie-breaker when events share a
-- timestamp. Keep that order indexed separately from retention's row-ID order.
CREATE INDEX mix_events_mam_authoritative_page_idx
    ON mix_events (channel_id, node, created_at DESC, authoritative_id DESC);
