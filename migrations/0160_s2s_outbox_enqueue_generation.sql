CREATE TABLE IF NOT EXISTS s2s_outbox_enqueue_generation (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    generation BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT s2s_outbox_enqueue_generation_singleton CHECK (singleton),
    CONSTRAINT s2s_outbox_enqueue_generation_nonnegative CHECK (generation >= 0)
);

INSERT INTO s2s_outbox_enqueue_generation (singleton, generation)
VALUES (TRUE, 0)
ON CONFLICT (singleton) DO NOTHING;

REVOKE ALL ON TABLE s2s_outbox_enqueue_generation FROM PUBLIC;
