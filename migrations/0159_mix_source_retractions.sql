CREATE TABLE mix_source_retractions (
    source_by TEXT COLLATE "C" NOT NULL,
    target_stanza_id UUID NOT NULL,
    action_stanza_id UUID NOT NULL,
    source_participant TEXT COLLATE "C" NOT NULL,
    first_for_target BOOLEAN NOT NULL,
    retracted_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CONSTRAINT mix_source_retractions_pkey
        PRIMARY KEY (source_by, action_stanza_id),
    CONSTRAINT mix_source_retractions_source_check
        CHECK (
            pg_catalog.octet_length(source_by) BETWEEN 3 AND 1277
            AND position('@' IN source_by) > 1
            AND position('/' IN source_by) = 0
        ),
    CONSTRAINT mix_source_retractions_participant_check
        CHECK (
            pg_catalog.octet_length(source_participant) BETWEEN 1 AND 1023
            AND position('@' IN source_participant) = 0
            AND position('/' IN source_participant) = 0
            AND position('#' IN source_participant) = 0
        ),
    CONSTRAINT mix_source_retractions_distinct_ids_check
        CHECK (target_stanza_id <> action_stanza_id)
);

CREATE UNIQUE INDEX mix_source_retractions_first_target_key
    ON mix_source_retractions (source_by, target_stanza_id)
    WHERE first_for_target;

REVOKE ALL ON TABLE mix_source_retractions FROM PUBLIC;
