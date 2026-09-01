\set ON_ERROR_STOP on
SET search_path TO :"fixture_schema";

-- Minimal 0057-compatible table proving that a completed upload may still
-- carry the worker claim which committed it. Migration 0061 must normalize
-- this crash-boundary state before installing its stricter fencing check.
CREATE TABLE upload_slots (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    uploaded BOOLEAN NOT NULL DEFAULT FALSE,
    uploading BOOLEAN NOT NULL DEFAULT FALSE,
    claim_token UUID,
    claim_expires_at TIMESTAMPTZ,
    content_sha256 BYTEA,
    completed_at TIMESTAMPTZ,
    CONSTRAINT upload_slots_completion_check CHECK (
        (NOT uploaded AND content_sha256 IS NULL AND completed_at IS NULL)
        OR (uploaded AND content_sha256 IS NOT NULL AND completed_at IS NOT NULL)
    )
);

INSERT INTO upload_slots
    (id,expires_at,uploaded,uploading,claim_token,claim_expires_at,
     content_sha256,completed_at)
VALUES
    ('00000000-0000-0000-0000-000000000061',
     clock_timestamp()+INTERVAL '1 hour',TRUE,TRUE,
     '00000000-0000-0000-0000-000000000062',
     clock_timestamp()+INTERVAL '1 minute',decode(repeat('aa',32),'hex'),
     clock_timestamp());

\ir ../migrations/0061_upload_lease_fencing.sql

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM upload_slots
        WHERE id='00000000-0000-0000-0000-000000000061'
          AND uploaded AND NOT uploading
          AND claim_token IS NULL AND claim_expires_at IS NULL
          AND put_expires_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION '0061 did not normalize the completed legacy claim';
    END IF;
END $$;
