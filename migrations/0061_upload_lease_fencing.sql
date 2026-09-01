-- Separate the short-lived PUT capability from object retention and close the
-- remaining lease-state combinations left compatible by 0057. Legacy files
-- remain downloadable; because their historical digest is unknowable, their
-- already-expired PUT window deliberately cannot replay a write.

ALTER TABLE upload_slots ADD COLUMN put_expires_at TIMESTAMPTZ;

UPDATE upload_slots
SET put_expires_at = CASE
    WHEN uploaded THEN LEAST(
        expires_at,
        COALESCE(completed_at,created_at) + INTERVAL '15 minutes'
    )
    ELSE expires_at
END;

-- A pre-0057 process could leave the boolean without a fenced token. Make it
-- immediately reclaimable rather than pretending the unknown worker owns a
-- valid modern lease.
UPDATE upload_slots
SET uploading=FALSE
WHERE uploaded
   OR (uploading AND (claim_token IS NULL OR claim_expires_at IS NULL));
UPDATE upload_slots
SET claim_token=NULL,claim_expires_at=NULL
WHERE NOT uploading;

ALTER TABLE upload_slots
    ALTER COLUMN put_expires_at SET NOT NULL,
    ADD CONSTRAINT upload_slots_put_expiry_check CHECK (
        put_expires_at >= created_at
    ),
    ADD CONSTRAINT upload_slots_fenced_claim_state_check CHECK (
        (uploading AND NOT uploaded
            AND claim_token IS NOT NULL AND claim_expires_at IS NOT NULL)
        OR (NOT uploading
            AND claim_token IS NULL AND claim_expires_at IS NULL)
    );

ALTER TABLE upload_slots DROP CONSTRAINT upload_slots_completion_check;
ALTER TABLE upload_slots ADD CONSTRAINT upload_slots_completion_check CHECK (
    (NOT uploaded AND content_sha256 IS NULL AND completed_at IS NULL)
    OR (uploaded AND (
        (content_sha256 IS NULL AND completed_at IS NULL)
        OR (content_sha256 IS NOT NULL AND completed_at IS NOT NULL)
    ))
);

CREATE INDEX upload_slots_put_expiry_idx
    ON upload_slots(put_expires_at,id)
    WHERE NOT uploaded;
