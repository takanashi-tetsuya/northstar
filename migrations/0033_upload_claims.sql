-- A slot must be claimed atomically before its body is accepted.  Without a
-- separate in-progress state, two concurrent PUT requests can both observe
-- `uploaded = FALSE` and race while writing the same object.
ALTER TABLE upload_slots
    ADD COLUMN uploading BOOLEAN NOT NULL DEFAULT FALSE;

-- Expiry scans normally use the existing expires_at index. Keeping the state
-- in the index avoids repeatedly visiting completed objects during cleanup.
CREATE INDEX upload_slots_pending_expiry_idx
    ON upload_slots(expires_at)
    WHERE NOT uploaded;
