-- Make online C2S delivery a database-backed state machine. Personal message
-- identity admission may now recover through either MAM, an undelivered C2S
-- row, or a completed-delivery tombstone. The trigger preserves the identity
-- after the transient content row is acknowledged.

ALTER TABLE personal_message_admissions
    ADD COLUMN offline_message_id UUID,
    ADD COLUMN delivery_completed_at TIMESTAMPTZ,
    DROP CONSTRAINT personal_message_admission_archive_check,
    ADD CONSTRAINT personal_message_admission_delivery_fk
        FOREIGN KEY (offline_message_id) REFERENCES offline_messages(id)
        ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT personal_message_admission_recovery_check CHECK (
        sender_archive_id IS NOT NULL
        OR recipient_archive_id IS NOT NULL
        OR offline_message_id IS NOT NULL
        OR delivery_completed_at IS NOT NULL
    );

CREATE INDEX personal_message_admission_offline_message_idx
    ON personal_message_admissions (offline_message_id)
    WHERE offline_message_id IS NOT NULL;

-- A delivery-only identity temporarily retains the admitted payload so an
-- exact replay can still be distinguished from a SHA-256 collision. Keep
-- that privacy-sensitive tombstone bounded even when MAM retention is off.
CREATE INDEX personal_message_admission_delivery_expiry_idx
    ON personal_message_admissions (delivery_completed_at, id)
    WHERE delivery_completed_at IS NOT NULL
      AND sender_archive_id IS NULL
      AND recipient_archive_id IS NULL;

CREATE FUNCTION preserve_personal_message_delivery_identity() RETURNS TRIGGER AS $$
BEGIN
    UPDATE personal_message_admissions
       SET offline_message_id = NULL,
           delivery_completed_at = clock_timestamp()
     WHERE offline_message_id = OLD.id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER personal_message_delivery_identity_delete
BEFORE DELETE ON offline_messages
FOR EACH ROW EXECUTE FUNCTION preserve_personal_message_delivery_identity();
