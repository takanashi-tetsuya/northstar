-- Treat a durable federation outbox row as an owned recovery projection for
-- XEP-0359 personal-message admission.  Migration 0080 allowed only MAM and
-- C2S delivery projections, so a plaintext remote message with no MAM write
-- could not atomically consume its origin-id even though its S2S outbox row
-- was created in the same transaction.

ALTER TABLE personal_message_admissions
    ADD COLUMN s2s_outbox_id UUID,
    DROP CONSTRAINT personal_message_admission_recovery_check,
    ADD CONSTRAINT personal_message_admission_s2s_outbox_fk
        FOREIGN KEY (s2s_outbox_id) REFERENCES s2s_outbox(id)
        ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT personal_message_admission_recovery_check CHECK (
        sender_archive_id IS NOT NULL
        OR recipient_archive_id IS NOT NULL
        OR offline_message_id IS NOT NULL
        OR s2s_outbox_id IS NOT NULL
        OR delivery_completed_at IS NOT NULL
    );

CREATE INDEX personal_message_admission_s2s_outbox_idx
    ON personal_message_admissions (s2s_outbox_id)
    WHERE s2s_outbox_id IS NOT NULL;

-- Once the outbox reaches any terminal deletion path, retain the bounded
-- identity tombstone used by migration 0080.  This prevents a client retry
-- after a successful write-before-delete window from enqueuing a duplicate;
-- the ordinary personal-delivery retention job later removes the payload.
CREATE FUNCTION preserve_personal_message_s2s_identity() RETURNS TRIGGER AS $$
BEGIN
    UPDATE personal_message_admissions
       SET s2s_outbox_id = NULL,
           delivery_completed_at = clock_timestamp()
     WHERE s2s_outbox_id = OLD.id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER personal_message_s2s_identity_delete
BEFORE DELETE ON s2s_outbox
FOR EACH ROW EXECUTE FUNCTION preserve_personal_message_s2s_identity();
