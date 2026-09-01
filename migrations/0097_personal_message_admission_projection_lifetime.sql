-- Preserve XEP-0359 personal-message admission identity until every durable
-- projection has ended.  The original archive ownership foreign keys used
-- ON DELETE CASCADE, so independently expiring either the sender or recipient
-- MAM copy could erase the admission even while another MAM, C2S, or S2S
-- projection was still live.

ALTER TABLE personal_message_admissions
    DROP CONSTRAINT personal_message_admissions_sender_archive_fk,
    DROP CONSTRAINT personal_message_admissions_recipient_archive_fk,
    ADD CONSTRAINT personal_message_admissions_sender_archive_fk
        FOREIGN KEY (sender_archive_id)
        REFERENCES message_archive(id)
        ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT personal_message_admissions_recipient_archive_fk
        FOREIGN KEY (recipient_archive_id)
        REFERENCES message_archive(id)
        ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED;

-- PostgreSQL does not create indexes for referencing foreign-key columns.
-- Each archive-retention batch invokes the BEFORE DELETE lookup once per row,
-- so both sides need their own selective index rather than repeatedly scanning
-- the payload-bearing admission table.
CREATE INDEX personal_message_admission_sender_archive_idx
    ON personal_message_admissions (sender_archive_id)
    WHERE sender_archive_id IS NOT NULL;
CREATE INDEX personal_message_admission_recipient_archive_idx
    ON personal_message_admissions (recipient_archive_id)
    WHERE recipient_archive_id IS NOT NULL;

-- Trigger functions use the schema of their trigger relation instead of the
-- caller's search_path.  `%I` quotes even unusual isolated-schema names, and
-- USING keeps projection UUIDs out of the dynamic SQL.  These are SECURITY
-- INVOKER routines: the fixed catalog-only path prevents name capture without
-- expanding the database privilege boundary.
CREATE FUNCTION preserve_personal_message_archive_identity() RETURNS TRIGGER AS $$
BEGIN
    EXECUTE pg_catalog.format(
        'UPDATE %I.personal_message_admissions
            SET sender_archive_id = CASE
                    WHEN sender_archive_id = $1 THEN NULL
                    ELSE sender_archive_id
                END,
                recipient_archive_id = CASE
                    WHEN recipient_archive_id = $1 THEN NULL
                    ELSE recipient_archive_id
                END,
                delivery_completed_at = pg_catalog.clock_timestamp()
          WHERE sender_archive_id = $1 OR recipient_archive_id = $1',
        TG_TABLE_SCHEMA
    ) USING OLD.id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp;

CREATE TRIGGER personal_message_archive_identity_delete
BEFORE DELETE ON message_archive
FOR EACH ROW EXECUTE FUNCTION preserve_personal_message_archive_identity();

-- Harden the two earlier projection-finalization triggers at the same time.
-- Refreshing (rather than only initially setting) the completion timestamp is
-- intentional: the bounded replay tombstone lifetime starts when the last
-- recoverable projection finishes, regardless of which projection finishes
-- first.
CREATE OR REPLACE FUNCTION preserve_personal_message_delivery_identity()
RETURNS TRIGGER AS $$
BEGIN
    EXECUTE pg_catalog.format(
        'UPDATE %I.personal_message_admissions
            SET offline_message_id = NULL,
                delivery_completed_at = pg_catalog.clock_timestamp()
          WHERE offline_message_id = $1',
        TG_TABLE_SCHEMA
    ) USING OLD.id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp;

CREATE OR REPLACE FUNCTION preserve_personal_message_s2s_identity()
RETURNS TRIGGER AS $$
BEGIN
    EXECUTE pg_catalog.format(
        'UPDATE %I.personal_message_admissions
            SET s2s_outbox_id = NULL,
                delivery_completed_at = pg_catalog.clock_timestamp()
          WHERE s2s_outbox_id = $1',
        TG_TABLE_SCHEMA
    ) USING OLD.id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp;

-- Keep the expiry index aligned with the deletion predicate.  A timestamp can
-- already be present after an earlier projection completed; it never makes a
-- tombstone eligible while any archive, C2S, or S2S recovery owner remains.
DROP INDEX personal_message_admission_delivery_expiry_idx;
CREATE INDEX personal_message_admission_delivery_expiry_idx
    ON personal_message_admissions (delivery_completed_at, id)
    WHERE delivery_completed_at IS NOT NULL
      AND sender_archive_id IS NULL
      AND recipient_archive_id IS NULL
      AND offline_message_id IS NULL
      AND s2s_outbox_id IS NULL;
