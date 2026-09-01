-- Per-subject retention, typed legal holds and bounded/immutable audit data.
--
-- A hold is historical state: it is never deleted or rewritten.  Releasing a
-- hold is the single permitted transition and retains both the original
-- target set and the release metadata.  Application APIs add RBAC,
-- idempotency and access-audit checks around these database invariants.

CREATE TABLE user_retention_policies (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    personal_mam_days INTEGER CHECK (personal_mam_days BETWEEN 1 AND 36500),
    offline_message_days INTEGER CHECK (offline_message_days BETWEEN 1 AND 36500),
    -- Moderation evidence inherits the same 30-day legal/compliance floor as
    -- the operator policy.  A user may shorten the operator ceiling, but may
    -- not turn a report into an immediate evidence-erasure mechanism.
    moderation_evidence_days INTEGER CHECK (moderation_evidence_days BETWEEN 30 AND 36500),
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (
        personal_mam_days IS NOT NULL
        OR offline_message_days IS NOT NULL
        OR moderation_evidence_days IS NOT NULL
    )
);

CREATE TABLE muc_retention_policies (
    room_id UUID PRIMARY KEY REFERENCES muc_rooms(id) ON DELETE CASCADE,
    retention_days INTEGER NOT NULL CHECK (retention_days BETWEEN 1 AND 36500),
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE legal_holds (
    id UUID PRIMARY KEY,
    title VARCHAR(256) NOT NULL CHECK (octet_length(title) BETWEEN 1 AND 1024),
    authority_reference VARCHAR(512) NOT NULL
        CHECK (octet_length(authority_reference) BETWEEN 1 AND 2048),
    reason TEXT NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 16384),
    -- Actor UUIDs are durable audit identities, not live ownership FKs.  A
    -- later account deletion must not rewrite historical governance records.
    created_by UUID,
    created_request_id UUID NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    released_by UUID,
    released_request_id UUID UNIQUE,
    released_at TIMESTAMPTZ,
    release_reason TEXT CHECK (
        release_reason IS NULL OR octet_length(release_reason) BETWEEN 1 AND 16384
    ),
    CHECK (
        (released_at IS NULL AND released_by IS NULL
            AND released_request_id IS NULL AND release_reason IS NULL)
        OR
        (released_at IS NOT NULL AND released_by IS NOT NULL
            AND released_request_id IS NOT NULL AND release_reason IS NOT NULL
            AND released_at >= created_at)
    )
);
CREATE INDEX legal_holds_active_idx ON legal_holds(created_at, id)
    WHERE released_at IS NULL;

-- Exact typed links intentionally do not use a foreign key to the protected
-- record.  The application locks and verifies the record before inserting the
-- link.  Keeping the UUID after release/deletion is required for an immutable
-- historical target manifest.  Database delete guards below provide the live
-- protection rather than ON DELETE CASCADE/SET NULL.
CREATE TABLE legal_hold_personal_archives (
    hold_id UUID NOT NULL REFERENCES legal_holds(id) ON DELETE RESTRICT,
    archive_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    encrypted BOOLEAN NOT NULL,
    record_created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (hold_id, archive_id)
);
CREATE INDEX legal_hold_personal_archive_record_idx
    ON legal_hold_personal_archives(archive_id, hold_id);

CREATE TABLE legal_hold_muc_archives (
    hold_id UUID NOT NULL REFERENCES legal_holds(id) ON DELETE RESTRICT,
    message_id UUID NOT NULL,
    room_id UUID NOT NULL,
    encrypted BOOLEAN NOT NULL,
    record_created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (hold_id, message_id)
);
CREATE INDEX legal_hold_muc_archive_record_idx
    ON legal_hold_muc_archives(message_id, hold_id);

CREATE TABLE legal_hold_offline_messages (
    hold_id UUID NOT NULL REFERENCES legal_holds(id) ON DELETE RESTRICT,
    message_id UUID NOT NULL,
    recipient_id UUID NOT NULL,
    encrypted BOOLEAN NOT NULL,
    record_created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (hold_id, message_id)
);
CREATE INDEX legal_hold_offline_message_record_idx
    ON legal_hold_offline_messages(message_id, hold_id);

CREATE TABLE legal_hold_report_evidence (
    hold_id UUID NOT NULL REFERENCES legal_holds(id) ON DELETE RESTRICT,
    evidence_id UUID NOT NULL,
    report_id UUID NOT NULL,
    encrypted BOOLEAN NOT NULL,
    record_created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (hold_id, evidence_id)
);
CREATE INDEX legal_hold_report_evidence_record_idx
    ON legal_hold_report_evidence(evidence_id, hold_id);

-- Controlled scopes are deliberately narrow.  `subject_id` is a user, room,
-- user, or report UUID respectively.  Scope creation takes a SHARE lock on
-- the corresponding data table before this row is inserted, closing the
-- scope-create/cleanup race without making every cleanup worker contend on a
-- global advisory lock.
CREATE TABLE legal_hold_scopes (
    hold_id UUID NOT NULL REFERENCES legal_holds(id) ON DELETE RESTRICT,
    scope_type VARCHAR(40) NOT NULL CHECK (scope_type IN (
        'personal_archive_owner',
        'muc_archive_room',
        'offline_message_recipient',
        'report_evidence_report'
    )),
    subject_id UUID NOT NULL,
    PRIMARY KEY (hold_id, scope_type, subject_id)
);
CREATE INDEX legal_hold_scope_subject_idx
    ON legal_hold_scopes(scope_type, subject_id, hold_id);

-- A held offline queue item must remain deliverable.  The normal transport
-- ACK may therefore delete the queue row, but this trigger copies the exact
-- server-visible stanza into immutable hold storage in the same transaction.
-- For OMEMO this is the encrypted stanza only; no decrypted text column exists.
CREATE TABLE legal_hold_offline_snapshots (
    hold_id UUID NOT NULL REFERENCES legal_holds(id) ON DELETE RESTRICT,
    message_id UUID NOT NULL,
    recipient_id UUID NOT NULL,
    sender_jid VARCHAR(3071) NOT NULL,
    stanza TEXT NOT NULL,
    encrypted BOOLEAN NOT NULL,
    record_created_at TIMESTAMPTZ NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (hold_id, message_id)
);
CREATE INDEX legal_hold_offline_snapshot_release_idx
    ON legal_hold_offline_snapshots(record_created_at, hold_id, message_id);

CREATE FUNCTION preserve_held_offline_message() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO legal_hold_offline_snapshots(
        hold_id,message_id,recipient_id,sender_jid,stanza,encrypted,record_created_at
    )
    SELECT DISTINCT hold.id,OLD.id,OLD.recipient_id,OLD.sender_jid,OLD.stanza,
           OLD.encrypted,OLD.created_at
      FROM legal_holds hold
     WHERE hold.released_at IS NULL
       AND (
           EXISTS (
               SELECT 1 FROM legal_hold_offline_messages exact_link
                WHERE exact_link.hold_id=hold.id AND exact_link.message_id=OLD.id
           )
           OR EXISTS (
               SELECT 1 FROM legal_hold_scopes scope_link
                WHERE scope_link.hold_id=hold.id
                  AND scope_link.scope_type='offline_message_recipient'
                  AND scope_link.subject_id=OLD.recipient_id
           )
       )
    ON CONFLICT (hold_id,message_id) DO NOTHING;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER offline_message_legal_hold_snapshot
BEFORE DELETE ON offline_messages
FOR EACH ROW EXECUTE FUNCTION preserve_held_offline_message();

-- Refuse destructive or payload-changing operations against held historical
-- data.  Offline transport lease/claim metadata may still change; its payload
-- is copied by the delete trigger above when delivery completes.
CREATE FUNCTION protect_held_data_record() RETURNS TRIGGER AS $$
DECLARE
    protected BOOLEAN;
BEGIN
    protected := FALSE;
    IF TG_TABLE_NAME='message_archive' THEN
        SELECT EXISTS (
            SELECT 1 FROM legal_holds hold
             WHERE hold.released_at IS NULL AND (
                 EXISTS (SELECT 1 FROM legal_hold_personal_archives link
                          WHERE link.hold_id=hold.id AND link.archive_id=OLD.id)
                 OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                            WHERE scope_link.hold_id=hold.id
                              AND scope_link.scope_type='personal_archive_owner'
                              AND scope_link.subject_id=OLD.owner_id)
             )
        ) INTO protected;
    ELSIF TG_TABLE_NAME='muc_messages' THEN
        SELECT EXISTS (
            SELECT 1 FROM legal_holds hold
             WHERE hold.released_at IS NULL AND (
                 EXISTS (SELECT 1 FROM legal_hold_muc_archives link
                          WHERE link.hold_id=hold.id AND link.message_id=OLD.id)
                 OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                            WHERE scope_link.hold_id=hold.id
                              AND scope_link.scope_type='muc_archive_room'
                              AND scope_link.subject_id=OLD.room_id)
             )
        ) INTO protected;
    ELSIF TG_TABLE_NAME='offline_messages' THEN
        -- Claim/lease fields are operational state and may change while held;
        -- payload or identity mutation may not.  DELETE is handled by the
        -- snapshot trigger so delivery acknowledgements remain functional.
        IF TG_OP='UPDATE' AND (
            OLD.recipient_id IS DISTINCT FROM NEW.recipient_id
            OR OLD.sender_jid IS DISTINCT FROM NEW.sender_jid
            OR OLD.stanza IS DISTINCT FROM NEW.stanza
            OR OLD.encrypted IS DISTINCT FROM NEW.encrypted
            OR OLD.created_at IS DISTINCT FROM NEW.created_at
        ) THEN
            SELECT EXISTS (
                SELECT 1 FROM legal_holds hold
                 WHERE hold.released_at IS NULL AND (
                     EXISTS (SELECT 1 FROM legal_hold_offline_messages link
                              WHERE link.hold_id=hold.id AND link.message_id=OLD.id)
                     OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                                WHERE scope_link.hold_id=hold.id
                                  AND scope_link.scope_type='offline_message_recipient'
                                  AND scope_link.subject_id=OLD.recipient_id)
                 )
            ) INTO protected;
        END IF;
    ELSIF TG_TABLE_NAME='abuse_report_evidence' THEN
        SELECT EXISTS (
            SELECT 1 FROM legal_holds hold
             WHERE hold.released_at IS NULL AND (
                 EXISTS (SELECT 1 FROM legal_hold_report_evidence link
                          WHERE link.hold_id=hold.id AND link.evidence_id=OLD.id)
                 OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                            WHERE scope_link.hold_id=hold.id
                              AND scope_link.scope_type='report_evidence_report'
                              AND scope_link.subject_id=OLD.report_id)
             )
        ) INTO protected;
    END IF;
    IF protected THEN
        RAISE EXCEPTION 'data record is protected by an active legal hold'
            USING ERRCODE='55000';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER personal_archive_legal_hold_guard
BEFORE UPDATE OR DELETE ON message_archive
FOR EACH ROW EXECUTE FUNCTION protect_held_data_record();
CREATE TRIGGER muc_archive_legal_hold_guard
BEFORE UPDATE OR DELETE ON muc_messages
FOR EACH ROW EXECUTE FUNCTION protect_held_data_record();
CREATE TRIGGER offline_message_legal_hold_guard
BEFORE UPDATE ON offline_messages
FOR EACH ROW EXECUTE FUNCTION protect_held_data_record();
CREATE TRIGGER report_evidence_legal_hold_guard
BEFORE UPDATE OR DELETE ON abuse_report_evidence
FOR EACH ROW EXECUTE FUNCTION protect_held_data_record();

-- Explicit account deletion and room destruction fail closed.  Operators must
-- export/release an active hold first; a cascade may never silently remove it.
CREATE FUNCTION protect_legal_hold_subject_delete() RETURNS TRIGGER AS $$
DECLARE
    protected BOOLEAN;
BEGIN
    IF TG_TABLE_NAME='users' THEN
        SELECT EXISTS (
            SELECT 1 FROM legal_holds hold
             WHERE hold.released_at IS NULL AND (
                 EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                          WHERE scope_link.hold_id=hold.id
                            AND scope_link.subject_id=OLD.id
                            AND scope_link.scope_type IN (
                                'personal_archive_owner','offline_message_recipient'))
                 OR EXISTS (SELECT 1 FROM legal_hold_personal_archives link
                            WHERE link.hold_id=hold.id AND link.owner_id=OLD.id)
                 OR EXISTS (SELECT 1 FROM legal_hold_offline_messages link
                            WHERE link.hold_id=hold.id AND link.recipient_id=OLD.id)
                 OR EXISTS (
                     SELECT 1 FROM abuse_reports report
                     JOIN legal_hold_scopes scope_link
                       ON scope_link.scope_type='report_evidence_report'
                      AND scope_link.subject_id=report.id
                      AND scope_link.hold_id=hold.id
                     WHERE report.reporter_id=OLD.id
                 )
                 OR EXISTS (
                     SELECT 1 FROM abuse_reports report
                     JOIN legal_hold_report_evidence link
                       ON link.report_id=report.id AND link.hold_id=hold.id
                     WHERE report.reporter_id=OLD.id
                 )
             )
        ) INTO protected;
    ELSE
        SELECT EXISTS (
            SELECT 1 FROM legal_holds hold
             WHERE hold.released_at IS NULL AND (
                 EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                          WHERE scope_link.hold_id=hold.id
                            AND scope_link.scope_type='muc_archive_room'
                            AND scope_link.subject_id=OLD.id)
                 OR EXISTS (SELECT 1 FROM legal_hold_muc_archives link
                            WHERE link.hold_id=hold.id AND link.room_id=OLD.id)
             )
        ) INTO protected;
    END IF;
    IF protected THEN
        RAISE EXCEPTION 'subject deletion is blocked by an active legal hold'
            USING ERRCODE='55000';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER user_legal_hold_delete_guard
BEFORE DELETE ON users
FOR EACH ROW EXECUTE FUNCTION protect_legal_hold_subject_delete();
CREATE TRIGGER muc_room_legal_hold_delete_guard
BEFORE DELETE ON muc_rooms
FOR EACH ROW EXECUTE FUNCTION protect_legal_hold_subject_delete();

-- Hold history and target manifests are append-only.  One atomic release
-- transition is allowed; no later mutation or deletion is accepted.
CREATE FUNCTION enforce_legal_hold_history() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'legal hold history is immutable' USING ERRCODE='55000';
    END IF;
    IF OLD.id<>NEW.id OR OLD.title<>NEW.title
       OR OLD.authority_reference<>NEW.authority_reference
       OR OLD.reason<>NEW.reason OR OLD.created_by IS DISTINCT FROM NEW.created_by
       OR OLD.created_request_id<>NEW.created_request_id
       OR OLD.created_at<>NEW.created_at THEN
        RAISE EXCEPTION 'legal hold creation history is immutable' USING ERRCODE='55000';
    END IF;
    IF OLD.released_at IS NOT NULL THEN
        RAISE EXCEPTION 'released legal hold history is immutable' USING ERRCODE='55000';
    END IF;
    IF NEW.released_at IS NULL OR NEW.released_by IS NULL
       OR NEW.released_request_id IS NULL OR NEW.release_reason IS NULL THEN
        RAISE EXCEPTION 'legal hold release must be complete' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER legal_hold_history_guard
BEFORE UPDATE OR DELETE ON legal_holds
FOR EACH ROW EXECUTE FUNCTION enforce_legal_hold_history();

CREATE FUNCTION prevent_legal_hold_link_mutation() RETURNS TRIGGER AS $$
BEGIN
    IF TG_TABLE_NAME='legal_hold_offline_snapshots' AND TG_OP='DELETE'
       AND current_setting('northstar.hold_snapshot_retention_cleanup',TRUE)='bounded-v1' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'legal hold target history is immutable' USING ERRCODE='55000';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER legal_hold_personal_link_guard BEFORE UPDATE OR DELETE
ON legal_hold_personal_archives FOR EACH ROW EXECUTE FUNCTION prevent_legal_hold_link_mutation();
CREATE TRIGGER legal_hold_muc_link_guard BEFORE UPDATE OR DELETE
ON legal_hold_muc_archives FOR EACH ROW EXECUTE FUNCTION prevent_legal_hold_link_mutation();
CREATE TRIGGER legal_hold_offline_link_guard BEFORE UPDATE OR DELETE
ON legal_hold_offline_messages FOR EACH ROW EXECUTE FUNCTION prevent_legal_hold_link_mutation();
CREATE TRIGGER legal_hold_report_link_guard BEFORE UPDATE OR DELETE
ON legal_hold_report_evidence FOR EACH ROW EXECUTE FUNCTION prevent_legal_hold_link_mutation();
CREATE TRIGGER legal_hold_scope_link_guard BEFORE UPDATE OR DELETE
ON legal_hold_scopes FOR EACH ROW EXECUTE FUNCTION prevent_legal_hold_link_mutation();
CREATE TRIGGER legal_hold_offline_snapshot_guard BEFORE UPDATE OR DELETE
ON legal_hold_offline_snapshots FOR EACH ROW EXECUTE FUNCTION prevent_legal_hold_link_mutation();

-- Audit rows are insert-only to every application path.  The only deletion
-- gate is this bounded database function, which validates the policy floor,
-- locks a chronological batch and identifies itself to the trigger with a
-- transaction-local marker.  Database owners/superusers remain an external
-- trust boundary and must be covered by PostgreSQL audit/WORM controls.
-- Keep actor UUIDs as historical identifiers.  ON DELETE SET NULL would turn
-- ordinary account deletion into a rewrite of every audit entry and would be
-- rejected by the immutability trigger.
ALTER TABLE audit_log DROP CONSTRAINT audit_log_actor_id_fkey;

CREATE FUNCTION enforce_audit_log_immutability() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP='DELETE'
       AND current_setting('northstar.audit_retention_cleanup',TRUE)='bounded-v1' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit history is immutable outside bounded retention cleanup'
        USING ERRCODE='55000';
END;
$$ LANGUAGE plpgsql;

-- Offline snapshots outlive transport delivery, but not the data policy.  A
-- released hold returns them to the recipient's original effective cutoff.
CREATE FUNCTION northstar_purge_released_hold_offline_snapshots(
    global_retention_days INTEGER,
    batch_size INTEGER
) RETURNS BIGINT AS $$
DECLARE
    removed BIGINT;
BEGIN
    IF global_retention_days < 0 OR global_retention_days > 36500 THEN
        RAISE EXCEPTION 'offline retention must be between 0 and 36500 days';
    END IF;
    PERFORM set_config('northstar.hold_snapshot_retention_cleanup','bounded-v1',TRUE);
    WITH expired AS MATERIALIZED (
        SELECT snapshot.hold_id,snapshot.message_id
          FROM legal_hold_offline_snapshots snapshot
          JOIN legal_holds hold ON hold.id=snapshot.hold_id
          LEFT JOIN user_retention_policies policy
            ON policy.user_id=snapshot.recipient_id
         WHERE hold.released_at IS NOT NULL
           AND COALESCE(policy.offline_message_days,NULLIF(global_retention_days,0)) IS NOT NULL
           AND snapshot.record_created_at < clock_timestamp()-(
               COALESCE(policy.offline_message_days,NULLIF(global_retention_days,0))::BIGINT
               * INTERVAL '1 day')
         ORDER BY snapshot.record_created_at,snapshot.hold_id,snapshot.message_id
         LIMIT LEAST(GREATEST(batch_size,1),10000)
         FOR UPDATE OF snapshot SKIP LOCKED
    ), deleted AS (
        DELETE FROM legal_hold_offline_snapshots snapshot USING expired
         WHERE snapshot.hold_id=expired.hold_id
           AND snapshot.message_id=expired.message_id
        RETURNING snapshot.message_id
    ) SELECT COUNT(*) INTO removed FROM deleted;
    RETURN removed;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_log_immutable_guard
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION enforce_audit_log_immutability();

CREATE FUNCTION northstar_purge_audit_log(retention_days INTEGER, batch_size INTEGER)
RETURNS BIGINT AS $$
DECLARE
    removed BIGINT;
BEGIN
    IF retention_days < 30 OR retention_days > 36500 THEN
        RAISE EXCEPTION 'audit retention must be between 30 and 36500 days';
    END IF;
    PERFORM set_config('northstar.audit_retention_cleanup','bounded-v1',TRUE);
    WITH expired AS MATERIALIZED (
        SELECT id FROM audit_log
         WHERE created_at < clock_timestamp()-(retention_days::BIGINT*INTERVAL '1 day')
         ORDER BY created_at,id
         LIMIT LEAST(GREATEST(batch_size,1),10000)
         FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM audit_log log USING expired WHERE log.id=expired.id
        RETURNING log.id
    ) SELECT COUNT(*) INTO removed FROM deleted;
    RETURN removed;
END;
$$ LANGUAGE plpgsql;

-- Scan indexes for per-subject policy resolution and hold exclusions.
CREATE INDEX message_archive_owner_retention_v2_idx
    ON message_archive(owner_id,created_at,id);
CREATE INDEX offline_messages_recipient_retention_v2_idx
    ON offline_messages(recipient_id,created_at,id);
CREATE INDEX abuse_reports_reporter_retention_idx
    ON abuse_reports(reporter_id,resolved_at,id)
    WHERE resolved_at IS NOT NULL;
