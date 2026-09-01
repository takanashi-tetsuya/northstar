-- Stable, bounded, cursor-driven DATA-HOLD / DATA-AUDIT exports.
--
-- A lease is an operational snapshot fence, not legal authority.  It binds a
-- single administrator to a fixed database-time boundary for at most fifteen
-- minutes.  Leases are never renewed: an abandoned export therefore cannot
-- block hold release or audit retention indefinitely.

CREATE TABLE governance_export_leases (
    id UUID PRIMARY KEY,
    export_kind VARCHAR(24) NOT NULL CHECK (export_kind IN ('audit','legal_hold')),
    actor_id UUID NOT NULL,
    hold_id UUID REFERENCES legal_holds(id) ON DELETE RESTRICT,
    filter_start TIMESTAMPTZ,
    filter_end TIMESTAMPTZ,
    snapshot_at TIMESTAMPTZ NOT NULL,
    snapshot_max_id BIGINT,
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (expires_at > snapshot_at),
    CHECK (expires_at <= snapshot_at + INTERVAL '15 minutes'),
    CHECK (filter_start IS NULL OR filter_end IS NULL OR filter_start < filter_end),
    CHECK (completed_at IS NULL OR
           (completed_at >= created_at AND completed_at <= expires_at)),
    CHECK (
        (export_kind='audit' AND hold_id IS NULL
            AND snapshot_max_id IS NOT NULL AND snapshot_max_id >= 0)
        OR
        (export_kind='legal_hold' AND hold_id IS NOT NULL
            AND snapshot_max_id IS NULL
            AND filter_start IS NULL AND filter_end IS NULL)
    )
);

CREATE INDEX governance_export_active_hold_idx
    ON governance_export_leases(hold_id,expires_at,id)
    WHERE export_kind='legal_hold' AND completed_at IS NULL;
CREATE INDEX governance_export_active_audit_idx
    ON governance_export_leases(expires_at,snapshot_max_id,id)
    WHERE export_kind='audit' AND completed_at IS NULL;
CREATE INDEX governance_export_cleanup_idx
    ON governance_export_leases(COALESCE(completed_at,expires_at),id);

-- Snapshot identity, scope and expiry never change.  The only normal update
-- is one irreversible completion transition.  Bounded retention cleanup uses
-- a transaction-local marker and is the only accepted delete path.
CREATE FUNCTION enforce_governance_export_lease_history() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP='DELETE'
       AND current_setting('northstar.governance_export_cleanup',TRUE)='bounded-v1' THEN
        RETURN OLD;
    END IF;
    IF TG_OP='UPDATE'
       AND OLD.id=NEW.id
       AND OLD.export_kind=NEW.export_kind
       AND OLD.actor_id=NEW.actor_id
       AND OLD.hold_id IS NOT DISTINCT FROM NEW.hold_id
       AND OLD.filter_start IS NOT DISTINCT FROM NEW.filter_start
       AND OLD.filter_end IS NOT DISTINCT FROM NEW.filter_end
       AND OLD.snapshot_at=NEW.snapshot_at
       AND OLD.snapshot_max_id IS NOT DISTINCT FROM NEW.snapshot_max_id
       AND OLD.expires_at=NEW.expires_at
       AND OLD.created_at=NEW.created_at
       AND OLD.completed_at IS NULL
       AND NEW.completed_at IS NOT NULL
       AND NEW.completed_at <= OLD.expires_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'governance export lease history is immutable'
        USING ERRCODE='55000';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER governance_export_lease_history_guard
BEFORE UPDATE OR DELETE ON governance_export_leases
FOR EACH ROW EXECUTE FUNCTION enforce_governance_export_lease_history();

-- A hold transition and lease creation both lock the legal_holds row.  The
-- trigger is the database-level backstop for any release path that bypasses
-- the application service precheck.
CREATE OR REPLACE FUNCTION enforce_legal_hold_history() RETURNS TRIGGER AS $$
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
    IF EXISTS (
        SELECT 1 FROM governance_export_leases export
         WHERE export.export_kind='legal_hold'
           AND export.hold_id=OLD.id
           AND export.completed_at IS NULL
           AND export.expires_at > clock_timestamp()
    ) THEN
        RAISE EXCEPTION 'legal hold has an active export lease'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- An in-progress audit export must remain retrievable until its non-renewable
-- lease expires.  Completed exports stop fencing retention immediately; an
-- exact idempotency replay already stores the final response bytes.
CREATE OR REPLACE FUNCTION northstar_purge_audit_log(
    retention_days INTEGER,
    batch_size INTEGER
) RETURNS BIGINT AS $$
DECLARE
    removed BIGINT;
BEGIN
    IF retention_days < 30 OR retention_days > 36500 THEN
        RAISE EXCEPTION 'audit retention must be between 30 and 36500 days';
    END IF;
    PERFORM set_config('northstar.audit_retention_cleanup','bounded-v1',TRUE);
    WITH expired AS MATERIALIZED (
        SELECT log.id FROM audit_log log
         WHERE log.created_at < clock_timestamp()-(retention_days::BIGINT*INTERVAL '1 day')
           AND NOT EXISTS (
               SELECT 1 FROM governance_export_leases export
                WHERE export.export_kind='audit'
                  AND export.completed_at IS NULL
                  AND export.expires_at > clock_timestamp()
                  AND log.id <= export.snapshot_max_id
                  AND (export.filter_start IS NULL OR log.created_at >= export.filter_start)
                  AND (export.filter_end IS NULL OR log.created_at < export.filter_end)
           )
         ORDER BY log.created_at,log.id
         LIMIT LEAST(GREATEST(batch_size,1),10000)
         FOR UPDATE OF log SKIP LOCKED
    ), deleted AS (
        DELETE FROM audit_log log USING expired WHERE log.id=expired.id
        RETURNING log.id
    ) SELECT COUNT(*) INTO removed FROM deleted;
    RETURN removed;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION northstar_purge_governance_export_leases(
    retention_days INTEGER,
    batch_size INTEGER
) RETURNS BIGINT AS $$
DECLARE
    removed BIGINT;
BEGIN
    IF retention_days < 30 OR retention_days > 36500 THEN
        RAISE EXCEPTION 'governance export retention must be between 30 and 36500 days';
    END IF;
    PERFORM set_config('northstar.governance_export_cleanup','bounded-v1',TRUE);
    WITH expired AS MATERIALIZED (
        SELECT id FROM governance_export_leases
         WHERE (completed_at IS NULL AND expires_at <= clock_timestamp())
            OR (completed_at IS NOT NULL AND completed_at
                < clock_timestamp()-(retention_days::BIGINT*INTERVAL '1 day'))
         ORDER BY COALESCE(completed_at,expires_at),id
         LIMIT LEAST(GREATEST(batch_size,1),10000)
         FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM governance_export_leases export USING expired
         WHERE export.id=expired.id
        RETURNING export.id
    ) SELECT COUNT(*) INTO removed FROM deleted;
    RETURN removed;
END;
$$ LANGUAGE plpgsql;
