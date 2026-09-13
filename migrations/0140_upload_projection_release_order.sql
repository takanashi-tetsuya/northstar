-- Row-level AFTER DELETE triggers observe every sibling projection as already
-- gone when one DELETE statement removes several rows.  The old accounting
-- therefore released one logical object for every physical row in a batched
-- storage-job delete.  Keep the physical counters row based, but make the
-- delete accounting run BEFORE DELETE: exactly the final surviving projection
-- observes that no sibling remains and releases the logical owner once.

CREATE OR REPLACE FUNCTION account_upload_storage_job_capacity()
RETURNS pg_catalog.trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $account_upload_storage_job_capacity$
DECLARE
    converts_debt pg_catalog.bool:=FALSE;
    acquires_retained pg_catalog.bool:=FALSE;
    releases_retained pg_catalog.bool:=FALSE;
    policy_bound pg_catalog.bool:=FALSE;
BEGIN
    SELECT configured_pending_limit IS NOT NULL
           AND configured_retained_files_limit IS NOT NULL
           AND configured_retained_bytes_limit IS NOT NULL
      INTO policy_bound
      FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'upload storage capacity authority is missing'
            USING ERRCODE='55000';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NOT policy_bound THEN
            RAISE EXCEPTION 'upload storage capacity policy is not fully bound'
                USING ERRCODE='55000';
        END IF;
        IF EXISTS(SELECT 1 FROM upload_slots
                   WHERE id=NEW.object_id AND size<>NEW.expected_size)
           OR EXISTS(SELECT 1 FROM upload_cleanup_queue
                      WHERE object_id=NEW.object_id
                        AND expected_size<>NEW.expected_size)
           OR EXISTS(SELECT 1 FROM upload_storage_jobs
                      WHERE object_id=NEW.object_id AND id<>NEW.id
                        AND expected_size<>NEW.expected_size) THEN
            RAISE EXCEPTION 'upload storage projection size conflicts with object authority'
                USING ERRCODE='55000';
        END IF;
        IF NEW.action='delete_stage' THEN
            SELECT EXISTS(SELECT 1 FROM upload_slots WHERE id=NEW.object_id
                AND storage_state='writing' AND storage_cleanup_debt_reserved
                AND storage_backend=NEW.storage_backend
                AND storage_attempt=NEW.storage_attempt
                AND storage_fence=NEW.storage_fence
                AND storage_stage_key=NEW.stage_key
                AND storage_stage_version IS NOT DISTINCT FROM NEW.stage_version
                AND COALESCE(storage_size,size)=NEW.expected_size)
              INTO converts_debt;
        END IF;
        SELECT NOT EXISTS(SELECT 1 FROM upload_slots WHERE id=NEW.object_id)
           AND NOT EXISTS(SELECT 1 FROM upload_cleanup_queue
                           WHERE object_id=NEW.object_id)
           AND NOT EXISTS(SELECT 1 FROM upload_storage_jobs
                           WHERE object_id=NEW.object_id AND id<>NEW.id)
          INTO acquires_retained;
        IF acquires_retained AND NEW.expected_size IS NULL THEN
            RAISE EXCEPTION 'first orphan upload storage projection has unknown retained size'
                USING ERRCODE='55000';
        END IF;
        UPDATE upload_storage_capacity_ledger SET pending_jobs=pending_jobs+1,
            cleanup_obligation_debt=cleanup_obligation_debt-
                CASE WHEN converts_debt THEN 1 ELSE 0 END,
            storage_jobs_pending=storage_jobs_pending+1,
            retained_files=retained_files+CASE WHEN acquires_retained THEN 1 ELSE 0 END,
            retained_bytes=retained_bytes+CASE WHEN acquires_retained
                THEN NEW.expected_size ELSE 0 END,
            recovery_retained_files=recovery_retained_files+1,
            recovery_retained_bytes=recovery_retained_bytes+NEW.expected_size,
            recovery_overcommit_draining=(
                configured_retained_files_limit IS NOT NULL
                AND configured_retained_bytes_limit IS NOT NULL
                AND (
                    retained_files+CASE WHEN acquires_retained THEN 1 ELSE 0 END+
                        recovery_retained_files+1>configured_retained_files_limit
                    OR retained_bytes+CASE WHEN acquires_retained
                           THEN NEW.expected_size ELSE 0 END+
                        recovery_retained_bytes+NEW.expected_size>
                            configured_retained_bytes_limit
                )),
            updated_at=pg_catalog.clock_timestamp() WHERE singleton
              AND cleanup_obligation_debt>=CASE WHEN converts_debt THEN 1 ELSE 0 END
              AND (converts_debt OR (
                  pending_jobs+cleanup_obligation_debt+1<=configured_pending_limit
                  AND pending_jobs+cleanup_obligation_debt+1<=absolute_disaster_limit));
        IF NOT FOUND THEN
            RAISE EXCEPTION 'upload recovery queue hard limit reached' USING ERRCODE='53300';
        END IF;
        IF converts_debt THEN
            UPDATE upload_slots SET storage_cleanup_debt_reserved=FALSE
             WHERE id=NEW.object_id AND storage_cleanup_debt_reserved
               AND storage_state='writing'
               AND storage_backend=NEW.storage_backend
               AND storage_attempt=NEW.storage_attempt
               AND storage_fence=NEW.storage_fence
               AND storage_stage_key=NEW.stage_key
               AND storage_stage_version IS NOT DISTINCT FROM NEW.stage_version
               AND COALESCE(storage_size,size)=NEW.expected_size;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'upload cleanup debt authority changed during job admission'
                    USING ERRCODE='40001';
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    -- This is a BEFORE DELETE trigger. The current row is still visible, so
    -- exclude its immutable primary key while testing whether it is the final
    -- physical projection for this object. A multi-row DELETE then releases
    -- retained ownership exactly once, on its final row.
    SELECT NOT EXISTS(SELECT 1 FROM upload_slots WHERE id=OLD.object_id)
       AND NOT EXISTS(SELECT 1 FROM upload_cleanup_queue
                       WHERE object_id=OLD.object_id)
       AND NOT EXISTS(SELECT 1 FROM upload_storage_jobs
                       WHERE object_id=OLD.object_id AND id<>OLD.id)
      INTO releases_retained;
    IF releases_retained AND OLD.expected_size IS NULL THEN
        RAISE EXCEPTION 'last upload storage projection has unknown retained size'
            USING ERRCODE='55000';
    END IF;
    UPDATE upload_storage_capacity_ledger SET pending_jobs=pending_jobs-1,
        storage_jobs_pending=storage_jobs_pending-1,
        legacy_overcommit_draining=(pending_jobs-1+cleanup_obligation_debt>
            LEAST(COALESCE(configured_pending_limit,absolute_disaster_limit),
                  absolute_disaster_limit)),
        retained_files=retained_files-CASE WHEN releases_retained THEN 1 ELSE 0 END,
        retained_bytes=retained_bytes-CASE WHEN releases_retained
            THEN OLD.expected_size ELSE 0 END,
        recovery_retained_files=recovery_retained_files-1,
        recovery_retained_bytes=recovery_retained_bytes-OLD.expected_size,
        recovery_overcommit_draining=(
            configured_retained_files_limit IS NOT NULL
            AND configured_retained_bytes_limit IS NOT NULL
            AND (
                retained_files-CASE WHEN releases_retained THEN 1 ELSE 0 END+
                    recovery_retained_files-1>configured_retained_files_limit
                OR retained_bytes-CASE WHEN releases_retained
                       THEN OLD.expected_size ELSE 0 END+
                    recovery_retained_bytes-OLD.expected_size>
                        configured_retained_bytes_limit
            )),
        updated_at=pg_catalog.clock_timestamp() WHERE singleton;
    IF OLD.action='delete_stage' THEN
        UPDATE upload_slots SET storage_cleanup_debt_reserved=FALSE
         WHERE id=OLD.object_id AND storage_state='writing'
           AND NOT storage_cleanup_debt_reserved
           AND storage_backend=OLD.storage_backend
           AND storage_attempt=OLD.storage_attempt
           AND storage_fence=OLD.storage_fence
           AND storage_stage_key=OLD.stage_key
           AND storage_stage_version IS NOT DISTINCT FROM OLD.stage_version
           AND COALESCE(storage_size,size)=OLD.expected_size;
    END IF;
    RETURN OLD;
END;
$account_upload_storage_job_capacity$;

CREATE OR REPLACE FUNCTION account_upload_cleanup_capacity()
RETURNS pg_catalog.trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $account_upload_cleanup_capacity$
DECLARE
    converts_debt pg_catalog.bool:=FALSE;
    acquires_retained pg_catalog.bool:=FALSE;
    releases_retained pg_catalog.bool:=FALSE;
    locator_units pg_catalog.int8:=1;
    policy_bound pg_catalog.bool:=FALSE;
BEGIN
    SELECT configured_pending_limit IS NOT NULL
           AND configured_retained_files_limit IS NOT NULL
           AND configured_retained_bytes_limit IS NOT NULL
      INTO policy_bound
      FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'upload storage capacity authority is missing'
            USING ERRCODE='55000';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NOT policy_bound THEN
            RAISE EXCEPTION 'upload storage capacity policy is not fully bound'
                USING ERRCODE='55000';
        END IF;
        locator_units:=CASE WHEN NEW.stage_key IS NULL
                              OR (NEW.stage_key=NEW.object_key
                                  AND NEW.stage_version IS NOT DISTINCT FROM NEW.object_version)
                            THEN 1 ELSE 2 END;
        IF EXISTS(SELECT 1 FROM upload_slots
                   WHERE id=NEW.object_id AND size<>NEW.expected_size)
           OR EXISTS(SELECT 1 FROM upload_storage_jobs
                      WHERE object_id=NEW.object_id
                        AND expected_size<>NEW.expected_size) THEN
            RAISE EXCEPTION 'upload cleanup projection size conflicts with object authority'
                USING ERRCODE='55000';
        END IF;
        SELECT EXISTS(SELECT 1 FROM upload_slots WHERE id=NEW.object_id
            AND storage_cleanup_debt_reserved
            AND storage_state IN ('writing','staged','promoting','committed','legacy_committed','deleting')
            AND storage_backend=NEW.storage_backend
            AND storage_object_key=NEW.object_key
            AND (CASE WHEN storage_backend='s3'
                                AND storage_stage_key=storage_object_key
                      THEN COALESCE(storage_object_version,storage_stage_version)
                      ELSE storage_object_version END)
                    IS NOT DISTINCT FROM NEW.object_version
            AND storage_stage_key IS NOT DISTINCT FROM NEW.stage_key
            AND storage_stage_version IS NOT DISTINCT FROM NEW.stage_version
            AND storage_attempt IS NOT DISTINCT FROM NEW.storage_attempt
            AND storage_fence=NEW.storage_fence
            AND COALESCE(storage_size,size)=NEW.expected_size
            AND storage_sha256 IS NOT DISTINCT FROM NEW.expected_sha256)
          INTO converts_debt;
        SELECT NOT EXISTS(SELECT 1 FROM upload_slots WHERE id=NEW.object_id)
           AND NOT EXISTS(SELECT 1 FROM upload_storage_jobs
                           WHERE object_id=NEW.object_id)
          INTO acquires_retained;
        IF NEW.slot_delete_projection THEN
            IF pg_catalog.pg_trigger_depth()<=1 THEN
                RAISE EXCEPTION 'slot-delete upload cleanup provenance requires nested trigger admission'
                    USING ERRCODE='42501';
            END IF;
            IF NOT converts_debt THEN
                RAISE EXCEPTION 'slot-delete upload cleanup lacks exact reserved cleanup debt'
                    USING ERRCODE='55000';
            END IF;
        END IF;
        UPDATE upload_storage_capacity_ledger SET pending_jobs=pending_jobs+1,
            cleanup_obligation_debt=cleanup_obligation_debt-
                CASE WHEN converts_debt THEN 1 ELSE 0 END,
            cleanup_jobs_pending=cleanup_jobs_pending+1,
            retained_files=retained_files+CASE WHEN acquires_retained THEN 1 ELSE 0 END,
            retained_bytes=retained_bytes+CASE WHEN acquires_retained
                THEN NEW.expected_size ELSE 0 END,
            recovery_retained_files=recovery_retained_files+locator_units,
            recovery_retained_bytes=recovery_retained_bytes+
                locator_units*NEW.expected_size,
            recovery_overcommit_draining=(
                configured_retained_files_limit IS NOT NULL
                AND configured_retained_bytes_limit IS NOT NULL
                AND (
                    retained_files+CASE WHEN acquires_retained THEN 1 ELSE 0 END+
                        recovery_retained_files+locator_units>
                            configured_retained_files_limit
                    OR retained_bytes+CASE WHEN acquires_retained
                           THEN NEW.expected_size ELSE 0 END+
                        recovery_retained_bytes+locator_units*NEW.expected_size>
                            configured_retained_bytes_limit
                )),
            updated_at=pg_catalog.clock_timestamp() WHERE singleton
              AND cleanup_obligation_debt>=CASE WHEN converts_debt THEN 1 ELSE 0 END
              AND (converts_debt OR (
                  pending_jobs+cleanup_obligation_debt+1<=configured_pending_limit
                  AND pending_jobs+cleanup_obligation_debt+1<=absolute_disaster_limit));
        IF NOT FOUND THEN
            RAISE EXCEPTION 'upload recovery queue hard limit reached' USING ERRCODE='53300';
        END IF;
        IF converts_debt AND NOT NEW.slot_delete_projection THEN
            UPDATE upload_slots SET storage_cleanup_debt_reserved=FALSE
             WHERE id=NEW.object_id AND storage_cleanup_debt_reserved
               AND storage_state IN ('writing','staged','promoting','committed','legacy_committed','deleting')
               AND storage_backend=NEW.storage_backend
               AND storage_object_key=NEW.object_key
               AND (CASE WHEN storage_backend='s3'
                                   AND storage_stage_key=storage_object_key
                         THEN COALESCE(storage_object_version,storage_stage_version)
                         ELSE storage_object_version END)
                       IS NOT DISTINCT FROM NEW.object_version
               AND storage_stage_key IS NOT DISTINCT FROM NEW.stage_key
               AND storage_stage_version IS NOT DISTINCT FROM NEW.stage_version
               AND storage_attempt IS NOT DISTINCT FROM NEW.storage_attempt
               AND storage_fence=NEW.storage_fence
               AND COALESCE(storage_size,size)=NEW.expected_size
               AND storage_sha256 IS NOT DISTINCT FROM NEW.expected_sha256;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'upload cleanup debt authority changed during cleanup admission'
                    USING ERRCODE='40001';
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    locator_units:=CASE WHEN OLD.stage_key IS NULL
                          OR (OLD.stage_key=OLD.object_key
                              AND OLD.stage_version IS NOT DISTINCT FROM OLD.object_version)
                        THEN 1 ELSE 2 END;
    -- `upload_cleanup_queue.object_id` is the primary key, so this BEFORE
    -- DELETE row is necessarily its sole cleanup projection. Storage-job and
    -- slot projections still block release of the object's logical owner.
    SELECT NOT EXISTS(SELECT 1 FROM upload_slots WHERE id=OLD.object_id)
       AND NOT EXISTS(SELECT 1 FROM upload_storage_jobs
                       WHERE object_id=OLD.object_id)
      INTO releases_retained;
    UPDATE upload_storage_capacity_ledger SET pending_jobs=pending_jobs-1,
        cleanup_jobs_pending=cleanup_jobs_pending-1,
        legacy_overcommit_draining=(pending_jobs-1+cleanup_obligation_debt>
            LEAST(COALESCE(configured_pending_limit,absolute_disaster_limit),
                  absolute_disaster_limit)),
        retained_files=retained_files-CASE WHEN releases_retained THEN 1 ELSE 0 END,
        retained_bytes=retained_bytes-CASE WHEN releases_retained
            THEN OLD.expected_size ELSE 0 END,
        recovery_retained_files=recovery_retained_files-locator_units,
        recovery_retained_bytes=recovery_retained_bytes-
            locator_units*OLD.expected_size,
        recovery_overcommit_draining=(
            configured_retained_files_limit IS NOT NULL
            AND configured_retained_bytes_limit IS NOT NULL
            AND (
                retained_files-CASE WHEN releases_retained THEN 1 ELSE 0 END+
                    recovery_retained_files-locator_units>
                        configured_retained_files_limit
                OR retained_bytes-CASE WHEN releases_retained
                       THEN OLD.expected_size ELSE 0 END+
                    recovery_retained_bytes-locator_units*OLD.expected_size>
                        configured_retained_bytes_limit
            )),
        updated_at=pg_catalog.clock_timestamp() WHERE singleton;
    RETURN OLD;
END;
$account_upload_cleanup_capacity$;

DROP TRIGGER upload_job_capacity_delete ON upload_storage_jobs;
CREATE TRIGGER upload_job_capacity_delete
BEFORE DELETE ON upload_storage_jobs
FOR EACH ROW EXECUTE FUNCTION account_upload_storage_job_capacity();

DROP TRIGGER upload_cleanup_capacity_delete ON upload_cleanup_queue;
CREATE TRIGGER upload_cleanup_capacity_delete
BEFORE DELETE ON upload_cleanup_queue
FOR EACH ROW EXECUTE FUNCTION account_upload_cleanup_capacity();

-- Preserve the existing owner-held routines and prove the timing change has
-- not widened their SQL-security boundary or created a duplicate attachment.
DO $upload_projection_release_order_security$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    expected_path pg_catalog.text;
    routine_signature pg_catalog.text;
    topology_is_exact pg_catalog.bool;
BEGIN
    expected_path := pg_catalog.format(
        'search_path=pg_catalog, %I, pg_temp', migration_schema
    );
    FOREACH routine_signature IN ARRAY ARRAY[
        'account_upload_storage_job_capacity()',
        'account_upload_cleanup_capacity()'
    ] LOOP
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s RESET ALL', migration_schema, routine_signature
        );
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema, routine_signature, migration_schema
        );
        IF NOT EXISTS(
            SELECT 1
              FROM pg_catalog.pg_proc routine
              JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
             WHERE namespace.nspname=migration_schema
               AND routine.oid=pg_catalog.to_regprocedure(
                   pg_catalog.format('%I.%s',migration_schema,routine_signature)
               )
               AND routine.prosecdef
               AND routine.proconfig=ARRAY[expected_path]::pg_catalog.text[]
        ) THEN
            RAISE EXCEPTION 'upload capacity routine % was not rebound safely',routine_signature
                USING ERRCODE='55000';
        END IF;
    END LOOP;

    SELECT pg_catalog.count(*)=2 AND pg_catalog.bool_and(
               trigger_row.tgenabled IN ('O','A')
               AND trigger_row.tgqual IS NULL
               AND trigger_row.tgtype::pg_catalog.int4=expected.trigger_type
               AND function_row.oid=pg_catalog.to_regprocedure(
                   pg_catalog.format('%I.%s',migration_schema,expected.function_signature)
               )
           )
      INTO topology_is_exact
      FROM (VALUES
          ('upload_storage_jobs','upload_job_capacity_delete',
           'account_upload_storage_job_capacity()',11),
          ('upload_cleanup_queue','upload_cleanup_capacity_delete',
           'account_upload_cleanup_capacity()',11)
      ) AS expected(relation_name,trigger_name,function_signature,trigger_type)
      JOIN pg_catalog.pg_namespace namespace ON namespace.nspname=migration_schema
      JOIN pg_catalog.pg_class relation ON relation.relnamespace=namespace.oid
       AND relation.relname=expected.relation_name
      JOIN pg_catalog.pg_trigger trigger_row ON trigger_row.tgrelid=relation.oid
       AND trigger_row.tgname=expected.trigger_name
      JOIN pg_catalog.pg_proc function_row ON function_row.oid=trigger_row.tgfoid;
    IF NOT COALESCE(topology_is_exact,FALSE) THEN
        RAISE EXCEPTION 'upload projection delete triggers were not converted to exact BEFORE DELETE authority'
            USING ERRCODE='55000';
    END IF;
END;
$upload_projection_release_order_security$;
