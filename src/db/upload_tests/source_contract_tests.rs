//! Cleanup-debt model and source contracts on the upload migrations and code.

#[test]
fn cleanup_debt_converts_once_and_survives_every_slot_lifecycle() {
    #[derive(Default, Debug, Eq, PartialEq)]
    struct Ledger {
        pending: u64,
        debt: u64,
    }
    fn locator_first_materializes(ledger: &mut Ledger, reserved: &mut bool) {
        if !*reserved {
            ledger.debt += 1;
            *reserved = true;
        }
    }
    fn enqueue_cleanup(ledger: &mut Ledger, reserved: &mut bool, inserted: bool) {
        if !inserted {
            return;
        }
        ledger.pending += 1;
        if *reserved {
            ledger.debt -= 1;
            *reserved = false;
        }
    }
    fn finish_cleanup(ledger: &mut Ledger) {
        ledger.pending -= 1;
    }

    for _state in [
        "writing",
        "committed",
        "legacy_committed",
        "retention",
        "account-delete",
    ] {
        let mut ledger = Ledger::default();
        let mut reserved = false;
        locator_first_materializes(&mut ledger, &mut reserved);
        locator_first_materializes(&mut ledger, &mut reserved); // replay
        assert_eq!(
            ledger,
            Ledger {
                pending: 0,
                debt: 1
            }
        );
        enqueue_cleanup(&mut ledger, &mut reserved, true);
        enqueue_cleanup(&mut ledger, &mut reserved, false); // ON CONFLICT replay
        assert_eq!(
            ledger,
            Ledger {
                pending: 1,
                debt: 0
            }
        );
        finish_cleanup(&mut ledger);
        assert_eq!(ledger, Ledger::default());
    }

    // A migration orphan already has a pending projection and therefore
    // backfills no slot debt.
    let orphan = Ledger {
        pending: 1,
        debt: 0,
    };
    assert_eq!(orphan.pending + orphan.debt, 1);

    // Migration backfill reserves one cleanup debt for a legacy committed
    // locator. Exact cleanup admission converts it and confirmed removal
    // releases the sole pending projection.
    let mut legacy_committed = Ledger {
        pending: 0,
        debt: 1,
    };
    let mut legacy_reserved = true;
    enqueue_cleanup(&mut legacy_committed, &mut legacy_reserved, true);
    assert_eq!(
        legacy_committed,
        Ledger {
            pending: 1,
            debt: 0
        }
    );
    finish_cleanup(&mut legacy_committed);
    assert_eq!(legacy_committed, Ledger::default());

    // Staged/promoting deletion is represented by one cleanup row even
    // when local storage has distinct stage/object locators. S3's equal
    // stage/object key is likewise owned and released exactly once.
    for (backend, stage_equals_object) in [("local", false), ("s3", true)] {
        let mut ledger = Ledger {
            pending: 0,
            debt: 1,
        };
        let mut reserved = true;
        enqueue_cleanup(&mut ledger, &mut reserved, true);
        assert_eq!(
            ledger,
            Ledger {
                pending: 1,
                debt: 0
            },
            "{backend}"
        );
        assert_eq!(stage_equals_object, backend == "s3");
        finish_cleanup(&mut ledger);
        assert_eq!(ledger, Ledger::default(), "{backend}");
    }

    // A legacy migration may start above both the requested and absolute
    // ceilings. Debt conversion is net-zero and must remain possible;
    // only fresh work is rejected while deletion monotonically drains.
    let requested = 128_u64;
    let absolute = 100_000_u64;
    let mut legacy = Ledger {
        pending: 100_000,
        debt: 7,
    };
    let mut reserved = true;
    let before = legacy.pending + legacy.debt;
    enqueue_cleanup(&mut legacy, &mut reserved, true);
    assert_eq!(legacy.pending + legacy.debt, before);
    assert!(legacy.pending + legacy.debt > requested);
    assert!(legacy.pending + legacy.debt > absolute);
    while legacy.debt > 0 {
        reserved = true;
        enqueue_cleanup(&mut legacy, &mut reserved, true);
        finish_cleanup(&mut legacy);
    }
    while legacy.pending > 0 {
        finish_cleanup(&mut legacy);
    }
    assert_eq!(legacy, Ledger::default());
}

#[test]
fn shared_storage_migration_contains_cleanup_debt_atomicity_guards() {
    let sql = include_str!("../../../migrations/0091_shared_upload_storage.sql");
    for required in [
        "storage_cleanup_debt_reserved BOOLEAN NOT NULL DEFAULT FALSE",
        "cleanup_obligation_debt BIGINT NOT NULL CHECK(cleanup_obligation_debt>=0)",
        "legacy_overcommit_draining BOOLEAN NOT NULL DEFAULT FALSE",
        "CREATE TRIGGER upload_slot_cleanup_debt_reserve BEFORE UPDATE ON upload_slots",
        "cleanup_obligation_debt=cleanup_obligation_debt-",
        "AND cleanup_obligation_debt>=CASE WHEN converts_debt THEN 1 ELSE 0 END",
        "pending_jobs+cleanup_obligation_debt+",
        "IF OLD.storage_state='writing'",
        "AND (converts_debt OR (",
        "legacy_overcommit_draining=(pending_jobs-1+cleanup_obligation_debt>",
        "'committed','legacy_committed','deleting'",
    ] {
        assert!(sql.contains(required), "missing debt invariant: {required}");
    }

    // A job insertion converts a reserved obligation in the same ledger
    // UPDATE; there must be no second statement that creates a crash gap.
    let storage_capacity_fn = sql
        .split("CREATE FUNCTION account_upload_storage_job_capacity()")
        .nth(1)
        .and_then(|tail| tail.split("$$ LANGUAGE plpgsql SECURITY DEFINER").next())
        .expect("storage job capacity trigger function");
    assert_eq!(
        storage_capacity_fn
            .matches("cleanup_obligation_debt=cleanup_obligation_debt-")
            .count(),
        1
    );
    assert!(!storage_capacity_fn.contains("TG_TABLE_NAME"));
    let cleanup_capacity_fn = sql
        .split("CREATE FUNCTION account_upload_cleanup_capacity()")
        .nth(1)
        .and_then(|tail| tail.split("$$ LANGUAGE plpgsql SECURITY DEFINER").next())
        .expect("cleanup capacity trigger function");
    assert!(!cleanup_capacity_fn.contains(".action"));
    assert!(!cleanup_capacity_fn.contains("TG_TABLE_NAME"));
    for exact_identity in [
        "storage_backend=NEW.storage_backend",
        "storage_attempt IS NOT DISTINCT FROM NEW.storage_attempt",
        "storage_fence=NEW.storage_fence",
        "storage_stage_version IS NOT DISTINCT FROM NEW.stage_version",
        "storage_object_version IS NOT DISTINCT FROM NEW.object_version",
        "storage_sha256 IS NOT DISTINCT FROM NEW.expected_sha256",
        "COALESCE(storage_size,size)=NEW.expected_size",
    ] {
        assert!(
            sql.contains(exact_identity),
            "missing exact debt authority: {exact_identity}"
        );
    }
    assert_eq!(
        sql.matches("SECURITY DEFINER SET search_path=pg_catalog,pg_temp")
            .count(),
        3
    );
    let lowercase_sql = sql.to_ascii_lowercase();
    for invalid_alias in ["pg_catalog.bigint", "pg_catalog.boolean"] {
        assert!(
            !lowercase_sql.contains(invalid_alias),
            "schema-qualified PostgreSQL aliases do not resolve through pg_type: {invalid_alias}"
        );
    }
    assert_eq!(lowercase_sql.matches("pg_catalog.int8").count(), 1);
    assert_eq!(lowercase_sql.matches("pg_catalog.bool").count(), 2);
    assert!(!sql.contains("SECURITY DEFINER SET search_path=pg_catalog,public"));
    assert!(!sql.contains("SET search_path FROM CURRENT"));
    assert!(!lowercase_sql.contains("public."));
    assert!(sql.contains("migration_schema pg_catalog.text := pg_catalog.current_schema()"));
    assert_eq!(
        sql.matches("SET search_path TO pg_catalog, %I, pg_temp'")
            .count(),
        3
    );
    for secured_function in [
        "offline_upgrade_upload_storage_authority_v1_to_v2(",
        "account_upload_storage_job_capacity()",
        "account_upload_cleanup_capacity()",
    ] {
        assert!(
            sql.contains(&format!("ALTER FUNCTION %I.{secured_function}")),
            "missing fixed schema binding for {secured_function}"
        );
    }
    for rejected_schema in [
        "'pg_catalog','information_schema'",
        "LIKE 'pg_temp_%'",
        "LIKE 'pg_toast_temp_%'",
    ] {
        assert!(sql.contains(rejected_schema));
    }
    for prerequisite in [
        "'upload_slots'",
        "'upload_cleanup_queue'",
        "'upload_cleanup_queue_order_idx'",
    ] {
        assert!(
            sql.contains(&format!(
                "pg_catalog.to_regclass(pg_catalog.format('%I.%I',target_schema,{prerequisite}))"
            )),
            "migration schema guard is missing {prerequisite}"
        );
    }
    assert!(storage_capacity_fn.contains("UPDATE upload_storage_capacity_ledger"));
    assert!(cleanup_capacity_fn.contains("UPDATE upload_storage_capacity_ledger"));
    assert!(sql.contains(
        "REVOKE INSERT,UPDATE,DELETE ON upload_storage_jobs,upload_cleanup_queue FROM PUBLIC"
    ));

    let authority_position = sql
        .find("CREATE FUNCTION offline_upgrade_upload_storage_authority_v1_to_v2(")
        .expect("offline upload authority function");
    for relation in [
        "CREATE TABLE upload_storage_jobs (",
        "ALTER TABLE upload_cleanup_queue ADD CONSTRAINT upload_cleanup_queue_state_check",
    ] {
        assert!(
            sql.find(relation).expect("offline authority dependency") < authority_position,
            "offline authority function was created before dependency: {relation}"
        );
    }
    let fixed_path_position = sql
        .find("$northstar_upload_function_paths$;")
        .expect("completed SECURITY DEFINER path binding");
    for trigger in [
        "CREATE TRIGGER upload_job_capacity_insert",
        "CREATE TRIGGER upload_job_capacity_delete",
        "CREATE TRIGGER upload_cleanup_capacity_insert",
        "CREATE TRIGGER upload_cleanup_capacity_delete",
    ] {
        assert!(
            sql.find(trigger).expect("capacity trigger") > fixed_path_position,
            "capacity trigger was attached before its function had a fixed schema: {trigger}"
        );
    }

    let cascade_fn = sql
        .split("CREATE FUNCTION queue_upload_storage_delete()")
        .nth(1)
        .and_then(|tail| tail.split("$$ LANGUAGE plpgsql;").next())
        .expect("cascade cleanup trigger function");
    assert!(cascade_fn.contains("IF OLD.storage_state='writing'"));
    assert_eq!(
        cascade_fn
            .matches("INSERT INTO upload_storage_jobs")
            .count(),
        1
    );
    assert_eq!(
        cascade_fn
            .matches("INSERT INTO upload_cleanup_queue")
            .count(),
        1
    );
    assert!(cascade_fn.contains("RETURN OLD;"));
}

#[test]
fn upload_cascade_capacity_requires_explicit_immutable_provenance() {
    let migration = include_str!("../../../migrations/0105_upload_cascade_cleanup_capacity.sql");
    for required in [
        "ADD COLUMN slot_delete_projection pg_catalog.bool NOT NULL DEFAULT FALSE",
        "ADD COLUMN recovery_retained_files pg_catalog.int8 NOT NULL DEFAULT 0",
        "ADD COLUMN recovery_retained_bytes pg_catalog.int8 NOT NULL DEFAULT 0",
        "ADD COLUMN configured_retained_files_limit pg_catalog.int8",
        "ADD COLUMN configured_retained_bytes_limit pg_catalog.int8",
        "ADD COLUMN recovery_overcommit_draining pg_catalog.bool NOT NULL DEFAULT FALSE",
        "ALTER TABLE upload_storage_jobs ALTER COLUMN expected_size SET NOT NULL",
        "matching_triggers<>1",
        "trigger_row.tgname='upload_storage_delete_queue'",
        "function_row.proname='queue_upload_storage_delete'",
        "trigger_row.tgenabled IN ('O','A')",
        "trigger_row.tgqual IS NULL",
        "trigger_row.tgtype::pg_catalog.int4=11",
        "'upload_storage_job_identity_guard'",
        "'upload_cleanup_identity_guard'",
        "'upload_capacity_policy_guard'",
        "must have one exact attachment in the installation schema",
        "must have exactly one INSERT and one DELETE attachment",
        "ON CONFLICT(object_id) DO NOTHING",
        "IF OLD.storage_cleanup_debt_reserved THEN",
        "NEW.slot_delete_projection IS DISTINCT FROM OLD.slot_delete_projection",
        "IF pg_catalog.pg_trigger_depth()<=1 THEN",
        "IF NOT converts_debt THEN",
        "IF converts_debt AND NOT NEW.slot_delete_projection THEN",
        "recovery_retained_files=recovery_retained_files+1",
        "recovery_retained_files=recovery_retained_files+locator_units",
        "recovery_retained_files=recovery_retained_files-1",
        "recovery_retained_files=recovery_retained_files-locator_units",
        "hand ownership back to",
        "requested_retained_files_limit pg_catalog.int8",
        "requested_retained_bytes_limit pg_catalog.int8",
        "upload retained-file and retained-byte limits must also be bound",
        "upload storage capacity policy is not fully bound",
        "COALESCE(OLD.storage_object_version,OLD.storage_stage_version)",
        "SECURITY DEFINER",
        "SET search_path TO pg_catalog, %I, pg_temp",
        "REVOKE ALL ON FUNCTION %I.%I() FROM PUBLIC",
        "pg_catalog.count(*)=11",
        "'reserve_upload_cleanup_debt'",
    ] {
        assert!(
            migration.contains(required),
            "missing cascade-capacity invariant: {required}"
        );
    }
    assert_eq!(
        migration
            .matches("ADD COLUMN slot_delete_projection")
            .count(),
        1
    );
    assert_eq!(
        migration
            .matches("NEW.slot_delete_projection IS DISTINCT FROM OLD.slot_delete_projection")
            .count(),
        1
    );
    assert_eq!(
        migration
            .matches("IF pg_catalog.pg_trigger_depth()<=1 THEN")
            .count(),
        1
    );
    let delete_trigger = migration
        .split("CREATE OR REPLACE FUNCTION queue_upload_storage_delete()")
        .nth(1)
        .and_then(|tail| tail.split("$$ LANGUAGE plpgsql;").next())
        .expect("replacement upload delete trigger");
    assert!(delete_trigger.contains("TRUE"));
    assert!(!delete_trigger.contains("INSERT INTO upload_storage_jobs"));
    assert!(!delete_trigger.contains("DO UPDATE SET"));
    assert_eq!(
        delete_trigger
            .matches("GET DIAGNOSTICS inserted_count=ROW_COUNT")
            .count(),
        1
    );
    assert_eq!(delete_trigger.matches("existing upload ").count(), 1);
    assert!(delete_trigger.contains("queue.storage_fence=OLD.storage_fence"));
    assert_eq!(
        migration
            .matches("RAISE EXCEPTION 'upload storage capacity policy is not fully bound'")
            .count(),
        3
    );

    let storage_capacity = migration
        .split("CREATE OR REPLACE FUNCTION account_upload_storage_job_capacity()")
        .nth(1)
        .and_then(|tail| tail.split("$$ LANGUAGE plpgsql;").next())
        .expect("replacement storage-job capacity trigger");
    assert!(!storage_capacity.contains("slot_delete_projection"));
    assert!(storage_capacity.contains("IF NOT policy_bound THEN"));
    assert!(!storage_capacity.contains("AND configured_pending_limit IS NOT NULL"));
    let cleanup_capacity = migration
        .split("CREATE OR REPLACE FUNCTION account_upload_cleanup_capacity()")
        .nth(1)
        .and_then(|tail| tail.split("$$ LANGUAGE plpgsql;").next())
        .expect("replacement cleanup capacity trigger");
    assert!(cleanup_capacity.contains("locator_units"));
    assert!(cleanup_capacity.contains("IF NOT policy_bound THEN"));
    assert!(!cleanup_capacity.contains("AND configured_pending_limit IS NOT NULL"));

    // Deletion has exactly one queue authority. Neither application path
    // may race it by pre-inserting a second cleanup projection.
    for source in [
        crate::db::users::module_source().as_str(),
        crate::tools::pie::module_source().as_str(),
        include_str!("../pie.rs"),
    ] {
        assert!(!source.contains("INSERT INTO upload_cleanup_queue"));
    }
    let account_delete = include_str!("../users.rs")
        .split("async fn delete_user_with_roster_inner(")
        .nth(1)
        .and_then(|tail| {
            tail.split("pub(super) async fn delete_user_with_roster_locked_in_transaction(")
                .next()
        })
        .expect("self-service account deletion implementation");
    let capacity_lock = account_delete
        .find("SELECT northstar_upload_capacity_lock()")
        .expect("account deletion capacity lock");
    let mutation_timeout = account_delete
        .find("SET LOCAL lock_timeout='2s'")
        .expect("account deletion post-admission mutation timeout");
    assert!(
            !account_delete.contains("SET LOCAL lock_timeout='50ms'")
                && capacity_lock < mutation_timeout,
            "account deletion must use SQL-native NOWAIT capacity admission before its normal mutation bound"
        );
    let pie = include_str!("../pie.rs");
    let capacity_lock = pie
        .find("SELECT northstar_upload_capacity_lock()")
        .expect("PIE replacement capacity lock");
    let domain_lock = pie
        .find("pg_advisory_xact_lock(hashtextextended($1, 227))")
        .expect("PIE domain lock");
    let user_lock = pie
        .find("SELECT id,is_admin FROM users WHERE username=$1 FOR UPDATE")
        .expect("PIE user lock");
    assert!(
        !pie.contains("SET LOCAL lock_timeout='50ms'")
            && capacity_lock < domain_lock
            && domain_lock < user_lock,
        "PIE must use SQL-native NOWAIT admission without shortening replacement work"
    );

    let upload_source = super::super::module_source();
    let authority = include_str!("../../../migrations/0113_upload_authority_capabilities.sql");
    for capability in [
        "northstar_upload_reserve_slot(",
        "northstar_upload_claim_slot(",
        "northstar_upload_record_stage(",
        "northstar_upload_complete_promotion(",
        "northstar_upload_admit_expired_cleanup(",
        "northstar_upload_delete_owned(",
    ] {
        assert!(
            authority.contains(&format!("CREATE FUNCTION {capability}")),
            "missing owner-held upload capability: {capability}"
        );
    }
    for invariant in [
        "ON CONFLICT(object_id,storage_attempt,action) DO NOTHING",
        "ON CONFLICT(object_id) DO NOTHING",
        "existing upload promotion projection has different identity",
        "existing upload cleanup projection differs or retained debt",
        "REVOKE ALL ON TABLE upload_storage_authority",
    ] {
        assert!(
            authority.contains(invariant),
            "missing upload invariant: {invariant}"
        );
    }
    // `upload_slots.content_type` is VARCHAR(255), while the public
    // capabilities intentionally expose TEXT. PL/pgSQL RETURN QUERY does
    // not apply that conversion implicitly, so every projection must keep
    // an explicit cast or the first PUT fails at runtime.
    assert_eq!(
        authority
            .matches("slot_row.content_type::pg_catalog.text")
            .count(),
        2,
        "upload claim replay/acquire projections must cast VARCHAR to TEXT"
    );
    assert!(
        authority.contains("slot.content_type::pg_catalog.text"),
        "public upload-file projection must cast VARCHAR to TEXT"
    );
    for (function_name, terminator) in [
        (
            "northstar_upload_confirm_cleanup_absence",
            "$northstar_upload_confirm_cleanup_absence$;",
        ),
        (
            "northstar_upload_confirm_stage_absence",
            "$northstar_upload_confirm_stage_absence$;",
        ),
    ] {
        let body = authority
            .split(&format!("CREATE FUNCTION {function_name}("))
            .nth(1)
            .and_then(|tail| tail.split(terminator).next())
            .expect("absence-fence capability");
        assert_eq!(
            body.matches("attempts=GREATEST(attempts-1,0)").count(),
            1,
            "a successful quiet-window observation must preserve retry capacity"
        );
    }
    let authorized_delete = upload_source
        .split("pub async fn queue_user_upload_delete_authorized(")
        .nth(1)
        .and_then(|tail| tail.split("#[cfg(test)]").next())
        .expect("authorized upload-delete implementation");
    let input_validation = authorized_delete
        .find("presented_session.len() != 64")
        .expect("authorized upload-delete bearer validation");
    let session_hash = authorized_delete
        .find("northstar_auth_core::token_hash(presented_session)")
        .expect("authorized upload-delete bearer hashing");
    let capability = authorized_delete
        .find("northstar_upload_delete_owned")
        .expect("authorized upload-delete typed capability");
    assert!(input_validation < capability && capability < session_hash);
}

#[test]
fn upload_capability_lock_scope_matches_cleanup_debt_invariant() {
    let source = super::super::module_source();
    let authority = include_str!("../../../migrations/0113_upload_authority_capabilities.sql");
    let nowait = include_str!("../../../migrations/0131_upload_capacity_nowait.sql");
    let trigger = nowait
        .split("CREATE OR REPLACE FUNCTION reserve_upload_cleanup_debt()")
        .nth(1)
        .and_then(|tail| {
            tail.split("$northstar_reserve_upload_cleanup_debt$;")
                .next()
        })
        .expect("cleanup-debt trigger definition");
    for condition in [
        "NOT OLD.storage_cleanup_debt_reserved",
        "(NEW.storage_object_key IS NOT NULL OR NEW.storage_stage_key IS NOT NULL)",
        "NOT EXISTS(",
        "PERFORM northstar_upload_require_capacity_lock()",
    ] {
        assert!(
            trigger.contains(condition),
            "cleanup-debt trigger must retain its precise admission condition: {condition}"
        );
    }
    let capacity_primitive = nowait
        .split("CREATE FUNCTION northstar_upload_require_capacity_lock()")
        .nth(1)
        .and_then(|tail| {
            tail.split("$northstar_upload_require_capacity_lock$;")
                .next()
        })
        .expect("private SQL-native capacity primitive");
    assert!(capacity_primitive.contains("FOR UPDATE NOWAIT"));
    assert!(capacity_primitive.contains("ERRCODE='55000'"));
    assert!(nowait.contains("CREATE FUNCTION guard_upload_capacity_nowait()"));
    for trigger_name in [
        "northstar_upload_capacity_nowait_slots_insert_delete",
        "northstar_upload_capacity_nowait_slot_locator_update",
        "northstar_upload_capacity_nowait_storage_job_insert_delete",
        "northstar_upload_capacity_nowait_cleanup_insert_delete",
    ] {
        assert!(
            nowait.contains(&format!("CREATE TRIGGER {trigger_name}")),
            "implicit capacity mutator must take the NOWAIT guard first: {trigger_name}"
        );
    }

    let claim_capability = authority
        .split("CREATE FUNCTION northstar_upload_claim_slot(")
        .nth(1)
        .and_then(|tail| tail.split("$northstar_upload_claim_slot$;").next())
        .expect("claim capability definition");
    let capacity_lock = claim_capability
        .find("FROM upload_storage_capacity_ledger")
        .expect("claim capability capacity lock");
    let first_debt_transition = claim_capability
        .find("SET uploading=TRUE,claim_token=new_claim")
        .expect("claim capability writes new attempt locators");
    assert!(
        capacity_lock < first_debt_transition
            && claim_capability.contains("storage_stage_key=new_stage_key")
            && claim_capability.contains("storage_object_key=new_object_key"),
        "only claim may introduce new locators, and it must acquire capacity first"
    );

    // Reservation and claim have no Rust lock-timeout wrapper. Their SQL
    // contracts preserve `false` and `in_progress` for both ledger and
    // later user/slot contention.
    for (name, next) in [
        (
            "create_upload_slot_bounded",
            "pub async fn validate_upload_storage_backend(",
        ),
        ("claim_upload_slot", "pub async fn renew_upload_claim("),
    ] {
        let body = source
            .split(&format!("pub async fn {name}("))
            .nth(1)
            .and_then(|tail| tail.split(next).next())
            .unwrap_or_else(|| panic!("{name} implementation"));
        assert!(
            !body.contains("lock_timeout") && !body.contains("northstar_upload_capacity_lock"),
            "{name} must rely exclusively on its typed SQL NOWAIT capability"
        );
    }

    let reserve = nowait
        .split("CREATE OR REPLACE FUNCTION northstar_upload_reserve_slot(")
        .nth(1)
        .and_then(|tail| tail.split("$northstar_upload_reserve_slot$;").next())
        .expect("replacement reserve capability");
    let reserve_ledger = reserve
        .find("FROM upload_storage_capacity_ledger\n         WHERE singleton FOR UPDATE NOWAIT")
        .expect("reserve capacity acquisition");
    let reserve_owner = reserve
        .find("users WHERE id=requested_user_id FOR UPDATE NOWAIT")
        .expect("reserve owner acquisition");
    let reserve_handler = reserve
        .find("WHEN lock_not_available THEN")
        .expect("reserve subtransaction contention handler");
    assert!(
            reserve_ledger < reserve_owner && reserve_owner < reserve_handler,
            "reserve must place ledger and owner NOWAIT acquisitions in one rollback-capable subtransaction"
        );
    assert!(
            reserve.contains("northstar_upload_reserve_slot_not_admitted")
                && reserve.contains("WHEN SQLSTATE 'P0001' THEN")
                && reserve.contains("GET STACKED DIAGNOSTICS caught_message = MESSAGE_TEXT"),
            "typed false outcomes must abort the capacity-acquiring subtransaction rather than retain its ledger lock"
        );
    let claim = nowait
        .split("CREATE OR REPLACE FUNCTION northstar_upload_claim_slot(")
        .nth(1)
        .and_then(|tail| tail.split("$northstar_upload_claim_slot$;").next())
        .expect("replacement claim capability");
    let claim_ledger = claim
        .find("FROM upload_storage_capacity_ledger\n       WHERE singleton FOR UPDATE NOWAIT")
        .expect("claim capacity acquisition");
    let claim_ledger_lock = claim[claim_ledger..]
        .find("FOR UPDATE NOWAIT;")
        .map(|offset| claim_ledger + offset)
        .expect("claim capacity lock clause");
    let claim_slot = claim[claim_ledger_lock + "FOR UPDATE NOWAIT;".len()..]
        .find("FOR UPDATE NOWAIT;")
        .map(|offset| claim_ledger_lock + "FOR UPDATE NOWAIT;".len() + offset)
        .expect("claim target-slot acquisition");
    let claim_handler = claim
        .find("WHEN lock_not_available THEN")
        .expect("claim subtransaction contention handler");
    assert!(
        claim_ledger < claim_ledger_lock
            && claim_ledger_lock < claim_slot
            && claim_slot < claim_handler,
        "claim must put ledger and slot NOWAIT acquisitions in one rollback-capable subtransaction"
    );
    assert!(
            claim.contains("northstar_upload_claim_slot_not_admitted")
                && claim.contains("WHEN SQLSTATE 'P0001' THEN")
                && claim.contains("RETURN NEXT;\n        RETURN;"),
            "typed claim outcomes must be emitted after rolling back the capacity-acquiring subtransaction"
        );

    // These state-only paths run only after claim established debt (or
    // while an exact same-slot cleanup projection exists).  They must stay
    // independent of unrelated capacity work.
    for (name, next) in [
        ("renew_upload_claim", "pub async fn release_upload_claim("),
        (
            "begin_upload_promotion",
            "pub async fn claim_upload_promotion_job(",
        ),
        ("record_upload_replay", "pub async fn uploaded_file("),
        (
            "claim_upload_scrub_jobs",
            "pub async fn complete_upload_scrub(",
        ),
        ("finish_upload_scrub", "#[cfg(test)]"),
    ] {
        let prefix = if name == "finish_upload_scrub" {
            "async fn"
        } else {
            "pub async fn"
        };
        let body = source
            .split(&format!("{prefix} {name}("))
            .nth(1)
            .and_then(|tail| tail.split(next).next())
            .unwrap_or_else(|| panic!("{name} implementation"));
        assert!(
            !body.contains("lock_timeout") && !body.contains("northstar_upload_capacity_lock"),
            "healthy {name} must not serialize on the global capacity ledger"
        );
    }

    for (function_name, terminator, proof) in [
        (
            "northstar_upload_renew_claim",
            "$northstar_upload_renew_claim$;",
            "storage_cleanup_debt_reserved",
        ),
        (
            "northstar_upload_begin_promotion",
            "$northstar_upload_begin_promotion$;",
            "storage_state IN ('staged','promoting')",
        ),
        (
            "northstar_upload_record_replay",
            "$northstar_upload_record_replay$;",
            "AND uploaded",
        ),
        (
            "northstar_upload_claim_scrub",
            "$northstar_upload_claim_scrub$;",
            "storage_state='committed'",
        ),
        (
            "northstar_upload_finish_scrub",
            "$northstar_upload_finish_scrub$;",
            "storage_scrub_claim_token=requested_claim",
        ),
    ] {
        let body = authority
            .split(&format!("CREATE FUNCTION {function_name}("))
            .nth(1)
            .and_then(|tail| tail.split(terminator).next())
            .unwrap_or_else(|| panic!("{function_name} definition"));
        assert!(
            body.contains(proof),
            "{function_name} must retain its state fence proving no new cleanup debt"
        );
    }

    for (name, next, capability) in [
        (
            "release_upload_claim",
            "/// Used by startup recovery",
            "northstar_upload_release_claim",
        ),
        (
            "record_upload_stage",
            "pub async fn begin_upload_promotion",
            "northstar_upload_record_stage",
        ),
        (
            "complete_promoted_upload",
            "/// Resolve the only benign",
            "northstar_upload_complete_promotion",
        ),
        (
            "retire_upload_promotion_for_cleanup",
            "#[cfg(test)]",
            "northstar_upload_retire_promotion_for_cleanup",
        ),
        (
            "cleanup_expired_upload_slots",
            "pub async fn queued_upload_cleanup",
            "northstar_upload_admit_expired_cleanup",
        ),
        (
            "complete_queued_upload_cleanup",
            "/// A deletion claimant",
            "northstar_upload_complete_cleanup",
        ),
        (
            "complete_upload_storage_job",
            "pub async fn confirm_upload_stage_absence",
            "northstar_upload_complete_storage_job",
        ),
        (
            "queue_user_upload_delete_authorized",
            "#[cfg(test)]",
            "northstar_upload_delete_owned",
        ),
    ] {
        let body = source
            .split(&format!("pub async fn {name}("))
            .nth(1)
            .and_then(|tail| tail.split(next).next())
            .unwrap_or_else(|| panic!("{name} implementation"));
        assert!(
            !body.contains("lock_timeout"),
            "{name} must rely on SQL-native NOWAIT capacity admission"
        );
        let definition = nowait
            .split(&format!("CREATE OR REPLACE FUNCTION {capability}("))
            .nth(1)
            .unwrap_or_else(|| panic!("{capability} migration definition"));
        assert!(
            definition.contains("PERFORM northstar_upload_require_capacity_lock();"),
            "{capability} must acquire the SQL-native capacity primitive first"
        );
    }
    let cleanup_completion = source
        .split("pub async fn complete_queued_upload_cleanup(")
        .nth(1)
        .and_then(|tail| {
            tail.split("pub async fn upload_cleanup_generation_is_quiescent(")
                .next()
        })
        .expect("upload cleanup completion implementation");
    assert!(
        cleanup_completion.contains("fetch_one(pool)")
            && !cleanup_completion.contains("lock_timeout"),
        "Run70 cleanup completion must expose SQL-native NOWAIT contention"
    );
    // Inspect the production portion only. The test's own literal
    // assertion names must not make a source-wide containment check
    // self-referential.
    let runtime_source = source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .expect("production upload source before its test module");
    assert!(!runtime_source.contains("begin_bounded_upload_admission"));
    assert!(!runtime_source.contains("finish_retryable_upload_capacity_mutation"));
}

#[test]
fn upload_projection_release_migration_uses_predelete_last_owner_cas() {
    let migration = include_str!("../../../migrations/0140_upload_projection_release_order.sql");
    for trigger in [
            "DROP TRIGGER upload_job_capacity_delete ON upload_storage_jobs;\nCREATE TRIGGER upload_job_capacity_delete\nBEFORE DELETE ON upload_storage_jobs",
            "DROP TRIGGER upload_cleanup_capacity_delete ON upload_cleanup_queue;\nCREATE TRIGGER upload_cleanup_capacity_delete\nBEFORE DELETE ON upload_cleanup_queue",
        ] {
            assert!(
                migration.contains(trigger),
                "upload projection release must make its delete trigger BEFORE DELETE: {trigger}"
            );
        }
    let storage_delete = migration
        .split("-- This is a BEFORE DELETE trigger.")
        .nth(1)
        .and_then(|tail| tail.split("$account_upload_storage_job_capacity$;").next())
        .expect("storage-job BEFORE DELETE body");
    assert!(storage_delete.contains("id<>OLD.id"));
    assert!(storage_delete
        .contains("recovery_retained_bytes=recovery_retained_bytes-OLD.expected_size"));
    let cleanup_delete = migration
        .split("-- `upload_cleanup_queue.object_id` is the primary key")
        .nth(1)
        .and_then(|tail| tail.split("$account_upload_cleanup_capacity$;").next())
        .expect("cleanup BEFORE DELETE body");
    assert!(cleanup_delete.contains("NOT EXISTS(SELECT 1 FROM upload_storage_jobs"));
    assert!(cleanup_delete.contains("locator_units*OLD.expected_size"));
    assert!(migration.contains(
        "upload projection delete triggers were not converted to exact BEFORE DELETE authority"
    ));
}

#[test]
fn upload_runtime_health_scans_are_bounded_and_timeout_fail_closed() {
    let migration =
        include_str!("../../../migrations/0115_upload_runtime_reconciliation_bounds.sql");
    assert!(!migration.contains("public."));
    assert_eq!(migration.matches("LIMIT 1001").count(), 4);
    for invariant in [
        "CREATE INDEX IF NOT EXISTS upload_storage_jobs_dead_idx",
        "CREATE INDEX IF NOT EXISTS upload_cleanup_queue_recovery_dead_idx",
        "CREATE INDEX IF NOT EXISTS upload_slots_storage_scrub_failures_idx",
        "bounded_dead_letters",
        "bounded_scrub_failures",
        "1001 means at least 1001",
        "routine.proowner=migration_owner",
    ] {
        assert!(
            migration.contains(invariant),
            "missing runtime reconciliation bound: {invariant}"
        );
    }
    for invariant in [
        "REVOKE ALL ON FUNCTION %I.northstar_upload_queue_snapshot() FROM PUBLIC CASCADE",
        "WHERE routine.oid=routine_oid)<>1",
        "privilege.grantee<>routine.proowner",
        "privilege.grantor<>routine.proowner",
        "bounded upload queue snapshot has unsafe owner, language, search_path, or non-owner ACL",
    ] {
        assert!(
            migration.contains(invariant),
            "missing fail-closed runtime snapshot ACL guard: {invariant}"
        );
    }

    let source = super::super::module_source();
    let reconciliation = source
        .split("pub async fn reconcile_upload_capacity_ledger(")
        .nth(1)
        .and_then(|tail| tail.split("/// Return a bounded snapshot").next())
        .expect("exact upload reconciliation implementation");
    for bound in [
        "SET TRANSACTION READ ONLY",
        "SET LOCAL lock_timeout='2s'",
        "SET LOCAL statement_timeout='15s'",
    ] {
        assert!(
            reconciliation.contains(bound),
            "missing exact-scan bound: {bound}"
        );
    }
    let snapshot = source
        .split("pub async fn upload_queue_metrics(")
        .nth(1)
        .and_then(|tail| tail.split("fn upload_queue_metrics_from_row").next())
        .expect("bounded upload metrics implementation");
    for bound in [
        "SET TRANSACTION READ ONLY",
        "SET LOCAL lock_timeout='1s'",
        "SET LOCAL statement_timeout='2s'",
    ] {
        assert!(
            snapshot.contains(bound),
            "missing health-scan bound: {bound}"
        );
    }
    let worker =
        include_str!("../../../crates/contexts/upload/northstar-upload-application/src/worker.rs");
    assert!(worker.contains("snapshot.dead_letter_jobs_capped"));
    assert!(worker.contains("snapshot.scrub_failures_capped"));
}
