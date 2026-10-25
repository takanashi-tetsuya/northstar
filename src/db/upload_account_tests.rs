//! Upload invariants shared with account deletion, the PIE import and API sessions. They read or call
//! root-crate code, so they stay with the composition root; the other upload PostgreSQL tests live in
//! northstar-upload-postgres.

use crate::db;
use northstar_upload_postgres::{
    claim_upload_slot, cleanup_expired_upload_slots, complete_queued_upload_cleanup,
    complete_upload, create_upload_slot, is_retryable_upload_capacity_lock,
    queue_user_upload_delete, queue_user_upload_delete_authorized, queued_upload_cleanup,
    record_upload_replay, release_upload_claim, renew_upload_claim, uploaded_file,
    validate_upload_capacity_policy, UploadClaimOutcome, UploadRenewOutcome, UploadReservation,
    UserUploadDeleteOutcome, MAX_UPLOAD_ATTEMPTS, TEST_UPLOAD_PENDING_LIMIT,
    TEST_UPLOAD_RETAINED_BYTES_LIMIT, TEST_UPLOAD_RETAINED_FILES_LIMIT,
};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Barrier;
use uuid::Uuid;

async fn insert_user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let username = format!("upload-{}", &id.simple().to_string()[..16]);
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, is_admin)
             VALUES ($1, $2, 'test-only', FALSE)",
    )
    .bind(id)
    .bind(username)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[test]
fn upload_cascade_capacity_requires_explicit_immutable_provenance() {
    let migration = include_str!("../../migrations/0105_upload_cascade_cleanup_capacity.sql");
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
        include_str!("pie.rs"),
    ] {
        assert!(!source.contains("INSERT INTO upload_cleanup_queue"));
    }
    let account_delete = include_str!("users.rs")
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
    let pie = include_str!("pie.rs");
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

    let upload_source = northstar_upload_postgres::module_source();
    let authority = include_str!("../../migrations/0113_upload_authority_capabilities.sql");
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
        .and_then(|tail| {
            tail.split("#[cfg(any(test, feature = \"test-support\"))]")
                .next()
        })
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

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn account_delete_and_upload_mutations_share_retryable_ledger_first_order() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    validate_upload_capacity_policy(
        &pool,
        TEST_UPLOAD_PENDING_LIMIT,
        TEST_UPLOAD_RETAINED_FILES_LIMIT,
        TEST_UPLOAD_RETAINED_BYTES_LIMIT,
    )
    .await
    .unwrap();
    let user_id = insert_user(&pool).await;
    let token = b"lock-order-token";
    let slot_id = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "lock-order.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: token,
            max_files_per_user: 10,
            max_bytes_per_user: 10,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let active_lease = match claim_upload_slot(&pool, slot_id, token, 90).await.unwrap() {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected initial upload claim outcome: {other:?}"),
    };

    // Model the prefix of account deletion: global ledger, then user.
    // Claim's SQL capability has a NOWAIT ledger admission; ordinary lease
    // renewal does not touch capacity authority. Generic capacity paths
    // and implicit trigger accounting must return SQLSTATE 55P03 without
    // waiting behind this owner.
    let mut account_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE")
        .fetch_one(&mut *account_tx)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user_id)
        .fetch_one(&mut *account_tx)
        .await
        .unwrap();
    assert!(matches!(
        claim_upload_slot(&pool, slot_id, token, 90).await.unwrap(),
        UploadClaimOutcome::InProgress { .. }
    ));
    assert_eq!(
        renew_upload_claim(&pool, slot_id, active_lease.claim_token, 90)
            .await
            .unwrap(),
        UploadRenewOutcome::Renewed,
        "a healthy lease renewal must remain independent of unrelated capacity work"
    );
    let queue_error = queue_user_upload_delete(&pool, user_id, slot_id, Uuid::new_v4())
        .await
        .unwrap_err();
    assert!(queue_error
        .to_string()
        .contains("upload storage capacity busy; retry"));
    let trigger_error = tokio::time::timeout(
        Duration::from_secs(1),
        sqlx::query(
            "INSERT INTO upload_cleanup_queue(
                     object_id,storage_backend,object_key,expected_size,storage_fence)
                 VALUES($1,'local',$1::text,1,0)",
        )
        .bind(Uuid::new_v4())
        .execute(&pool),
    )
    .await
    .expect("implicit cleanup accounting must reject a held ledger promptly")
    .unwrap_err();
    assert!(
        is_retryable_upload_capacity_lock(&trigger_error),
        "implicit upload cleanup accounting must expose SQLSTATE 55P03: {trigger_error}"
    );
    let completion_error = tokio::time::timeout(
        Duration::from_secs(1),
        complete_queued_upload_cleanup(&pool, Uuid::new_v4(), Uuid::new_v4()),
    )
    .await
    .expect("cleanup completion must reject ledger contention without waiting for the outer test")
    .unwrap_err();
    assert!(
            completion_error
                .chain()
                .filter_map(|cause| cause.downcast_ref::<sqlx::Error>())
                .any(is_retryable_upload_capacity_lock),
            "generic cleanup completion must preserve SQLSTATE 55P03 for central retry mapping: {completion_error:#}"
        );
    account_tx.rollback().await.unwrap();

    // A committed replay cannot establish another cleanup obligation: it
    // must remain available while unrelated work holds the singleton.
    let replay_digest = [7_u8; 32];
    assert!(complete_upload(
        &pool,
        slot_id,
        active_lease.claim_token,
        &replay_digest,
        600,
    )
    .await
    .unwrap());
    let mut healthy_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE")
        .fetch_one(&mut *healthy_tx)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            record_upload_replay(&pool, slot_id, token, &replay_digest),
        )
        .await
        .expect("committed replay must not wait for unrelated capacity authority")
        .unwrap(),
        "committed replay must retain normal dedupe accounting"
    );
    healthy_tx.rollback().await.unwrap();

    // `reserve_slot` takes ledger then user internally. Both acquisitions
    // are SQL NOWAIT, so user-row contention preserves the established
    // unavailable result and releases the singleton with no Rust-side
    // timeout or pre-acquisition.
    let mut user_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user_id)
        .fetch_one(&mut *user_tx)
        .await
        .unwrap();
    let reservation = tokio::time::timeout(
        Duration::from_secs(1),
        create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "user-row-contention.bin",
                content_type: "application/octet-stream",
                size: 1,
                token_hash: b"user-row-contention",
                max_files_per_user: 10,
                max_bytes_per_user: 10,
                storage_backend: "local",
            },
        ),
    )
    .await
    .expect("reservation must not retain the ledger behind a user-row lock")
    .unwrap();
    assert!(reservation.is_none());
    sqlx::query(
        "SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_one(&pool)
    .await
    .expect("reservation contention must release the global ledger");
    user_tx.rollback().await.unwrap();

    // The same requirement applies to the sole debt-creating claim
    // transition: its SQL capability uses NOWAIT for both the ledger and
    // target slot, returning the established retry result without holding
    // the capability transaction behind either owner.
    let contention_slot = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "slot-row-contention.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: b"slot-row-contention",
            max_files_per_user: 10,
            max_bytes_per_user: 10,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let mut slot_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM upload_slots WHERE id=$1 FOR UPDATE")
        .bind(contention_slot)
        .fetch_one(&mut *slot_tx)
        .await
        .unwrap();
    let claim = tokio::time::timeout(
        Duration::from_secs(1),
        claim_upload_slot(&pool, contention_slot, b"slot-row-contention", 90),
    )
    .await
    .expect("claim must not retain the ledger behind a slot-row lock")
    .unwrap();
    assert!(matches!(
        claim,
        UploadClaimOutcome::InProgress {
            retry_after_seconds: 1
        }
    ));
    sqlx::query(
        "SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_one(&pool)
    .await
    .expect("claim contention must release the global ledger");
    slot_tx.rollback().await.unwrap();

    // Reverse pressure: a cleanup owner holds ledger then its queue row.
    // Account deletion must surface the SQL-native 55P03 before it locks
    // the user and can form a cycle.
    let cleanup_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,expected_size,storage_fence)
             VALUES($1,'local',$1::text,1,0)",
    )
    .bind(cleanup_id)
    .execute(&pool)
    .await
    .unwrap();
    let mut cleanup_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE")
        .fetch_one(&mut *cleanup_tx)
        .await
        .unwrap();
    sqlx::query("SELECT object_id FROM upload_cleanup_queue WHERE object_id=$1 FOR UPDATE")
        .bind(cleanup_id)
        .fetch_one(&mut *cleanup_tx)
        .await
        .unwrap();
    let delete_error = crate::db::users::delete_user_with_roster(&pool, user_id, "example.test")
        .await
        .unwrap_err();
    assert!(delete_error
        .to_string()
        .contains("upload storage capacity busy; retry account deletion"));
    cleanup_tx.rollback().await.unwrap();

    sqlx::query("DELETE FROM upload_cleanup_queue WHERE object_id=$1")
        .bind(cleanup_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        crate::db::users::delete_user_with_roster(&pool, user_id, "example.test",)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn upload_claim_is_atomic_and_cleanup_is_retryable() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    // Production binds this durable deployment authority in AppState
    // before opening any listener. Mirror that startup boundary here: an
    // unbound policy intentionally rejects every new cleanup obligation.
    validate_upload_capacity_policy(
        &pool,
        TEST_UPLOAD_PENDING_LIMIT,
        TEST_UPLOAD_RETAINED_FILES_LIMIT,
        TEST_UPLOAD_RETAINED_BYTES_LIMIT,
    )
    .await
    .unwrap();

    let user_id = insert_user(&pool).await;
    let token_hash = b"concurrent-test-token-hash".to_vec();
    let slot_id = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "concurrent.bin",
            content_type: "application/octet-stream",
            size: 4,
            token_hash: &token_hash,
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        claim_upload_slot(&pool, slot_id, b"wrong-token", 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Rejected
    ));

    let competitors = 12;
    let barrier = Arc::new(Barrier::new(competitors + 1));
    let mut tasks = Vec::with_capacity(competitors);
    for _ in 0..competitors {
        let pool = pool.clone();
        let barrier = barrier.clone();
        let token_hash = token_hash.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            match claim_upload_slot(&pool, slot_id, &token_hash, 90)
                .await
                .unwrap()
            {
                UploadClaimOutcome::Acquired(lease) => Some(lease),
                _ => None,
            }
        }));
    }
    barrier.wait().await;
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(lease) = task.await.unwrap() {
            winners.push(lease);
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "exactly one concurrent PUT may claim a slot"
    );
    assert!(uploaded_file(&pool, slot_id).await.unwrap().is_none());
    let before_forgery: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let forged_stage = format!("staging/{slot_id}/{}", winners[0].claim_token);
    let forged_error = sqlx::query(
        "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,stage_key,storage_attempt,
                 expected_size,storage_fence,slot_delete_projection)
             VALUES($1,'local',$1::text,$3,$2,4,$4,TRUE)",
    )
    .bind(slot_id)
    .bind(winners[0].claim_token)
    .bind(&forged_stage)
    .bind(winners[0].storage_fence)
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(
        matches!(&forged_error,sqlx::Error::Database(error)
                if error.code().as_deref()==Some("42501")),
        "direct writers must not forge slot-delete provenance: {forged_error}"
    );
    let after_forgery: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_forgery, before_forgery);

    // A mandatory retry-cleanup projection temporarily converts the
    // slot's debt. If cleanup completes before a replacement writer is
    // admitted, the DELETE trigger must hand that obligation back to the
    // still-live writing slot instead of leaving an unaccounted locator.
    sqlx::query(
        "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,stage_key,
                 storage_fence,expected_size)
             VALUES($1,$2,'delete_stage','local',$3,$4,4)",
    )
    .bind(slot_id)
    .bind(winners[0].claim_token)
    .bind(&forged_stage)
    .bind(winners[0].storage_fence)
    .execute(&pool)
    .await
    .unwrap();
    let converted: (i64, i64, bool) = sqlx::query_as(
        "SELECT ledger.pending_jobs,ledger.cleanup_obligation_debt,
                    slot.storage_cleanup_debt_reserved
               FROM upload_storage_capacity_ledger ledger
               JOIN upload_slots slot ON slot.id=$1
              WHERE ledger.singleton",
    )
    .bind(slot_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (converted.0, converted.1),
        (before_forgery.0 + 1, before_forgery.1 - 1)
    );
    assert!(!converted.2);
    sqlx::query(
        "DELETE FROM upload_storage_jobs
             WHERE object_id=$1 AND storage_attempt=$2 AND action='delete_stage'",
    )
    .bind(slot_id)
    .bind(winners[0].claim_token)
    .execute(&pool)
    .await
    .unwrap();
    let rearmed: (i64, i64, bool) = sqlx::query_as(
        "SELECT ledger.pending_jobs,ledger.cleanup_obligation_debt,
                    slot.storage_cleanup_debt_reserved
               FROM upload_storage_capacity_ledger ledger
               JOIN upload_slots slot ON slot.id=$1
              WHERE ledger.singleton",
    )
    .bind(slot_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((rearmed.0, rearmed.1), before_forgery);
    assert!(rearmed.2);
    assert!(release_upload_claim(&pool, slot_id, winners[0].claim_token)
        .await
        .unwrap());
    let lease = match claim_upload_slot(&pool, slot_id, &token_hash, 90)
        .await
        .unwrap()
    {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected upload claim outcome: {other:?}"),
    };
    let digest = [9_u8; 32];
    assert!(
        complete_upload(&pool, slot_id, lease.claim_token, &digest, 3_600)
            .await
            .unwrap()
    );
    assert!(uploaded_file(&pool, slot_id).await.unwrap().is_some());
    let expiry = sqlx::query(
        "SELECT EXTRACT(EPOCH FROM (put_expires_at-clock_timestamp()))::bigint AS put_seconds,
                    EXTRACT(EPOCH FROM (expires_at-clock_timestamp()))::bigint AS object_seconds
             FROM upload_slots WHERE id=$1",
    )
    .bind(slot_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let put_seconds: i64 = expiry.get("put_seconds");
    let object_seconds: i64 = expiry.get("object_seconds");
    assert!((295..=300).contains(&put_seconds));
    assert!((3_590..=3_600).contains(&object_seconds));
    assert!(matches!(
        claim_upload_slot(&pool, slot_id, &token_hash, 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Replay { content_sha256, .. } if content_sha256 == digest
    ));
    assert!(!release_upload_claim(&pool, slot_id, lease.claim_token)
        .await
        .unwrap());
    assert!(record_upload_replay(&pool, slot_id, &token_hash, &digest)
        .await
        .unwrap());
    assert!(
        !record_upload_replay(&pool, slot_id, &token_hash, &[8_u8; 32])
            .await
            .unwrap()
    );
    let replay_count: i64 = sqlx::query_scalar("SELECT replay_count FROM upload_slots WHERE id=$1")
        .bind(slot_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(replay_count, 1);
    for expected_count in 2..=3_i64 {
        assert!(matches!(
            claim_upload_slot(&pool, slot_id, &token_hash, 90)
                .await
                .unwrap(),
            UploadClaimOutcome::Replay { content_sha256, .. } if content_sha256 == digest
        ));
        assert!(record_upload_replay(&pool, slot_id, &token_hash, &digest)
            .await
            .unwrap());
        let count: i64 = sqlx::query_scalar("SELECT replay_count FROM upload_slots WHERE id=$1")
            .bind(slot_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, expected_count);
    }
    assert!(matches!(
        claim_upload_slot(&pool, slot_id, &token_hash, 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Rejected
    ));

    let legacy = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO upload_slots
             (id,user_id,filename,content_type,size,token_hash,expires_at,put_expires_at)
             VALUES($1,$2,'legacy.bin','application/octet-stream',4,$3,
                    clock_timestamp()+INTERVAL '1 hour',
                    clock_timestamp()+INTERVAL '5 minutes')",
    )
    .bind(legacy)
    .bind(user_id)
    .bind(b"legacy-token")
    .execute(&pool)
    .await
    .unwrap();
    // Materialize a schema-valid pre-digest legacy object through UPDATE,
    // so the cleanup-debt trigger reserves its eventual deletion exactly
    // as the 0091 backfill does. It remains unclaimable without a digest.
    sqlx::query(
        "UPDATE upload_slots
             SET uploaded=TRUE,storage_state='legacy_committed',
                 storage_object_key=id::text,storage_size=size
             WHERE id=$1",
    )
    .bind(legacy)
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        claim_upload_slot(&pool, legacy, b"legacy-token", 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Rejected
    ));

    let exhausted = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "attempts.bin",
            content_type: "application/octet-stream",
            size: 4,
            token_hash: b"attempt-token",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    for _ in 0..MAX_UPLOAD_ATTEMPTS {
        let lease = match claim_upload_slot(&pool, exhausted, b"attempt-token", 90)
            .await
            .unwrap()
        {
            UploadClaimOutcome::Acquired(lease) => lease,
            other => panic!("unexpected bounded-attempt outcome: {other:?}"),
        };
        assert!(release_upload_claim(&pool, exhausted, lease.claim_token)
            .await
            .unwrap());
    }
    assert!(matches!(
        claim_upload_slot(&pool, exhausted, b"attempt-token", 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Rejected
    ));

    let fenced = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "fenced.bin",
            content_type: "application/octet-stream",
            size: 4,
            token_hash: b"fenced-token",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let stale = match claim_upload_slot(&pool, fenced, b"fenced-token", 90)
        .await
        .unwrap()
    {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected first fenced claim: {other:?}"),
    };
    assert!(matches!(
        claim_upload_slot(&pool, fenced, b"fenced-token", 90)
            .await
            .unwrap(),
        UploadClaimOutcome::InProgress { .. }
    ));
    sqlx::query(
        "UPDATE upload_slots SET claim_expires_at=clock_timestamp()-INTERVAL '1 second'
             WHERE id=$1",
    )
    .bind(fenced)
    .execute(&pool)
    .await
    .unwrap();
    let replacement = match claim_upload_slot(&pool, fenced, b"fenced-token", 90)
        .await
        .unwrap()
    {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected replacement claim: {other:?}"),
    };
    assert_ne!(stale.claim_token, replacement.claim_token);
    assert_eq!(
        renew_upload_claim(&pool, fenced, stale.claim_token, 90)
            .await
            .unwrap(),
        UploadRenewOutcome::Lost
    );
    assert!(!release_upload_claim(&pool, fenced, stale.claim_token)
        .await
        .unwrap());
    assert!(
        !complete_upload(&pool, fenced, stale.claim_token, &[1_u8; 32], 3_600,)
            .await
            .unwrap()
    );
    assert!(
        complete_upload(&pool, fenced, replacement.claim_token, &[2_u8; 32], 3_600,)
            .await
            .unwrap()
    );

    let authorized_deletable = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "authorized-delete.bin",
            content_type: "application/octet-stream",
            size: 7,
            token_hash: b"authorized-delete-token",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let live_session = db::create_api_session(&pool, user_id, 1).await.unwrap();
    assert_eq!(
        queue_user_upload_delete_authorized(
            &pool,
            user_id,
            0,
            &live_session,
            authorized_deletable,
            Uuid::new_v4(),
        )
        .await
        .unwrap(),
        UserUploadDeleteOutcome::Accepted
    );

    let stale_deletable = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "stale-delete.bin",
            content_type: "application/octet-stream",
            size: 7,
            token_hash: b"stale-delete-token",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let stale_session = db::create_api_session(&pool, user_id, 1).await.unwrap();
    let mut logout = pool.begin().await.unwrap();
    assert!(
        db::delete_api_session_audited_in_tx(&mut logout, &stale_session, Uuid::new_v4(),)
            .await
            .unwrap()
    );
    logout.commit().await.unwrap();
    assert_eq!(
        queue_user_upload_delete_authorized(
            &pool,
            user_id,
            0,
            &stale_session,
            stale_deletable,
            Uuid::new_v4(),
        )
        .await
        .unwrap(),
        UserUploadDeleteOutcome::Unauthorized
    );
    assert!(sqlx::query("SELECT 1 FROM upload_slots WHERE id=$1")
        .bind(stale_deletable)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .is_some());

    let deletable = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "delete-me.bin",
            content_type: "application/octet-stream",
            size: 7,
            token_hash: b"delete-token",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let other_user = insert_user(&pool).await;
    assert!(
        !queue_user_upload_delete(&pool, other_user, deletable, Uuid::new_v4())
            .await
            .unwrap()
    );
    let delete_request = Uuid::new_v4();
    assert!(
        queue_user_upload_delete(&pool, user_id, deletable, delete_request)
            .await
            .unwrap()
    );
    assert!(
        !queue_user_upload_delete(&pool, user_id, deletable, Uuid::new_v4())
            .await
            .unwrap()
    );
    let delete_projection: (i64, i64) = sqlx::query_as(
        "SELECT
                 (SELECT COUNT(*) FROM upload_cleanup_queue WHERE object_id=$1),
                 (SELECT COUNT(*) FROM audit_log
                   WHERE actor_id=$2 AND action='user.upload.delete'
                     AND target=$1::text AND request_id=$3)",
    )
    .bind(deletable)
    .bind(user_id)
    .bind(delete_request)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(delete_projection, (0, 1));
    assert!(sqlx::query("SELECT 1 FROM upload_slots WHERE id=$1")
        .bind(deletable)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .is_none());

    let expired = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "expired.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: b"expired",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let active_expired = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "active.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: b"active",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let abandoned = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "abandoned.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: b"abandoned",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let active_claim = Uuid::new_v4();
    let abandoned_claim = Uuid::new_v4();
    let active_stage = format!("staging/{active_expired}/{active_claim}");
    let active_object = format!("objects/{active_expired}/{active_claim}");
    let abandoned_stage = format!("staging/{abandoned}/{abandoned_claim}");
    let abandoned_object = format!("objects/{abandoned}/{abandoned_claim}");
    sqlx::query(
        "UPDATE upload_slots
             SET expires_at = CASE
                 WHEN id = $1 THEN NOW() - INTERVAL '1 minute'
                 WHEN id = $2 THEN NOW() - INTERVAL '1 minute'
                 WHEN id = $3 THEN NOW() - INTERVAL '10 minutes'
                 ELSE expires_at
             END,
             uploading = id IN ($2, $3),
             claim_token = CASE
                 WHEN id = $2 THEN $4
                 WHEN id = $3 THEN $5
                 ELSE NULL
             END,
             claim_expires_at = CASE
                 WHEN id = $2 THEN clock_timestamp() + INTERVAL '1 minute'
                 WHEN id = $3 THEN clock_timestamp() - INTERVAL '9 minutes'
                 ELSE NULL
             END,
             storage_state = CASE WHEN id IN ($2,$3) THEN 'writing' ELSE 'reserved' END,
             storage_attempt = CASE WHEN id=$2 THEN $4 WHEN id=$3 THEN $5 ELSE NULL END,
             storage_stage_key = CASE WHEN id=$2 THEN $6 WHEN id=$3 THEN $8 ELSE NULL END,
             storage_object_key = CASE WHEN id=$2 THEN $7 WHEN id=$3 THEN $9 ELSE NULL END,
             storage_fence = CASE WHEN id IN ($2,$3) THEN storage_fence+1 ELSE storage_fence END
             WHERE id IN ($1, $2, $3)",
    )
    .bind(expired)
    .bind(active_expired)
    .bind(abandoned)
    .bind(active_claim)
    .bind(abandoned_claim)
    .bind(active_stage)
    .bind(active_object)
    .bind(abandoned_stage)
    .bind(abandoned_object)
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        claim_upload_slot(&pool, expired, b"expired", 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Rejected
    ));

    let candidates = cleanup_expired_upload_slots(&pool).await.unwrap();
    assert!(candidates.contains(&expired));
    assert!(candidates.contains(&abandoned));
    assert!(!candidates.contains(&active_expired));
    assert!(sqlx::query("SELECT 1 FROM upload_slots WHERE id=$1")
        .bind(expired)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .is_none());
    let abandoned_quiet_period: bool = sqlx::query_scalar(
        "SELECT available_at>clock_timestamp()
             FROM upload_cleanup_queue WHERE object_id=$1",
    )
    .bind(abandoned)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        abandoned_quiet_period,
        "an expired in-flight writer keeps a durable delayed tombstone"
    );
    // Advance only this fixture past the external-I/O quiet period. The
    // worker must then be able to claim and complete the same tombstone.
    sqlx::query(
        "UPDATE upload_cleanup_queue SET available_at=clock_timestamp()
             WHERE object_id=$1",
    )
    .bind(abandoned)
    .execute(&pool)
    .await
    .unwrap();
    let cleanup = queued_upload_cleanup(&pool).await.unwrap();
    let abandoned_job = cleanup
        .iter()
        .find(|job| job.object_id == abandoned)
        .expect("abandoned upload has durable cleanup work");
    assert!(complete_queued_upload_cleanup(
        &pool,
        abandoned_job.object_id,
        abandoned_job.claim_token,
    )
    .await
    .unwrap());
    let active_still_exists: bool = sqlx::query("SELECT id FROM upload_slots WHERE id = $1")
        .bind(active_expired)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .is_some();
    assert!(active_still_exists);

    let uploaded_still_exists: bool =
        sqlx::query("SELECT uploaded FROM upload_slots WHERE id = $1")
            .bind(slot_id)
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("uploaded");
    assert!(uploaded_still_exists);

    sqlx::query("UPDATE upload_slots SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(slot_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(uploaded_file(&pool, slot_id).await.unwrap().is_none());
    assert!(cleanup_expired_upload_slots(&pool)
        .await
        .unwrap()
        .contains(&slot_id));
    let cleanup = queued_upload_cleanup(&pool).await.unwrap();
    let uploaded_job = cleanup
        .iter()
        .find(|job| job.object_id == slot_id)
        .expect("uploaded object has durable cleanup work");
    assert!(complete_queued_upload_cleanup(
        &pool,
        uploaded_job.object_id,
        uploaded_job.claim_token,
    )
    .await
    .unwrap());

    let cascade_states: Vec<String> = sqlx::query_scalar(
        "SELECT storage_state FROM upload_slots
             WHERE id=ANY($1) ORDER BY storage_state",
    )
    .bind([active_expired, fenced, legacy])
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        cascade_states,
        ["committed", "legacy_committed", "writing"],
        "account cascade fixture must cover every locator lifecycle"
    );
    let before_rollback: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt,
                    storage_jobs_pending,cleanup_jobs_pending
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut rolled_back_delete = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&mut *rolled_back_delete)
        .await
        .unwrap();
    rolled_back_delete.rollback().await.unwrap();
    let after_rollback: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt,
                    storage_jobs_pending,cleanup_jobs_pending
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_rollback, before_rollback);

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    let cascade_projection: (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT ledger.pending_jobs,ledger.cleanup_obligation_debt,
                    ledger.storage_jobs_pending,ledger.cleanup_jobs_pending,
                    (SELECT COUNT(*) FROM upload_storage_jobs),
                    (SELECT COUNT(*) FROM upload_cleanup_queue),
                    (SELECT COUNT(*) FROM upload_slots WHERE user_id=$1)
             FROM upload_storage_capacity_ledger ledger WHERE singleton",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        cascade_projection.0,
        cascade_projection.4 + cascade_projection.5
    );
    assert_eq!(cascade_projection.1, 0);
    assert_eq!(cascade_projection.2, cascade_projection.4);
    assert_eq!(cascade_projection.3, cascade_projection.5);
    assert_eq!(cascade_projection.6, 0);
}
