use northstar_abuse_policy::{
    admission_execution::*, admission_transaction::FinalizeDecision, message_admission::*, *,
};
use northstar_abuse_postgres::message_admission::PostgresMessageAdmissionRepository;
use northstar_message_application::message_admission::{begin_command, witness::AdmissionWitness};
use northstar_workflows::abuse_effects::persistent_guard;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

fn witness(command: Command) -> AdmissionWitness {
    AdmissionWitness::new(Effect {
        correlation: Correlation {
            operation: Uuid::from_u128(0x573_30101),
            effect: 1,
            generation: 0,
            attempt: 1,
        },
        command,
    })
}

fn receipt(witness: &AdmissionWitness, scope: TransactionScope) -> Receipt {
    let Knowledge::ReceiptKnown(receipt) = witness.snapshot().knowledge().clone() else {
        panic!("SQL did not retain a positive COMMIT receipt");
    };
    assert_eq!(receipt.scope, scope);
    receipt
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn admission_scopes_and_finalization_facts_match_independent_committed_rows() {
    let pool = crate::support::operation_mutation_pool().await;
    let user = Uuid::from_u128(0x573_30102);
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'admission-receipt','test-only')",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let guard = Arc::new(persistent_guard(
        AbuseConfig {
            base_work_factor: 1,
            max_work_factor: 16,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(8),
            message_free_burst: 60,
            approximate_max_device_seconds: 8,
        },
        pool.clone(),
        Some(b"admission-receipt-secret-at-least-32-bytes"),
        None,
    ));
    let repository = PostgresMessageAdmissionRepository::new(guard, pool.clone());
    let actors = vec!["user:admission-receipt".to_owned()];
    let payload = "<message to='peer@remote.test'><body>original</body></message>";
    let request = MessageAdmissionRequest {
        actor_id: user,
        account_bare: "admission-receipt@example.test",
        normalized_target: "peer@remote.test",
        origin_id: Some("receipt-origin"),
        normalized_payload: payload,
        pow_intent_payload: payload,
        subject: "message:admission-receipt",
        actors: &actors,
        proof: None,
    };
    let first = witness(begin_command(&request).unwrap());
    let MessageAdmissionStart::Proceed {
        lease: Some(old), ..
    } = repository.begin(&request, &first).await.unwrap()
    else {
        panic!("free-burst reservation failed");
    };
    assert_eq!(
        receipt(
            &first,
            TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation)
        )
        .fact,
        CommitFact::Reserved(acceptance_fence(&old.acceptance()))
    );
    let pending = witness(begin_command(&request).unwrap());
    assert!(matches!(
        repository.begin(&request, &pending).await.unwrap(),
        MessageAdmissionStart::InProgress { .. }
    ));
    assert_eq!(
        receipt(
            &pending,
            TransactionScope::RatedBegin(BeginCommitPurpose::PendingRequirement)
        )
        .fact,
        CommitFact::InProgress
    );
    let changed = MessageAdmissionRequest {
        normalized_payload: "<message><body>changed</body></message>",
        ..request
    };
    let conflict = witness(begin_command(&changed).unwrap());
    assert!(matches!(
        repository.begin(&changed, &conflict).await.unwrap(),
        MessageAdmissionStart::Conflict
    ));
    assert_eq!(
        *conflict.snapshot().knowledge(),
        Knowledge::NoCommitRequested,
        "payload conflict rolls back without a commit witness"
    );

    sqlx::query(
        "UPDATE abuse_message_admissions SET lease_expires_at=created_at WHERE admission_key=$1",
    )
    .bind(old.acceptance().admission_key())
    .execute(&pool)
    .await
    .unwrap();
    let reclaim = witness(begin_command(&request).unwrap());
    let MessageAdmissionStart::Proceed {
        lease: Some(current),
        ..
    } = repository.begin(&request, &reclaim).await.unwrap()
    else {
        panic!("expired pending row was not reclaimed");
    };
    assert_ne!(
        acceptance_fence(&old.acceptance()).lease_token,
        acceptance_fence(&current.acceptance()).lease_token
    );
    assert_eq!(
        receipt(
            &reclaim,
            TransactionScope::RatedBegin(BeginCommitPurpose::Reclaim)
        )
        .fact,
        CommitFact::Reserved(acceptance_fence(&current.acceptance()))
    );
    let stale = witness(Command::Finalize(acceptance_fence(&old.acceptance())));
    assert_eq!(
        repository.accept(&old.acceptance(), &stale).await.unwrap(),
        FinalizeDecision::LostFence
    );
    assert_eq!(*stale.snapshot().knowledge(), Knowledge::NoCommitRequested);

    // Finalization owns the issued fence even after its lease deadline; it
    // must not silently apply begin's expiry or capacity policy again.
    sqlx::query(
        "UPDATE abuse_message_admissions SET lease_expires_at=created_at WHERE admission_key=$1",
    )
    .bind(current.acceptance().admission_key())
    .execute(&pool)
    .await
    .unwrap();
    let finalize = witness(Command::Finalize(acceptance_fence(&current.acceptance())));
    sqlx::query(
        "CREATE FUNCTION hold_admission_finalize_commit() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN PERFORM pg_advisory_xact_lock(573336::bigint); RETURN NEW; END; $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE CONSTRAINT TRIGGER hold_admission_finalize_commit
         AFTER UPDATE ON abuse_message_admissions DEFERRABLE INITIALLY DEFERRED
         FOR EACH ROW WHEN (NEW.state='accepted' AND OLD.state='pending')
         EXECUTE FUNCTION hold_admission_finalize_commit()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut commit_blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(573336::bigint)")
        .execute(&mut *commit_blocker)
        .await
        .unwrap();
    let commit_blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *commit_blocker)
        .await
        .unwrap();
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(message_admission_lock_id(
            current.acceptance().admission_key(),
        ))
        .execute(&mut *blocker)
        .await
        .unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let worker_repository = repository.clone();
    let worker_lease = current.clone();
    let worker_witness = finalize.clone();
    let finalizing = tokio::spawn(async move {
        worker_repository
            .accept(&worker_lease.acceptance(), &worker_witness)
            .await
    });
    crate::support::blocked_backend(&pool, blocker_pid).await;
    assert_eq!(
        *finalize.snapshot().knowledge(),
        Knowledge::NoCommitRequested,
        "finalization has no commit fact before its advisory fence"
    );
    let mut probe = pool.begin().await.unwrap();
    sqlx::query("SELECT admission_key FROM abuse_message_admissions WHERE admission_key=$1 FOR UPDATE NOWAIT")
        .bind(current.acceptance().admission_key()).fetch_one(&mut *probe).await.expect("finalization took a row lock before the advisory fence");
    probe.rollback().await.unwrap();
    blocker.rollback().await.unwrap();
    crate::support::blocked_backend(&pool, commit_blocker_pid).await;
    let Knowledge::CommitCallEntered(prepared) = finalize.snapshot().knowledge().clone() else {
        panic!("finalization did not retain its prospective fact before the actual COMMIT await");
    };
    assert_eq!(prepared.scope, TransactionScope::AdmissionFinalize);
    assert_eq!(
        prepared.fact,
        CommitFact::Finalized {
            fence: acceptance_fence(&current.acceptance()),
            result: FinalizeSuccess::PendingAccepted,
        }
    );
    let mut observer = pool.acquire().await.unwrap();
    let still_pending: String =
        sqlx::query_scalar("SELECT state FROM abuse_message_admissions WHERE admission_key=$1")
            .bind(current.acceptance().admission_key())
            .fetch_one(&mut *observer)
            .await
            .unwrap();
    assert_eq!(
        still_pending, "pending",
        "COMMIT entry does not make acceptance durable"
    );
    drop(observer);
    commit_blocker.rollback().await.unwrap();
    assert_eq!(
        finalizing.await.unwrap().unwrap(),
        FinalizeDecision::AcceptPending
    );
    sqlx::query("DROP TRIGGER hold_admission_finalize_commit ON abuse_message_admissions")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION hold_admission_finalize_commit()")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        receipt(&finalize, TransactionScope::AdmissionFinalize).fact,
        CommitFact::Finalized {
            fence: acceptance_fence(&current.acceptance()),
            result: FinalizeSuccess::PendingAccepted,
        }
    );
    let mut observer = pool.acquire().await.unwrap();
    let (state, token, lifetime): (String, Uuid, f64) = sqlx::query_as(
        "SELECT state,lease_token,EXTRACT(EPOCH FROM expires_at-accepted_at)::float8 FROM abuse_message_admissions WHERE admission_key=$1",
    ).bind(current.acceptance().admission_key()).fetch_one(&mut *observer).await.unwrap();
    assert_eq!(state, "accepted");
    assert_eq!(token, acceptance_fence(&current.acceptance()).lease_token);
    assert_eq!(lifetime, 6.0 * 60.0 * 60.0);
    drop(observer);
    let already = witness(Command::Finalize(acceptance_fence(&old.acceptance())));
    assert_eq!(
        repository
            .accept(&old.acceptance(), &already)
            .await
            .unwrap(),
        FinalizeDecision::AlreadyAccepted,
        "accepted evidence precedes stale token rejection"
    );
    assert_eq!(
        receipt(&already, TransactionScope::AdmissionFinalize).fact,
        CommitFact::Finalized {
            fence: acceptance_fence(&old.acceptance()),
            result: FinalizeSuccess::AlreadyAccepted,
        }
    );
    let replay = witness(begin_command(&request).unwrap());
    assert!(matches!(
        repository.begin(&request, &replay).await.unwrap(),
        MessageAdmissionStart::ReplayAccepted
    ));
    assert_eq!(
        receipt(
            &replay,
            TransactionScope::RatedBegin(BeginCommitPurpose::ReplayRead)
        )
        .fact,
        CommitFact::ReplayAccepted
    );
    let bad_proof = PowProof {
        challenge_id: Uuid::from_u128(0x573_30103),
        nonce: "0".into(),
    };
    let denied_request = MessageAdmissionRequest {
        origin_id: Some("denied-origin"),
        proof: Some(&bad_proof),
        ..request
    };
    let denied = witness(begin_command(&denied_request).unwrap());
    assert!(matches!(
        repository.begin(&denied_request, &denied).await.unwrap(),
        MessageAdmissionStart::Denied(_)
    ));
    assert_eq!(
        receipt(
            &denied,
            TransactionScope::RatedBegin(BeginCommitPurpose::GuardDenial)
        )
        .fact,
        CommitFact::Denied
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM abuse_message_admissions WHERE actor_id=$1")
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        rows, 1,
        "denial commits a penalty without a new reservation"
    );
    let effect = Effect {
        correlation: Correlation {
            operation: Uuid::from_u128(0x573_30104),
            effect: 2,
            generation: 0,
            attempt: 1,
        },
        command: Command::Reconcile {
            unresolved: Correlation {
                operation: Uuid::from_u128(0x573_30104),
                effect: 1,
                generation: 0,
                attempt: 1,
            },
            fence: acceptance_fence(&current.acceptance()),
        },
    };
    let reconciled = repository.reconcile(&effect).await.unwrap();
    assert_eq!(
        *reconciled.effect, effect,
        "read-only reconciliation retains the exact command"
    );
    let after: (String, Uuid) = sqlx::query_as(
        "SELECT state,lease_token FROM abuse_message_admissions WHERE admission_key=$1",
    )
    .bind(current.acceptance().admission_key())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        after,
        (state, token),
        "reconciliation leaves committed authority unchanged"
    );
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn guard_only_receipts_and_actor_contention_keep_reservation_authority_separate() {
    let pool = crate::support::operation_mutation_pool().await;
    let user = Uuid::from_u128(0x573_34401);
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'guard-only-receipt','test-only')",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let guard = Arc::new(persistent_guard(
        AbuseConfig {
            // Work is base * step^2; a base of 2 makes the first step past the
            // free burst require a proof (a work factor of 1 is still free).
            base_work_factor: 2,
            max_work_factor: 16,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(8),
            message_free_burst: 1,
            approximate_max_device_seconds: 8,
        },
        pool.clone(),
        Some(b"guard-only-conformance-secret-at-least-32-bytes"),
        None,
    ));
    let repository = PostgresMessageAdmissionRepository::new(Arc::clone(&guard), pool.clone());
    let actors = vec![
        "user:guard-only-z".into(),
        "user:guard-only-a".into(),
        "user:guard-only-z".into(),
    ];
    let request = MessageAdmissionRequest {
        actor_id: user,
        account_bare: "guard-only-receipt@example.test",
        normalized_target: "peer@remote.test",
        origin_id: None,
        normalized_payload: "<message><body>guard only</body></message>",
        pow_intent_payload: "<message><body>guard only</body></message>",
        subject: "message:guard-only-receipt",
        actors: &actors,
        proof: None,
    };
    let allowed = witness(begin_command(&request).unwrap());
    assert!(matches!(
        repository.begin(&request, &allowed).await.unwrap(),
        MessageAdmissionStart::Proceed { lease: None, .. }
    ));
    assert_eq!(
        receipt(&allowed, TransactionScope::GuardOnlyVerification).fact,
        CommitFact::GuardOnly(GuardDecision::Allowed)
    );
    let keys = northstar_abuse_application::guard::test_support::actor_state_keys(
        AbuseAction::Message,
        &actors,
        guard.actor_key_secret(),
    );
    let before: Vec<(String, i64, i32)> = sqlx::query_as("SELECT state_key,sequence,penalty_level FROM abuse_actor_states WHERE state_key=ANY($1::text[]) ORDER BY state_key")
        .bind(&keys).fetch_all(&pool).await.unwrap();
    assert_eq!(
        before.len(),
        2,
        "duplicate actor keys name one durable state"
    );
    for (label, advisory) in [
        ("contended actor advisory lock", true),
        ("contended actor row", false),
    ] {
        let mut blocker = pool.begin().await.unwrap();
        if advisory {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text,$2::bigint))")
                .bind(&keys[0])
                .bind(ABUSE_STATE_ADVISORY_HASH_SEED)
                .execute(&mut *blocker)
                .await
                .unwrap();
        } else {
            sqlx::query("SELECT state_key FROM abuse_actor_states WHERE state_key=$1 FOR UPDATE")
                .bind(&keys[0])
                .fetch_one(&mut *blocker)
                .await
                .unwrap();
        }
        let blocked = witness(begin_command(&request).unwrap());
        let result =
            tokio::time::timeout(Duration::from_secs(2), repository.begin(&request, &blocked))
                .await
                .expect("actor contention must fail fast");
        let Err(error) = result else {
            panic!("{label}: lock contention was accepted");
        };
        assert!(is_abuse_state_busy(&error), "{label}: {error}");
        assert_eq!(
            *blocked.snapshot().knowledge(),
            Knowledge::NoCommitRequested,
            "{label}"
        );
        let mut observer = pool.acquire().await.unwrap();
        let after: Vec<(String, i64, i32)> = sqlx::query_as("SELECT state_key,sequence,penalty_level FROM abuse_actor_states WHERE state_key=ANY($1::text[]) ORDER BY state_key")
            .bind(&keys).fetch_all(&mut *observer).await.unwrap();
        assert_eq!(after, before, "{label}: no committed actor mutation");
        drop(observer);
        blocker.rollback().await.unwrap();
    }
    // The free burst is spent: step one needs work 2 > 1 and no proof was sent.
    let denied = witness(begin_command(&request).unwrap());
    assert!(matches!(
        repository.begin(&request, &denied).await.unwrap(),
        MessageAdmissionStart::Denied(_)
    ));
    assert_eq!(
        receipt(&denied, TransactionScope::GuardOnlyVerification).fact,
        CommitFact::GuardOnly(GuardDecision::Denied)
    );
    let reservations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM abuse_message_admissions WHERE actor_id=$1")
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        reservations, 0,
        "guard-only commits do not issue a durable reservation"
    );
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
