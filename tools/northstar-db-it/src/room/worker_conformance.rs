use northstar_room_application::mix_service::{outbox::core::*, MixDeliveryRepository};
use northstar_room_postgres::mix as db;
use northstar_workflows::room_effects::PostgresMixRepository;
use sqlx::PgPool;
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;

const TEMPLATE: &str =
    "<message xmlns='jabber:client' type='groupchat'><body>receipt</body></message>";

fn recipient(ordinal: u128) -> String {
    if ordinal >= 30 {
        "archive-receipt@example.test".into()
    } else {
        format!("receipt-{ordinal}@example.test")
    }
}

async fn seed(pool: &PgPool, ordinal: u128, archive: bool) -> (Uuid, Uuid) {
    seed_with_stanza(pool, ordinal, archive, TEMPLATE).await
}

async fn seed_with_stanza(
    pool: &PgPool,
    ordinal: u128,
    archive: bool,
    stanza: &str,
) -> (Uuid, Uuid) {
    let event = Uuid::from_u128(0x573_170000 + ordinal * 4);
    let delivery = Uuid::from_u128(0x573_170001 + ordinal * 4);
    let recipient = recipient(ordinal);
    let (mut tx, fence) = db::begin_mix_delivery_admission(pool).await.unwrap();
    sqlx::query(
        "INSERT INTO mix_delivery_events(event_id,channel_id,channel_jid,stanza_template,authoritative_stanza_id,archive,encrypted)
         VALUES($1,$2,'receipts@mix.example.test',$3,$4,$5,TRUE)",
    ).bind(event).bind(Uuid::from_u128(0x573_170002)).bind(stanza)
        .bind(archive.then_some(Uuid::from_u128(0x573_170003))).bind(archive)
        .execute(&mut *tx).await.unwrap();
    sqlx::query(
        "INSERT INTO mix_delivery_recipients(delivery_id,event_id,recipient_participant_id,recipient_jid,delivery_sequence)
         VALUES($1,$2,$3,$4,1)",
    ).bind(delivery).bind(event).bind(Uuid::from_u128(0x573_170004)).bind(&recipient)
        .execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO mix_delivery_recipient_sequences(recipient_jid,next_sequence) VALUES($1,2) ON CONFLICT(recipient_jid) DO NOTHING")
        .bind(&recipient).execute(&mut *tx).await.unwrap();
    let mut deltas = BTreeMap::new();
    db::add_mix_delivery_capacity_delta(
        &mut deltas,
        db::mix_delivery_capacity_bucket(event),
        0,
        stanza.len() as i64,
    )
    .unwrap();
    db::add_mix_delivery_capacity_delta(
        &mut deltas,
        db::mix_delivery_capacity_bucket(delivery),
        1,
        recipient.len() as i64 + 128,
    )
    .unwrap();
    db::reserve_mix_delivery_capacity_tx(&mut tx, &fence, &deltas)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (event, delivery)
}

async fn claim(repository: &PostgresMixRepository, delivery: Uuid) -> Attempt {
    let observation = ClaimObservation::new(ClaimCommand {
        limit: 1,
        max_bytes: 65_536,
    });
    let request = observation.request().unwrap();
    request.start().unwrap();
    let rows = repository
        .claim_mix_deliveries_observed(&request)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "bound row limit");
    assert_eq!(
        rows[0].source.delivery_id, delivery,
        "original delivery identity"
    );
    assert_eq!(rows[0].channel_id, Uuid::from_u128(0x573_170002));
    assert_eq!(rows[0].participant_id, Uuid::from_u128(0x573_170004));
    assert_eq!(rows[0].attempt_count, 0);
    assert_eq!(rows[0].route_wake_generation, 0);
    let ClaimKnowledge::StatementReceipt(receipt) = observation.snapshot().knowledge else {
        panic!("claim omitted its SQL statement receipt");
    };
    assert!(
        Arc::ptr_eq(&receipt, &rows),
        "returned rows are the acknowledged allocation"
    );
    request.returned(rows).unwrap().pop().unwrap()
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn worker_claim_and_settlement_receipts_match_committed_exact_fences() {
    let pool = crate::support::operation_mutation_pool().await;
    let repository = PostgresMixRepository::new(pool.clone());
    for (ordinal, label, kind, replace, attempts, wake, expected) in [
        (
            0,
            "exact ack",
            SettlementKind::Ack,
            false,
            0,
            false,
            SettlementResult::Ack(true),
        ),
        (
            1,
            "stale ack",
            SettlementKind::Ack,
            true,
            0,
            false,
            SettlementResult::Ack(false),
        ),
        (
            2,
            "exact defer",
            SettlementKind::Defer,
            false,
            0,
            false,
            SettlementResult::Defer(true),
        ),
        (
            3,
            "stale defer",
            SettlementKind::Defer,
            true,
            0,
            false,
            SettlementResult::Defer(false),
        ),
        (
            4,
            "exact dead letter",
            SettlementKind::DeadLetter,
            false,
            0,
            false,
            SettlementResult::DeadLetter(true),
        ),
        (
            5,
            "stale dead letter",
            SettlementKind::DeadLetter,
            true,
            0,
            false,
            SettlementResult::DeadLetter(false),
        ),
        (
            6,
            "retry backoff",
            SettlementKind::Retry,
            false,
            0,
            false,
            SettlementResult::Retry(RetryResult::Retried),
        ),
        (
            7,
            "stale retry",
            SettlementKind::Retry,
            true,
            0,
            false,
            SettlementResult::Retry(RetryResult::LeaseLost),
        ),
        (
            8,
            "persisted attempt limit",
            SettlementKind::Retry,
            false,
            19,
            false,
            SettlementResult::Retry(RetryResult::DeadLettered),
        ),
        (
            9,
            "persisted route wake",
            SettlementKind::Retry,
            false,
            19,
            true,
            SettlementResult::Retry(RetryResult::RouteWokenAtAttemptLimit),
        ),
    ] {
        let (event, delivery) = seed(&pool, ordinal, false).await;
        let attempt = claim(&repository, delivery).await;
        let row = attempt.row();
        assert_eq!(row.event_id, event, "{label}");
        assert_eq!(row.channel_jid, "receipts@mix.example.test", "{label}");
        assert_eq!(row.recipient_jid, recipient(ordinal), "{label}");
        assert_eq!(row.recipient_nick, None, "{label}");
        assert_eq!(row.stanza, TEMPLATE, "{label}");
        assert!(
            row.encrypted && !row.archive && row.authoritative_stanza_id.is_none(),
            "{label}"
        );
        let original_token = row.source.lease_token;
        let replacement = Uuid::from_u128(0x573_179000 + ordinal);
        sqlx::query("UPDATE mix_delivery_recipients SET lease_token=$2,attempt_count=$3,route_wake_generation=route_wake_generation+$4 WHERE delivery_id=$1")
            .bind(delivery).bind(if replace { replacement } else { original_token }).bind(attempts)
            .bind(i64::from(wake)).execute(&pool).await.unwrap();
        let observation = attempt.observation();
        let route = attempt
            .route(format!(
                "<message to='{}'><body>receipt</body></message>",
                recipient(ordinal)
            ))
            .unwrap();
        route.start().unwrap();
        let result = match kind {
            SettlementKind::Ack => RouteResult::CompletedByWorker,
            SettlementKind::Defer => RouteResult::Pending,
            SettlementKind::Retry => RouteResult::Retry,
            SettlementKind::DeadLetter => RouteResult::Permanent,
        };
        let command = match kind {
            SettlementKind::Ack => SettlementCommand::Ack,
            SettlementKind::Defer => SettlementCommand::Defer { delay_seconds: 17 },
            SettlementKind::Retry => SettlementCommand::Retry {
                error: "exact retry error".into(),
            },
            SettlementKind::DeadLetter => SettlementCommand::DeadLetter {
                reason: "invalid-template".into(),
                error: "exact terminal error".into(),
            },
        };
        let closed = observation.close_renewal_scope().unwrap();
        let request = route
            .returned(result)
            .unwrap()
            .settlement(command, closed)
            .unwrap()
            .unwrap();
        request.start().unwrap();
        let returned = repository
            .settle_mix_delivery_observed(&request)
            .await
            .unwrap();
        assert_eq!(returned, expected, "{label}: repository return");
        let snapshot = observation.snapshot().settlement.unwrap();
        assert_eq!(
            snapshot.knowledge,
            SettlementKnowledge::ReceiptKnown(expected),
            "{label}: acknowledged SQL"
        );
        assert_eq!(
            snapshot.returned, None,
            "{label}: raw return is a separate fact"
        );
        assert_eq!(request.returned(returned).unwrap(), expected, "{label}");
        assert_eq!(
            observation.snapshot().settlement.unwrap().returned,
            Some(SettlementReturned::Outcome(expected)),
            "{label}"
        );

        let mut observer = pool.acquire().await.unwrap();
        let live: Option<(Option<Uuid>, i32, Option<String>, bool)> = sqlx::query_as(
            "SELECT lease_token,attempt_count,last_error,next_attempt_at>clock_timestamp() FROM mix_delivery_recipients WHERE delivery_id=$1",
        ).bind(delivery).fetch_optional(&mut *observer).await.unwrap();
        if replace {
            assert_eq!(
                live.as_ref().map(|row| row.0),
                Some(Some(replacement)),
                "{label}: replacement survives"
            );
        } else if matches!(
            expected,
            SettlementResult::Ack(true)
                | SettlementResult::DeadLetter(true)
                | SettlementResult::Retry(RetryResult::DeadLettered)
        ) {
            assert!(live.is_none(), "{label}: durable deletion");
        } else {
            let (token, count, error, delayed) = live.unwrap();
            assert_eq!(token, None, "{label}: released lease");
            if kind == SettlementKind::Retry {
                assert_eq!(count, if wake { 19 } else { 1 }, "{label}: locked count");
                assert_eq!(error.as_deref(), Some("exact retry error"), "{label}");
                assert_eq!(delayed, !wake, "{label}: original wake generation");
            } else {
                assert!(delayed, "{label}: requested delay");
            }
        }
        let dead: Option<(String, String)> = sqlx::query_as(
            "SELECT terminal_reason,last_error FROM mix_delivery_dead_letters WHERE delivery_id=$1",
        )
        .bind(delivery)
        .fetch_optional(&mut *observer)
        .await
        .unwrap();
        if expected == SettlementResult::DeadLetter(true) {
            assert_eq!(
                dead,
                Some(("invalid-template".into(), "exact terminal error".into())),
                "{label}: command arguments"
            );
        } else if expected == SettlementResult::Retry(RetryResult::DeadLettered) {
            assert_eq!(
                dead,
                Some(("attempt-limit".into(), "exact retry error".into())),
                "{label}"
            );
        } else {
            assert!(dead.is_none(), "{label}: no terminal projection");
        }
        drop(observer);
        sqlx::query("DELETE FROM mix_delivery_recipients WHERE delivery_id=$1")
            .bind(delivery)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM mix_delivery_dead_letters WHERE delivery_id=$1")
            .bind(delivery)
            .execute(&pool)
            .await
            .unwrap();
        db::reconcile_mix_delivery_capacity_committed(&pool)
            .await
            .unwrap();
    }
    let observation = ClaimObservation::new(ClaimCommand {
        limit: 1,
        max_bytes: 65_536,
    });
    let request = observation.request().unwrap();
    request.start().unwrap();
    let empty = repository
        .claim_mix_deliveries_observed(&request)
        .await
        .unwrap();
    assert!(empty.is_empty(), "authorized empty read");
    assert_eq!(
        observation.snapshot().knowledge,
        ClaimKnowledge::ReadEmpty,
        "empty queue does not enter a claim statement"
    );
    assert!(request.returned(empty).unwrap().is_empty());
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn worker_renewal_and_archive_keep_exact_statement_and_commit_receipts() {
    let pool = crate::support::operation_mutation_pool().await;
    let repository = PostgresMixRepository::new(pool.clone());
    let user = Uuid::from_u128(0x573_176601);
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'worker-archive','test-only')",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let (_, delivery) = seed(&pool, 30, true).await;
    let attempt = claim(&repository, delivery).await;
    assert!(attempt.row().archive && attempt.row().encrypted);
    assert_eq!(
        attempt.row().authoritative_stanza_id,
        Some(Uuid::from_u128(0x573_170003))
    );
    let observation = attempt.observation();
    let route = attempt
        .route("<message to='archive-receipt@example.test'/>".into())
        .unwrap();
    route.start().unwrap();
    for (label, replace, expected) in [
        ("renew exact lease", false, true),
        ("renew replaced lease", true, false),
    ] {
        if replace {
            sqlx::query("UPDATE mix_delivery_recipients SET lease_token=$2 WHERE delivery_id=$1")
                .bind(delivery)
                .bind(Uuid::from_u128(0x573_176602))
                .execute(&pool)
                .await
                .unwrap();
        }
        let request = observation.renewal_request().unwrap();
        request.start().unwrap();
        let renewed = repository
            .renew_mix_delivery_lease_observed(&request)
            .await
            .unwrap();
        assert_eq!(renewed, expected, "{label}");
        assert_eq!(
            observation.snapshot().renewal.knowledge,
            RenewalKnowledge::StatementReceipt(expected),
            "{label}"
        );
        assert_eq!(request.returned(renewed).unwrap(), expected, "{label}");
    }
    sqlx::query("DELETE FROM mix_delivery_recipients WHERE delivery_id=$1")
        .bind(delivery)
        .execute(&pool)
        .await
        .unwrap();
    db::reconcile_mix_delivery_capacity_committed(&pool)
        .await
        .unwrap();

    let original = Uuid::from_u128(0x573_176603);
    for (index, label, candidate, expected) in [
        (
            31,
            "archive stored",
            original,
            ArchiveResult::Stored(original),
        ),
        (
            32,
            "archive exact replay",
            Uuid::from_u128(0x573_176604),
            ArchiveResult::Replay(original),
        ),
    ] {
        let (_, delivery) = seed(&pool, index, true).await;
        let attempt = claim(&repository, delivery).await;
        let observation = attempt.observation();
        let route = attempt.route("<message to='archive-receipt@example.test'><body>archived receipt</body></message>".into()).unwrap();
        route.start().unwrap();
        let request = route
            .archive_request(user, candidate, Some("client-stanza".into()))
            .unwrap();
        request.start().unwrap();
        let result = repository
            .archive_mix_message_once_observed(&request)
            .await
            .unwrap();
        assert_eq!(result, expected, "{label}");
        assert_eq!(
            observation.snapshot().archive.knowledge,
            ArchiveKnowledge::ReceiptKnown(expected),
            "{label}"
        );
        assert_eq!(request.returned(result).unwrap(), expected, "{label}");
        let mut observer = pool.acquire().await.unwrap();
        let archived: (Uuid, String, String, bool) = sqlx::query_as(
            "SELECT id,peer_jid,stanza,encrypted FROM message_archive WHERE owner_id=$1 AND id=$2",
        )
        .bind(user)
        .bind(original)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert_eq!(
            archived,
            (
                original,
                "receipts@mix.example.test".into(),
                route.stanza().to_owned(),
                true
            ),
            "{label}: committed projection"
        );
        drop(observer);
        sqlx::query("DELETE FROM mix_delivery_recipients WHERE delivery_id=$1")
            .bind(delivery)
            .execute(&pool)
            .await
            .unwrap();
        db::reconcile_mix_delivery_capacity_committed(&pool)
            .await
            .unwrap();
    }
    let (_, delivery) = seed(&pool, 33, true).await;
    let attempt = claim(&repository, delivery).await;
    let observation = attempt.observation();
    let route = attempt
        .route(
            "<message to='archive-receipt@example.test'><body>changed archive</body></message>"
                .into(),
        )
        .unwrap();
    route.start().unwrap();
    let request = route
        .archive_request(
            user,
            Uuid::from_u128(0x573_176605),
            Some("client-stanza".into()),
        )
        .unwrap();
    request.start().unwrap();
    assert!(
        repository
            .archive_mix_message_once_observed(&request)
            .await
            .is_err(),
        "changed archive content is not an authenticated replay"
    );
    assert_eq!(
        observation.snapshot().archive.knowledge,
        ArchiveKnowledge::NoCommitEntered,
        "failed replay cannot manufacture a COMMIT receipt"
    );
    let mut observer = pool.acquire().await.unwrap();
    let originals: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM message_archive WHERE owner_id=$1")
            .bind(user)
            .fetch_all(&mut *observer)
            .await
            .unwrap();
    assert_eq!(
        originals,
        vec![original],
        "failed replay leaves only the original committed projection"
    );
    drop(observer);
    sqlx::query("DELETE FROM mix_delivery_recipients WHERE delivery_id=$1")
        .bind(delivery)
        .execute(&pool)
        .await
        .unwrap();
    db::reconcile_mix_delivery_capacity_committed(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn settlement_receipt_waits_for_the_actual_commit_acknowledgment() {
    let pool = crate::support::operation_mutation_pool().await;
    // A deferred constraint trigger runs during COMMIT, after the DELETE has
    // succeeded. Its lock separates entering COMMIT from acknowledging it.
    sqlx::query(
        "CREATE FUNCTION hold_mix_settlement_commit() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN PERFORM pg_advisory_xact_lock(5731745::bigint); RETURN OLD; END; $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE CONSTRAINT TRIGGER hold_mix_settlement_commit
         AFTER DELETE ON mix_delivery_recipients DEFERRABLE INITIALLY DEFERRED
         FOR EACH ROW WHEN (OLD.recipient_jid IN ('receipt-20@example.test','receipt-21@example.test'))
         EXECUTE FUNCTION hold_mix_settlement_commit()",
    ).execute(&pool).await.unwrap();
    for (ordinal, label, command, route_result, expected) in [
        (
            20,
            "ack commit",
            SettlementCommand::Ack,
            RouteResult::CompletedByWorker,
            SettlementResult::Ack(true),
        ),
        (
            21,
            "dead letter commit",
            SettlementCommand::DeadLetter {
                reason: "invalid-template".into(),
                error: "commit barrier".into(),
            },
            RouteResult::Permanent,
            SettlementResult::DeadLetter(true),
        ),
    ] {
        let (_, delivery) = seed(&pool, ordinal, false).await;
        let repository = PostgresMixRepository::new(pool.clone());
        let attempt = claim(&repository, delivery).await;
        let observation = attempt.observation();
        let route = attempt
            .route(format!("<message to='{}'/>", recipient(ordinal)))
            .unwrap();
        route.start().unwrap();
        let closed = observation.close_renewal_scope().unwrap();
        let request = route
            .returned(route_result)
            .unwrap()
            .settlement(command, closed)
            .unwrap()
            .unwrap();
        request.start().unwrap();
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(5731745::bigint)")
            .execute(&mut *blocker)
            .await
            .unwrap();
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        let settling = tokio::spawn(async move {
            let result = repository.settle_mix_delivery_observed(&request).await;
            (request, result)
        });
        crate::support::blocked_backend(&pool, blocker_pid).await;
        let snapshot = observation.snapshot().settlement.unwrap();
        assert_eq!(
            snapshot.knowledge,
            SettlementKnowledge::CommitCallEntered(expected),
            "{label}: COMMIT is pending"
        );
        assert_eq!(snapshot.returned, None, "{label}: no raw return yet");
        let mut observer = pool.acquire().await.unwrap();
        let visible: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mix_delivery_recipients WHERE delivery_id=$1)",
        )
        .bind(delivery)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert!(
            visible,
            "{label}: the unacknowledged deletion is still invisible to another session"
        );
        drop(observer);
        blocker.rollback().await.unwrap();
        let (request, result) = settling.await.unwrap();
        assert_eq!(result.unwrap(), expected, "{label}");
        assert_eq!(
            observation.snapshot().settlement.unwrap().knowledge,
            SettlementKnowledge::ReceiptKnown(expected),
            "{label}: acknowledged COMMIT"
        );
        assert_eq!(request.returned(expected).unwrap(), expected);
        let mut observer = pool.acquire().await.unwrap();
        let visible: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mix_delivery_recipients WHERE delivery_id=$1)",
        )
        .bind(delivery)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert!(!visible, "{label}: acknowledged deletion is durable");
        drop(observer);
        sqlx::query("DELETE FROM mix_delivery_dead_letters WHERE delivery_id=$1")
            .bind(delivery)
            .execute(&pool)
            .await
            .unwrap();
        db::reconcile_mix_delivery_capacity_committed(&pool)
            .await
            .unwrap();
    }
    sqlx::query("DROP TRIGGER hold_mix_settlement_commit ON mix_delivery_recipients")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION hold_mix_settlement_commit()")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn claim_row_and_byte_limits_bound_the_acknowledged_sql_allocation() {
    let pool = crate::support::operation_mutation_pool().await;
    let repository = PostgresMixRepository::new(pool.clone());
    let stanza = format!(
        "<message xmlns='jabber:client'><body>{}</body></message>",
        "x".repeat(40_000)
    );
    let mut remaining = std::collections::BTreeSet::new();
    let mut all = Vec::new();
    for ordinal in 24..27 {
        let (_, delivery) = seed_with_stanza(&pool, ordinal, false, &stanza).await;
        remaining.insert(delivery);
        all.push(delivery);
    }
    for (label, limit, max_bytes) in [
        ("row bound", 1, 1_048_576),
        ("byte bound", 3, 65_536),
        ("remaining head", 3, 1_048_576),
    ] {
        let observation = ClaimObservation::new(ClaimCommand { limit, max_bytes });
        let request = observation.request().unwrap();
        request.start().unwrap();
        let rows = repository
            .claim_mix_deliveries_observed(&request)
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "{label}: actual SQL allocation obeys the bound"
        );
        let ClaimKnowledge::StatementReceipt(receipt) = observation.snapshot().knowledge else {
            panic!("{label}: no SQL receipt");
        };
        assert!(
            Arc::ptr_eq(&receipt, &rows),
            "{label}: original returned allocation"
        );
        assert_eq!(rows[0].stanza, stanza, "{label}: bound payload survives");
        let source = rows[0].source;
        assert!(
            remaining.remove(&source.delivery_id),
            "{label}: a distinct original delivery"
        );
        let mut observer = pool.acquire().await.unwrap();
        let durable_token: Uuid = sqlx::query_scalar(
            "SELECT lease_token FROM mix_delivery_recipients WHERE delivery_id=$1",
        )
        .bind(source.delivery_id)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert_eq!(
            durable_token, source.lease_token,
            "{label}: statement receipt is committed independently"
        );
        assert_eq!(request.returned(rows).unwrap().len(), 1, "{label}");
    }
    assert!(remaining.is_empty());
    sqlx::query("DELETE FROM mix_delivery_recipients WHERE delivery_id=ANY($1::uuid[])")
        .bind(all)
        .execute(&pool)
        .await
        .unwrap();
    db::reconcile_mix_delivery_capacity_committed(&pool)
        .await
        .unwrap();
    pool.close().await;
}
