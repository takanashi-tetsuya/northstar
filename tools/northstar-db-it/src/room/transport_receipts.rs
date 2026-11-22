use crate::support::delivery::{bosh_operation, native_ack, seed_mix};
use northstar_delivery_core::{
    bosh_ownership::TransferKnowledge,
    native_write::{AckDisposition, AckFact, AckKnowledge},
    MixDelivery, TransportOwnershipSource as Source,
};
use northstar_room_application::mix_service::MixDeliveryRepository;
use northstar_room_postgres::mix as db;
use northstar_time::{DateTime, TimeDelta, Utc};
use northstar_workflows::room_effects::PostgresMixRepository;
use uuid::Uuid;

type FenceRow = (
    Uuid,
    Uuid,
    Option<i64>,
    DateTime<Utc>,
    DateTime<Utc>,
    Uuid,
    DateTime<Utc>,
);

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn mix_native_ack_receipts_distinguish_no_match() {
    let pool = crate::support::operation_mutation_pool().await;
    sqlx::query(
        "CREATE TABLE mix_native_receipt_guard(delivery_id uuid PRIMARY KEY
             REFERENCES mix_delivery_recipients(delivery_id) DEFERRABLE INITIALLY DEFERRED)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut observer = pool.acquire().await.unwrap();
    let mut events = Vec::new();
    for (label, base, present, stale, guarded) in [
        ("deleted", 0x581_0200, true, false, false),
        ("replaced lease", 0x581_0210, true, true, false),
        ("absent source", 0x581_0220, false, false, false),
        ("commit rejected", 0x581_0230, true, false, true),
    ] {
        let source = if present {
            let (event, source) = seed_mix(&pool, base).await;
            events.push(event);
            source
        } else {
            MixDelivery {
                delivery_id: Uuid::from_u128(base + 1),
                lease_token: Uuid::from_u128(base + 2),
            }
        };
        if guarded {
            sqlx::query("INSERT INTO mix_native_receipt_guard VALUES($1)")
                .bind(source.delivery_id)
                .execute(&pool)
                .await
                .unwrap();
        }
        let supplied = if stale {
            MixDelivery {
                lease_token: Uuid::from_u128(base + 5),
                ..source
            }
        } else {
            source
        };
        let (observation, request) = native_ack(Source::Mix(supplied));
        let result = db::acknowledge_mix_delivery_observed(
            &pool,
            supplied.delivery_id,
            supplied.lease_token,
            Some(&request),
        )
        .await;
        let removed = present && !stale;
        let fact = AckFact {
            source: Source::Mix(supplied),
            disposition: if removed {
                AckDisposition::Deleted
            } else {
                AckDisposition::NoMatchingMix
            },
        };
        if guarded {
            let Err(error) = result else {
                panic!("{label}: protected row was deleted");
            };
            assert!(
                format!("{error:#}").contains("mix_native_receipt_guard"),
                "{label}: {error:#}"
            );
            assert_eq!(
                observation.snapshot().ack,
                AckKnowledge::CommitCallEntered(fact),
                "{label}"
            );
        } else {
            assert_eq!(result.unwrap(), removed, "{label}");
            assert_eq!(
                observation.snapshot().ack,
                AckKnowledge::ReceiptKnown(fact),
                "{label}"
            );
        }
        let token: Option<Uuid> = sqlx::query_scalar(
            "SELECT lease_token FROM mix_delivery_recipients WHERE delivery_id=$1",
        )
        .bind(source.delivery_id)
        .fetch_optional(&mut *observer)
        .await
        .unwrap();
        assert_eq!(
            token,
            (present && (!removed || guarded)).then_some(source.lease_token),
            "{label}: committed row"
        );
    }
    drop(observer);
    sqlx::query("DROP TABLE mix_native_receipt_guard")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM mix_delivery_events WHERE event_id=ANY($1)")
        .bind(&events)
        .execute(&pool)
        .await
        .unwrap();
    db::reconcile_mix_delivery_capacity_committed(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn bosh_transfer_receipts_bind_clamped_inputs() {
    let pool = crate::support::operation_mutation_pool().await;
    let repository = PostgresMixRepository::new(pool.clone());
    let session = Uuid::from_u128(0x581_0300);
    let refused_session = Uuid::from_u128(0x581_0301);
    let suppressed_session = Uuid::from_u128(0x581_0302);
    sqlx::query(
        "CREATE FUNCTION hold_bosh_transfer_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN PERFORM pg_advisory_xact_lock(5810300::bigint); RETURN NEW; END; $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE CONSTRAINT TRIGGER hold_bosh_transfer_receipt
         AFTER INSERT ON mix_bosh_delivery_fences DEFERRABLE INITIALLY DEFERRED
         FOR EACH ROW WHEN (NEW.session_id='{session}'::uuid)
         EXECUTE FUNCTION hold_bosh_transfer_receipt()",
    )))
    .execute(&pool)
    .await
    .unwrap();
    let mut observer = pool.acquire().await.unwrap();
    let observer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *observer)
        .await
        .unwrap();
    let mut events = Vec::new();
    for (label, base, ttl, expected_ttl) in [
        ("minimum ttl", 0x581_0310, 0, 1),
        ("requested ttl", 0x581_0320, 47, 47),
        ("maximum ttl", 0x581_0330, u64::MAX, 300),
    ] {
        let (event, source) = seed_mix(&pool, base).await;
        events.push(event);
        let operation = bosh_operation(session, ttl);
        let request = operation.begin_transfer(source).unwrap();
        let original_row: serde_json::Value = sqlx::query_scalar(
            "SELECT to_jsonb(recipient) FROM mix_delivery_recipients recipient WHERE delivery_id=$1",
        ).bind(source.delivery_id).fetch_one(&mut *observer).await.unwrap();
        let before: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *observer)
            .await
            .unwrap();
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(5810300::bigint)")
            .execute(&mut *blocker)
            .await
            .unwrap();
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        let worker_repository = repository.clone();
        let mut transferring = tokio::spawn(async move {
            let result = worker_repository
                .transfer_mix_delivery_to_bosh(&request)
                .await;
            (request, result)
        });
        let worker_pid = tokio::select! {
            pid = crate::support::blocked_backend(&pool, blocker_pid) => pid,
            finished = &mut transferring => {
                let (_, result) = finished.unwrap();
                panic!("{label}: transfer returned before its COMMIT barrier: {result:?}");
            }
        };
        assert_ne!(worker_pid, observer_pid, "{label}: independent observer");
        let TransferKnowledge::CommitCallEntered(prepared) =
            operation.snapshot().transfers[0].knowledge
        else {
            panic!("{label}: transfer did not enter its COMMIT observer");
        };
        assert_eq!(prepared.delivery_id, source.delivery_id, "{label}");
        let visible: Option<Uuid> = sqlx::query_scalar(
            "SELECT lease_token FROM mix_bosh_delivery_fences WHERE delivery_id=$1",
        )
        .bind(source.delivery_id)
        .fetch_optional(&mut *observer)
        .await
        .unwrap();
        assert_eq!(visible, None, "{label}: pending insert is not committed");
        let pending_row: serde_json::Value = sqlx::query_scalar(
            "SELECT to_jsonb(recipient) FROM mix_delivery_recipients recipient WHERE delivery_id=$1",
        ).bind(source.delivery_id).fetch_one(&mut *observer).await.unwrap();
        assert_eq!(
            pending_row, original_row,
            "{label}: pending rotation and TTL are not committed"
        );
        blocker.rollback().await.unwrap();
        let (request, result) = transferring.await.unwrap();
        let current = result.unwrap();
        assert_eq!(
            current, prepared,
            "{label}: returned source equals COMMIT preparation"
        );
        assert_eq!(
            operation.snapshot().transfers[0].knowledge,
            TransferKnowledge::ReceiptKnown(current),
            "{label}"
        );
        request.returned(current).unwrap();
        assert!(
            operation.snapshot().transfers[0].return_matches_receipt,
            "{label}"
        );
        let after: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *observer)
            .await
            .unwrap();
        let rows: Vec<FenceRow> = sqlx::query_as(
            "SELECT fence.session_id,fence.lease_token,fence.response_rid,fence.expires_at,
                    fence.first_owned_at,recipient.lease_token,recipient.lease_until
             FROM mix_bosh_delivery_fences fence JOIN mix_delivery_recipients recipient USING(delivery_id)
             WHERE delivery_id=$1",
        ).bind(source.delivery_id).fetch_all(&mut *observer).await.unwrap();
        assert_eq!(rows.len(), 1, "{label}: exactly one pending fence");
        let (owner, token, rid, expiry, first_owned, recipient_token, lease) = rows[0];
        assert_eq!(
            (owner, token, rid, recipient_token),
            (session, current.lease_token, None, current.lease_token),
            "{label}"
        );
        // One clock read: a separately read first-owned time could put the
        // maximum TTL past the five-minute ownership CHECK.
        assert_eq!(
            expiry - first_owned,
            TimeDelta::seconds(expected_ttl),
            "{label}: expiry measured from the first-owned instant"
        );
        for deadline in [expiry, lease] {
            assert!(
                deadline >= before + TimeDelta::seconds(expected_ttl)
                    && deadline <= after + TimeDelta::seconds(expected_ttl),
                "{label}: clamped database TTL"
            );
        }
    }
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE mix_bosh_delivery_fences ADD CONSTRAINT reject_transfer_receipt_session
         CHECK (session_id<>'{refused_session}'::uuid) NOT VALID",
    )))
    .execute(&pool)
    .await
    .unwrap();
    // A successful INSERT statement can affect zero rows when a BEFORE
    // trigger suppresses it. The adapter must check the affected-row count
    // and roll back the earlier lease rotation in this case too.
    sqlx::query(
        "CREATE FUNCTION suppress_bosh_transfer_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN RETURN NULL; END; $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TRIGGER suppress_bosh_transfer_receipt BEFORE INSERT ON mix_bosh_delivery_fences
         FOR EACH ROW WHEN (NEW.session_id='{suppressed_session}'::uuid)
         EXECUTE FUNCTION suppress_bosh_transfer_receipt()",
    )))
    .execute(&pool)
    .await
    .unwrap();
    for (label, base, stale, owner, expected_error) in [
        (
            "stale source refused",
            0x581_0340,
            true,
            refused_session,
            "MIX lease changed before BOSH ownership transfer",
        ),
        (
            "fence insertion rejected",
            0x581_0350,
            false,
            refused_session,
            "reject_transfer_receipt_session",
        ),
        (
            "zero inserted rows",
            0x581_0360,
            false,
            suppressed_session,
            "MIX BOSH ownership transfer did not create its fence",
        ),
    ] {
        let (event, source) = seed_mix(&pool, base).await;
        events.push(event);
        let supplied = if stale {
            MixDelivery {
                lease_token: Uuid::from_u128(base + 5),
                ..source
            }
        } else {
            source
        };
        let operation = bosh_operation(owner, 90);
        let request = operation.begin_transfer(supplied).unwrap();
        let before: serde_json::Value = sqlx::query_scalar(
            "SELECT to_jsonb(recipient) FROM mix_delivery_recipients recipient WHERE delivery_id=$1",
        ).bind(source.delivery_id).fetch_one(&mut *observer).await.unwrap();
        let Err(error) = repository.transfer_mix_delivery_to_bosh(&request).await else {
            panic!("{label}: invalid transfer succeeded");
        };
        assert!(
            format!("{error:#}").contains(expected_error),
            "{label}: {error:#}"
        );
        assert_eq!(
            operation.snapshot().transfers[0].knowledge,
            TransferKnowledge::NoCommitRequested,
            "{label}"
        );
        let after: serde_json::Value = sqlx::query_scalar(
            "SELECT to_jsonb(recipient) FROM mix_delivery_recipients recipient WHERE delivery_id=$1",
        ).bind(source.delivery_id).fetch_one(&mut *observer).await.unwrap();
        assert_eq!(after, before, "{label}: lease rotation and TTL rolled back");
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mix_bosh_delivery_fences WHERE delivery_id=$1",
        )
        .bind(source.delivery_id)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert_eq!(count, 0, "{label}: no committed transfer fence");
    }
    drop(observer);
    sqlx::query(
        "ALTER TABLE mix_bosh_delivery_fences DROP CONSTRAINT reject_transfer_receipt_session",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DROP TRIGGER hold_bosh_transfer_receipt ON mix_bosh_delivery_fences")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION hold_bosh_transfer_receipt()")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER suppress_bosh_transfer_receipt ON mix_bosh_delivery_fences")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION suppress_bosh_transfer_receipt()")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM mix_delivery_events WHERE event_id=ANY($1)")
        .bind(&events)
        .execute(&pool)
        .await
        .unwrap();
    db::reconcile_mix_delivery_capacity_committed(&pool)
        .await
        .unwrap();
    pool.close().await;
}
