use crate::support::delivery::{native_ack, seed_c2s};
use northstar_delivery_core::{
    native_write::{AckDisposition, AckFact, AckKnowledge},
    DurableDelivery, TransportOwnershipSource as Source,
};
use northstar_session_postgres::replay::acknowledge_durable_deliveries_observed;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn native_ack_receipts_follow_commit() {
    let pool = crate::support::operation_mutation_pool().await;
    let user = Uuid::from_u128(0x581_0100);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'native-receipts','test')")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    let deleted = DurableDelivery {
        recipient_id: user,
        message_id: Uuid::from_u128(0x581_0101),
        claim_id: Some(Uuid::from_u128(0x581_0102)),
    };
    seed_c2s(&pool, deleted).await;
    sqlx::query(
        "CREATE FUNCTION hold_native_receipt_commit() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN PERFORM pg_advisory_xact_lock(5810101::bigint); RETURN OLD; END; $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE CONSTRAINT TRIGGER hold_native_receipt_commit
         AFTER DELETE ON offline_messages DEFERRABLE INITIALLY DEFERRED
         FOR EACH ROW WHEN (OLD.id='{}'::uuid)
         EXECUTE FUNCTION hold_native_receipt_commit()",
        deleted.message_id,
    )))
    .execute(&pool)
    .await
    .unwrap();
    let (observation, request) = native_ack(Source::C2s(deleted));
    let fact = AckFact {
        source: Source::C2s(deleted),
        disposition: AckDisposition::Deleted,
    };
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(5810101::bigint)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let mut observer = pool.acquire().await.unwrap();
    let observer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *observer)
        .await
        .unwrap();
    let worker_pool = pool.clone();
    let acknowledging = tokio::spawn(async move {
        let result =
            acknowledge_durable_deliveries_observed(&worker_pool, &[deleted], Some(&request)).await;
        (request, result)
    });
    let worker_pid = crate::support::blocked_backend(&pool, blocker_pid).await;
    assert_ne!(
        worker_pid, observer_pid,
        "independent committed-row observer"
    );
    assert_eq!(
        observation.snapshot().ack,
        AckKnowledge::CommitCallEntered(fact)
    );
    let claim: Option<Uuid> =
        sqlx::query_scalar("SELECT delivery_claim_id FROM offline_messages WHERE id=$1")
            .bind(deleted.message_id)
            .fetch_one(&mut *observer)
            .await
            .unwrap();
    assert_eq!(
        claim, deleted.claim_id,
        "pending COMMIT leaves the claimed row visible"
    );
    blocker.rollback().await.unwrap();
    let (request, result) = acknowledging.await.unwrap();
    result.unwrap();
    assert_eq!(observation.snapshot().ack, AckKnowledge::ReceiptKnown(fact));
    request.returned(true);
    assert_eq!(observation.snapshot().ack_returned, Some(true));
    let visible: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM offline_messages WHERE id=$1)")
            .bind(deleted.message_id)
            .fetch_one(&mut *observer)
            .await
            .unwrap();
    assert!(!visible, "acknowledged deletion is committed");

    // This fixture's deferred FK permits DELETE and rejects COMMIT itself.
    sqlx::query(
        "CREATE TABLE native_receipt_guard(message_id uuid PRIMARY KEY
             REFERENCES offline_messages(id) DEFERRABLE INITIALLY DEFERRED)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE FUNCTION suppress_native_receipt_delete() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN RETURN NULL; END; $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TRIGGER suppress_native_receipt_delete BEFORE DELETE ON offline_messages
         FOR EACH ROW WHEN (OLD.id='{}'::uuid)
         EXECUTE FUNCTION suppress_native_receipt_delete()",
        Uuid::from_u128(0x581_0140),
    )))
    .execute(&pool)
    .await
    .unwrap();
    for (label, base, stale, guard, suppressed) in [
        ("stale claim", 0x581_0110, true, false, false),
        ("commit rejected", 0x581_0120, false, true, false),
        ("missing claimed row", 0x581_0130, false, false, false),
        ("zero deleted rows", 0x581_0140, false, false, true),
    ] {
        let source = DurableDelivery {
            recipient_id: user,
            message_id: Uuid::from_u128(base),
            claim_id: Some(Uuid::from_u128(base + 1)),
        };
        if stale || guard || suppressed {
            seed_c2s(&pool, source).await;
        }
        if guard {
            sqlx::query("INSERT INTO native_receipt_guard VALUES($1)")
                .bind(source.message_id)
                .execute(&pool)
                .await
                .unwrap();
        }
        let supplied = if stale {
            DurableDelivery {
                claim_id: Some(Uuid::from_u128(base + 2)),
                ..source
            }
        } else {
            source
        };
        let (observation, request) = native_ack(Source::C2s(supplied));
        let Err(error) =
            acknowledge_durable_deliveries_observed(&pool, &[supplied], Some(&request)).await
        else {
            panic!("{label}: invalid deletion succeeded");
        };
        let expected = if guard {
            AckKnowledge::CommitCallEntered(AckFact {
                source: Source::C2s(source),
                disposition: AckDisposition::Deleted,
            })
        } else {
            AckKnowledge::NoCommitRequested
        };
        assert_eq!(observation.snapshot().ack, expected, "{label}");
        assert!(
            format!("{error:#}").contains(if guard {
                "native_receipt_guard"
            } else if suppressed {
                "durable delivery disappeared during acknowledgement"
            } else {
                "offline delivery claim was lost before acknowledgement"
            }),
            "{label}: {error:#}"
        );
        let row: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
            "SELECT recipient_id,delivery_claim_id FROM offline_messages WHERE id=$1",
        )
        .bind(source.message_id)
        .fetch_optional(&mut *observer)
        .await
        .unwrap();
        assert_eq!(
            row,
            (stale || guard || suppressed).then_some((user, source.claim_id)),
            "{label}: rollback"
        );
    }
    drop(observer);
    sqlx::query("DROP TABLE native_receipt_guard")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER hold_native_receipt_commit ON offline_messages")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION hold_native_receipt_commit()")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER suppress_native_receipt_delete ON offline_messages")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION suppress_native_receipt_delete()")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
