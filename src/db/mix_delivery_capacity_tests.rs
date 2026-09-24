use super::*;
use crate::db;

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn delivery_ack_is_independent_of_the_producer_fence_and_release_is_atomic() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();

    let event_id = Uuid::new_v4();
    let delivery_id = Uuid::new_v4();
    let lease_token = Uuid::new_v4();
    let recipient_participant_id = Uuid::new_v4();
    let channel_id = Uuid::new_v4();
    let recipient = "ack-target@example.test";
    let stanza = "<message xmlns='jabber:client' type='groupchat'><body>capacity fence regression</body></message>";

    // Use the same typed producer boundary as production so setup does not
    // bypass either complete reconciliation or exact capacity reservation.
    let (mut setup, fence) = begin_mix_delivery_admission(&pool).await.unwrap();
    let baseline: (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(queued_rows),0)::bigint,
                    COALESCE(SUM(queued_bytes),0)::bigint
               FROM mix_delivery_capacity",
    )
    .fetch_one(&mut *setup)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO mix_delivery_events(
                 event_id,channel_id,channel_jid,stanza_template,
                 authoritative_stanza_id,archive,encrypted
             ) VALUES($1,$2,'capacity@mix.example.test',$3,NULL,FALSE,FALSE)",
    )
    .bind(event_id)
    .bind(channel_id)
    .bind(stanza)
    .execute(&mut *setup)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO mix_delivery_recipients(
                 delivery_id,event_id,recipient_participant_id,recipient_jid,
                 delivery_sequence,lease_token,lease_until
             ) VALUES($1,$2,$3,$4,1,$5,clock_timestamp()+INTERVAL '90 seconds')",
    )
    .bind(delivery_id)
    .bind(event_id)
    .bind(recipient_participant_id)
    .bind(recipient)
    .bind(lease_token)
    .execute(&mut *setup)
    .await
    .unwrap();
    let mut deltas = BTreeMap::new();
    add_mix_delivery_capacity_delta(
        &mut deltas,
        mix_delivery_capacity_bucket(event_id),
        0,
        i64::try_from(stanza.len()).unwrap(),
    )
    .unwrap();
    add_mix_delivery_capacity_delta(
        &mut deltas,
        mix_delivery_capacity_bucket(delivery_id),
        1,
        i64::try_from(recipient.len() + 128).unwrap(),
    )
    .unwrap();
    reserve_mix_delivery_capacity_tx(&mut setup, &fence, &deltas)
        .await
        .unwrap();
    setup.commit().await.unwrap();
    audit_mix_delivery_capacity_ledger(&pool).await.unwrap();

    // Reproduce the old 55P03 window exactly: another transaction owns the
    // global producer fence while the leased recipient is acknowledged.
    // Completion must neither wait for that fence nor touch a hot capacity
    // row; it commits one authentic release fact with the recipient delete.
    let (producer, _held_fence) = begin_mix_delivery_fenced_transaction(&pool).await.unwrap();
    let acknowledged = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        acknowledge_mix_delivery(&pool, delivery_id, lease_token),
    )
    .await
    .expect("MIX ACK waited behind the producer capacity fence")
    .expect("MIX ACK failed while an unrelated producer held the fence");
    assert!(
        acknowledged,
        "the exact leased recipient was not acknowledged"
    );
    let release_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM mix_delivery_capacity_releases
              WHERE release_kind=1 AND object_id=$1 AND parent_event_id=$2",
    )
    .bind(delivery_id)
    .bind(event_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        release_count, 1,
        "ACK did not commit one exact release fact"
    );
    producer.rollback().await.unwrap();
    audit_mix_delivery_capacity_ledger(&pool).await.unwrap();

    // A crash-equivalent rollback after reconciliation must restore the
    // orphan event, release fact and original conservative ledger together.
    let (mut rollback, _rollback_fence) =
        begin_mix_delivery_fenced_transaction(&pool).await.unwrap();
    let _: i64 = sqlx::query_scalar("SELECT northstar_mix_delivery_capacity_reconcile()")
        .fetch_one(&mut *rollback)
        .await
        .unwrap();
    let staged_event: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mix_delivery_events WHERE event_id=$1)")
            .bind(event_id)
            .fetch_one(&mut *rollback)
            .await
            .unwrap();
    let staged_releases: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM mix_delivery_capacity_releases
              WHERE object_id IN ($1,$2)",
    )
    .bind(delivery_id)
    .bind(event_id)
    .fetch_one(&mut *rollback)
    .await
    .unwrap();
    assert!(!staged_event && staged_releases == 0);
    rollback.rollback().await.unwrap();

    let restored_event: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mix_delivery_events WHERE event_id=$1)")
            .bind(event_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let restored_release: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM mix_delivery_capacity_releases
              WHERE release_kind=1 AND object_id=$1 AND parent_event_id=$2",
    )
    .bind(delivery_id)
    .bind(event_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(restored_event && restored_release == 1);
    audit_mix_delivery_capacity_ledger(&pool).await.unwrap();

    // The separately committed production reconciliation now removes the
    // orphan template, consumes both release facts and returns exactly to
    // the pre-test capacity totals without worker pages or retry timing.
    reconcile_mix_delivery_capacity_committed(&pool)
        .await
        .unwrap();
    let final_event: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mix_delivery_events WHERE event_id=$1)")
            .bind(event_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let final_releases: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM mix_delivery_capacity_releases
              WHERE object_id IN ($1,$2)",
    )
    .bind(delivery_id)
    .bind(event_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let final_totals: (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(queued_rows),0)::bigint,
                    COALESCE(SUM(queued_bytes),0)::bigint
               FROM mix_delivery_capacity",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!final_event);
    assert_eq!(final_releases, 0);
    assert_eq!(final_totals, baseline);
    audit_mix_delivery_capacity_ledger(&pool).await.unwrap();
}
