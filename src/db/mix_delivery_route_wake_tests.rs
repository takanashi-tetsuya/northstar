use super::*;
use crate::db;

async fn isolated_pool() -> PgPool {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    pool
}

/// Insert through the same fenced capacity boundary used by production.
/// The caller selects a sequence explicitly so the ordering regression can
/// exercise a dead-letter predecessor and a deferred live successor.
pub(super) async fn insert_delivery(
    pool: &PgPool,
    recipient: &str,
    delivery_sequence: i64,
) -> (Uuid, Uuid) {
    let event_id = Uuid::new_v4();
    let delivery_id = Uuid::new_v4();
    let channel_id = Uuid::new_v4();
    let stanza = "<message xmlns='jabber:client' type='groupchat'><body>route wake regression</body></message>";
    let (mut transaction, fence) = begin_mix_delivery_admission(pool).await.unwrap();
    sqlx::query(
        "INSERT INTO mix_delivery_recipient_sequences(recipient_jid,next_sequence)
              VALUES($1,$2)
              ON CONFLICT(recipient_jid) DO UPDATE
                  SET next_sequence=GREATEST(
                      mix_delivery_recipient_sequences.next_sequence,EXCLUDED.next_sequence
                  )",
    )
    .bind(recipient)
    .bind(delivery_sequence + 1)
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO mix_delivery_events(
                 event_id,channel_id,channel_jid,stanza_template,
                 authoritative_stanza_id,archive,encrypted
             ) VALUES($1,$2,'route-wake@mix.example.test',$3,NULL,FALSE,FALSE)",
    )
    .bind(event_id)
    .bind(channel_id)
    .bind(stanza)
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO mix_delivery_recipients(
                 delivery_id,event_id,recipient_participant_id,recipient_jid,delivery_sequence
             ) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(delivery_id)
    .bind(event_id)
    .bind(Uuid::new_v4())
    .bind(recipient)
    .bind(delivery_sequence)
    .execute(&mut *transaction)
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
        i64::try_from(recipient.len() + MIX_DELIVERY_RECIPIENT_OVERHEAD as usize).unwrap(),
    )
    .unwrap();
    reserve_mix_delivery_capacity_tx(&mut transaction, &fence, &deltas)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    (event_id, delivery_id)
}

async fn claim_delivery(pool: &PgPool, delivery_id: Uuid) -> ClaimedMixDelivery {
    claim_mix_deliveries(pool, 128, 65_536)
        .await
        .unwrap()
        .into_iter()
        .find(|delivery| delivery.delivery_id == delivery_id)
        .expect("the due test delivery was not claimed")
}

async fn schedule_is_due(pool: &PgPool, delivery_id: Uuid) -> (bool, Option<Uuid>, i32, i64) {
    sqlx::query_as(
        "SELECT next_attempt_at<=clock_timestamp(),lease_token,attempt_count,route_wake_generation
               FROM mix_delivery_recipients WHERE delivery_id=$1",
    )
    .bind(delivery_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn an_expired_unowned_head_blocks_until_terminalized() {
    let pool = isolated_pool().await;
    let recipient = format!("expired-head-{}@example.test", Uuid::new_v4());
    let (expired_event_id, expired_delivery_id) = insert_delivery(&pool, &recipient, 1).await;
    let (_, live_delivery_id) = insert_delivery(&pool, &recipient, 2).await;

    assert_eq!(
        sqlx::query(
            "UPDATE mix_delivery_events
                    SET created_at=clock_timestamp()-INTERVAL '2 seconds',
                        expires_at=clock_timestamp()-INTERVAL '1 second'
                  WHERE event_id=$1",
        )
        .bind(expired_event_id)
        .execute(&pool)
        .await
        .unwrap()
        .rows_affected(),
        1
    );

    // MX08: expiry does not bypass the same-recipient ordering contract.
    // The predecessor is not eligible for delivery, but its successor may
    // advance only after the bounded retention page records its terminal
    // dead-letter projection and removes the ordered head.
    let claimed = claim_mix_deliveries(&pool, 128, 65_536).await.unwrap();
    assert!(
        !claimed
            .iter()
            .any(|row| row.delivery_id == expired_delivery_id),
        "expired head must never be delivered"
    );
    assert!(
        !claimed
            .iter()
            .any(|row| row.delivery_id == live_delivery_id),
        "successor must wait until the expired head is terminalized"
    );
    let pending_expired: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_delivery_recipients WHERE delivery_id=$1)",
    )
    .bind(expired_delivery_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(pending_expired, "claim must not perform retention cleanup");

    maintain_mix_delivery_retention(&pool).await.unwrap();
    let dead_lettered: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_delivery_dead_letters WHERE delivery_id=$1)",
    )
    .bind(expired_delivery_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(dead_lettered, "the bounded maintenance page records expiry");

    let claimed = claim_mix_deliveries(&pool, 128, 65_536).await.unwrap();
    assert!(
        claimed
            .iter()
            .any(|row| row.delivery_id == live_delivery_id),
        "successor becomes eligible after terminalization removes its head"
    );
    let successor = claimed
        .into_iter()
        .find(|row| row.delivery_id == live_delivery_id)
        .unwrap();
    assert!(
        acknowledge_mix_delivery(&pool, successor.delivery_id, successor.lease_token)
            .await
            .unwrap()
    );
    reconcile_mix_delivery_capacity_committed(&pool)
        .await
        .unwrap();
    audit_mix_delivery_capacity_ledger(&pool).await.unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn leased_route_wake_defeats_defer_and_retry_but_not_unrelated_backoff() {
    let pool = isolated_pool().await;
    let recipient = format!("route-wake-{}@example.test", Uuid::new_v4());

    let (_, deferred_id) = insert_delivery(&pool, &recipient, 1).await;
    let deferred = claim_delivery(&pool, deferred_id).await;
    assert_eq!(
        wake_mix_delivery_recipient(&pool, &recipient)
            .await
            .unwrap(),
        1
    );
    assert!(defer_mix_delivery(
        &pool,
        deferred.delivery_id,
        deferred.lease_token,
        deferred.route_wake_generation,
        30,
    )
    .await
    .unwrap());
    let (due, lease, attempts, generation) = schedule_is_due(&pool, deferred_id).await;
    assert!(
        due,
        "a leased-head wake must defeat the later defer backoff"
    );
    assert!(lease.is_none());
    assert_eq!(attempts, 0);
    assert_eq!(generation, deferred.route_wake_generation + 1);
    let deferred_again = claim_delivery(&pool, deferred_id).await;
    assert!(acknowledge_mix_delivery(
        &pool,
        deferred_again.delivery_id,
        deferred_again.lease_token
    )
    .await
    .unwrap());

    let (_, retry_id) = insert_delivery(&pool, &recipient, 2).await;
    let retry = claim_delivery(&pool, retry_id).await;
    assert_eq!(
        wake_mix_delivery_recipient(&pool, &recipient)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        retry_mix_delivery(
            &pool,
            retry.delivery_id,
            retry.lease_token,
            retry.route_wake_generation,
            "route wake regression",
        )
        .await
        .unwrap(),
        MixDeliveryRetryOutcome::Retried
    );
    let (due, lease, attempts, generation) = schedule_is_due(&pool, retry_id).await;
    assert!(
        due,
        "a leased-head wake must defeat the later retry backoff"
    );
    assert!(lease.is_none());
    assert_eq!(attempts, retry.attempt_count + 1);
    assert_eq!(generation, retry.route_wake_generation + 1);
    let retry_again = claim_delivery(&pool, retry_id).await;
    assert!(
        acknowledge_mix_delivery(&pool, retry_again.delivery_id, retry_again.lease_token)
            .await
            .unwrap()
    );

    // Controls deliberately omit wake: normal recovery remains delayed.
    let (_, defer_control_id) = insert_delivery(&pool, &recipient, 3).await;
    let defer_control = claim_delivery(&pool, defer_control_id).await;
    assert!(defer_mix_delivery(
        &pool,
        defer_control.delivery_id,
        defer_control.lease_token,
        defer_control.route_wake_generation,
        30,
    )
    .await
    .unwrap());
    let (due, lease, attempts, generation) = schedule_is_due(&pool, defer_control_id).await;
    assert!(!due, "no-wake defer must retain its bounded recovery delay");
    assert!(lease.is_none());
    assert_eq!(attempts, 0);
    assert_eq!(generation, defer_control.route_wake_generation);

    // Clean this delayed control by making the route transition explicit,
    // then verify retry's independent no-wake control below.
    assert_eq!(
        wake_mix_delivery_recipient(&pool, &recipient)
            .await
            .unwrap(),
        1
    );
    let defer_control_again = claim_delivery(&pool, defer_control_id).await;
    assert!(acknowledge_mix_delivery(
        &pool,
        defer_control_again.delivery_id,
        defer_control_again.lease_token,
    )
    .await
    .unwrap());

    let (_, retry_control_id) = insert_delivery(&pool, &recipient, 4).await;
    let retry_control = claim_delivery(&pool, retry_control_id).await;
    assert_eq!(
        retry_mix_delivery(
            &pool,
            retry_control.delivery_id,
            retry_control.lease_token,
            retry_control.route_wake_generation,
            "normal retry control",
        )
        .await
        .unwrap(),
        MixDeliveryRetryOutcome::Retried
    );
    let (due, lease, attempts, generation) = schedule_is_due(&pool, retry_control_id).await;
    assert!(!due, "no-wake retry must retain exponential backoff");
    assert!(lease.is_none());
    assert_eq!(attempts, retry_control.attempt_count + 1);
    assert_eq!(generation, retry_control.route_wake_generation);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn attempt_limit_route_wake_gets_one_fresh_claim_before_dead_letter() {
    let pool = isolated_pool().await;

    // Reproduce the P1-C boundary with the real capacity admission,
    // ordered claim, lease token, and committed route-wake transaction.
    // The row's claimed snapshot is deliberately not the terminal
    // authority: retry must reread this persisted count under its lease
    // row lock.
    let woken_recipient = format!("route-limit-woken-{}@example.test", Uuid::new_v4());
    let (_, woken_id) = insert_delivery(&pool, &woken_recipient, 1).await;
    assert_eq!(
        sqlx::query("UPDATE mix_delivery_recipients SET attempt_count=19 WHERE delivery_id=$1",)
            .bind(woken_id)
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    let claimed = claim_delivery(&pool, woken_id).await;
    assert_eq!(claimed.attempt_count, 19);
    assert_eq!(
        wake_mix_delivery_recipient(&pool, &woken_recipient)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        retry_mix_delivery(
            &pool,
            claimed.delivery_id,
            claimed.lease_token,
            claimed.route_wake_generation,
            "route wake at retry boundary",
        )
        .await
        .unwrap(),
        MixDeliveryRetryOutcome::RouteWokenAtAttemptLimit
    );
    let (due, lease, attempts, generation) = schedule_is_due(&pool, woken_id).await;
    assert!(due, "a committed wake must release the terminal row now");
    assert!(lease.is_none());
    assert_eq!(attempts, 19, "the wake preserves one fresh attempt");
    assert_eq!(generation, claimed.route_wake_generation + 1);
    let woken_dead_letters: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM mix_delivery_dead_letters WHERE delivery_id=$1",
    )
    .bind(woken_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(woken_dead_letters, 0);

    let fresh_claim = claim_delivery(&pool, woken_id).await;
    assert_eq!(fresh_claim.attempt_count, 19);
    assert!(
        acknowledge_mix_delivery(&pool, fresh_claim.delivery_id, fresh_claim.lease_token)
            .await
            .unwrap()
    );

    // The control keeps the exact old behavior: the same persisted count
    // without a newer route generation becomes one attempt-limit dead
    // letter. This prevents a route-wake exception from silently raising
    // the ordinary retry ceiling.
    let terminal_recipient = format!("route-limit-terminal-{}@example.test", Uuid::new_v4());
    let (_, terminal_id) = insert_delivery(&pool, &terminal_recipient, 1).await;
    assert_eq!(
        sqlx::query("UPDATE mix_delivery_recipients SET attempt_count=19 WHERE delivery_id=$1",)
            .bind(terminal_id)
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    let terminal_claim = claim_delivery(&pool, terminal_id).await;
    assert_eq!(
        retry_mix_delivery(
            &pool,
            terminal_claim.delivery_id,
            terminal_claim.lease_token,
            terminal_claim.route_wake_generation,
            "normal terminal retry boundary",
        )
        .await
        .unwrap(),
        MixDeliveryRetryOutcome::DeadLettered
    );
    let source_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_delivery_recipients WHERE delivery_id=$1)",
    )
    .bind(terminal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!source_exists);
    let terminal_dead_letter: (i32, String) = sqlx::query_as(
        "SELECT attempt_count,terminal_reason
               FROM mix_delivery_dead_letters WHERE delivery_id=$1",
    )
    .bind(terminal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(terminal_dead_letter.0, 19);
    assert_eq!(terminal_dead_letter.1, "attempt-limit");

    reconcile_mix_delivery_capacity_committed(&pool)
        .await
        .unwrap();
    audit_mix_delivery_capacity_ledger(&pool).await.unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn dead_letter_requeue_uses_tail_and_preserves_current_head_wake() {
    let pool = isolated_pool().await;
    let recipient = format!("route-tail-{}@example.test", Uuid::new_v4());
    let (_, dead_id) = insert_delivery(&pool, &recipient, 1).await;
    let (_, successor_id) = insert_delivery(&pool, &recipient, 2).await;

    let dead = claim_delivery(&pool, dead_id).await;
    assert!(
        dead_letter_mix_delivery(&pool, dead.delivery_id, dead.lease_token, "test", "tail")
            .await
            .unwrap()
    );
    let successor = claim_delivery(&pool, successor_id).await;
    assert!(defer_mix_delivery(
        &pool,
        successor.delivery_id,
        successor.lease_token,
        successor.route_wake_generation,
        30,
    )
    .await
    .unwrap());
    let letters = mix_delivery_dead_letters(&pool, None, 32).await.unwrap();
    let letter = letters
        .into_iter()
        .find(|letter| letter.delivery_id == dead_id)
        .expect("the terminal predecessor was not recorded");
    assert!(
        requeue_mix_delivery_dead_letter(&pool, letter.dead_letter_id)
            .await
            .unwrap()
    );

    let order: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT delivery_id,delivery_sequence FROM mix_delivery_recipients
              WHERE recipient_jid=$1 ORDER BY delivery_sequence",
    )
    .bind(&recipient)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        order,
        vec![(successor_id, 2), (dead_id, 3)],
        "dead-letter recovery must append at the live recipient tail"
    );

    assert_eq!(
        wake_mix_delivery_recipient(&pool, &recipient)
            .await
            .unwrap(),
        1
    );
    let (due, _, _, generation) = schedule_is_due(&pool, successor_id).await;
    assert!(due, "the extant deferred head must receive the route wake");
    assert_eq!(generation, successor.route_wake_generation + 1);
    let woken_head = claim_delivery(&pool, successor_id).await;
    assert!(
        acknowledge_mix_delivery(&pool, woken_head.delivery_id, woken_head.lease_token)
            .await
            .unwrap()
    );
    let requeued_tail = claim_delivery(&pool, dead_id).await;
    assert!(
        acknowledge_mix_delivery(&pool, requeued_tail.delivery_id, requeued_tail.lease_token)
            .await
            .unwrap()
    );
    reconcile_mix_delivery_capacity_committed(&pool)
        .await
        .unwrap();
    audit_mix_delivery_capacity_ledger(&pool).await.unwrap();
}
