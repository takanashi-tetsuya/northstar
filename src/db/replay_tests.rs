use super::*;
use tokio::sync::mpsc;

async fn insert_replay_message(
    pool: &PgPool,
    recipient_id: Uuid,
    sender: &str,
    stanza: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO offline_messages(
            id,recipient_id,sender_jid,stanza,encrypted,mam_backed
         ) VALUES($1,$2,$3,$4,FALSE,FALSE)",
    )
    .bind(id)
    .bind(recipient_id)
    .bind(sender)
    .bind(stanza)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn insert_resource_replay_message(
    pool: &PgPool,
    recipient_id: Uuid,
    target_resource: Option<&str>,
    stanza_id: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO offline_messages(
            id,recipient_id,sender_jid,stanza,target_resource,encrypted,mam_backed
         ) VALUES($1,$2,'sender@remote.test/Phone',$3,$4,FALSE,FALSE)",
    )
    .bind(id)
    .bind(recipient_id)
    .bind(format!("<message id='{stanza_id}'/>"))
    .bind(target_resource)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[test]
fn resource_owner_lease_strictly_outlives_page_claim_and_jitter() {
    const {
        assert!(REPLAY_OWNER_LEASE_SECONDS >= CLAIM_LEASE_SECONDS + 15);
    }
    let migration = include_str!("../../migrations/0103_offline_replay_leases.sql");
    assert!(migration.contains("expires_at >= renewed_at + INTERVAL '75 seconds'"));
    assert!(!migration.to_ascii_lowercase().contains("public."));
    let migration_0122 = include_str!("../../migrations/0122_offline_replay_resource_leases.sql");
    assert!(migration_0122.contains("PRIMARY KEY (recipient_id, resource)"));
    assert!(!migration_0122.to_ascii_lowercase().contains("public."));
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn replay_enforces_resource_affinity_and_immutable_ownership() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let recipient = Uuid::new_v4();
    let other_recipient = Uuid::new_v4();
    let recipient_text = recipient.simple().to_string();
    let suffix = &recipient_text[..12];
    let username = format!("affinity{suffix}");
    let other_username = format!("affinityother{suffix}");
    for (id, username) in [(recipient, &username), (other_recipient, &other_username)] {
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(id)
            .bind(username)
            .execute(&pool)
            .await
            .unwrap();
    }
    let account_scoped =
        insert_resource_replay_message(&pool, recipient, None, "account-scoped").await;
    let phone = insert_resource_replay_message(&pool, recipient, Some("Phone"), "phone-only").await;
    let tablet =
        insert_resource_replay_message(&pool, recipient, Some("Tablet"), "tablet-only").await;

    let phone_lease = acquire_offline_replay_lease(
        &pool,
        recipient,
        "Phone",
        Uuid::new_v4(),
        None,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    .into_acquired()
    .unwrap();
    let phone_page = match claim_offline_replay_page(
        &pool,
        &phone_lease,
        30,
        &format!("{username}@example.test"),
        &format!("{username}@example.test/Phone"),
        None,
        false,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    {
        OfflineReplayPageOutcome::Claimed(page) => page,
        other => panic!("expected phone replay page, got {other:?}"),
    };
    let phone_ids = phone_page
        .messages
        .iter()
        .map(|message| message.id)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(phone_ids, [account_scoped, phone].into_iter().collect());
    assert!(!phone_ids.contains(&tablet));
    assert!(release_offline_replay_lease(&pool, &phone_lease)
        .await
        .unwrap());

    let tablet_lease = acquire_offline_replay_lease(
        &pool,
        recipient,
        "Tablet",
        Uuid::new_v4(),
        None,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    .into_acquired()
    .unwrap();
    let tablet_page = match claim_offline_replay_page(
        &pool,
        &tablet_lease,
        30,
        &format!("{username}@example.test"),
        &format!("{username}@example.test/Tablet"),
        None,
        false,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    {
        OfflineReplayPageOutcome::Claimed(page) => page,
        other => panic!("expected tablet replay page, got {other:?}"),
    };
    assert_eq!(tablet_page.messages.len(), 1);
    assert_eq!(tablet_page.messages[0].id, tablet);

    assert!(
        sqlx::query("UPDATE offline_messages SET target_resource='Other' WHERE id=$1")
            .bind(tablet)
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE offline_messages SET recipient_id=$2 WHERE id=$1")
            .bind(tablet)
            .bind(other_recipient)
            .execute(&pool)
            .await
            .is_err()
    );

    let _ = release_offline_replay_lease(&pool, &tablet_lease).await;
    sqlx::query("DELETE FROM users WHERE id=ANY($1)")
        .bind(vec![recipient, other_recipient])
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn logical_owner_is_exclusive_crash_recoverable_and_does_not_hold_the_pool() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(1))
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let recipient = Uuid::new_v4();
    let username = format!("lease{}", &recipient.simple().to_string()[..12]);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
        .bind(recipient)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();
    for index in 0..3 {
        insert_replay_message(
            &pool,
            recipient,
            "sender@example.test/Phone",
            &format!("<message id='lease-{index}'/>"),
        )
        .await;
    }

    let first_token = Uuid::new_v4();
    let second_token = Uuid::new_v4();
    let (first, second) = tokio::join!(
        acquire_offline_replay_lease(
            &pool,
            recipient,
            "test-replay",
            first_token,
            None,
            REPLAY_OWNER_LEASE_SECONDS,
        ),
        acquire_offline_replay_lease(
            &pool,
            recipient,
            "test-replay",
            second_token,
            None,
            REPLAY_OWNER_LEASE_SECONDS,
        ),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_ne!(first.is_acquired(), second.is_acquired());
    let owner = first
        .into_acquired()
        .or_else(|| second.into_acquired())
        .unwrap();
    let page = match claim_offline_replay_page(
        &pool,
        &owner,
        30,
        &format!("{username}@example.test"),
        &format!("{username}@example.test/test-replay"),
        None,
        false,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    {
        OfflineReplayPageOutcome::Claimed(page) => page,
        other => panic!("expected claimed page, got {other:?}"),
    };
    assert_eq!(page.messages.len(), 3);

    // Model a slow client after the short page transaction has returned.
    // The blocked network await owns no PostgreSQL connection, so even a
    // two-connection pool remains immediately usable.
    let (slow_tx, mut slow_rx) = mpsc::channel(1);
    let slow_tx = crate::outbound::OutboundSender::new(slow_tx);
    slow_tx.send("occupied".to_owned()).await.unwrap();
    let slow_message = page.messages[0].clone();
    let slow_claim = page.claim_token;
    let slow_sender = slow_tx.clone();
    let blocked_send = tokio::spawn(async move {
        slow_sender
            .send_durable(
                slow_message.stanza,
                crate::outbound::DurableDelivery {
                    recipient_id: recipient,
                    message_id: slow_message.id,
                    claim_id: Some(slow_claim),
                },
            )
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    assert!(!blocked_send.is_finished());
    let probe = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&pool),
    )
    .await
    .expect("a slow transport must not retain a primary pool connection")
    .unwrap();
    assert_eq!(probe, 1);
    assert_eq!(slow_rx.recv().await.unwrap().stanza, "occupied");
    assert!(blocked_send.await.unwrap().is_ok());
    drop(slow_rx);

    // Only the unsent suffix is released. The accepted prefix retains its
    // exact claim until the durable transport acknowledgement.
    let accepted = page.messages[0].id;
    let suffix = page.messages[1..]
        .iter()
        .map(|message| message.id)
        .collect::<Vec<_>>();
    assert_eq!(
        release_untransferred_offline_claims(&pool, recipient, page.claim_token, &suffix,)
            .await
            .unwrap(),
        2
    );
    let claims = sqlx::query(
        "SELECT id,delivery_claim_id FROM offline_messages
          WHERE recipient_id=$1 ORDER BY id",
    )
    .bind(recipient)
    .fetch_all(&pool)
    .await
    .unwrap();
    for row in claims {
        let id: Uuid = row.get("id");
        let claim: Option<Uuid> = row.get("delivery_claim_id");
        assert_eq!(claim, (id == accepted).then_some(page.claim_token));
    }
    acknowledge_durable_delivery(
        &pool,
        crate::outbound::DurableDelivery {
            recipient_id: recipient,
            message_id: accepted,
            claim_id: Some(page.claim_token),
        },
    )
    .await
    .unwrap();
    assert!(release_offline_replay_lease(&pool, &owner).await.unwrap());

    // Crash after claiming the remaining page: by the time the longer
    // account lease expires, the 60-second row claims have also expired.
    // The replacement owner claims them in this same login/replay pass.
    let crashed = acquire_offline_replay_lease(
        &pool,
        recipient,
        "test-replay",
        Uuid::new_v4(),
        None,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    .into_acquired()
    .unwrap();
    let crashed_page = match claim_offline_replay_page(
        &pool,
        &crashed,
        30,
        &format!("{username}@example.test"),
        &format!("{username}@example.test/test-replay"),
        None,
        false,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    {
        OfflineReplayPageOutcome::Claimed(page) => page,
        other => panic!("expected crash fixture page, got {other:?}"),
    };
    assert_eq!(crashed_page.messages.len(), 2);
    sqlx::query(
        "UPDATE offline_replay_leases
            SET acquired_at=clock_timestamp()-INTERVAL '100 seconds',
                renewed_at=clock_timestamp()-INTERVAL '100 seconds',
                expires_at=clock_timestamp()-INTERVAL '10 seconds'
          WHERE recipient_id=$1 AND owner_token=$2",
    )
    .bind(recipient)
    .bind(crashed.owner_token)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE offline_messages
            SET delivery_claim_expires_at=clock_timestamp()-INTERVAL '40 seconds'
          WHERE recipient_id=$1 AND delivery_claim_id=$2",
    )
    .bind(recipient)
    .bind(crashed_page.claim_token)
    .execute(&pool)
    .await
    .unwrap();
    let replacement = acquire_offline_replay_lease(
        &pool,
        recipient,
        "test-replay",
        Uuid::new_v4(),
        None,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    .into_acquired()
    .unwrap();
    let crashed_ids = crashed_page
        .messages
        .iter()
        .map(|message| message.id)
        .collect::<Vec<_>>();
    assert!(!renew_offline_replay_before_send(
        &pool,
        &crashed,
        crashed_page.claim_token,
        &crashed_ids,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap());
    assert!(!release_offline_replay_lease(&pool, &crashed).await.unwrap());
    let replacement_page = match claim_offline_replay_page(
        &pool,
        &replacement,
        30,
        &format!("{username}@example.test"),
        &format!("{username}@example.test/test-replay"),
        None,
        false,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    {
        OfflineReplayPageOutcome::Claimed(page) => page,
        other => panic!("replacement did not recover crash page: {other:?}"),
    };
    let replacement_ids = replacement_page
        .messages
        .iter()
        .map(|message| message.id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        replacement_ids,
        crashed_ids
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
    );
    release_untransferred_offline_claims(
        &pool,
        recipient,
        replacement_page.claim_token,
        &replacement_ids.iter().copied().collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    assert!(release_offline_replay_lease(&pool, &replacement)
        .await
        .unwrap());
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(recipient)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn replay_policy_snapshot_is_consistent_and_missing_policy_rolls_back() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let recipient = Uuid::new_v4();
    let username = format!("policy{}", &recipient.simple().to_string()[..12]);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
        .bind(recipient)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();
    let message_id = insert_replay_message(
        &pool,
        recipient,
        "sender@example.test/Phone",
        "<message id='policy-rollback'/>",
    )
    .await;
    let lease = acquire_offline_replay_lease(
        &pool,
        recipient,
        "test-replay",
        Uuid::new_v4(),
        None,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    .into_acquired()
    .unwrap();
    let missing = claim_offline_replay_page(
        &pool,
        &lease,
        30,
        &format!("{username}@example.test"),
        &format!("{username}@example.test/test-replay"),
        Some("missing-active-list"),
        false,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await;
    assert!(missing.is_err());
    let row = sqlx::query(
        "SELECT delivery_claim_id,delivery_claim_expires_at
           FROM offline_messages WHERE id=$1",
    )
    .bind(message_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<Option<Uuid>, _>("delivery_claim_id"), None);
    assert_eq!(
        row.get::<Option<DateTime<Utc>>, _>("delivery_claim_expires_at"),
        None
    );

    let allow = crate::db::PrivacyList {
        name: "snapshot".to_owned(),
        items: vec![crate::db::PrivacyItem {
            order: 1,
            action: crate::db::PrivacyAction::Allow,
            match_type: None,
            match_value: None,
            message: false,
            iq: false,
            presence_in: false,
            presence_out: false,
        }],
    };
    crate::db::replace_privacy_list(&pool, recipient, &allow)
        .await
        .unwrap();
    let mut snapshot = pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *snapshot)
        .await
        .unwrap();
    let candidates = vec!["sender@example.test/Phone".to_owned()];
    let (blocked, privacy, roster) =
        replay_policy_snapshot(&mut snapshot, recipient, Some("snapshot"), &candidates)
            .await
            .unwrap();
    assert!(!replay_policy_denies(
        &format!("{username}@example.test"),
        &candidates[0],
        crate::db::PrivacyStanzaKind::Message,
        &blocked,
        &privacy,
        &roster,
    )
    .unwrap());
    let deny = crate::db::PrivacyList {
        name: "snapshot".to_owned(),
        items: vec![crate::db::PrivacyItem {
            order: 1,
            action: crate::db::PrivacyAction::Deny,
            match_type: None,
            match_value: None,
            message: false,
            iq: false,
            presence_in: false,
            presence_out: false,
        }],
    };
    crate::db::replace_privacy_list(&pool, recipient, &deny)
        .await
        .unwrap();
    let (blocked_again, privacy_again, roster_again) =
        replay_policy_snapshot(&mut snapshot, recipient, Some("snapshot"), &candidates)
            .await
            .unwrap();
    assert!(!replay_policy_denies(
        &format!("{username}@example.test"),
        &candidates[0],
        crate::db::PrivacyStanzaKind::Message,
        &blocked_again,
        &privacy_again,
        &roster_again,
    )
    .unwrap());
    snapshot.commit().await.unwrap();
    let mut fresh = pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *fresh)
        .await
        .unwrap();
    let (fresh_blocked, fresh_privacy, fresh_roster) =
        replay_policy_snapshot(&mut fresh, recipient, Some("snapshot"), &candidates)
            .await
            .unwrap();
    assert!(replay_policy_denies(
        &format!("{username}@example.test"),
        &candidates[0],
        crate::db::PrivacyStanzaKind::Message,
        &fresh_blocked,
        &fresh_privacy,
        &fresh_roster,
    )
    .unwrap());
    fresh.commit().await.unwrap();
    assert!(release_offline_replay_lease(&pool, &lease).await.unwrap());
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(recipient)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn durable_ack_batch_validates_every_fence_before_deleting_any_row() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let recipient = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
        .bind(recipient)
        .bind(format!("ackbatch{}", &recipient.simple().to_string()[..12]))
        .execute(&pool)
        .await
        .unwrap();
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let actual_claim = Uuid::new_v4();
    for (message_id, claim_id) in [(first, None), (second, Some(actual_claim))] {
        sqlx::query(
            "INSERT INTO offline_messages(
                id,recipient_id,sender_jid,stanza,encrypted,mam_backed,
                delivery_claim_id,delivery_claim_expires_at
             ) VALUES($1,$2,'sender@example.test','<message/>',FALSE,FALSE,$3,
                      CASE WHEN $3::UUID IS NULL THEN NULL ELSE NOW()+INTERVAL '1 minute' END)",
        )
        .bind(message_id)
        .bind(recipient)
        .bind(claim_id)
        .execute(&pool)
        .await
        .unwrap();
    }
    let first_delivery = crate::outbound::DurableDelivery {
        recipient_id: recipient,
        message_id: first,
        claim_id: None,
    };
    let invalid_second = crate::outbound::DurableDelivery {
        recipient_id: recipient,
        message_id: second,
        claim_id: Some(Uuid::new_v4()),
    };
    assert!(
        acknowledge_durable_deliveries(&pool, &[first_delivery, invalid_second])
            .await
            .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=ANY($1)",)
            .bind(vec![first, second])
            .fetch_one(&pool)
            .await
            .unwrap(),
        2,
        "a later invalid fence must roll back the valid prefix"
    );
    let valid_second = crate::outbound::DurableDelivery {
        claim_id: Some(actual_claim),
        ..invalid_second
    };
    acknowledge_durable_deliveries(&pool, &[first_delivery, valid_second])
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=ANY($1)",)
            .bind(vec![first, second])
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(recipient)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn replay_high_water_excludes_rows_inserted_after_replay_started() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let recipient = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
        .bind(recipient)
        .bind(format!("water{}", &recipient.simple().to_string()[..12]))
        .execute(&pool)
        .await
        .unwrap();
    for index in 0..65_u32 {
        sqlx::query(
            "INSERT INTO offline_messages \
             (id,recipient_id,sender_jid,stanza,encrypted,mam_backed) \
             VALUES($1,$2,'sender@example.test',$3,FALSE,FALSE)",
        )
        .bind(Uuid::new_v4())
        .bind(recipient)
        .bind(format!("<message id='before-{index}'/>"))
        .execute(&pool)
        .await
        .unwrap();
    }

    let (tx, mut rx) = mpsc::channel(1);
    let tx = crate::outbound::OutboundSender::new(tx);
    let delivery_pool = pool.clone();
    let delivery = tokio::spawn(async move {
        deliver_offline_leased(&delivery_pool, recipient, 30, &tx, false, None)
            .await
            .unwrap()
    });
    let first = rx.recv().await.expect("first pre-existing row");
    let late_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO offline_messages \
         (id,recipient_id,sender_jid,stanza,encrypted,mam_backed) \
         VALUES($1,$2,'late@example.test','<message id=''after-start''/>',FALSE,FALSE)",
    )
    .bind(late_id)
    .bind(recipient)
    .execute(&pool)
    .await
    .unwrap();

    acknowledge_durable_delivery(&pool, first.c2s_delivery().unwrap())
        .await
        .unwrap();
    let mut delivered = vec![first.stanza];
    while delivered.len() < 65 {
        let item = rx.recv().await.expect("remaining pre-existing row");
        assert!(!item.stanza.contains("after-start"));
        acknowledge_durable_delivery(&pool, item.c2s_delivery().unwrap())
            .await
            .unwrap();
        delivered.push(item.stanza);
    }
    assert_eq!(delivery.await.unwrap(), 65);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM offline_messages WHERE recipient_id=$1 AND id=$2",
        )
        .bind(recipient)
        .bind(late_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(recipient)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn replay_is_paged_exclusive_and_retryable() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let recipient = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
        .bind(recipient)
        .bind(format!("replay{}", &recipient.simple().to_string()[..12]))
        .execute(&pool)
        .await
        .unwrap();
    let first_message_id = Uuid::new_v4();
    for index in 0..600_u32 {
        sqlx::query(
            "INSERT INTO offline_messages \
             (id,recipient_id,sender_jid,stanza,encrypted,mam_backed,created_at) \
             VALUES($1,$2,'sender@example.test',$3,FALSE,FALSE, \
                    clock_timestamp()+($4*INTERVAL '1 microsecond'))",
        )
        .bind(if index == 0 {
            first_message_id
        } else {
            Uuid::new_v4()
        })
        .bind(recipient)
        .bind(format!("<message id='{index}'/>"))
        .bind(i64::from(index))
        .execute(&pool)
        .await
        .unwrap();
    }

    // Model a process that died while holding a claim. The next worker
    // cannot steal it before expiry, but it becomes retryable afterwards.
    sqlx::query(
        "UPDATE offline_messages SET delivery_claim_id=$2, \
         delivery_claim_expires_at=clock_timestamp()+INTERVAL '1 hour' WHERE id=$1",
    )
    .bind(first_message_id)
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .unwrap();

    // A closed queue must release the complete first claim immediately.
    let (closed_tx, closed_rx) = mpsc::channel(1);
    drop(closed_rx);
    let closed_tx = crate::outbound::OutboundSender::new(closed_tx);
    assert_eq!(
        deliver_offline_leased(&pool, recipient, 30, &closed_tx, false, None)
            .await
            .unwrap(),
        0
    );
    let claimed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM offline_messages WHERE delivery_claim_id IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(claimed, 1);

    sqlx::query(
        "UPDATE offline_messages SET delivery_claim_expires_at=clock_timestamp()-INTERVAL '1 second' \
         WHERE id=$1",
    )
    .bind(first_message_id)
    .execute(&pool)
    .await
    .unwrap();

    let (tx, mut rx) = mpsc::channel(8);
    let tx = crate::outbound::OutboundSender::new(tx);
    let pool_for_delivery = pool.clone();
    let delivery = tokio::spawn(async move {
        deliver_offline_leased(&pool_for_delivery, recipient, 30, &tx, false, None)
            .await
            .unwrap()
    });
    let mut received = Vec::new();
    while let Some(item) = rx.recv().await {
        acknowledge_durable_delivery(&pool, item.c2s_delivery().unwrap())
            .await
            .unwrap();
        received.push(item.stanza);
        if received.len() == 600 {
            break;
        }
    }
    assert_eq!(delivery.await.unwrap(), 600);
    assert_eq!(received.len(), 600);
    assert_eq!(received.first().unwrap(), "<message id='0'/>");
    assert_eq!(received.last().unwrap(), "<message id='599'/>");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM offline_messages WHERE recipient_id=$1",
        )
        .bind(recipient)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );

    sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,'blocked@example.test')")
        .bind(recipient)
        .execute(&pool)
        .await
        .unwrap();
    let privacy = crate::db::PrivacyList {
        name: "offline-replay".to_owned(),
        items: vec![
            crate::db::PrivacyItem {
                order: 1,
                action: crate::db::PrivacyAction::Deny,
                match_type: Some(crate::db::PrivacyMatchType::Jid),
                match_value: Some("private@example.test".to_owned()),
                message: true,
                iq: false,
                presence_in: false,
                presence_out: false,
            },
            crate::db::PrivacyItem {
                order: 2,
                action: crate::db::PrivacyAction::Allow,
                match_type: None,
                match_value: None,
                message: false,
                iq: false,
                presence_in: false,
                presence_out: false,
            },
        ],
    };
    crate::db::replace_privacy_list(&pool, recipient, &privacy)
        .await
        .unwrap();
    for (sender, id) in [
        ("blocked@example.test/Phone", "blocked"),
        ("private@example.test/Phone", "private"),
        ("allowed@example.test/Phone", "allowed"),
    ] {
        sqlx::query(
            "INSERT INTO offline_messages \
             (id,recipient_id,sender_jid,stanza,encrypted,mam_backed) \
             VALUES($1,$2,$3,$4,FALSE,FALSE)",
        )
        .bind(Uuid::new_v4())
        .bind(recipient)
        .bind(sender)
        .bind(format!("<message id='{id}'/>"))
        .execute(&pool)
        .await
        .unwrap();
    }
    let (policy_tx, mut policy_rx) = mpsc::channel(8);
    let policy_tx = crate::outbound::OutboundSender::new(policy_tx);
    assert_eq!(
        deliver_offline_leased(
            &pool,
            recipient,
            30,
            &policy_tx,
            false,
            Some("offline-replay"),
        )
        .await
        .unwrap(),
        1
    );
    drop(policy_tx);
    let allowed = policy_rx.recv().await.unwrap();
    acknowledge_durable_delivery(&pool, allowed.c2s_delivery().unwrap())
        .await
        .unwrap();
    assert_eq!(allowed.stanza, "<message id='allowed'/>");
    assert!(policy_rx.recv().await.is_none());

    // Two resources can become available at the same instant. The
    // account-scoped advisory owner prevents page 1 and page 2 from being
    // split across those resources; one receives the entire ordered
    // queue and the other observes an already-owned replay.
    for index in 0..129_u32 {
        sqlx::query(
            "INSERT INTO offline_messages \
             (id,recipient_id,sender_jid,stanza,encrypted,mam_backed,created_at) \
             VALUES($1,$2,'race@example.test',$3,FALSE,FALSE, \
                    clock_timestamp()+($4*INTERVAL '1 microsecond'))",
        )
        .bind(Uuid::new_v4())
        .bind(recipient)
        .bind(format!("<message id='race-{index}'/>"))
        .bind(i64::from(index))
        .execute(&pool)
        .await
        .unwrap();
    }
    let (first_tx, mut first_rx) = mpsc::channel(129);
    let (second_tx, mut second_rx) = mpsc::channel(129);
    let first_tx = crate::outbound::OutboundSender::new(first_tx);
    let second_tx = crate::outbound::OutboundSender::new(second_tx);
    let (first, second) = tokio::join!(
        deliver_offline_leased(&pool, recipient, 30, &first_tx, false, None),
        deliver_offline_leased(&pool, recipient, 30, &second_tx, false, None),
    );
    drop(first_tx);
    drop(second_tx);
    let mut first_messages = Vec::new();
    while let Some(message) = first_rx.recv().await {
        acknowledge_durable_delivery(&pool, message.c2s_delivery().unwrap())
            .await
            .unwrap();
        first_messages.push(message.stanza);
    }
    let mut second_messages = Vec::new();
    while let Some(message) = second_rx.recv().await {
        acknowledge_durable_delivery(&pool, message.c2s_delivery().unwrap())
            .await
            .unwrap();
        second_messages.push(message.stanza);
    }
    assert_eq!(first.unwrap() + second.unwrap(), 129);
    let winner = if first_messages.is_empty() {
        &second_messages
    } else {
        assert!(second_messages.is_empty());
        &first_messages
    };
    assert_eq!(winner.len(), 129);
    assert_eq!(winner.first().unwrap(), "<message id='race-0'/>");
    assert_eq!(winner.last().unwrap(), "<message id='race-128'/>");

    // More than one transport queue of pending subscription requests is
    // paged without truncation, and remains available to a second newly
    // available resource rather than being consumed globally.
    for index in 0..600_u32 {
        sqlx::query(
            "INSERT INTO federated_presence_pending(recipient_id,from_jid,stanza,created_at) \
             VALUES($1,$2,$3,clock_timestamp()+($4*INTERVAL '1 microsecond'))",
        )
        .bind(recipient)
        .bind(format!("sender{index:04}@remote.test"))
        .bind(format!(
            "<presence from='sender{index:04}@remote.test' type='subscribe'/>"
        ))
        .bind(i64::from(index))
        .execute(&pool)
        .await
        .unwrap();
    }
    for _resource in 0..2 {
        let mut cursor = None;
        let mut requesters = Vec::new();
        loop {
            let page =
                pending_presence_replay_page(&pool, recipient, "example.test", cursor.as_ref())
                    .await
                    .unwrap();
            assert!(page.len() <= REPLAY_PAGE_SIZE as usize);
            if page.is_empty() {
                break;
            }
            cursor = page.last().map(|row| row.cursor.clone());
            requesters.extend(page.into_iter().map(|row| row.requester));
        }
        assert_eq!(requesters.len(), 600);
        assert_eq!(requesters.first().unwrap(), "sender0000@remote.test");
        assert_eq!(requesters.last().unwrap(), "sender0599@remote.test");
    }
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(recipient)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn bosh_delivery_is_owned_by_response_rid_until_a_live_client_ack() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let recipient = Uuid::new_v4();
    let username = format!("boshfence{}", &recipient.simple().to_string()[..10]);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
        .bind(recipient)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();

    let message_id = Uuid::new_v4();
    let claim_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO offline_messages(
            id,recipient_id,sender_jid,stanza,encrypted,mam_backed,
            delivery_claim_id,delivery_claim_expires_at
         ) VALUES($1,$2,'sender@example.test','<message id=''bosh''/>',FALSE,FALSE,
                  $3,clock_timestamp()+INTERVAL '1 hour')",
    )
    .bind(message_id)
    .bind(recipient)
    .bind(claim_id)
    .execute(&pool)
    .await
    .unwrap();
    let delivery = crate::outbound::DurableDelivery {
        recipient_id: recipient,
        message_id,
        claim_id: Some(claim_id),
    };
    assert!(
        acknowledge_durable_delivery(
            &pool,
            crate::outbound::DurableDelivery {
                claim_id: None,
                ..delivery
            },
        )
        .await
        .is_err(),
        "an unfenced live writer must not consume another replay claim"
    );
    let session_id = Uuid::new_v4();
    bind_bosh_delivery_response(&pool, session_id, 100, &[delivery], 60)
        .await
        .unwrap();
    assert!(acknowledge_durable_delivery(&pool, delivery).await.is_err());
    // Rebuilding the exact response is idempotent, but a second BOSH
    // session cannot steal the same live response fence.
    bind_bosh_delivery_response(&pool, session_id, 100, &[delivery], 60)
        .await
        .unwrap();
    assert!(
        bind_bosh_delivery_response(&pool, Uuid::new_v4(), 100, &[delivery], 60)
            .await
            .is_err()
    );
    let claim: Option<Uuid> =
        sqlx::query_scalar("SELECT delivery_claim_id FROM offline_messages WHERE id=$1")
            .bind(message_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claim, None);
    assert_eq!(
        acknowledge_bosh_delivery_responses(&pool, session_id, 99)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
            .bind(message_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    renew_bosh_delivery_fences(&pool, session_id, Some((100, &[message_id])), 60)
        .await
        .unwrap();
    assert_eq!(
        acknowledge_bosh_delivery_responses(&pool, session_id, 100)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
            .bind(message_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );

    // A non-SM socket takes an exact short claim immediately before its
    // bounded write. Queue acceptance alone cannot authorize deletion,
    // and a crash before acknowledgement leaves the row reclaimable when
    // this lease expires.
    let socket_message = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted,mam_backed)
         VALUES($1,$2,'sender@example.test','<message id=''socket''/>',FALSE,FALSE)",
    )
    .bind(socket_message)
    .bind(recipient)
    .execute(&pool)
    .await
    .unwrap();
    let unfenced_socket = crate::outbound::DurableDelivery {
        recipient_id: recipient,
        message_id: socket_message,
        claim_id: None,
    };
    let fenced_socket = fence_durable_socket_write(&pool, unfenced_socket)
        .await
        .unwrap();
    assert!(fenced_socket.claim_id.is_some());
    assert!(acknowledge_durable_delivery(&pool, unfenced_socket)
        .await
        .is_err());
    acknowledge_durable_delivery(&pool, fenced_socket)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
            .bind(socket_message)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );

    // Once a response lease expires it cannot be renewed or acknowledged
    // by the stale actor. Candidate selection first removes the expired
    // fence, then atomically gives the offline row a fresh replay claim.
    let expired_message = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted,mam_backed)
         VALUES($1,$2,'sender@example.test','<message id=''expired''/>',FALSE,FALSE)",
    )
    .bind(expired_message)
    .bind(recipient)
    .execute(&pool)
    .await
    .unwrap();
    let expired_delivery = crate::outbound::DurableDelivery {
        recipient_id: recipient,
        message_id: expired_message,
        claim_id: None,
    };
    let expired_session = Uuid::new_v4();
    bind_bosh_delivery_response(&pool, expired_session, 200, &[expired_delivery], 60)
        .await
        .unwrap();
    assert!(
        acknowledge_durable_delivery(&pool, expired_delivery)
            .await
            .is_err(),
        "an unfenced transport ACK must not consume a BOSH-owned live row"
    );
    sqlx::query(
        "UPDATE offline_messages
            SET created_at=clock_timestamp()-INTERVAL '31 days'
          WHERE id=$1",
    )
    .bind(expired_message)
    .execute(&pool)
    .await
    .unwrap();
    let active_lease = acquire_offline_replay_lease(
        &pool,
        recipient,
        "test-replay",
        Uuid::new_v4(),
        None,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    .into_acquired()
    .unwrap();
    let active_fence_probe = claim_offline_replay_page(
        &pool,
        &active_lease,
        30,
        &format!("{username}@example.test"),
        &format!("{username}@example.test/test-replay"),
        None,
        false,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap();
    assert!(matches!(
        active_fence_probe,
        OfflineReplayPageOutcome::Empty
    ));
    assert!(release_offline_replay_lease(&pool, &active_lease)
        .await
        .unwrap());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
            .bind(expired_message)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1,
        "retention must not delete a BOSH-owned response before client ack"
    );
    sqlx::query(
        "UPDATE bosh_delivery_fences SET expires_at=clock_timestamp()-INTERVAL '1 second'
          WHERE session_id=$1",
    )
    .bind(expired_session)
    .execute(&pool)
    .await
    .unwrap();
    assert!(renew_bosh_delivery_fences(
        &pool,
        expired_session,
        Some((200, &[expired_message])),
        60,
    )
    .await
    .is_err());
    let replay_lease = acquire_offline_replay_lease(
        &pool,
        recipient,
        "test-replay",
        Uuid::new_v4(),
        None,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    .into_acquired()
    .unwrap();
    let page = match claim_offline_replay_page(
        &pool,
        &replay_lease,
        30,
        &format!("{username}@example.test"),
        &format!("{username}@example.test/test-replay"),
        None,
        false,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    {
        OfflineReplayPageOutcome::Claimed(page) => page,
        other => panic!("expected reclaimed BOSH page, got {other:?}"),
    };
    assert_eq!(page.messages.len(), 1);
    assert_eq!(page.messages[0].id, expired_message);
    assert_eq!(
        acknowledge_bosh_delivery_responses(&pool, expired_session, 200)
            .await
            .unwrap(),
        0
    );
    assert!(
        bind_bosh_delivery_response(&pool, expired_session, 200, &[expired_delivery], 60,)
            .await
            .is_err()
    );
    release_untransferred_offline_claims(&pool, recipient, page.claim_token, &[expired_message])
        .await
        .unwrap();
    assert!(release_offline_replay_lease(&pool, &replay_lease)
        .await
        .unwrap());

    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(recipient)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn concurrent_resources_replay_without_starvation_and_fence_wrong_claims() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let recipient = Uuid::new_v4();
    let username = format!("concur{}", &recipient.simple().to_string()[..12]);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
        .bind(recipient)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();

    // 1. Insert 1 account-scoped, 1 phone-only, 1 tablet-only message.
    let account_msg = insert_resource_replay_message(&pool, recipient, None, "account-wide").await;
    let phone_msg =
        insert_resource_replay_message(&pool, recipient, Some("Phone"), "phone-only").await;
    let tablet_msg =
        insert_resource_replay_message(&pool, recipient, Some("Tablet"), "tablet-only").await;

    // 2. Phone acquires its lease and HOLDS it (does not release).
    let phone_token = Uuid::new_v4();
    let phone_lease = acquire_offline_replay_lease(
        &pool,
        recipient,
        "Phone",
        phone_token,
        None,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    .into_acquired()
    .expect("Phone lease acquisition must succeed");

    // 3. Concurrently, Tablet acquires its lease while Phone is STILL holding its lease.
    // Under the old account-level design, Tablet would return None (starvation).
    // Under the resource-scoped design, Tablet MUST succeed!
    let tablet_token = Uuid::new_v4();
    let tablet_lease = acquire_offline_replay_lease(
        &pool,
        recipient,
        "Tablet",
        tablet_token,
        None,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    .into_acquired()
    .expect("Tablet lease acquisition must succeed in parallel with Phone");

    // 4. Duplicate acquire on Phone's exact resource must be rejected (single-flight per resource).
    let dup_phone = acquire_offline_replay_lease(
        &pool,
        recipient,
        "Phone",
        Uuid::new_v4(),
        None,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap();
    assert!(
        !dup_phone.is_acquired(),
        "duplicate active lease on Phone must be rejected"
    );

    // 5. Both resources claim concurrently. The account-scoped row may be
    // won by either resource, but row-level SKIP LOCKED fencing must make
    // it appear exactly once while each affine row stays on its resource.
    let owner_bare = format!("{username}@example.test");
    let phone_full = format!("{username}@example.test/Phone");
    let tablet_full = format!("{username}@example.test/Tablet");
    let (phone_claim, tablet_claim) = tokio::join!(
        claim_offline_replay_page(
            &pool,
            &phone_lease,
            30,
            &owner_bare,
            &phone_full,
            None,
            false,
            REPLAY_OWNER_LEASE_SECONDS,
        ),
        claim_offline_replay_page(
            &pool,
            &tablet_lease,
            30,
            &owner_bare,
            &tablet_full,
            None,
            false,
            REPLAY_OWNER_LEASE_SECONDS,
        )
    );
    let phone_page = match phone_claim.unwrap() {
        OfflineReplayPageOutcome::Claimed(page) => page,
        other => panic!("expected phone claimed page, got {other:?}"),
    };
    let tablet_page = match tablet_claim.unwrap() {
        OfflineReplayPageOutcome::Claimed(page) => page,
        other => panic!("expected tablet claimed page, got {other:?}"),
    };
    let phone_ids = phone_page
        .messages
        .iter()
        .map(|m| m.id)
        .collect::<std::collections::HashSet<_>>();
    assert!(phone_ids.contains(&phone_msg));
    assert!(!phone_ids.contains(&tablet_msg));

    let tablet_ids = tablet_page
        .messages
        .iter()
        .map(|m| m.id)
        .collect::<std::collections::HashSet<_>>();
    assert!(tablet_ids.contains(&tablet_msg));
    assert!(!tablet_ids.contains(&phone_msg));
    assert_eq!(
        usize::from(phone_ids.contains(&account_msg))
            + usize::from(tablet_ids.contains(&account_msg)),
        1,
        "the account-scoped row must be claimed exactly once"
    );

    // 7. Security: Attempting to use Phone lease to claim Tablet JID must fail.
    let cross_claim = claim_offline_replay_page(
        &pool,
        &phone_lease,
        30,
        &format!("{username}@example.test"),
        &format!("{username}@example.test/Tablet"),
        None,
        false,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await;
    assert!(
        cross_claim.is_err(),
        "cross-resource claim must be rejected"
    );

    // 8. Security: Renewing with wrong owner_token must return false.
    let wrong_token_lease = OfflineReplayLease {
        recipient_id: recipient,
        resource: "Phone".to_owned(),
        owner_token: Uuid::new_v4(),
        replay_started_at: phone_lease.replay_started_at,
    };
    let renew_wrong = renew_offline_replay_before_send(
        &pool,
        &wrong_token_lease,
        phone_page.claim_token,
        &[phone_msg],
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap();
    assert!(!renew_wrong, "renew with wrong owner token must fail");

    // 9. Security: Renewing with wrong resource must return false.
    let wrong_res_lease = OfflineReplayLease {
        recipient_id: recipient,
        resource: "Desktop".to_owned(),
        owner_token: phone_token,
        replay_started_at: phone_lease.replay_started_at,
    };
    let renew_wrong_res = renew_offline_replay_before_send(
        &pool,
        &wrong_res_lease,
        phone_page.claim_token,
        &[phone_msg],
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap();
    assert!(!renew_wrong_res, "renew with wrong resource must fail");

    // 10. Security: Releasing with wrong owner_token or wrong resource must return false.
    assert!(!release_offline_replay_lease(&pool, &wrong_token_lease)
        .await
        .unwrap());
    assert!(!release_offline_replay_lease(&pool, &wrong_res_lease)
        .await
        .unwrap());

    // 11. Clean release.
    assert!(release_offline_replay_lease(&pool, &phone_lease)
        .await
        .unwrap());
    assert!(release_offline_replay_lease(&pool, &tablet_lease)
        .await
        .unwrap());

    // 12. Immutability trigger: updating recipient_id or resource on offline_replay_leases must fail.
    let test_lease = acquire_offline_replay_lease(
        &pool,
        recipient,
        "ImmutableTest",
        Uuid::new_v4(),
        None,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    .into_acquired()
    .unwrap();
    assert!(
        sqlx::query("UPDATE offline_replay_leases SET resource='Modified' WHERE recipient_id=$1 AND resource='ImmutableTest'")
            .bind(recipient)
            .execute(&pool)
            .await
            .is_err()
    );
    let _ = release_offline_replay_lease(&pool, &test_lease).await;

    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(recipient)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn repeatable_read_account_claim_serialization_retries_with_fresh_snapshot() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let recipient = Uuid::new_v4();
    let username = format!("rrretry{}", &recipient.simple().to_string()[..12]);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
        .bind(recipient)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();
    let account_message =
        insert_resource_replay_message(&pool, recipient, None, "rr-account").await;
    let phone_message =
        insert_resource_replay_message(&pool, recipient, Some("Phone"), "rr-phone").await;
    let tablet_message =
        insert_resource_replay_message(&pool, recipient, Some("Tablet"), "rr-tablet").await;
    let phone_lease = acquire_offline_replay_lease(
        &pool,
        recipient,
        "Phone",
        Uuid::new_v4(),
        None,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    .into_acquired()
    .unwrap();
    let tablet_lease = acquire_offline_replay_lease(
        &pool,
        recipient,
        "Tablet",
        Uuid::new_v4(),
        None,
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap()
    .into_acquired()
    .unwrap();
    let hook = ReplayClaimTestHook {
        snapshot_fixed: std::sync::Arc::new(tokio::sync::Barrier::new(2)),
        resume_after_competing_commit: std::sync::Arc::new(tokio::sync::Barrier::new(2)),
        fired: std::sync::atomic::AtomicBool::new(false),
        serialization_retries: std::sync::atomic::AtomicUsize::new(0),
    };
    let owner_bare = format!("{username}@example.test");
    let phone_full = format!("{owner_bare}/Phone");
    let tablet_full = format!("{owner_bare}/Tablet");

    let tablet_claim = claim_offline_replay_page_with_test_hook(
        &pool,
        &tablet_lease,
        30,
        &owner_bare,
        &tablet_full,
        None,
        false,
        REPLAY_OWNER_LEASE_SECONDS,
        &hook,
    );
    let phone_claim_after_tablet_snapshot = async {
        hook.snapshot_fixed.wait().await;
        let result = claim_offline_replay_page(
            &pool,
            &phone_lease,
            30,
            &owner_bare,
            &phone_full,
            None,
            false,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await;
        hook.resume_after_competing_commit.wait().await;
        result
    };
    let (tablet_claim, phone_claim) = tokio::join!(tablet_claim, phone_claim_after_tablet_snapshot);
    let phone_page = match phone_claim.unwrap() {
        OfflineReplayPageOutcome::Claimed(page) => page,
        other => panic!("expected phone page, got {other:?}"),
    };
    let tablet_page = match tablet_claim.unwrap() {
        OfflineReplayPageOutcome::Claimed(page) => page,
        other => panic!("expected tablet page after serialization retry, got {other:?}"),
    };
    assert_eq!(
        hook.serialization_retries
            .load(std::sync::atomic::Ordering::Acquire),
        1,
        "the forced stale RR snapshot must be discarded exactly once"
    );
    let phone_ids = phone_page
        .messages
        .iter()
        .map(|message| message.id)
        .collect::<std::collections::HashSet<_>>();
    let tablet_ids = tablet_page
        .messages
        .iter()
        .map(|message| message.id)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        phone_ids,
        [account_message, phone_message].into_iter().collect()
    );
    assert_eq!(tablet_ids, [tablet_message].into_iter().collect());

    release_untransferred_offline_claims(
        &pool,
        recipient,
        phone_page.claim_token,
        &phone_ids.iter().copied().collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    release_untransferred_offline_claims(
        &pool,
        recipient,
        tablet_page.claim_token,
        &tablet_ids.iter().copied().collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    assert!(release_offline_replay_lease(&pool, &phone_lease)
        .await
        .unwrap());
    assert!(release_offline_replay_lease(&pool, &tablet_lease)
        .await
        .unwrap());
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(recipient)
        .execute(&pool)
        .await
        .unwrap();
}
