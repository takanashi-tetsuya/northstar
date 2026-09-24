use super::*;
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, Ipv6Addr};

async fn session_capability_catalog_healthy(pool: &PgPool) -> bool {
    sqlx::query_scalar(
        "SELECT northstar_session_capability_catalog_healthy(
            pg_catalog.current_schema())",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn owner_only_session_catalog_is_strict_and_development_safe() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();

    assert!(session_capability_catalog_healthy(&pool).await);

    sqlx::query("GRANT EXECUTE ON FUNCTION northstar_sm_count(text,uuid,bigint,text) TO PUBLIC")
        .execute(&pool)
        .await
        .unwrap();
    assert!(!session_capability_catalog_healthy(&pool).await);
    sqlx::query("REVOKE EXECUTE ON FUNCTION northstar_sm_count(text,uuid,bigint,text) FROM PUBLIC")
        .execute(&pool)
        .await
        .unwrap();
    assert!(session_capability_catalog_healthy(&pool).await);

    sqlx::query("GRANT SELECT ON TABLE sm_resume_sessions TO PUBLIC")
        .execute(&pool)
        .await
        .unwrap();
    assert!(!session_capability_catalog_healthy(&pool).await);
    sqlx::query("REVOKE SELECT ON TABLE sm_resume_sessions FROM PUBLIC")
        .execute(&pool)
        .await
        .unwrap();
    assert!(session_capability_catalog_healthy(&pool).await);

    sqlx::query(
        "ALTER TABLE sm_resume_sessions DISABLE TRIGGER \
         sm_resume_sessions_deployment_capacity_insert",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(!session_capability_catalog_healthy(&pool).await);
    sqlx::query(
        "ALTER TABLE sm_resume_sessions ENABLE TRIGGER \
         sm_resume_sessions_deployment_capacity_insert",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(session_capability_catalog_healthy(&pool).await);
}

async fn install_authorization_test_sm(
    pool: &PgPool,
    user_id: Uuid,
    username: &str,
    marker: u8,
) -> ([u8; 32], Uuid, SmSessionSnapshot) {
    let bearer = [marker; 32];
    let hash: [u8; 32] = Sha256::digest(bearer).into();
    let snapshot = SmSessionSnapshot {
        inbound_h: 3,
        outbound_h: 5,
        acked_h: 4,
        available: true,
        carbons: true,
        priority: 7,
        blocklist_requested: true,
        roster_requested: true,
        active_privacy_list: None,
        privacy_requested: false,
        peer_ip: "192.0.2.33".parse().unwrap(),
        user_agent_id: Some(Uuid::new_v4()),
        joined_rooms: vec![SmMucMembership {
            room_jid: "room@conference.example.test".to_owned(),
            nick: format!("Device-{marker}"),
        }],
        directed_presence: vec!["friend@example.net".to_owned()],
        last_presence: Some("<presence xmlns='jabber:client'/>".to_owned()),
        unacked: vec![crate::outbound::SmUnackedStanza::plain(format!(
            "<message id='queued-{marker}'/>"
        ))],
    };
    let id = create_sm_session(
        pool,
        &hash,
        user_id,
        0,
        &format!("{username}@example.test/Device-{marker}"),
        &format!("Device-{marker}"),
        "example.test",
        Uuid::new_v4(),
        &snapshot,
        300,
        30,
        8,
        100,
    )
    .await
    .unwrap();
    (hash, id, snapshot)
}

async fn assert_authorization_revocation_is_durably_teardownable(
    pool: &PgPool,
    user_id: Uuid,
    hash: &[u8; 32],
    id: Uuid,
    snapshot: &SmSessionSnapshot,
) {
    assert!(matches!(
        claim_sm_session_status(
            pool,
            hash,
            user_id,
            snapshot.peer_ip,
            snapshot.user_agent_id,
            SmIpPolicy::Exact,
            true,
            30,
        )
        .await
        .unwrap(),
        SmClaimStatus::Rejected
    ));
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sm_resume_sessions WHERE id=$1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(rows, 1, "authorization mutation destroyed teardown state");
    let teardown = take_user_sm_sessions_for_teardown(pool, user_id, 30)
        .await
        .unwrap()
        .snapshots
        .into_iter()
        .find(|candidate| candidate.session_id == id)
        .expect("expired authorization epoch must retain a teardown lease");
    assert!(teardown.available);
    assert_eq!(teardown.joined_rooms, snapshot.joined_rooms);
    assert_eq!(teardown.directed_presence, snapshot.directed_presence);
    assert!(finalize_sm_teardown(pool, id, teardown.teardown_token)
        .await
        .unwrap());
}

#[test]
fn subnet_binding_uses_v4_24_and_v6_64() {
    assert!(peer_ip_matches(
        SmIpPolicy::Subnet,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 250))
    ));
    assert!(!peer_ip_matches(
        SmIpPolicy::Subnet,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 3, 1))
    ));
    assert!(peer_ip_matches(
        SmIpPolicy::Subnet,
        IpAddr::V6("2001:db8:1:2::1".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("2001:db8:1:2::ffff".parse::<Ipv6Addr>().unwrap())
    ));
}

#[test]
fn queue_limits_are_enforced() {
    assert!(validate_queue(&[crate::outbound::SmUnackedStanza::plain("x".into())], 1, 1).is_ok());
    assert!(validate_queue(
        &[
            crate::outbound::SmUnackedStanza::plain("x".into()),
            crate::outbound::SmUnackedStanza::plain("y".into())
        ],
        1,
        2
    )
    .is_err());
    assert!(validate_queue(
        &[crate::outbound::SmUnackedStanza::plain("xy".into())],
        1,
        1
    )
    .is_err());
}

#[test]
fn snapshot_identity_keys_are_canonical_and_resources_remain_case_sensitive() {
    let mut snapshot = SmSessionSnapshot {
        inbound_h: 0,
        outbound_h: 0,
        acked_h: 0,
        available: false,
        carbons: false,
        priority: 0,
        blocklist_requested: false,
        roster_requested: false,
        active_privacy_list: None,
        privacy_requested: false,
        peer_ip: "192.0.2.10".parse().unwrap(),
        user_agent_id: None,
        joined_rooms: vec![SmMucMembership {
            room_jid: "room@conference.bücher.example".to_owned(),
            nick: "Nick".to_owned(),
        }],
        directed_presence: vec![
            "friend@bücher.example/Phone".to_owned(),
            "friend@bücher.example/phone".to_owned(),
        ],
        last_presence: None,
        unacked: vec![],
    };
    let (rooms, directed) = canonical_snapshot_identities(&snapshot).unwrap();
    assert_eq!(
        rooms,
        serde_json::json!([{
            "room_jid":"room@conference.bücher.example",
            "nick":"Nick"
        }])
    );
    assert_eq!(
        directed,
        serde_json::json!(["friend@bücher.example/Phone", "friend@bücher.example/phone"])
    );

    snapshot.joined_rooms.push(SmMucMembership {
        room_jid: "room@conference.bücher.example".to_owned(),
        nick: "Other".to_owned(),
    });
    assert!(canonical_snapshot_identities(&snapshot).is_err());
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn authorization_mutations_retain_sm_presence_and_muc_teardown_state() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let actor_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users(id,username,password_hash,is_admin)
         VALUES($1,$2,'test-only',TRUE)",
    )
    .bind(actor_id)
    .bind(format!("sm-actor-{}", &actor_id.simple().to_string()[..10]))
    .execute(&pool)
    .await
    .unwrap();

    let password_user = Uuid::new_v4();
    let password_name = format!("sm-password-{}", &password_user.simple().to_string()[..10]);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(password_user)
        .bind(&password_name)
        .execute(&pool)
        .await
        .unwrap();
    let (hash, id, snapshot) =
        install_authorization_test_sm(&pool, password_user, &password_name, 21).await;
    crate::db::change_password(
        &pool,
        password_user,
        "Correct-Horse-Battery-21",
        4096,
        false,
    )
    .await
    .unwrap();
    assert_authorization_revocation_is_durably_teardownable(
        &pool,
        password_user,
        &hash,
        id,
        &snapshot,
    )
    .await;

    let disabled_user = Uuid::new_v4();
    let disabled_name = format!("sm-disabled-{}", &disabled_user.simple().to_string()[..10]);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(disabled_user)
        .bind(&disabled_name)
        .execute(&pool)
        .await
        .unwrap();
    let (hash, id, snapshot) =
        install_authorization_test_sm(&pool, disabled_user, &disabled_name, 22).await;
    crate::db::set_user_status(&pool, actor_id, disabled_user, Some(true), None)
        .await
        .unwrap();
    assert_authorization_revocation_is_durably_teardownable(
        &pool,
        disabled_user,
        &hash,
        id,
        &snapshot,
    )
    .await;

    let ended_user = Uuid::new_v4();
    let ended_name = format!("sm-ended-{}", &ended_user.simple().to_string()[..10]);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(ended_user)
        .bind(&ended_name)
        .execute(&pool)
        .await
        .unwrap();
    let (hash, id, snapshot) =
        install_authorization_test_sm(&pool, ended_user, &ended_name, 23).await;
    assert!(crate::db::end_user_sessions(&pool, actor_id, ended_user)
        .await
        .unwrap());
    assert_authorization_revocation_is_durably_teardownable(
        &pool, ended_user, &hash, id, &snapshot,
    )
    .await;

    sqlx::query("DELETE FROM users WHERE id=ANY($1)")
        .bind(vec![actor_id, password_user, disabled_user, ended_user])
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn durable_delivery_fence_survives_checkpoint_resume_and_revocation() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let user_id = Uuid::new_v4();
    let username = format!("smfence{}", &user_id.simple().to_string()[..10]);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(user_id)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();
    let peer_ip = "192.0.2.44".parse().unwrap();

    async fn insert_delivery(pool: &PgPool, user_id: Uuid) -> crate::outbound::DurableDelivery {
        let message_id = Uuid::new_v4();
        let claim_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO offline_messages(
                id,recipient_id,sender_jid,stanza,encrypted,mam_backed,
                delivery_claim_id,delivery_claim_expires_at
             ) VALUES($1,$2,'sender@example.test','<message id=''sm''/>',FALSE,FALSE,
                      $3,clock_timestamp()+INTERVAL '1 hour')",
        )
        .bind(message_id)
        .bind(user_id)
        .bind(claim_id)
        .execute(pool)
        .await
        .unwrap();
        crate::outbound::DurableDelivery {
            recipient_id: user_id,
            message_id,
            claim_id: Some(claim_id),
        }
    }

    fn snapshot(peer_ip: IpAddr, delivery: crate::outbound::DurableDelivery) -> SmSessionSnapshot {
        SmSessionSnapshot {
            inbound_h: 0,
            outbound_h: 1,
            acked_h: 0,
            available: true,
            carbons: false,
            priority: 0,
            blocklist_requested: false,
            roster_requested: false,
            active_privacy_list: None,
            privacy_requested: false,
            peer_ip,
            user_agent_id: None,
            joined_rooms: vec![],
            directed_presence: vec![],
            last_presence: Some("<presence xmlns='jabber:client'/>".to_owned()),
            unacked: vec![crate::outbound::SmUnackedStanza::with_delivery(
                "<message id='sm'/>".to_owned(),
                Some(delivery),
            )],
        }
    }

    // A live checkpoint transfers the replay claim into the exact SM
    // sequence row. Only the matching client h removes both projections.
    let first = insert_delivery(&pool, user_id).await;
    let first_snapshot = snapshot(peer_ip, first);
    let first_connection = Uuid::new_v4();
    let first_id = create_sm_session(
        &pool,
        &[31_u8; 32],
        user_id,
        0,
        &format!("{username}@example.test/first"),
        "first",
        "example.test",
        first_connection,
        &first_snapshot,
        300,
        30,
        128,
        10_000,
    )
    .await
    .unwrap();
    let stored: (Option<Uuid>, i64) = sqlx::query_as(
        "SELECT message.delivery_claim_id,COUNT(stanza.delivery_message_id)
           FROM offline_messages message
           JOIN sm_resume_stanzas stanza ON stanza.delivery_message_id=message.id
          WHERE message.id=$1 GROUP BY message.delivery_claim_id",
    )
    .bind(first.message_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored, (None, 1));
    assert!(
        crate::db::replay::bind_bosh_delivery_response(&pool, Uuid::new_v4(), 1, &[first], 60,)
            .await
            .is_err()
    );
    let mut acknowledged_snapshot = first_snapshot.clone();
    acknowledged_snapshot.acked_h = 1;
    acknowledged_snapshot.unacked.clear();
    assert!(checkpoint_sm_session_and_acknowledge(
        &pool,
        first_id,
        first_connection,
        &acknowledged_snapshot,
        &first_snapshot.unacked,
        300,
        30,
        128,
        10_000,
    )
    .await
    .unwrap());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
            .bind(first.message_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    revoke_sm_session(&pool, first_id).await.unwrap();

    // If a non-resumable stream disappears before h advances, deleting
    // the SM owner frees (rather than deletes) the durable offline row.
    let second = insert_delivery(&pool, user_id).await;
    let second_snapshot = snapshot(peer_ip, second);
    let second_id = create_sm_session(
        &pool,
        &[32_u8; 32],
        user_id,
        0,
        &format!("{username}@example.test/second"),
        "second",
        "example.test",
        Uuid::new_v4(),
        &second_snapshot,
        300,
        30,
        128,
        10_000,
    )
    .await
    .unwrap();
    revoke_sm_session(&pool, second_id).await.unwrap();
    let second_row: Option<Uuid> =
        sqlx::query_scalar("SELECT delivery_claim_id FROM offline_messages WHERE id=$1")
            .bind(second.message_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(second_row, None);

    // Resume h is committed with fence completion in the activation
    // transaction, before the replacement route becomes authoritative.
    let third = insert_delivery(&pool, user_id).await;
    let third_snapshot = snapshot(peer_ip, third);
    let third_connection = Uuid::new_v4();
    let third_hash = [33_u8; 32];
    let third_id = create_sm_session(
        &pool,
        &third_hash,
        user_id,
        0,
        &format!("{username}@example.test/third"),
        "third",
        "example.test",
        third_connection,
        &third_snapshot,
        300,
        30,
        128,
        10_000,
    )
    .await
    .unwrap();
    assert!(suspend_sm_session(
        &pool,
        third_id,
        third_connection,
        &third_snapshot,
        300,
        128,
        10_000,
    )
    .await
    .unwrap());
    let claim = claim_sm_session(
        &pool,
        &third_hash,
        user_id,
        peer_ip,
        None,
        SmIpPolicy::Exact,
        false,
        30,
    )
    .await
    .unwrap()
    .unwrap();
    let mut transaction = pool.begin().await.unwrap();
    let activated = activate_claimed_sm_session_in_transaction(
        &mut transaction,
        claim.session_id,
        claim.claim_token,
        Uuid::new_v4(),
        1,
        1,
        peer_ip,
        None,
        300,
        30,
        128,
        10_000,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(activated.unacked.is_empty());
    transaction.commit().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
            .bind(third.message_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    revoke_sm_session(&pool, third_id).await.unwrap();

    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn strict_same_device_claim_rejects_legacy_and_null_claimant() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let user_id = Uuid::new_v4();
    let username = format!("smdevice{}", user_id.simple());
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(user_id)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();
    let peer_ip = "192.0.2.44".parse().unwrap();
    let recorded_device = Uuid::new_v4();
    let base_snapshot = SmSessionSnapshot {
        inbound_h: 0,
        outbound_h: 0,
        acked_h: 0,
        available: false,
        carbons: false,
        priority: 0,
        blocklist_requested: false,
        roster_requested: false,
        active_privacy_list: None,
        privacy_requested: false,
        peer_ip,
        user_agent_id: None,
        joined_rooms: Vec::new(),
        directed_presence: Vec::new(),
        last_presence: None,
        unacked: Vec::new(),
    };

    // A legacy snapshot cannot prove continuity. Strict mode rejects it
    // even when the reconnect supplies a well-formed device identifier.
    let legacy_hash = [31_u8; 32];
    let legacy_connection = Uuid::new_v4();
    let legacy_id = create_sm_session(
        &pool,
        &legacy_hash,
        user_id,
        0,
        &format!("{username}@example.test/legacy"),
        "legacy",
        "example.test",
        legacy_connection,
        &base_snapshot,
        300,
        30,
        8,
        100,
    )
    .await
    .unwrap();
    assert!(suspend_sm_session(
        &pool,
        legacy_id,
        legacy_connection,
        &base_snapshot,
        300,
        8,
        4_096,
    )
    .await
    .unwrap());
    assert!(matches!(
        claim_sm_session_status(
            &pool,
            &legacy_hash,
            user_id,
            peer_ip,
            Some(recorded_device),
            SmIpPolicy::Exact,
            true,
            30,
        )
        .await
        .unwrap(),
        SmClaimStatus::Rejected
    ));
    let compatibility_claim = match claim_sm_session_status(
        &pool,
        &legacy_hash,
        user_id,
        peer_ip,
        None,
        SmIpPolicy::Exact,
        false,
        30,
    )
    .await
    .unwrap()
    {
        SmClaimStatus::Claimed(claim) => *claim,
        status => panic!("legacy compatibility claim was not accepted: {status:?}"),
    };
    release_sm_claim(
        &pool,
        compatibility_claim.session_id,
        compatibility_claim.claim_token,
    )
    .await
    .unwrap();
    revoke_sm_session(&pool, legacy_id).await.unwrap();

    // Conversely, a recorded device cannot be resumed in strict mode by
    // an anonymous claimant. A matching identifier remains valid.
    let mut bound_snapshot = base_snapshot;
    bound_snapshot.user_agent_id = Some(recorded_device);
    let bound_hash = [32_u8; 32];
    let bound_connection = Uuid::new_v4();
    let bound_id = create_sm_session(
        &pool,
        &bound_hash,
        user_id,
        0,
        &format!("{username}@example.test/bound"),
        "bound",
        "example.test",
        bound_connection,
        &bound_snapshot,
        300,
        30,
        8,
        100,
    )
    .await
    .unwrap();
    assert!(suspend_sm_session(
        &pool,
        bound_id,
        bound_connection,
        &bound_snapshot,
        300,
        8,
        4_096,
    )
    .await
    .unwrap());
    for claimant in [None, Some(Uuid::new_v4())] {
        assert!(matches!(
            claim_sm_session_status(
                &pool,
                &bound_hash,
                user_id,
                peer_ip,
                claimant,
                SmIpPolicy::Exact,
                true,
                30,
            )
            .await
            .unwrap(),
            SmClaimStatus::Rejected
        ));
    }
    let matching_claim = match claim_sm_session_status(
        &pool,
        &bound_hash,
        user_id,
        peer_ip,
        Some(recorded_device),
        SmIpPolicy::Exact,
        true,
        30,
    )
    .await
    .unwrap()
    {
        SmClaimStatus::Claimed(claim) => *claim,
        status => panic!("matching strict device claim was not accepted: {status:?}"),
    };
    release_sm_claim(&pool, matching_claim.session_id, matching_claim.claim_token)
        .await
        .unwrap();
    revoke_sm_session(&pool, bound_id).await.unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn durable_claim_is_single_consumer_and_revocable() {
    use sha2::{Digest, Sha256};
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let user_id = Uuid::new_v4();
    let username = format!("smtest{}", user_id.simple());
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(user_id)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();
    let bearer = [9_u8; 32];
    let hash: [u8; 32] = Sha256::digest(bearer).into();
    let snapshot = SmSessionSnapshot {
        inbound_h: u32::MAX,
        outbound_h: 1,
        acked_h: u32::MAX,
        available: true,
        carbons: true,
        priority: 1,
        blocklist_requested: false,
        roster_requested: true,
        active_privacy_list: None,
        privacy_requested: true,
        peer_ip: "192.0.2.10".parse().unwrap(),
        user_agent_id: Some(Uuid::new_v4()),
        joined_rooms: vec![],
        directed_presence: vec![],
        last_presence: Some("<presence xmlns='jabber:client'/>".to_owned()),
        unacked: vec![
            crate::outbound::SmUnackedStanza::plain("<message id='one'/>".into()),
            crate::outbound::SmUnackedStanza::plain("<message id='two'/>".into()),
        ],
    };
    let connection_id = Uuid::new_v4();
    let id = create_sm_session(
        &pool,
        &hash,
        user_id,
        0,
        &format!("{username}@example.test/r"),
        "r",
        "example.test",
        connection_id,
        &snapshot,
        300,
        30,
        4,
        100,
    )
    .await
    .unwrap();
    let (stored_privacy, stored_peer_ip): (bool, String) = sqlx::query_as(
        "SELECT privacy_requested,pg_catalog.host(peer_ip)
           FROM sm_resume_sessions WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(stored_privacy);
    assert_eq!(stored_peer_ip, snapshot.peer_ip.to_string());
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT token_hash FROM sm_resume_sessions WHERE id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored, hash);
    assert_ne!(stored, bearer);
    assert!(
        suspend_sm_session(&pool, id, connection_id, &snapshot, 300, 8, 4096)
            .await
            .unwrap()
    );

    let device = snapshot.user_agent_id;
    let first = claim_sm_session(
        &pool,
        &hash,
        user_id,
        snapshot.peer_ip,
        device,
        SmIpPolicy::Exact,
        true,
        30,
    );
    let second = claim_sm_session(
        &pool,
        &hash,
        user_id,
        snapshot.peer_ip,
        device,
        SmIpPolicy::Exact,
        true,
        30,
    );
    let (first, second) = tokio::join!(first, second);
    let claims = [first.unwrap(), second.unwrap()];
    assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);
    let claim = claims.into_iter().flatten().next().unwrap();
    assert_eq!(claim.unacked, snapshot.unacked);
    assert!(claim.roster_requested);
    release_sm_claim(&pool, claim.session_id, claim.claim_token)
        .await
        .unwrap();

    // A reconnect can arrive after the transport closes but before Drop's
    // asynchronous durable suspension commits. The valid bearer/binding
    // is reported as Pending (never confused with an invalid token), then
    // becomes claimable within the protocol's bounded grace window.
    let race_hash: [u8; 32] = Sha256::digest([12_u8; 32]).into();
    let race_connection = Uuid::new_v4();
    let race_id = create_sm_session(
        &pool,
        &race_hash,
        user_id,
        0,
        &format!("{username}@example.test/race"),
        "race",
        "example.test",
        race_connection,
        &snapshot,
        300,
        30,
        4,
        100,
    )
    .await
    .unwrap();
    assert!(matches!(
        claim_sm_session_status(
            &pool,
            &race_hash,
            user_id,
            snapshot.peer_ip,
            device,
            SmIpPolicy::Exact,
            true,
            30,
        )
        .await
        .unwrap(),
        SmClaimStatus::Pending(_)
    ));
    let suspend_pool = pool.clone();
    let suspend_snapshot = snapshot.clone();
    let delayed_suspend = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        suspend_sm_session(
            &suspend_pool,
            race_id,
            race_connection,
            &suspend_snapshot,
            300,
            8,
            4096,
        )
        .await
        .unwrap()
    });
    let raced_claim = loop {
        match claim_sm_session_status(
            &pool,
            &race_hash,
            user_id,
            snapshot.peer_ip,
            device,
            SmIpPolicy::Exact,
            true,
            30,
        )
        .await
        .unwrap()
        {
            SmClaimStatus::Claimed(claim) => break *claim,
            SmClaimStatus::Pending(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await
            }
            SmClaimStatus::Rejected => panic!("valid racing SM token was rejected"),
        }
    };
    assert!(delayed_suspend.await.unwrap());
    let resumed_connection = Uuid::new_v4();
    let mut resume_tx = crate::db::lock_auth_generation(&pool, user_id, 0)
        .await
        .unwrap()
        .unwrap();
    assert!(activate_claimed_sm_session_in_transaction(
        &mut resume_tx,
        raced_claim.session_id,
        raced_claim.claim_token,
        resumed_connection,
        raced_claim.acked_h,
        0,
        snapshot.peer_ip,
        device,
        300,
        30,
        8,
        4096,
    )
    .await
    .unwrap()
    .is_some());
    resume_tx.commit().await.unwrap();
    assert!(
        !suspend_sm_session(&pool, race_id, race_connection, &snapshot, 300, 8, 4096)
            .await
            .unwrap()
    );
    let owner: (Uuid, bool) =
        sqlx::query_as("SELECT connection_id,resumable FROM sm_resume_sessions WHERE id=$1")
            .bind(race_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(owner, (resumed_connection, false));
    revoke_sm_session(&pool, race_id).await.unwrap();

    // A password/status generation change invalidates the old bearer even
    // if a disconnect races a new checkpoint.
    sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(claim_sm_session(
        &pool,
        &hash,
        user_id,
        snapshot.peer_ip,
        device,
        SmIpPolicy::Exact,
        true,
        30,
    )
    .await
    .unwrap()
    .is_none());

    // Simulate a process crash: no clean `resumable` transition happened,
    // but the heartbeat lease elapsed. The durable row remains claimable.
    let crash_hash: [u8; 32] = Sha256::digest([10_u8; 32]).into();
    let crash_id = create_sm_session(
        &pool,
        &crash_hash,
        user_id,
        1,
        &format!("{username}@example.test/crash"),
        "crash",
        "example.test",
        Uuid::new_v4(),
        &snapshot,
        300,
        30,
        4,
        100,
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE sm_resume_sessions SET live_lease_until=NOW()-INTERVAL '1 second' WHERE id=$1",
    )
    .bind(crash_id)
    .execute(&pool)
    .await
    .unwrap();
    let crash_claim = claim_sm_session(
        &pool,
        &crash_hash,
        user_id,
        snapshot.peer_ip,
        device,
        SmIpPolicy::Exact,
        true,
        30,
    )
    .await
    .unwrap()
    .expect("expired live lease must be recoverable after a crash");
    release_sm_claim(&pool, crash_id, crash_claim.claim_token)
        .await
        .unwrap();
    sqlx::query("UPDATE sm_resume_sessions SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1")
        .bind(crash_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(claim_sm_session(
        &pool,
        &crash_hash,
        user_id,
        snapshot.peer_ip,
        device,
        SmIpPolicy::Exact,
        true,
        30,
    )
    .await
    .unwrap()
    .is_none());
    let crash_teardown = cleanup_expired_sm_sessions(&pool, 30)
        .await
        .unwrap()
        .into_iter()
        .find(|snapshot| snapshot.session_id == crash_id)
        .unwrap();
    assert!(!finalize_sm_teardown(&pool, crash_id, Uuid::new_v4())
        .await
        .unwrap());
    assert!(
        finalize_sm_teardown(&pool, crash_id, crash_teardown.teardown_token)
            .await
            .unwrap()
    );

    // A resume claimant that acquired the row before expiry owns it for
    // the bounded claim lease. Maintenance must not delete or tear it
    // down underneath activation; once released, exactly one cleanup
    // pass receives the complete teardown snapshot.
    let protected_hash: [u8; 32] = Sha256::digest([11_u8; 32]).into();
    let mut protected_snapshot = snapshot.clone();
    protected_snapshot.joined_rooms = vec![SmMucMembership {
        room_jid: "room@conference.example.test".to_owned(),
        nick: "Phone User".to_owned(),
    }];
    protected_snapshot.directed_presence = vec![
        "friend@example.net".to_owned(),
        "friend@example.test/Tablet".to_owned(),
    ];
    let protected_connection = Uuid::new_v4();
    let protected_id = create_sm_session(
        &pool,
        &protected_hash,
        user_id,
        1,
        &format!("{username}@example.test/protected"),
        "protected",
        "example.test",
        protected_connection,
        &protected_snapshot,
        300,
        30,
        4,
        100,
    )
    .await
    .unwrap();
    assert!(suspend_sm_session(
        &pool,
        protected_id,
        protected_connection,
        &protected_snapshot,
        300,
        8,
        4096,
    )
    .await
    .unwrap());
    let protected_claim = claim_sm_session(
        &pool,
        &protected_hash,
        user_id,
        protected_snapshot.peer_ip,
        protected_snapshot.user_agent_id,
        SmIpPolicy::Exact,
        true,
        30,
    )
    .await
    .unwrap()
    .unwrap();
    sqlx::query("UPDATE sm_resume_sessions SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1")
        .bind(protected_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(!cleanup_expired_sm_sessions(&pool, 30)
        .await
        .unwrap()
        .iter()
        .any(|candidate| candidate.session_id == protected_id));
    release_sm_claim(
        &pool,
        protected_claim.session_id,
        protected_claim.claim_token,
    )
    .await
    .unwrap();
    let first_cleanup = cleanup_expired_sm_sessions(&pool, 30);
    let second_cleanup = cleanup_expired_sm_sessions(&pool, 30);
    let (first_cleanup, second_cleanup) = tokio::join!(first_cleanup, second_cleanup);
    let teardowns = first_cleanup
        .unwrap()
        .into_iter()
        .chain(second_cleanup.unwrap())
        .filter(|candidate| candidate.session_id == protected_id)
        .collect::<Vec<_>>();
    assert_eq!(teardowns.len(), 1);
    let teardown = teardowns.into_iter().next().unwrap();
    assert_eq!(teardown.username, username);
    assert!(teardown.available);
    assert_eq!(teardown.joined_rooms, protected_snapshot.joined_rooms);
    assert_eq!(
        teardown.directed_presence,
        protected_snapshot.directed_presence
    );
    assert!(!finalize_sm_teardown(&pool, protected_id, Uuid::new_v4())
        .await
        .unwrap());
    // Simulate the teardown worker crashing before finalization. Once its
    // lease expires, maintenance acquires a new token and can repeat the
    // idempotent unavailable/MUC side effects.
    sqlx::query(
        "UPDATE sm_resume_sessions SET claimed_until=NOW()-INTERVAL '1 second' WHERE id=$1",
    )
    .bind(protected_id)
    .execute(&pool)
    .await
    .unwrap();
    let retry = cleanup_expired_sm_sessions(&pool, 30)
        .await
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.session_id == protected_id)
        .unwrap();
    assert_ne!(retry.teardown_token, teardown.teardown_token);
    assert!(
        !finalize_sm_teardown(&pool, protected_id, teardown.teardown_token)
            .await
            .unwrap()
    );
    assert!(
        finalize_sm_teardown(&pool, protected_id, retry.teardown_token)
            .await
            .unwrap()
    );

    sqlx::query("UPDATE users SET is_disabled=TRUE WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(claim_sm_session(
        &pool,
        &hash,
        user_id,
        snapshot.peer_ip,
        device,
        SmIpPolicy::Exact,
        true,
        30,
    )
    .await
    .unwrap()
    .is_none());
    let revoked = take_user_sm_sessions_for_teardown(&pool, user_id, 30)
        .await
        .unwrap()
        .snapshots;
    assert_eq!(revoked.len(), 1);
    assert!(
        finalize_sm_teardown(&pool, revoked[0].session_id, revoked[0].teardown_token)
            .await
            .unwrap()
    );
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn every_teardown_scope_preserves_the_active_privacy_list() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();

    let user_id = Uuid::new_v4();
    let username = format!("sm-privacy-{}", &user_id.simple().to_string()[..10]);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(user_id)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO privacy_lists(owner_id,name) VALUES($1,'trusted')")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    async fn install(pool: &PgPool, user_id: Uuid, username: &str, marker: u8) -> (Uuid, String) {
        let (_, id, _snapshot) =
            install_authorization_test_sm(pool, user_id, username, marker).await;
        sqlx::query(
            "UPDATE sm_resume_sessions SET active_privacy_list='trusted', privacy_requested=TRUE WHERE id=$1",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
        (id, format!("{username}@example.test/Device-{marker}"))
    }

    async fn finish(pool: &PgPool, snapshot: SmTeardownSnapshot, expected: Uuid) {
        assert_eq!(snapshot.session_id, expected);
        assert_eq!(snapshot.active_privacy_list.as_deref(), Some("trusted"));
        assert!(
            finalize_sm_teardown(pool, expected, snapshot.teardown_token)
                .await
                .unwrap()
        );
    }

    let (single_id, _) = install(&pool, user_id, &username, 91).await;
    finish(
        &pool,
        take_sm_session_for_teardown(&pool, single_id, 30)
            .await
            .unwrap()
            .unwrap(),
        single_id,
    )
    .await;

    let (user_id_row, _) = install(&pool, user_id, &username, 92).await;
    let user_batch = take_user_sm_sessions_for_teardown(&pool, user_id, 30)
        .await
        .unwrap();
    assert_eq!(user_batch.pending, 0);
    assert_eq!(user_batch.snapshots.len(), 1);
    finish(
        &pool,
        user_batch.snapshots.into_iter().next().unwrap(),
        user_id_row,
    )
    .await;

    let (full_id, full_jid) = install(&pool, user_id, &username, 93).await;
    let full_batch = take_sm_sessions_for_full_jid_teardown(&pool, &full_jid, 30)
        .await
        .unwrap();
    assert_eq!(full_batch.pending, 0);
    assert_eq!(full_batch.snapshots.len(), 1);
    finish(
        &pool,
        full_batch.snapshots.into_iter().next().unwrap(),
        full_id,
    )
    .await;

    let (all_id, _) = install(&pool, user_id, &username, 94).await;
    let all_batch = take_all_sm_sessions_for_teardown(&pool, 30).await.unwrap();
    assert_eq!(all_batch.pending, 0);
    assert_eq!(all_batch.snapshots.len(), 1);
    finish(
        &pool,
        all_batch.snapshots.into_iter().next().unwrap(),
        all_id,
    )
    .await;

    let (expired_id, _) = install(&pool, user_id, &username, 95).await;
    sqlx::query("UPDATE sm_resume_sessions SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1")
        .bind(expired_id)
        .execute(&pool)
        .await
        .unwrap();
    let expired = cleanup_expired_sm_sessions(&pool, 30)
        .await
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.session_id == expired_id)
        .unwrap();
    finish(&pool, expired, expired_id).await;

    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn account_deletion_quiesce_closes_all_sm_race_barriers() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let user_id = Uuid::new_v4();
    let username = format!("sm-delete-{}", &user_id.simple().to_string()[..10]);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(user_id)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();
    let (hash, session_id, snapshot) =
        install_authorization_test_sm(&pool, user_id, &username, 81).await;
    sqlx::query("UPDATE sm_resume_sessions SET resumable=TRUE,live_lease_until=NOW() WHERE id=$1")
        .bind(session_id)
        .execute(&pool)
        .await
        .unwrap();
    let claim = match claim_sm_session_status(
        &pool,
        &hash,
        user_id,
        snapshot.peer_ip,
        snapshot.user_agent_id,
        SmIpPolicy::Exact,
        true,
        30,
    )
    .await
    .unwrap()
    {
        SmClaimStatus::Claimed(claim) => claim,
        other => panic!("expected a held claim, got {other:?}"),
    };

    // Barrier 1: none of the bulk teardown scopes may steal a live claim.
    let user_batch = take_user_sm_sessions_for_teardown(&pool, user_id, 30)
        .await
        .unwrap();
    assert!(user_batch.snapshots.is_empty());
    assert_eq!(user_batch.pending, 1);
    let full_batch = take_sm_sessions_for_full_jid_teardown(&pool, &claim.full_jid, 30)
        .await
        .unwrap();
    assert!(full_batch.snapshots.is_empty());
    assert_eq!(full_batch.pending, 1);
    let all_batch = take_all_sm_sessions_for_teardown(&pool, 30).await.unwrap();
    assert!(all_batch.snapshots.is_empty());
    assert_eq!(all_batch.pending, 1);
    let persisted_token: Option<Uuid> =
        sqlx::query_scalar("SELECT claim_token FROM sm_resume_sessions WHERE id=$1")
            .bind(session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(persisted_token, Some(claim.claim_token));

    assert!(crate::db::begin_account_deletion_quiesce(&pool, user_id)
        .await
        .unwrap());

    // Barrier 2: a claim obtained before quiesce cannot activate after it.
    let mut activation = pool.begin().await.unwrap();
    assert!(activate_claimed_sm_session_in_transaction(
        &mut activation,
        claim.session_id,
        claim.claim_token,
        Uuid::new_v4(),
        claim.acked_h,
        0,
        snapshot.peer_ip,
        snapshot.user_agent_id,
        300,
        30,
        8,
        4096,
    )
    .await
    .unwrap()
    .is_none());
    activation.rollback().await.unwrap();

    // Barrier 3: a stale live connection cannot enable new durable SM.
    assert!(create_sm_session(
        &pool,
        &[82_u8; 32],
        user_id,
        0,
        &format!("{username}@example.test/new"),
        "new",
        "example.test",
        Uuid::new_v4(),
        &snapshot,
        300,
        30,
        8,
        100,
    )
    .await
    .is_err());

    // Barrier 4: quiesce rejects a new resume and the pending old claim
    // becomes teardownable without changing ownership behind its back.
    assert!(matches!(
        claim_sm_session_status(
            &pool,
            &hash,
            user_id,
            snapshot.peer_ip,
            snapshot.user_agent_id,
            SmIpPolicy::Exact,
            true,
            30,
        )
        .await
        .unwrap(),
        SmClaimStatus::Rejected
    ));
    release_sm_claim(&pool, session_id, claim.claim_token)
        .await
        .unwrap();
    let batch = take_user_sm_sessions_for_teardown(&pool, user_id, 30)
        .await
        .unwrap();
    assert_eq!(batch.pending, 0);
    assert_eq!(batch.snapshots.len(), 1);
    assert!(
        finalize_sm_teardown(&pool, session_id, batch.snapshots[0].teardown_token)
            .await
            .unwrap()
    );
    assert_eq!(count_user_sm_rows(&pool, user_id).await.unwrap(), 0);
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
}
