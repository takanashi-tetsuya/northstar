//! Database tests of the SM service over the root SM repository.
use crate::db::{self};
use northstar_session_application::sm::{
    BindingFinalizationOutcome, BindingReservationOutcome, SmResumeFinalizationOutcome,
    SmResumeFinalizationRequest, SmService,
};
use northstar_session_postgres::capacity::DeploymentCapacityConfiguration;
use northstar_workflows::sm::{SmClaimStatus, SmSessionSnapshot};
use sqlx::postgres::PgPoolOptions;
use std::{net::IpAddr, str::FromStr, sync::Arc, time::Duration};
use uuid::Uuid;

async fn migrated_pool(max_connections: u32) -> sqlx::PgPool {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    pool
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn binding_reservation_is_bounded_leased_and_rechecks_auth_generation() {
    let pool = migrated_pool(4).await;
    northstar_session_postgres::capacity::reconcile_deployment_capacity(
        &pool,
        DeploymentCapacityConfiguration {
            epoch: 1,
            accounts: 8,
            muc_rooms: 8,
            muc_rooms_per_owner: 4,
            live_sessions: 1,
            sessions_per_account: 1,
            resumable_sessions: 8,
        },
    )
    .await
    .unwrap();
    let user_id = Uuid::new_v4();
    let username = format!("smphase{}", user_id.simple());
    sqlx::query(
        "INSERT INTO users(id,username,password_hash,auth_generation) VALUES($1,$2,'test',0)",
    )
    .bind(user_id)
    .bind(&username)
    .execute(&pool)
    .await
    .unwrap();
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let service = SmService::new(
        northstar_workflows::sm_repository::PostgresSmRepository::new(
            pool.clone(),
            Arc::new(zeroize::Zeroizing::new(vec![7_u8; 32])),
        ),
        schema,
    )
    .unwrap();
    let first_connection = Uuid::new_v4();
    let first_jid = format!("{username}@example.test/first");
    assert_eq!(
        service
            .reserve_binding(first_connection, user_id, 0, &first_jid, 30)
            .await
            .unwrap(),
        BindingReservationOutcome::Reserved
    );
    let bounded_lease: bool = sqlx::query_scalar(
        "SELECT lease_until>clock_timestamp()+INTERVAL '20 seconds'
                    AND lease_until<=clock_timestamp()+INTERVAL '31 seconds'
               FROM deployment_session_leases WHERE connection_id=$1",
    )
    .bind(first_connection)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(bounded_lease);
    assert_eq!(
        service
            .reserve_binding(
                Uuid::new_v4(),
                user_id,
                0,
                &format!("{username}@example.test/second"),
                30,
            )
            .await
            .unwrap(),
        BindingReservationOutcome::CapacityExhausted
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM deployment_session_leases")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );

    // Phase one has committed and released every DB guard. A credential
    // mutation therefore cannot be stalled by the caller pausing on a
    // Redis/cluster await between the two service calls.
    tokio::time::timeout(
        Duration::from_secs(1),
        sqlx::query("UPDATE users SET auth_generation=1 WHERE id=$1")
            .bind(user_id)
            .execute(&pool),
    )
    .await
    .expect("phase-one reservation retained a user-row lock")
    .unwrap();
    assert!(matches!(
        service
            .finalize_binding(first_connection, user_id, 0, &first_jid, 30, None, None,)
            .await
            .unwrap(),
        BindingFinalizationOutcome::CredentialsExpired
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_agent_login_epochs WHERE user_id=$1",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    assert!(service
        .release_live_session(first_connection)
        .await
        .unwrap());
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn sm_activation_and_privacy_selection_commit_or_roll_back_together() {
    let pool = migrated_pool(4).await;
    let user_id = Uuid::new_v4();
    let username = format!("smprivacy{}", user_id.simple());
    sqlx::query(
        "INSERT INTO users(id,username,password_hash,auth_generation) VALUES($1,$2,'test',0)",
    )
    .bind(user_id)
    .bind(&username)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO privacy_lists(owner_id,name) VALUES($1,'resume-list')")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    let peer_ip = IpAddr::from_str("127.0.0.1").unwrap();
    let old_connection = Uuid::new_v4();
    let full_jid = format!("{username}@example.test/device");
    let snapshot = SmSessionSnapshot {
        inbound_h: 3,
        outbound_h: 4,
        acked_h: 4,
        available: true,
        carbons: true,
        priority: 0,
        blocklist_requested: true,
        roster_requested: true,
        active_privacy_list: Some("resume-list".to_owned()),
        privacy_requested: true,
        peer_ip,
        user_agent_id: None,
        joined_rooms: Vec::new(),
        directed_presence: Vec::new(),
        last_presence: None,
        unacked: Vec::new(),
    };
    let service_snapshot = northstar_session_application::sm::SmSessionSnapshot::from(&snapshot);
    let token_hash = [19_u8; 32];
    let session_id = northstar_workflows::sm::create_sm_session(
        &pool,
        &token_hash,
        user_id,
        0,
        &full_jid,
        "device",
        "example.test",
        old_connection,
        &snapshot,
        300,
        30,
        8,
        64,
    )
    .await
    .unwrap();
    assert!(northstar_workflows::sm::suspend_sm_session(
        &pool,
        session_id,
        old_connection,
        &snapshot,
        300,
        64,
        65_536,
    )
    .await
    .unwrap());
    let claim = match northstar_workflows::sm::claim_sm_session_status(
        &pool,
        &token_hash,
        user_id,
        peer_ip,
        None,
        northstar_workflows::sm::SmIpPolicy::Exact,
        false,
        30,
    )
    .await
    .unwrap()
    {
        SmClaimStatus::Claimed(claim) => *claim,
        status => panic!("unexpected claim status: {status:?}"),
    };
    sqlx::query(
        "CREATE FUNCTION fail_sm_privacy_activation() RETURNS trigger
             LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced privacy failure'; END $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER fail_sm_privacy_activation
             BEFORE INSERT OR UPDATE ON privacy_active_sessions
             FOR EACH ROW EXECUTE FUNCTION fail_sm_privacy_activation()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let new_connection = Uuid::new_v4();
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let service = SmService::new(
        northstar_workflows::sm_repository::PostgresSmRepository::new(
            pool.clone(),
            Arc::new(zeroize::Zeroizing::new(vec![9_u8; 32])),
        ),
        schema,
    )
    .unwrap();
    let request = || SmResumeFinalizationRequest {
        session_id,
        claim_token: claim.claim_token,
        connection_id: new_connection,
        user_id,
        expected_auth_generation: 0,
        client_h: 4,
        acknowledged_count: 0,
        peer_ip,
        user_agent_id: None,
        active_privacy_list: Some("resume-list"),
        ttl_seconds: 300,
        live_lease_seconds: 30,
        max_stanzas: 64,
        max_bytes: 65_536,
        fast_plan: None,
    };
    assert!(service.finalize_resume(request()).await.is_err());
    let rolled_back: (Uuid, Option<Uuid>, bool) = sqlx::query_as(
        "SELECT connection_id,claim_token,resumable FROM sm_resume_sessions WHERE id=$1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rolled_back, (old_connection, Some(claim.claim_token), true));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM privacy_active_sessions WHERE owner_id=$1",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );

    sqlx::query("DROP TRIGGER fail_sm_privacy_activation ON privacy_active_sessions")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION fail_sm_privacy_activation()")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        service.finalize_resume(request()).await.unwrap(),
        SmResumeFinalizationOutcome::Committed(_)
    ));
    let committed: (Uuid, Option<Uuid>, Option<String>) = sqlx::query_as(
        "SELECT s.connection_id,s.claim_token,p.list_name
               FROM sm_resume_sessions s
               LEFT JOIN privacy_active_sessions p
                 ON p.owner_id=s.user_id AND p.connection_id=s.connection_id
              WHERE s.id=$1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        committed,
        (new_connection, None, Some("resume-list".to_owned()))
    );
    assert!(!service
        .suspend_exact_session(
            session_id,
            Uuid::new_v4(),
            user_id,
            0,
            &service_snapshot,
            300,
            64,
            65_536,
        )
        .await
        .unwrap());
    sqlx::query("UPDATE users SET auth_generation=1 WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(!service
        .suspend_exact_session(
            session_id,
            new_connection,
            user_id,
            0,
            &service_snapshot,
            300,
            64,
            65_536,
        )
        .await
        .unwrap());
    let revocation_won: (Uuid, bool) =
        sqlx::query_as("SELECT connection_id,resumable FROM sm_resume_sessions WHERE id=$1")
            .bind(session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(revocation_won, (new_connection, false));

    // Restore only the fixture's generation to exercise the successful
    // exact post-commit abort path. Production never decrements it.
    sqlx::query("UPDATE users SET auth_generation=0 WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(service
        .suspend_exact_session(
            session_id,
            new_connection,
            user_id,
            0,
            &service_snapshot,
            300,
            64,
            65_536,
        )
        .await
        .unwrap());
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT resumable FROM sm_resume_sessions WHERE id=$1",)
            .bind(session_id)
            .fetch_one(&pool)
            .await
            .unwrap()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM privacy_active_sessions
                  WHERE owner_id=$1 AND connection_id=$2",
        )
        .bind(user_id)
        .bind(new_connection)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0,
        "exact suspension must atomically clear the live privacy selection"
    );
    assert!(
        service
            .suspend_exact_session(
                session_id,
                new_connection,
                user_id,
                0,
                &service_snapshot,
                300,
                64,
                65_536,
            )
            .await
            .unwrap(),
        "a lost COMMIT response must replay as the same exact suspension"
    );
    let volatile_source_id = Uuid::new_v4();
    let before: (i64, i64) = sqlx::query_as(
        "SELECT s.outbound_h, COUNT(q.position)
               FROM sm_resume_sessions s
               LEFT JOIN sm_resume_stanzas q ON q.session_id=s.id
              WHERE s.id=$1 GROUP BY s.outbound_h",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    for _ in 0..2 {
        assert!(northstar_workflows::sm::append_suspended_sm_stanza(
            &pool,
            session_id,
            volatile_source_id,
            "<message id='ambiguous-commit'/>",
            64,
            65_536,
        )
        .await
        .unwrap());
    }
    let after: (i64, i64) = sqlx::query_as(
        "SELECT s.outbound_h, COUNT(q.position)
               FROM sm_resume_sessions s
               LEFT JOIN sm_resume_stanzas q ON q.session_id=s.id
              WHERE s.id=$1 GROUP BY s.outbound_h",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after, (before.0 + 1, before.1 + 1));
    northstar_workflows::sm::revoke_sm_session(&pool, session_id)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn resumable_binding_lease_transfers_only_after_transport_publication() {
    let pool = migrated_pool(4).await;
    northstar_session_postgres::capacity::reconcile_deployment_capacity(
        &pool,
        DeploymentCapacityConfiguration {
            epoch: 1,
            accounts: 8,
            muc_rooms: 8,
            muc_rooms_per_owner: 4,
            // Keep the isolated SM suite on one authoritative capacity
            // snapshot. This scenario exercises resumable replacement,
            // which must work without raising the deployment ceiling.
            live_sessions: 1,
            sessions_per_account: 1,
            resumable_sessions: 8,
        },
    )
    .await
    .unwrap();
    let user_id = Uuid::new_v4();
    let username = format!("smpublish{}", user_id.simple());
    sqlx::query(
        "INSERT INTO users(id,username,password_hash,auth_generation) VALUES($1,$2,'test',0)",
    )
    .bind(user_id)
    .bind(&username)
    .execute(&pool)
    .await
    .unwrap();
    let full_jid = format!("{username}@example.test/device");
    let peer_ip = IpAddr::from_str("127.0.0.1").unwrap();
    let old_connection = Uuid::new_v4();
    let snapshot = SmSessionSnapshot {
        inbound_h: 0,
        outbound_h: 0,
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
        joined_rooms: Vec::new(),
        directed_presence: Vec::new(),
        last_presence: None,
        unacked: Vec::new(),
    };
    let sm_session_id = northstar_workflows::sm::create_sm_session(
        &pool,
        &[0x45; 32],
        user_id,
        0,
        &full_jid,
        "device",
        "example.test",
        old_connection,
        &snapshot,
        300,
        120,
        8,
        8,
    )
    .await
    .unwrap();
    assert!(northstar_workflows::sm::suspend_sm_session(
        &pool,
        sm_session_id,
        old_connection,
        &snapshot,
        300,
        64,
        65_536,
    )
    .await
    .unwrap());

    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let sm = SmService::new(
        northstar_workflows::sm_repository::PostgresSmRepository::new(
            pool.clone(),
            Arc::new(zeroize::Zeroizing::new(vec![0x56; 32])),
        ),
        schema,
    )
    .unwrap();
    let device_id = Uuid::new_v4();

    // A completed phase two whose response never reaches the transport
    // leaves only a bounded claim/stage. Releasing the new connection must
    // not delete or transfer the old resumable stream's live lease.
    let abandoned_connection = Uuid::new_v4();
    assert_eq!(
        sm.reserve_binding(abandoned_connection, user_id, 0, &full_jid, 120)
            .await
            .unwrap(),
        BindingReservationOutcome::Reserved
    );
    let abandoned_receipt = match sm
        .finalize_binding(
            abandoned_connection,
            user_id,
            0,
            &full_jid,
            120,
            Some(device_id),
            None,
        )
        .await
        .unwrap()
    {
        BindingFinalizationOutcome::Committed { receipt } => receipt,
        other => panic!("unexpected abandoned binding outcome: {other:?}"),
    };
    assert_eq!(
        sqlx::query_scalar::<_, Uuid>(
            "SELECT connection_id FROM deployment_session_leases WHERE full_jid=$1",
        )
        .bind(&full_jid)
        .fetch_one(&pool)
        .await
        .unwrap(),
        old_connection
    );
    drop(abandoned_receipt);
    assert!(sm.release_live_session(abandoned_connection).await.unwrap());
    assert_eq!(
        sqlx::query_scalar::<_, Uuid>(
            "SELECT connection_id FROM deployment_session_leases WHERE full_jid=$1",
        )
        .bind(&full_jid)
        .fetch_one(&pool)
        .await
        .unwrap(),
        old_connection
    );

    let published_connection = Uuid::new_v4();
    assert_eq!(
        sm.reserve_binding(published_connection, user_id, 0, &full_jid, 120)
            .await
            .unwrap(),
        BindingReservationOutcome::Reserved
    );
    let receipt = match sm
        .finalize_binding(
            published_connection,
            user_id,
            0,
            &full_jid,
            120,
            Some(device_id),
            None,
        )
        .await
        .unwrap()
    {
        BindingFinalizationOutcome::Committed { receipt } => receipt,
        other => panic!("unexpected publishable binding outcome: {other:?}"),
    };
    assert_eq!(
        sqlx::query_scalar::<_, Uuid>(
            "SELECT connection_id FROM deployment_session_leases WHERE full_jid=$1",
        )
        .bind(&full_jid)
        .fetch_one(&pool)
        .await
        .unwrap(),
        old_connection,
        "phase two must retain the old resumable lease"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_agent_login_epochs WHERE user_id=$1 AND device_id=$2",
        )
        .bind(user_id)
        .bind(device_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );

    let authentication = northstar_auth_application::authentication::AuthenticationService::new(
        crate::db::authentication_effects::PostgresAuthenticationRepository::new(
            pool.clone(),
            std::sync::Arc::new(zeroize::Zeroizing::new(vec![0x56; 32])),
            crate::db::authentication_effects::RootAuthenticationEffects,
        ),
        std::sync::Arc::new(zeroize::Zeroizing::new(vec![0xa7; 32])),
        northstar_auth_core::MIN_SCRAM_ITERATIONS,
        false,
    );
    assert!(matches!(
        authentication.publish_credential_commit(&receipt).await,
        northstar_auth_application::authentication::AuthenticationResult::Authenticated(Some(2))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, Uuid>(
            "SELECT connection_id FROM deployment_session_leases WHERE full_jid=$1",
        )
        .bind(&full_jid)
        .fetch_one(&pool)
        .await
        .unwrap(),
        published_connection
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM deployment_session_binding_claims WHERE connection_id=$1",
        )
        .bind(published_connection)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT resumable FROM sm_resume_sessions WHERE id=$1",)
            .bind(sm_session_id)
            .fetch_one(&pool)
            .await
            .unwrap()
    );
}
