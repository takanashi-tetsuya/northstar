use northstar_message_core::OfflineStorePolicy;
use northstar_message_postgres::direct_spool_wake::record_direct_spool_wake_in_transaction;
use northstar_message_postgres::personal_history::{
    insert_c2s_delivery_in_transaction, release_cluster_live_delivery_reservation_and_rearm,
    reserve_cluster_live_delivery_in_transaction, PersonalC2sDeliveryAdmission,
};
use northstar_session_application::node_message_contract_verifier::{
    NodeMessageContractVerifier, RequestedNodeMessageProjection, VerifiedNodeMessageProjection,
};
use northstar_session_postgres::node_message_projection_repository::PostgresNodeMessageProjectionRepository;
use northstar_session_postgres::replay::{
    acknowledge_durable_delivery, acquire_offline_replay_lease, claim_offline_replay_page,
    fence_durable_socket_write, OfflineReplayLeaseAcquire, OfflineReplayPageOutcome,
};
use northstar_stream::outbound::{DurableDelivery, DurableDeliverySuperseded};
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "example.test";
const BARE: &str = "bob@example.test";
const FULL: &str = "bob@example.test/Phone";
const SENDER: &str = "alice@remote.test/Desk";

struct LiveFixture {
    admin: PgPool,
    pool: PgPool,
    schema: String,
    source: DurableDelivery,
    stanza: String,
}

impl LiveFixture {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL").expect("set disposable TEST_DATABASE_URL");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("cluster_live_handoff_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        eprintln!("isolated_schema_created={schema}");
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {connection_schema}");
                Box::pin(async move {
                    sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        crate::support::migrate(&pool).await.unwrap();
        let recipient_id = Uuid::new_v4();
        let message_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'bob','test')")
            .bind(recipient_id)
            .execute(&pool)
            .await
            .unwrap();
        let stanza = format!(
            "<message xmlns='jabber:client' type='chat' from='{SENDER}' to='{BARE}'>\
             <body>reserved live message</body><stanza-id xmlns='urn:xmpp:sid:0' \
             by='{BARE}' id='{message_id}'/></message>"
        );
        let mut transaction = pool.begin().await.unwrap();
        northstar_postgres::cluster_lock::lock_direct_spool_instance_claims_in_transaction(
            &mut transaction,
        )
        .await
        .unwrap();
        insert_c2s_delivery_in_transaction(
            &mut transaction,
            &PersonalC2sDeliveryAdmission {
                id: message_id,
                recipient_id,
                recipient_bare_jid: BARE,
                local_actor_id: None,
                sender_jid: SENDER,
                stanza: &stanza,
                target_full_jid: None,
                encrypted: false,
                policy: OfflineStorePolicy {
                    max_messages: 10,
                    max_bytes: 65_536,
                    ttl_days: 30,
                    mam_backed: false,
                },
            },
            SENDER,
        )
        .await
        .unwrap();
        reserve_cluster_live_delivery_in_transaction(&mut transaction, recipient_id, message_id)
            .await
            .unwrap();
        record_direct_spool_wake_in_transaction(&mut transaction, DOMAIN, recipient_id)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        Self {
            admin,
            pool,
            schema,
            source: DurableDelivery {
                recipient_id,
                message_id,
                claim_id: Some(message_id),
            },
            stanza,
        }
    }

    async fn verify(&self) -> anyhow::Result<VerifiedNodeMessageProjection> {
        NodeMessageContractVerifier::new(PostgresNodeMessageProjectionRepository::new(
            self.pool.clone(),
        ))
        .resolve(
            RequestedNodeMessageProjection::DurableC2sReserved {
                recipient_id: self.source.recipient_id,
                message_id: self.source.message_id,
                initial_claim_id: self.source.message_id,
            },
            &self.stanza,
            FULL,
        )
        .await
    }

    async fn verified_source(&self) -> DurableDelivery {
        let VerifiedNodeMessageProjection::Durable(source) = self.verify().await.unwrap() else {
            panic!("receiver did not attach a durable source");
        };
        assert_eq!(source, self.source);
        source
    }

    async fn drop_schema(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable TEST_DATABASE_URL; migrates and removes an isolated schema"]
async fn committed_live_reservation_verifies_and_fences_exactly_once() {
    let fixture = LiveFixture::new().await;
    let source = fixture.verified_source().await;
    let fenced = fence_durable_socket_write(&fixture.pool, source)
        .await
        .unwrap();
    assert!(fenced.claim_id.is_some());
    assert_ne!(fenced.claim_id, source.claim_id);
    assert_eq!(
        fence_durable_socket_write(&fixture.pool, source)
            .await
            .unwrap_err()
            .downcast_ref::<DurableDeliverySuperseded>(),
        Some(&DurableDeliverySuperseded {
            message_id: source.message_id
        })
    );
    assert!(fixture.verify().await.is_err());
    acknowledge_durable_delivery(&fixture.pool, fenced)
        .await
        .unwrap();
    assert!(fixture.verify().await.is_err());
    fixture.drop_schema().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable TEST_DATABASE_URL; migrates and removes an isolated schema"]
async fn replay_takeover_after_verification_prevents_the_stale_socket_fence() {
    let fixture = LiveFixture::new().await;
    let source = fixture.verified_source().await;
    let replay_claim = Uuid::new_v4();
    let mut replay = fixture.pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *replay)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM offline_messages WHERE id=$1 FOR UPDATE")
        .bind(source.message_id)
        .fetch_one(&mut *replay)
        .await
        .unwrap();
    let fence_pool = fixture.pool.clone();
    let stale = tokio::spawn(async move { fence_durable_socket_write(&fence_pool, source).await });
    crate::support::blocked_backend(&fixture.pool, blocker).await;
    sqlx::query("UPDATE offline_messages SET delivery_claim_id=$2,delivery_claim_expires_at=clock_timestamp()+INTERVAL '60 seconds' WHERE id=$1")
        .bind(source.message_id).bind(replay_claim).execute(&mut *replay).await.unwrap();
    replay.commit().await.unwrap();
    assert_eq!(
        stale
            .await
            .unwrap()
            .unwrap_err()
            .downcast_ref::<DurableDeliverySuperseded>(),
        Some(&DurableDeliverySuperseded {
            message_id: source.message_id
        })
    );
    let replay_fence = fence_durable_socket_write(
        &fixture.pool,
        DurableDelivery {
            claim_id: Some(replay_claim),
            ..source
        },
    )
    .await
    .unwrap();
    assert_eq!(replay_fence.claim_id, Some(replay_claim));
    acknowledge_durable_delivery(&fixture.pool, replay_fence)
        .await
        .unwrap();
    fixture.drop_schema().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable TEST_DATABASE_URL; migrates and removes an isolated schema"]
async fn released_reservation_refuses_live_verification_and_remains_replayable() {
    let fixture = LiveFixture::new().await;
    let DurableDelivery {
        recipient_id,
        message_id,
        ..
    } = fixture.source;
    assert!(release_cluster_live_delivery_reservation_and_rearm(
        &fixture.pool,
        DOMAIN,
        recipient_id,
        message_id,
        message_id,
    )
    .await
    .unwrap());
    assert_eq!(
        fixture.verify().await.unwrap_err().to_string(),
        "cluster durable delivery claim changed"
    );

    let OfflineReplayLeaseAcquire::Acquired(lease) = acquire_offline_replay_lease(
        &fixture.pool,
        recipient_id,
        "Phone",
        Uuid::new_v4(),
        None,
        75,
    )
    .await
    .unwrap() else {
        panic!("replay lease not acquired")
    };
    let OfflineReplayPageOutcome::Claimed(page) =
        claim_offline_replay_page(&fixture.pool, &lease, 30, BARE, FULL, None, false, 75)
            .await
            .unwrap()
    else {
        panic!("released row must be replayable")
    };
    assert_eq!(page.messages.len(), 1);
    assert_eq!(page.messages[0].id, message_id);
    assert_eq!(page.messages[0].stanza, fixture.stanza);
    assert_ne!(page.claim_token, message_id);
    fixture.drop_schema().await;
}
