use northstar_auth_postgres::users::{change_password, create_user, find_user_by_id};
use northstar_operations_postgres::admin_commands::set_admin_service_message;
use northstar_roster_application::presence::{
    PresenceService, ServiceMessageClaim, ServiceMessageRoute,
};
use northstar_stream::outbound::{OutboundItem, OutboundSender};
use northstar_workflows::account_lifecycle::set_user_status;
use northstar_workflows::presence_repository::PostgresPresenceRepository;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use uuid::Uuid;

const NOTICE: &str = "Daily notice";
const SCRAM_ITERATIONS: u32 = 4096;

struct Fixture {
    admin_pool: PgPool,
    pool: PgPool,
    schema: String,
    admin_id: Uuid,
    first: ServiceMessageRoute,
    service: PresenceService<PostgresPresenceRepository>,
}

impl Fixture {
    async fn new(kind: &str) -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("service_message_claim_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin_pool)
            .await
            .unwrap();
        let connection_schema = schema.clone();
        let pool = PgPoolOptions::new()
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
        let admin = create_user(
            &pool,
            "admin",
            "test admin password",
            true,
            true,
            SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let member = create_user(
            &pool,
            "member",
            "test member password",
            false,
            true,
            SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        assert!(set_admin_service_message(
            &pool,
            admin.id,
            admin.auth_generation,
            kind,
            Some(NOTICE),
        )
        .await
        .unwrap());
        let first = ServiceMessageRoute {
            account_id: member.id,
            auth_generation: member.auth_generation,
            connection_id: Uuid::new_v4(),
            full_jid: "member@example.test/Phone".to_owned(),
        };
        let service = PresenceService::new(PostgresPresenceRepository::new(pool.clone()));
        Self {
            admin_pool,
            pool,
            schema,
            admin_id: admin.id,
            first,
            service,
        }
    }

    fn second(&self) -> ServiceMessageRoute {
        ServiceMessageRoute {
            connection_id: Uuid::new_v4(),
            full_jid: "member@example.test/Tablet".to_owned(),
            ..self.first.clone()
        }
    }

    async fn claim(&self, route: &ServiceMessageRoute) -> ServiceMessageClaim {
        let claims = self.service.claim_service_messages(route).await.unwrap();
        assert_eq!(claims.len(), 1);
        let claim = claims.into_iter().next().unwrap();
        assert_eq!(claim.route(), route);
        assert_eq!(claim.body(), NOTICE);
        claim
    }

    async fn close(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin_pool)
        .await
        .unwrap();
        self.admin_pool.close().await;
    }
}

struct BlockedHandoff {
    queue: mpsc::Receiver<OutboundItem>,
    task: JoinHandle<bool>,
}

impl BlockedHandoff {
    async fn start(
        service: &PresenceService<PostgresPresenceRepository>,
        claim: ServiceMessageClaim,
    ) -> Self {
        let service = service.clone();
        let (sender, queue) = mpsc::channel(1);
        let sender = OutboundSender::new(sender);
        sender.try_send("occupy slot".to_owned()).unwrap();
        let (arrived, waiting) = oneshot::channel();
        let arrived = std::sync::Mutex::new(Some(arrived));
        let task = tokio::spawn(async move {
            sender
                .send_if_current(
                    claim.body().to_owned(),
                    || {
                        if let Some(arrived) = arrived.lock().unwrap().take() {
                            arrived.send(()).unwrap();
                        }
                        true
                    },
                    async { service.admit_service_message_claim(&claim).await.unwrap() },
                )
                .await
                .unwrap()
        });
        waiting.await.unwrap();
        Self { queue, task }
    }

    async fn finish(mut self, expected: bool) {
        assert_eq!(self.queue.recv().await.unwrap().stanza, "occupy slot");
        assert_eq!(self.task.await.unwrap(), expected);
        if expected {
            assert_eq!(self.queue.try_recv().unwrap().stanza, NOTICE);
        }
        assert!(self.queue.try_recv().is_err());
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn expired_service_message_claim_cannot_handoff_after_reclaim() {
    let fixture = Fixture::new("motd").await;
    let old_claim = fixture.claim(&fixture.first).await;
    let first = BlockedHandoff::start(&fixture.service, old_claim.clone()).await;
    assert_eq!(
        sqlx::query(
            "UPDATE admin_service_message_deliveries
             SET claim_expires_at=statement_timestamp()-INTERVAL '1 second'
             WHERE claim_id=$1",
        )
        .bind(old_claim.lease().claim_id)
        .execute(&fixture.pool)
        .await
        .unwrap()
        .rows_affected(),
        1
    );
    assert!(!fixture
        .service
        .admit_service_message_claim(&old_claim)
        .await
        .unwrap());
    let new_claim = fixture.claim(&fixture.second()).await;
    assert_ne!(new_claim.lease().claim_id, old_claim.lease().claim_id);
    assert_eq!(new_claim.lease().revision, old_claim.lease().revision);
    assert_eq!(
        new_claim.lease().delivery_date,
        old_claim.lease().delivery_date
    );
    BlockedHandoff::start(&fixture.service, new_claim.clone())
        .await
        .finish(true)
        .await;
    first.finish(false).await;
    assert!(!fixture
        .service
        .complete_service_message_claim(&old_claim)
        .await
        .unwrap());
    assert!(fixture
        .service
        .complete_service_message_claim(&new_claim)
        .await
        .unwrap());
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn disabled_account_cannot_handoff_service_message_claim() {
    let fixture = Fixture::new("motd").await;
    let claim = fixture.claim(&fixture.first).await;
    let handoff = BlockedHandoff::start(&fixture.service, claim.clone()).await;
    set_user_status(
        &fixture.pool,
        fixture.admin_id,
        fixture.first.account_id,
        Some(true),
        None,
    )
    .await
    .unwrap();
    let member = find_user_by_id(&fixture.pool, fixture.first.account_id)
        .await
        .unwrap()
        .unwrap();
    assert!(member.is_disabled);
    let current_generation_claim = ServiceMessageClaim::from_lease(
        ServiceMessageRoute {
            auth_generation: member.auth_generation,
            ..fixture.first.clone()
        },
        claim.lease().clone(),
    );
    assert!(!fixture
        .service
        .admit_service_message_claim(&current_generation_claim)
        .await
        .unwrap());
    handoff.finish(false).await;
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn password_change_cannot_handoff_service_message_claim() {
    let fixture = Fixture::new("motd").await;
    let claim = fixture.claim(&fixture.first).await;
    let handoff = BlockedHandoff::start(&fixture.service, claim).await;
    change_password(
        &fixture.pool,
        fixture.first.account_id,
        "replacement member password",
        SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let member = find_user_by_id(&fixture.pool, fixture.first.account_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!member.is_disabled);
    assert!(member.auth_generation > fixture.first.auth_generation);
    handoff.finish(false).await;
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn service_message_claim_handoffs_and_completes_once() {
    let fixture = Fixture::new("welcome").await;
    let claim = fixture.claim(&fixture.first).await;
    BlockedHandoff::start(&fixture.service, claim.clone())
        .await
        .finish(true)
        .await;
    assert!(fixture
        .service
        .complete_service_message_claim(&claim)
        .await
        .unwrap());
    assert!(!fixture
        .service
        .complete_service_message_claim(&claim)
        .await
        .unwrap());
    assert!(!fixture
        .service
        .admit_service_message_claim(&claim)
        .await
        .unwrap());
    assert!(fixture
        .service
        .claim_service_messages(&fixture.second())
        .await
        .unwrap()
        .is_empty());
    fixture.close().await;
}
