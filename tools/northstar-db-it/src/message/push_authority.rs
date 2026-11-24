use crate::support::blocked_backend;
use northstar_auth_postgres::users::{self, PreparedPasswordChange, User};
use northstar_message_application::push::{PushHandoffAuthority, PushRepository};
use northstar_message_core::{ActorGenerationFence, OfflineStoreOutcome, OfflineStorePolicy};
use northstar_message_postgres::offline::store_offline;
use northstar_message_postgres::push::{PushEnableOutcome, PushResponseKind, PushResponseOutcome};
use northstar_roster_postgres::roster::transition_local_presence_subscription_in_transaction;
use northstar_time::{DateTime, Duration, Utc};
use northstar_workflows::push_repository::PostgresPushRepository;
use northstar_workflows::roster::WorkflowRosterEffects;
use sqlx::postgres::PgPoolOptions;
use sqlx::{AssertSqlSafe, PgPool, Postgres, Transaction};
use std::future::Future;
use uuid::Uuid;

const SERVICE: &str = "push.example.test";
const DEVICE: &str = "device";
const PASSWORD: &str = "test-password-long-enough";

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    schema: String,
    url: String,
}

impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL").expect("set disposable TEST_DATABASE_URL");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("push_authority_{}", Uuid::new_v4().simple());
        sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        eprintln!("isolated_schema_created={schema}");
        let pool = connect(&url, &schema, None).await;
        crate::support::migrate(&pool).await.unwrap();
        Self {
            admin,
            pool,
            schema,
            url,
        }
    }

    fn repository(&self) -> PostgresPushRepository {
        PostgresPushRepository::new(self.pool.clone())
    }

    async fn user(&self, name: &str) -> User {
        users::create_user(&self.pool, name, PASSWORD, false, false, 4096, false)
            .await
            .unwrap()
    }

    async fn close(self) {
        self.pool.close().await;
        sqlx::query(AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
    }
}

async fn connect(url: &str, schema: &str, database_time: Option<DateTime<Utc>>) -> PgPool {
    let search_path = if database_time.is_some() {
        format!("{schema}, pg_catalog")
    } else {
        schema.to_owned()
    };
    PgPoolOptions::new()
        .max_connections(6)
        .after_connect(move |connection, _| {
            let search_path = search_path.clone();
            Box::pin(async move {
                sqlx::query("SELECT pg_catalog.set_config('search_path', $1, false)")
                    .bind(search_path)
                    .execute(&mut *connection)
                    .await?;
                if let Some(database_time) = database_time {
                    sqlx::query(
                        "SELECT pg_catalog.set_config('northstar.test_push_time', $1, false)",
                    )
                    .bind(database_time.to_rfc3339())
                    .execute(&mut *connection)
                    .await?;
                }
                Ok(())
            })
        })
        .connect(url)
        .await
        .unwrap()
}

fn fence(user: &User) -> ActorGenerationFence {
    ActorGenerationFence {
        account_id: user.id,
        auth_generation: user.auth_generation,
    }
}

async fn enable(
    repository: &PostgresPushRepository,
    user: &User,
    node: &str,
    options: Option<&str>,
) {
    assert_eq!(
        repository
            .enable(fence(user), SERVICE, node, options)
            .await
            .unwrap(),
        PushEnableOutcome::Enabled,
    );
}

async fn backend(transaction: &mut Transaction<'_, Postgres>) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **transaction)
        .await
        .unwrap()
}

async fn lock_push_account(transaction: &mut Transaction<'_, Postgres>, user_id: Uuid) {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 7))")
        .bind(user_id)
        .execute(&mut **transaction)
        .await
        .unwrap();
}

async fn bounded<T>(operation: impl Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(5), operation)
        .await
        .expect("Push operation did not complete after its barrier was released")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable TEST_DATABASE_URL; migrates and removes an isolated schema"]
async fn claim_counts_and_targets_share_a_snapshot() {
    let fixture = Fixture::new().await;
    let recipient = fixture.user("recipient").await;
    let requester = fixture.user("requester").await;
    let repository = fixture.repository();
    enable(&repository, &recipient, DEVICE, None).await;
    assert_eq!(
        store_offline(
            &fixture.pool,
            recipient.id,
            "requester@example.test",
            "<message id='snapshot'><body>Hello</body></message>",
            false,
            OfflineStorePolicy {
                max_messages: 10,
                max_bytes: 1024,
                ttl_days: 1,
                mam_backed: false
            },
        )
        .await
        .unwrap(),
        OfflineStoreOutcome::Stored,
    );
    let mut change = fixture.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE federated_presence_pending IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *change)
        .await
        .unwrap();
    let blocker = backend(&mut change).await;
    let user_id = recipient.id;
    let claimant = tokio::spawn(async move { repository.claim_batch(user_id).await.unwrap() });
    blocked_backend(&fixture.pool, blocker).await;

    assert_eq!(
        sqlx::query("DELETE FROM offline_messages WHERE recipient_id = $1")
            .bind(recipient.id)
            .execute(&mut *change)
            .await
            .unwrap()
            .rows_affected(),
        1,
    );
    transition_local_presence_subscription_in_transaction(
        &WorkflowRosterEffects,
        &mut change,
        requester.id,
        "requester@example.test",
        recipient.id,
        "recipient@example.test",
        "subscribe",
        "<presence type='subscribe' from='requester@example.test' to='recipient@example.test'/>",
    )
    .await
    .unwrap();
    change.commit().await.unwrap();

    let batch = bounded(claimant).await.unwrap();
    assert!(matches!(
        (batch.message_count, batch.pending_subscription_count),
        (1, 0) | (0, 1)
    ));
    assert_eq!(batch.deliveries.len(), 1);
    assert_eq!(batch.deliveries[0].node, DEVICE);
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable TEST_DATABASE_URL; migrates and removes an isolated schema"]
async fn replacement_revokes_claim_before_handoff_even_for_identical_options() {
    let fixture = Fixture::new().await;
    let user = fixture.user("recipient").await;
    let repository = fixture.repository();
    let options = Some("<x xmlns='jabber:x:data' type='submit'/>");
    enable(&repository, &user, DEVICE, options).await;
    let old = repository
        .claim_batch(user.id)
        .await
        .unwrap()
        .deliveries
        .remove(0);
    assert!(repository.validate_handoff(user.id, &old).await.unwrap());

    let (release, barrier) = tokio::sync::oneshot::channel();
    let handoff_repository = repository.clone();
    let user_id = user.id;
    let handoff = tokio::spawn(async move {
        barrier.await.unwrap();
        handoff_repository
            .validate_handoff(user_id, &old)
            .await
            .unwrap()
    });
    assert_eq!(
        repository
            .disable(fence(&user), SERVICE, Some(DEVICE))
            .await
            .unwrap(),
        Some(1)
    );
    enable(&repository, &user, DEVICE, options).await;
    let new = repository
        .claim_batch(user.id)
        .await
        .unwrap()
        .deliveries
        .remove(0);
    release.send(()).unwrap();
    assert!(!bounded(handoff).await.unwrap());
    assert!(repository.validate_handoff(user.id, &new).await.unwrap());
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable TEST_DATABASE_URL; migrates and removes an isolated schema"]
async fn owner_disable_and_response_serialize_on_the_account_before_rows() {
    let fixture = Fixture::new().await;
    let user = fixture.user("recipient").await;
    let repository = fixture.repository();
    enable(&repository, &user, DEVICE, None).await;
    let request_id = repository.claim_batch(user.id).await.unwrap().deliveries[0].request_id;

    let mut barrier = fixture.pool.begin().await.unwrap();
    lock_push_account(&mut barrier, user.id).await;
    let blocker = backend(&mut barrier).await;
    let actor = fence(&user);
    let disabler = repository.clone();
    let disable = tokio::spawn(async move {
        disabler
            .disable(actor, SERVICE, Some(DEVICE))
            .await
            .unwrap()
    });
    let disable_backend = blocked_backend(&fixture.pool, blocker).await;
    let response = tokio::spawn(async move {
        repository
            .complete_response(request_id, SERVICE, PushResponseKind::Success)
            .await
            .unwrap()
    });
    blocked_backend(&fixture.pool, disable_backend).await;
    barrier.commit().await.unwrap();

    assert_eq!(bounded(disable).await.unwrap(), Some(1));
    assert_eq!(
        bounded(response).await.unwrap(),
        PushResponseOutcome::Unknown
    );
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable TEST_DATABASE_URL; migrates and removes an isolated schema"]
async fn expired_cleanup_skips_locked_attempts_without_blocking_a_claim() {
    let fixture = Fixture::new().await;
    let expired_user = fixture.user("expired").await;
    let recipient = fixture.user("recipient").await;
    let repository = fixture.repository();
    enable(&repository, &recipient, DEVICE, None).await;
    enable(&repository, &expired_user, "locked", None).await;
    enable(&repository, &expired_user, "unlocked", None).await;
    let expired = repository
        .claim_batch(expired_user.id)
        .await
        .unwrap()
        .deliveries;
    assert_eq!(expired.len(), 2);
    sqlx::query("UPDATE push_delivery_attempts SET expires_at = now() WHERE user_id = $1")
        .bind(expired_user.id)
        .execute(&fixture.pool)
        .await
        .unwrap();
    let mut pinned = fixture.pool.begin().await.unwrap();
    sqlx::query("SELECT request_id FROM push_delivery_attempts WHERE request_id = $1 FOR UPDATE")
        .bind(expired[0].request_id)
        .execute(&mut *pinned)
        .await
        .unwrap();
    let mut barrier = fixture.pool.begin().await.unwrap();
    lock_push_account(&mut barrier, recipient.id).await;
    let blocker = backend(&mut barrier).await;
    let user_id = recipient.id;
    let claimant = tokio::spawn(async move { repository.claim_batch(user_id).await.unwrap() });
    blocked_backend(&fixture.pool, blocker).await;

    let expired_requests = || async {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT request_id FROM push_delivery_attempts WHERE user_id = $1",
        )
        .bind(expired_user.id)
        .fetch_all(&fixture.pool)
        .await
        .unwrap()
    };
    assert_eq!(expired_requests().await, [expired[0].request_id]);
    barrier.commit().await.unwrap();
    assert_eq!(bounded(claimant).await.unwrap().deliveries.len(), 1);
    pinned.commit().await.unwrap();
    fixture
        .repository()
        .claim_batch(recipient.id)
        .await
        .unwrap();
    assert!(expired_requests().await.is_empty());
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable TEST_DATABASE_URL; migrates and removes an isolated schema"]
async fn password_rotation_while_enable_waits_rejects_the_session_generation() {
    let fixture = Fixture::new().await;
    let user = fixture.user("recipient").await;
    let PreparedPasswordChange::Ready(credentials) = users::prepare_password_change(
        &user.password_hash,
        PASSWORD,
        "changed-test-password",
        4096,
        false,
    )
    .await
    .unwrap() else {
        panic!("could not prepare fixture password change");
    };
    let mut rotation = fixture.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM northstar_lock_user_rows_update(ARRAY[$1::uuid])")
        .bind(user.id)
        .execute(&mut *rotation)
        .await
        .unwrap();
    let blocker = backend(&mut rotation).await;
    let actor = fence(&user);
    let repository = fixture.repository();
    let enabling = tokio::spawn(async move {
        repository
            .enable(actor, SERVICE, DEVICE, None)
            .await
            .unwrap()
    });
    blocked_backend(&fixture.pool, blocker).await;
    assert!(users::apply_password_credentials_in_tx(
        &mut rotation,
        user.id,
        user.auth_generation,
        credentials
    )
    .await
    .unwrap());
    rotation.commit().await.unwrap();
    assert_eq!(
        bounded(enabling).await.unwrap(),
        PushEnableOutcome::AccountUnavailable
    );

    let wrote_anything: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM push_subscriptions WHERE user_id = $1)
              OR EXISTS (SELECT 1 FROM push_enable_rate_limits WHERE user_id = $1)",
    )
    .bind(user.id)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert!(!wrote_anything);
    let current = users::find_user(&fixture.pool, &user.username)
        .await
        .unwrap()
        .unwrap();
    let repository = fixture.repository();
    enable(&repository, &current, DEVICE, None).await;
    assert_eq!(
        repository
            .disable(actor, SERVICE, Some(DEVICE))
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        repository
            .claim_batch(user.id)
            .await
            .unwrap()
            .deliveries
            .len(),
        1
    );
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable TEST_DATABASE_URL; migrates and removes an isolated schema"]
async fn request_timestamps_and_expiry_follow_the_database_clock_under_skew() {
    let fixture = Fixture::new().await;
    let user = fixture.user("recipient").await;
    sqlx::query(
        "CREATE FUNCTION now() RETURNS timestamptz LANGUAGE SQL STABLE
         AS $$ SELECT current_setting('northstar.test_push_time')::timestamptz $$",
    )
    .execute(&fixture.pool)
    .await
    .unwrap();
    let skewed_time = Utc::now() - Duration::days(2);
    let pool = connect(&fixture.url, &fixture.schema, Some(skewed_time)).await;
    let repository = PostgresPushRepository::new(pool.clone());
    enable(&repository, &user, DEVICE, None).await;
    let claimed = repository
        .claim_batch(user.id)
        .await
        .unwrap()
        .deliveries
        .remove(0);
    type Timestamp = DateTime<Utc>;
    let (database_now, created, expires, next, updated, window) =
        sqlx::query_as::<_, (Timestamp, Timestamp, Timestamp, Timestamp, Timestamp, Timestamp)>(
            "SELECT now(), attempt.created_at, attempt.expires_at,
                    subscription.next_notification_at, subscription.updated_at, rate.window_started_at
               FROM push_delivery_attempts attempt
               JOIN push_subscriptions subscription USING (user_id, service_jid, node)
               JOIN push_enable_rate_limits rate USING (user_id)
              WHERE attempt.request_id = $1",
        )
        .bind(claimed.request_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        (created, updated, window),
        (database_now, database_now, database_now)
    );
    assert_eq!(next, database_now + Duration::seconds(15));
    assert_eq!(expires, database_now + Duration::seconds(300));
    assert!(repository
        .validate_handoff(user.id, &claimed)
        .await
        .unwrap());

    let expiry_pool = connect(&fixture.url, &fixture.schema, Some(expires)).await;
    let expiry_repository = PostgresPushRepository::new(expiry_pool.clone());
    assert!(!expiry_repository
        .validate_handoff(user.id, &claimed)
        .await
        .unwrap());
    assert_eq!(
        expiry_repository
            .complete_response(claimed.request_id, SERVICE, PushResponseKind::Success)
            .await
            .unwrap(),
        PushResponseOutcome::Unknown,
    );
    pool.close().await;
    expiry_pool.close().await;
    fixture.close().await;
}
