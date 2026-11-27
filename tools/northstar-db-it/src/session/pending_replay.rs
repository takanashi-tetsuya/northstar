use northstar_roster_application::presence::{
    LocalSubscriptionRequest, PresenceMutation, PresenceRepository,
};
use northstar_roster_application::subscription_retry::{
    SubscriptionRetryAdmission, SubscriptionRetryRepository, SubscriptionRetryRequest,
    SubscriptionRetryTarget,
};
use northstar_roster_core::{PresenceAccount, RosterActor};
use northstar_roster_postgres::{privacy, roster};
use northstar_session_application::replay::{
    pending_presence::PendingPresenceAuthority, PendingPresenceReplay, ReplayRoute, ReplayService,
};
use northstar_session_postgres::replay_repository::PostgresReplayRepository;
use northstar_stream::local_routes::{
    pending_subscription::deliver_pending_subscription, session::test_online_session,
};
use northstar_workflows::{
    presence_repository::PostgresPresenceRepository, roster::WorkflowRosterEffects,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::atomic::Ordering;
use uuid::Uuid;

const DOMAIN: &str = "local.test";
const REQUEST: &str = "<presence xmlns='jabber:client' from='alice@local.test' to='bob@local.test' type='subscribe'/>";
const REMOTE_CONTACT: &str = "peer@remote.test";
const RETRY: &str = "<presence xmlns='jabber:client' from='alice@local.test' to='peer@remote.test' type='subscribe'/>";
const CANCEL: &str = "<presence xmlns='jabber:client' from='alice@local.test' to='peer@remote.test' type='unsubscribe'/>";

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    schema: String,
    service: ReplayService<PostgresReplayRepository>,
    presence: PostgresPresenceRepository,
}

impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("pending_replay_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        eprintln!("isolated_schema_created={schema}");
        let connection_schema = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(8)
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
        let service = ReplayService::new(PostgresReplayRepository::new(pool.clone()), DOMAIN, 30);
        let presence = PostgresPresenceRepository::new(pool.clone());
        Self {
            admin,
            pool,
            schema,
            service,
            presence,
        }
    }

    async fn user(&self, name: &str) -> RosterActor {
        let account_id = Uuid::new_v4();
        let auth_generation = sqlx::query_scalar(
            "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')
             RETURNING auth_generation",
        )
        .bind(account_id)
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .unwrap();
        RosterActor {
            account_id,
            auth_generation,
            connection_id: Uuid::new_v4(),
            full_jid: format!("{name}@{DOMAIN}/phone"),
        }
    }

    async fn local_transition(&self, actor: &RosterActor, kind: &str, stanza: &str) {
        let (target_id, target_generation): (Uuid, i64) =
            sqlx::query_as("SELECT id,auth_generation FROM users WHERE username='bob'")
                .fetch_one(&self.pool)
                .await
                .unwrap();
        let target = PresenceAccount {
            id: target_id,
            username: "bob".into(),
            auth_generation: target_generation,
        };
        let outcome = self
            .presence
            .transition_local(LocalSubscriptionRequest {
                actor_id: actor.account_id,
                expected_auth_generation: actor.auth_generation,
                connection_id: actor.connection_id,
                local_domain: DOMAIN,
                target_username: "bob",
                kind,
                stanza,
                expected_target: &target,
            })
            .await
            .unwrap();
        assert!(matches!(outcome, PresenceMutation::Transition(_)));
    }

    async fn pending(&self, route: &ReplayRoute, expects_active: bool) -> PendingPresenceReplay {
        let authority = PendingPresenceAuthority {
            route,
            expects_active,
        };
        let mut page = self
            .service
            .pending_presence_page(authority, None)
            .await
            .unwrap();
        assert!(page.complete);
        assert_eq!(page.items.len(), 1);
        let pending = page.items.pop().unwrap();
        assert!(self
            .service
            .pending_presence_is_current(authority, &pending)
            .await
            .unwrap());
        pending
    }

    async fn close(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
        self.admin.close().await;
    }
}

fn route(actor: RosterActor) -> ReplayRoute {
    ReplayRoute {
        recipient_id: actor.account_id,
        auth_generation: actor.auth_generation,
        connection_id: actor.connection_id,
        full_jid: actor.full_jid,
    }
}

fn list(action: privacy::PrivacyAction) -> privacy::PrivacyList {
    privacy::PrivacyList {
        name: "selected".to_owned(),
        items: vec![privacy::PrivacyItem {
            order: 1,
            action,
            match_type: None,
            match_value: None,
            message: false,
            iq: false,
            presence_in: true,
            presence_out: false,
        }],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn pending_handoff_rechecks_cancellation_and_accepts_the_new_request() {
    let fixture = Fixture::new().await;
    let alice = fixture.user("alice").await;
    let route = route(fixture.user("bob").await);
    let authority = PendingPresenceAuthority {
        route: &route,
        expects_active: false,
    };
    fixture.local_transition(&alice, "subscribe", REQUEST).await;
    let old = fixture.pending(&route, false).await;
    let (resource, mut queue) = test_online_session(
        route.recipient_id,
        route.auth_generation,
        route.connection_id,
        "phone",
        2,
    );
    resource.available.store(true, Ordering::Release);
    assert!(deliver_pending_subscription(
        &resource,
        0,
        (&old.cursor).into(),
        || {
            resource
                .sender
                .try_send(old.stanza.clone().unwrap())
                .is_ok()
        }
    ));
    fixture
        .local_transition(&alice, "unsubscribe", REQUEST)
        .await;
    assert!(!fixture
        .service
        .pending_presence_is_current(authority, &old)
        .await
        .unwrap());
    fixture.local_transition(&alice, "subscribe", REQUEST).await;
    let new = fixture.pending(&route, false).await;
    assert_ne!(new.cursor, old.cursor);
    assert!(!fixture
        .service
        .pending_presence_is_current(authority, &old)
        .await
        .unwrap());
    assert!(fixture
        .service
        .pending_presence_is_current(authority, &new)
        .await
        .unwrap());
    assert!(deliver_pending_subscription(
        &resource,
        0,
        (&new.cursor).into(),
        || { resource.sender.try_send(new.stanza.unwrap()).is_ok() }
    ));
    assert_eq!(queue.try_recv().unwrap().stanza, REQUEST);
    assert_eq!(queue.try_recv().unwrap().stanza, REQUEST);
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn pending_handoff_rechecks_block_and_stored_stanza_edit() {
    let fixture = Fixture::new().await;
    let alice = fixture.user("alice").await;
    let route = route(fixture.user("bob").await);
    let authority = PendingPresenceAuthority {
        route: &route,
        expects_active: false,
    };
    fixture.local_transition(&alice, "subscribe", REQUEST).await;
    let old = fixture.pending(&route, false).await;
    let edited = REQUEST.replace("/>", " id='edited'/>");
    sqlx::query(
        "UPDATE pending_presence_subscriptions SET stanza=$3 WHERE requester_id=$1 AND recipient_id=$2",
    ).bind(alice.account_id).bind(route.recipient_id).bind(&edited)
        .execute(&fixture.pool).await.unwrap();
    assert!(!fixture
        .service
        .pending_presence_is_current(authority, &old)
        .await
        .unwrap());
    let new = fixture.pending(&route, false).await;
    assert_eq!(old.cursor, new.cursor);
    assert_eq!(new.stanza.as_deref(), Some(edited.as_str()));
    roster::block_jids(
        &fixture.pool,
        route.recipient_id,
        &["local.test/phone".to_owned()],
    )
    .await
    .unwrap();
    assert!(fixture
        .service
        .pending_presence_is_current(authority, &new)
        .await
        .unwrap());
    roster::block_jids(
        &fixture.pool,
        route.recipient_id,
        &[alice.bare_jid().to_owned()],
    )
    .await
    .unwrap();
    assert!(!fixture
        .service
        .pending_presence_is_current(authority, &new)
        .await
        .unwrap());
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn pending_handoff_rechecks_requester_disablement_and_recreation() {
    let fixture = Fixture::new().await;
    let alice = fixture.user("alice").await;
    let route = route(fixture.user("bob").await);
    let authority = PendingPresenceAuthority {
        route: &route,
        expects_active: false,
    };
    fixture.local_transition(&alice, "subscribe", REQUEST).await;
    let old = fixture.pending(&route, false).await;
    sqlx::query("UPDATE users SET is_disabled=TRUE,auth_generation=auth_generation+1 WHERE id=$1")
        .bind(alice.account_id)
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert!(!fixture
        .service
        .pending_presence_is_current(authority, &old)
        .await
        .unwrap());
    assert!(fixture
        .service
        .pending_presence_page(authority, None)
        .await
        .unwrap()
        .items
        .is_empty());
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(alice.account_id)
        .execute(&fixture.pool)
        .await
        .unwrap();
    let replacement = fixture.user("alice").await;
    fixture
        .local_transition(&replacement, "subscribe", REQUEST)
        .await;
    let new = fixture.pending(&route, false).await;
    assert_eq!(old.requester, new.requester);
    assert_ne!(old.cursor.key, new.cursor.key);
    assert!(!fixture
        .service
        .pending_presence_is_current(authority, &old)
        .await
        .unwrap());
    let stale = ReplayRoute {
        auth_generation: route.auth_generation + 1,
        ..route.clone()
    };
    assert!(!fixture
        .service
        .pending_presence_is_current(
            PendingPresenceAuthority {
                route: &stale,
                expects_active: false
            },
            &new,
        )
        .await
        .unwrap());
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn pending_handoff_rechecks_selector_expiry_missing_lease_and_same_name_edit() {
    let fixture = Fixture::new().await;
    let alice = fixture.user("alice").await;
    let route = route(fixture.user("bob").await);
    let authority = PendingPresenceAuthority {
        route: &route,
        expects_active: true,
    };
    fixture.local_transition(&alice, "subscribe", REQUEST).await;
    let allow = list(privacy::PrivacyAction::Allow);
    let deny = list(privacy::PrivacyAction::Deny);
    let mut default = deny.clone();
    default.name = "default-deny".to_owned();
    privacy::replace_privacy_list(&fixture.pool, route.recipient_id, &allow)
        .await
        .unwrap();
    privacy::replace_privacy_list(&fixture.pool, route.recipient_id, &default)
        .await
        .unwrap();
    assert!(privacy::set_default_privacy_list(
        &fixture.pool,
        route.recipient_id,
        Some(&default.name)
    )
    .await
    .unwrap());
    let without_hint = PendingPresenceAuthority {
        expects_active: false,
        ..authority
    };
    assert!(fixture
        .service
        .pending_presence_page(without_hint, None)
        .await
        .unwrap()
        .items
        .is_empty());
    assert!(privacy::set_active_privacy_list(
        &fixture.pool,
        route.recipient_id,
        route.connection_id,
        Some(&allow.name),
    )
    .await
    .unwrap());
    fixture.pending(&route, false).await;
    let request = fixture.pending(&route, true).await;
    privacy::replace_privacy_list(&fixture.pool, route.recipient_id, &deny)
        .await
        .unwrap();
    assert!(!fixture
        .service
        .pending_presence_is_current(authority, &request)
        .await
        .unwrap());
    privacy::replace_privacy_list(&fixture.pool, route.recipient_id, &allow)
        .await
        .unwrap();
    let request = fixture.pending(&route, true).await;
    let expired = sqlx::query_scalar::<_, northstar_time::DateTime<northstar_time::Utc>>(
        "UPDATE privacy_active_sessions
            SET expires_at=NOW()-INTERVAL '1 second', updated_at=NOW()-INTERVAL '2 days'
          WHERE owner_id=$1 AND connection_id=$2 RETURNING expires_at",
    )
    .bind(route.recipient_id)
    .bind(route.connection_id)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert!(!fixture
        .service
        .pending_presence_is_current(authority, &request)
        .await
        .unwrap());
    assert!(fixture
        .service
        .pending_presence_page(without_hint, None)
        .await
        .unwrap()
        .items
        .is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, northstar_time::DateTime<northstar_time::Utc>>(
            "SELECT expires_at FROM privacy_active_sessions WHERE owner_id=$1 AND connection_id=$2",
        )
        .bind(route.recipient_id)
        .bind(route.connection_id)
        .fetch_one(&fixture.pool)
        .await
        .unwrap(),
        expired
    );
    privacy::clear_active_privacy_session(&fixture.pool, route.recipient_id, route.connection_id)
        .await
        .unwrap();
    assert!(!fixture
        .service
        .pending_presence_is_current(authority, &request)
        .await
        .unwrap());
    assert!(!fixture
        .service
        .pending_presence_is_current(without_hint, &request)
        .await
        .unwrap());
    assert!(
        privacy::set_default_privacy_list(&fixture.pool, route.recipient_id, None)
            .await
            .unwrap()
    );
    assert!(fixture
        .service
        .pending_presence_is_current(without_hint, &request)
        .await
        .unwrap());
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn retry_serializes_with_cancel_and_approval_and_preserves_outbox_order() {
    let fixture = Fixture::new().await;
    let alice = fixture.user("alice").await;
    let policy = northstar_federation_core::S2sOutboxPolicy::new(300, 100, 1_048_576, 100);
    let request = SubscriptionRetryRequest {
        actor: &alice,
        contact: REMOTE_CONTACT,
        expects_active: false,
        target: SubscriptionRetryTarget::Federated { policy },
    };
    for cancel in [true, false] {
        let initial = fixture
            .presence
            .transition_remote_with_outbox(
                alice.account_id,
                alice.auth_generation,
                alice.connection_id,
                DOMAIN,
                REMOTE_CONTACT,
                "subscribe",
                "remote.test",
                RETRY,
                Some(alice.bare_jid()),
                policy,
            )
            .await
            .unwrap();
        assert!(matches!(initial, PresenceMutation::Transition(_)));
        let observed = fixture
            .presence
            .pending_retry_identity(request)
            .await
            .unwrap()
            .unwrap();
        if cancel {
            assert_eq!(
                fixture
                    .presence
                    .retry_outbound_subscription(request, observed, RETRY)
                    .await
                    .unwrap(),
                SubscriptionRetryAdmission::FederatedQueued,
            );
        }
        let mut transition = fixture.pool.begin().await.unwrap();
        let blocker = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *transition)
            .await
            .unwrap();
        sqlx::query("SELECT id FROM northstar_lock_user_rows_update(ARRAY[$1::uuid])")
            .bind(alice.account_id)
            .execute(&mut *transition)
            .await
            .unwrap();
        let repository = fixture.presence.clone();
        let actor = alice.clone();
        let waiting = tokio::spawn(async move {
            let request = SubscriptionRetryRequest {
                actor: &actor,
                contact: REMOTE_CONTACT,
                expects_active: false,
                target: SubscriptionRetryTarget::Federated { policy },
            };
            repository
                .retry_outbound_subscription(request, observed, RETRY)
                .await
                .unwrap()
        });
        crate::support::blocked_backend(&fixture.pool, blocker).await;
        if cancel {
            roster::transition_remote_presence_subscription_in_transaction(
                &WorkflowRosterEffects,
                &mut transition,
                alice.account_id,
                REMOTE_CONTACT,
                "unsubscribe",
                Some(("remote.test", CANCEL, Some(alice.bare_jid()), policy)),
            )
            .await
            .unwrap()
            .unwrap();
        } else {
            roster::update_subscription_in_transaction(
                &WorkflowRosterEffects,
                &mut transition,
                alice.account_id,
                REMOTE_CONTACT,
                "to",
                None,
                None,
            )
            .await
            .unwrap();
        }
        transition.commit().await.unwrap();
        assert_eq!(waiting.await.unwrap(), SubscriptionRetryAdmission::Stale);
    }
    let queued = sqlx::query_scalar::<_, String>(
        "SELECT stanza FROM s2s_outbox WHERE target_domain='remote.test' ORDER BY enqueue_sequence",
    )
    .fetch_all(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(queued, [RETRY, RETRY, CANCEL, RETRY]);
    fixture.close().await;
}
