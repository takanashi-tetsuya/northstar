use super::presence_service::IsolatedDatabase;
use northstar_auth_postgres::users::create_user;
use northstar_roster_application::probe_decision::{
    BroadcastCandidate, BroadcastFacts, BroadcastQuery, PresenceRoute, ProbeCandidate,
    ProbeDecision, ProbeQuery,
};
use northstar_roster_core::{ExactPresenceRoute, PresenceAccount, RosterActor};
use northstar_roster_postgres::{
    privacy::{replace_privacy_list, set_default_privacy_list, ReplacePrivacyListOutcome},
    roster::{block_jids, decide_probe, read_broadcast_facts, unblock_jids, BlockJidsUpdate},
};
use northstar_workflows::account_lifecycle::set_user_status;
use northstar_workflows::roster::transition_local_presence_subscription;
use northstar_xep_0016::{PrivacyAction, PrivacyItem, PrivacyList};
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "example.test";
const OWNER: &str = "alice@example.test";
const OWNER_FULL: &str = "alice@example.test/Phone";
const SIBLING: &str = "alice@example.test/Laptop";
const SUBSCRIBER: &str = "bob@example.test";
const SUBSCRIBER_FULL: &str = "bob@example.test/Tablet";

struct Fixture {
    database: IsolatedDatabase,
    owner: PresenceAccount,
    subscriber: PresenceAccount,
    actor: RosterActor,
    owner_route: ProbeCandidate,
    subscriber_route: PresenceRoute,
}

impl Fixture {
    async fn new(label: &str) -> Self {
        let database = IsolatedDatabase::create(label).await;
        let owner = user(&database.pool, "alice").await;
        let subscriber = user(&database.pool, "bob").await;
        let owner_route = ProbeCandidate {
            route: route(&owner, OWNER_FULL),
            available: true,
            directed: false,
        };
        let subscriber_route = route(&subscriber, SUBSCRIBER_FULL);
        let actor = RosterActor {
            account_id: owner.id,
            auth_generation: owner.auth_generation,
            connection_id: owner_route.route.exact.connection_id,
            full_jid: OWNER_FULL.to_owned(),
        };
        Self {
            database,
            owner,
            subscriber,
            actor,
            owner_route,
            subscriber_route,
        }
    }

    async fn subscribe(&self) {
        self.transition(
            &self.subscriber,
            SUBSCRIBER,
            &self.owner,
            OWNER,
            "subscribe",
        )
        .await;
        self.transition(
            &self.owner,
            OWNER,
            &self.subscriber,
            SUBSCRIBER,
            "subscribed",
        )
        .await;
    }

    async fn cancel(&self) {
        self.transition(
            &self.owner,
            OWNER,
            &self.subscriber,
            SUBSCRIBER,
            "unsubscribed",
        )
        .await;
    }

    async fn transition(
        &self,
        actor: &PresenceAccount,
        from: &str,
        target: &PresenceAccount,
        to: &str,
        kind: &str,
    ) {
        let stanza = format!("<presence from='{from}' to='{to}' type='{kind}'/>");
        assert!(transition_local_presence_subscription(
            &self.database.pool,
            actor.id,
            from,
            target.id,
            to,
            kind,
            &stanza,
        )
        .await
        .unwrap()
        .is_some());
    }

    fn broadcast_candidate(&self) -> BroadcastCandidate {
        BroadcastCandidate {
            jid: SUBSCRIBER.to_owned(),
            account: Some(self.subscriber.clone()),
            routes: vec![self.subscriber_route.clone()],
        }
    }

    async fn broadcast(&self) -> Vec<BroadcastFacts> {
        broadcast(&self.database.pool, &self.actor, self.broadcast_candidate()).await
    }

    async fn probe(&self, candidates: &[ProbeCandidate], explicit: bool) -> ProbeDecision {
        decide_probe(
            &self.database.pool,
            ProbeQuery {
                owner: &self.owner,
                target: OWNER_FULL,
                requester: SUBSCRIBER_FULL,
                candidates,
                recipients: std::slice::from_ref(&self.subscriber_route),
                explicit,
            },
        )
        .await
        .unwrap()
    }
}

async fn user(pool: &PgPool, name: &str) -> PresenceAccount {
    let user = create_user(
        pool,
        name,
        "Initial password for test!42",
        false,
        true,
        4096,
        false,
    )
    .await
    .unwrap();
    PresenceAccount {
        id: user.id,
        username: user.username.clone(),
        auth_generation: user.auth_generation,
    }
}

fn route(account: &PresenceAccount, jid: &str) -> PresenceRoute {
    PresenceRoute {
        exact: ExactPresenceRoute {
            account_id: account.id,
            auth_generation: account.auth_generation,
            connection_id: Uuid::new_v4(),
            full_jid: jid.to_owned(),
            node_id: None,
        },
        active_list: None,
    }
}

async fn broadcast(
    pool: &PgPool,
    actor: &RosterActor,
    candidate: BroadcastCandidate,
) -> Vec<BroadcastFacts> {
    read_broadcast_facts(
        pool,
        BroadcastQuery {
            actor,
            expects_active: false,
            local_domain: DOMAIN,
            candidates: &[candidate],
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn broadcast_policy_swap_with_no_allowed_snapshot_never_leaks() {
    let fixture = Fixture::new("presence_policy_swap").await;
    fixture.subscribe().await;
    let pool = &fixture.database.pool;
    let owner_id = fixture.owner.id;
    assert_eq!(
        replace_privacy_list(
            pool,
            owner_id,
            &PrivacyList {
                name: "swap".to_owned(),
                items: vec![PrivacyItem {
                    order: 1,
                    action: PrivacyAction::Deny,
                    match_type: None,
                    match_value: None,
                    message: false,
                    iq: false,
                    presence_in: false,
                    presence_out: true,
                }],
            }
        )
        .await
        .unwrap(),
        ReplacePrivacyListOutcome::Stored
    );
    assert!(set_default_privacy_list(pool, owner_id, Some("swap"))
        .await
        .unwrap());
    assert!(fixture.broadcast().await.is_empty());

    let mut writer = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE privacy_list_items IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *writer)
        .await
        .unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    let reader = pool.clone();
    let actor = fixture.actor.clone();
    let candidate = fixture.broadcast_candidate();
    let read = tokio::spawn(async move { broadcast(&reader, &actor, candidate).await });
    let waiter = crate::support::blocked_backend(pool, blocker).await;
    let reads_policy_together: bool = sqlx::query_scalar(
        "SELECT backend_xmin IS NOT NULL AND position('blocked_jids' IN query)>0
           FROM pg_stat_activity WHERE pid=$1",
    )
    .bind(waiter)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(reads_policy_together);

    sqlx::query("INSERT INTO blocked_jids(owner_id, blocked_jid) VALUES($1,$2)")
        .bind(owner_id)
        .bind(SUBSCRIBER)
        .execute(&mut *writer)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query(
            "UPDATE privacy_list_items SET action='allow' WHERE owner_id=$1 AND list_name='swap'",
        )
        .bind(owner_id)
        .execute(&mut *writer)
        .await
        .unwrap()
        .rows_affected(),
        1
    );
    writer.commit().await.unwrap();

    assert!(read.await.unwrap().is_empty());
    assert!(fixture.broadcast().await.is_empty());
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn broadcast_uses_current_direction_and_enabled_account_incarnation() {
    let fixture = Fixture::new("audience_incarnation").await;
    fixture.subscribe().await;
    let initial = fixture.broadcast().await;
    assert_eq!(initial.len(), 1);
    assert_eq!(
        initial[0].recipients,
        std::slice::from_ref(&fixture.subscriber_route)
    );
    fixture.cancel().await;
    assert!(fixture
        .broadcast()
        .await
        .iter()
        .all(|fact| fact.recipients.is_empty()));
    fixture.subscribe().await;
    assert_eq!(fixture.broadcast().await[0].recipients.len(), 1);
    set_user_status(
        &fixture.database.pool,
        fixture.owner.id,
        fixture.subscriber.id,
        Some(true),
        None,
    )
    .await
    .unwrap();
    assert!(fixture.broadcast().await.is_empty());
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(fixture.subscriber.id)
        .execute(&fixture.database.pool)
        .await
        .unwrap();
    let replacement = user(&fixture.database.pool, "bob").await;
    assert_ne!(replacement.id, fixture.subscriber.id);
    assert!(fixture.broadcast().await.is_empty());
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn replay_checks_grant_again_after_recipient_capture() {
    let fixture = Fixture::new("approval_revoke").await;
    fixture.subscribe().await;
    let candidates = [fixture.owner_route.clone()];
    assert!(matches!(
        fixture.probe(&candidates, false).await,
        ProbeDecision::Available(_)
    ));
    let (resume, paused) = tokio::sync::oneshot::channel();
    let pool = fixture.database.pool.clone();
    let owner = fixture.owner.clone();
    let recipient = fixture.subscriber_route.clone();
    let replay = tokio::spawn(async move {
        paused.await.unwrap();
        decide_probe(
            &pool,
            ProbeQuery {
                owner: &owner,
                target: OWNER,
                requester: SUBSCRIBER,
                candidates: &candidates,
                recipients: &[recipient],
                explicit: false,
            },
        )
        .await
        .unwrap()
    });
    fixture.cancel().await;
    resume.send(()).unwrap();
    assert_eq!(replay.await.unwrap(), ProbeDecision::Silent);
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn probe_honors_exact_directed_authority_and_bilateral_blocks() {
    let fixture = Fixture::new("probe_directed").await;
    let mut owner = fixture.owner_route.clone();
    owner.directed = true;
    let sibling = ProbeCandidate {
        route: route(&fixture.owner, SIBLING),
        ..owner.clone()
    };
    assert_eq!(
        fixture.probe(&[sibling, owner.clone()], true).await,
        ProbeDecision::Available(vec![
            northstar_roster_application::probe_decision::ProbeDelivery {
                owner: 1,
                recipient: Some(0),
                directed: true,
            },
        ])
    );
    let pool = &fixture.database.pool;
    assert!(matches!(
        block_jids(pool, fixture.subscriber.id, &[OWNER_FULL.to_owned()])
            .await
            .unwrap(),
        BlockJidsUpdate::Changed(_)
    ));
    assert_eq!(
        fixture.probe(std::slice::from_ref(&owner), true).await,
        ProbeDecision::Silent
    );
    unblock_jids(pool, fixture.subscriber.id, None)
        .await
        .unwrap();
    assert!(matches!(
        block_jids(pool, fixture.owner.id, &[SUBSCRIBER_FULL.to_owned()])
            .await
            .unwrap(),
        BlockJidsUpdate::Changed(_)
    ));
    assert_eq!(fixture.probe(&[owner], true).await, ProbeDecision::Silent);
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn a_same_name_recreated_owner_cannot_supply_a_captured_probe() {
    let fixture = Fixture::new("probe_recreation").await;
    fixture.subscribe().await;
    assert!(matches!(
        fixture
            .probe(std::slice::from_ref(&fixture.owner_route), true)
            .await,
        ProbeDecision::Available(_)
    ));
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(fixture.owner.id)
        .execute(&fixture.database.pool)
        .await
        .unwrap();
    let replacement = user(&fixture.database.pool, "alice").await;
    assert_ne!(replacement.id, fixture.owner.id);
    let candidate = ProbeCandidate {
        route: route(&replacement, OWNER_FULL),
        available: true,
        directed: true,
    };
    assert_eq!(
        fixture.probe(&[candidate], true).await,
        ProbeDecision::Silent
    );
    fixture.database.finish().await;
}
