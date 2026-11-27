use super::presence_service::IsolatedDatabase;
use northstar_auth_postgres::users::{create_user, User};
use northstar_roster_application::{
    blocking_mutation::{
        BlockingMutation, BlockingMutationOutcome, BlockingRouteCandidate, CommittedBlockingChange,
    },
    blocking_mutation_repository::BlockingMutationRepository,
    CommunicationDecision, ExactPresenceRoute, RosterActor,
};
use northstar_roster_postgres::{
    privacy::{read_communication_policies, replace_privacy_list, set_active_privacy_list},
    roster::{
        begin_authorized_roster_mutation, block_jids, blocked_jid_matches, blocked_jids,
        is_blocked, update_subscription_in_transaction, PostgresBlockingRepository,
        MAX_BLOCKED_JIDS_PER_ACCOUNT,
    },
};
use northstar_workflows::roster::WorkflowRosterEffects;
use northstar_xep_0016::{PrivacyAction, PrivacyItem, PrivacyList, PrivacyStanzaKind};
use northstar_xmpp_types::jid::CanonicalJid;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

const BARE: &str = "bob@example.test";
const FULL: &str = "bob@example.test/Phone";
const SOURCE: &str = "alice@example.test/Desktop";

struct Fixture {
    db: IsolatedDatabase,
    actor: RosterActor,
    bob: User,
    routes: Vec<BlockingRouteCandidate>,
    repository: PostgresBlockingRepository,
}

impl Fixture {
    async fn new() -> Self {
        let db = IsolatedDatabase::create("blocking_presence").await;
        let alice = user(&db.pool, "alice").await;
        let bob = user(&db.pool, "bob").await;
        let source = route(&alice, SOURCE);
        let actor = RosterActor {
            account_id: alice.id,
            auth_generation: alice.auth_generation,
            connection_id: source.route.connection_id,
            full_jid: SOURCE.into(),
        };
        let routes = vec![source, route(&bob, FULL)];
        let repository = PostgresBlockingRepository::new(db.pool.clone());
        Self {
            db,
            actor,
            bob,
            routes,
            repository,
        }
    }

    async fn lock_owner(&self) -> Transaction<'_, Postgres> {
        begin_authorized_roster_mutation(
            &self.db.pool,
            self.actor.account_id,
            self.actor.auth_generation,
        )
        .await
        .unwrap()
        .unwrap()
    }

    async fn subscribe(&self) {
        let mut transaction = self.lock_owner().await;
        grant(&mut transaction, self.actor.account_id).await;
        transaction.commit().await.unwrap();
    }

    async fn apply(&self, mutation: BlockingMutation) -> CommittedBlockingChange {
        committed(
            self.repository
                .apply_blocking(self.actor.clone(), mutation, &self.routes)
                .await
                .unwrap(),
        )
    }
}

async fn user(pool: &PgPool, username: &str) -> User {
    create_user(
        pool,
        username,
        "Initial password for test!42",
        false,
        true,
        4096,
        false,
    )
    .await
    .unwrap()
}

async fn grant(transaction: &mut Transaction<'_, Postgres>, owner: Uuid) {
    update_subscription_in_transaction(
        &WorkflowRosterEffects,
        transaction,
        owner,
        BARE,
        "from",
        None,
        None,
    )
    .await
    .unwrap();
}

fn route(user: &User, full_jid: &str) -> BlockingRouteCandidate {
    BlockingRouteCandidate {
        route: ExactPresenceRoute {
            account_id: user.id,
            auth_generation: user.auth_generation,
            connection_id: Uuid::new_v4(),
            full_jid: full_jid.into(),
            node_id: None,
        },
        available: true,
        expects_active: false,
        directed: Vec::new(),
    }
}

fn jid(jid: &str) -> CanonicalJid {
    CanonicalJid::parse(jid).unwrap()
}

fn committed(outcome: BlockingMutationOutcome) -> CommittedBlockingChange {
    match outcome {
        BlockingMutationOutcome::Committed(change) => change,
        other => panic!("expected a commit, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn subscription_update_while_block_waits_is_in_the_committed_audience() {
    let fixture = Fixture::new().await;
    let mut subscription = fixture.lock_owner().await;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *subscription)
        .await
        .unwrap();
    let repository = fixture.repository.clone();
    let actor = fixture.actor.clone();
    let routes = fixture.routes.clone();
    let operation = tokio::spawn(async move {
        repository
            .apply_blocking(actor, BlockingMutation::Block(vec![jid(BARE)]), &routes)
            .await
    });
    crate::support::blocked_backend(&fixture.db.pool, pid).await;
    grant(&mut subscription, fixture.actor.account_id).await;
    subscription.commit().await.unwrap();

    let change = committed(operation.await.unwrap().unwrap());
    assert_eq!(change.delta, vec![BARE]);
    assert_eq!(change.contacts.len(), 1);
    let contact = &change.contacts[0];
    assert!(!contact.covered_before && contact.covered_after && contact.other_policy_allows);
    assert_eq!(
        contact.route.recipient.as_ref(),
        Some(&fixture.routes[1].route)
    );
    fixture.db.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn empty_delta_skips_roster_lock_and_stale_actor_is_unavailable() {
    let fixture = Fixture::new().await;
    fixture
        .apply(BlockingMutation::Block(vec![jid(BARE)]))
        .await;

    let mut blocker = fixture.db.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE roster_items IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let no_op = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.apply(BlockingMutation::Block(vec![jid(BARE)])),
    )
    .await
    .expect("no-op must complete while the roster is inaccessible");
    assert!(no_op.delta.is_empty() && no_op.contacts.is_empty());
    blocker.rollback().await.unwrap();

    let mut stale = fixture.actor.clone();
    stale.auth_generation += 1;
    assert_eq!(
        fixture
            .repository
            .apply_blocking(stale, BlockingMutation::UnblockAll, &fixture.routes)
            .await
            .unwrap(),
        BlockingMutationOutcome::Unavailable,
    );
    assert_eq!(
        blocked_jids(&fixture.db.pool, fixture.actor.account_id)
            .await
            .unwrap(),
        vec![BARE]
    );
    fixture.db.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn quota_refusal_rolls_back_the_actual_delta() {
    let fixture = Fixture::new().await;
    let patterns = (0..MAX_BLOCKED_JIDS_PER_ACCOUNT)
        .map(|index| format!("user{index}@example.test"))
        .collect::<Vec<_>>();
    block_jids(&fixture.db.pool, fixture.actor.account_id, &patterns)
        .await
        .unwrap();
    let before = blocked_jids(&fixture.db.pool, fixture.actor.account_id)
        .await
        .unwrap();
    let result = fixture
        .repository
        .apply_blocking(
            fixture.actor.clone(),
            BlockingMutation::Block(vec![jid(&patterns[0]), jid(BARE)]),
            &fixture.routes,
        )
        .await
        .unwrap();
    assert_eq!(result, BlockingMutationOutcome::QuotaExceeded);
    assert_eq!(
        blocked_jids(&fixture.db.pool, fixture.actor.account_id)
            .await
            .unwrap(),
        before
    );
    fixture.db.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn residual_and_reverse_blocks_and_reblock_keep_presence_hidden() {
    let fixture = Fixture::new().await;
    fixture.subscribe().await;
    fixture
        .apply(BlockingMutation::Block(vec![jid(BARE), jid(FULL)]))
        .await;
    let residual = fixture
        .apply(BlockingMutation::Unblock(vec![jid(FULL)]))
        .await;
    assert!(residual.contacts[0].covered_before && residual.contacts[0].covered_after);

    block_jids(&fixture.db.pool, fixture.bob.id, &[SOURCE.into()])
        .await
        .unwrap();
    let reverse = fixture.apply(BlockingMutation::UnblockAll).await;
    assert!(reverse.contacts[0].covered_before && !reverse.contacts[0].covered_after);
    assert!(!reverse.contacts[0].other_policy_allows);
    northstar_roster_postgres::roster::unblock_jids(&fixture.db.pool, fixture.bob.id, None)
        .await
        .unwrap();

    fixture
        .apply(BlockingMutation::Block(vec![jid(BARE)]))
        .await;
    let restore = fixture.apply(BlockingMutation::UnblockAll).await;
    let contact = &restore.contacts[0];
    assert!(contact.covered_before && !contact.covered_after && contact.other_policy_allows);
    fixture
        .apply(BlockingMutation::Block(vec![jid(BARE)]))
        .await;
    let policies = contact
        .route
        .policies(true)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(
        read_communication_policies(&fixture.db.pool, &policies)
            .await
            .unwrap(),
        vec![
            CommunicationDecision::OwnerBlocks,
            CommunicationDecision::Allow
        ],
    );
    fixture.db.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn commit_uses_only_the_supplied_route_incarnations() {
    let mut fixture = Fixture::new().await;
    fixture.subscribe().await;
    let captured = fixture.routes[1].route.clone();
    let rebound = route(&fixture.bob, FULL);
    let block = fixture
        .apply(BlockingMutation::Block(vec![jid(BARE)]))
        .await;
    assert_eq!(block.contacts[0].route.recipient.as_ref(), Some(&captured));
    assert_ne!(
        block.contacts[0].route.recipient.as_ref(),
        Some(&rebound.route)
    );

    fixture.routes.truncate(1);
    let unblock = fixture.apply(BlockingMutation::UnblockAll).await;
    assert_eq!(unblock.delta, vec![BARE]);
    assert!(unblock.contacts.is_empty());

    fixture.routes.push(rebound.clone());
    let block = fixture
        .apply(BlockingMutation::Block(vec![jid(BARE)]))
        .await;
    assert_eq!(
        block.contacts[0].route.recipient.as_ref(),
        Some(&rebound.route)
    );
    fixture.db.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn strict_indexed_matching_agrees_with_scalar_patterns() {
    let fixture = Fixture::new().await;
    let keys = [
        "example.test",
        "example.test/Phone",
        BARE,
        FULL,
        "other.test/Phone",
    ];
    for pattern in keys {
        fixture
            .apply(BlockingMutation::Block(vec![jid(pattern)]))
            .await;
        for candidate in keys {
            assert_eq!(
                is_blocked(&fixture.db.pool, fixture.actor.account_id, candidate)
                    .await
                    .unwrap(),
                blocked_jid_matches(pattern, candidate),
                "{pattern} -> {candidate}",
            );
        }
        fixture.apply(BlockingMutation::UnblockAll).await;
    }
    fixture.db.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn commit_samples_inbound_and_outbound_privacy_per_resource() {
    let mut fixture = Fixture::new().await;
    fixture.subscribe().await;
    let mut masked_source = fixture.routes[0].clone();
    masked_source.route.full_jid = "alice@example.test/Laptop".into();
    masked_source.route.connection_id = Uuid::new_v4();
    masked_source.expects_active = true;
    let mut masked_recipient = route(&fixture.bob, "bob@example.test/Tablet");
    masked_recipient.expects_active = true;
    for (candidate, kind) in [
        (&masked_source, PrivacyStanzaKind::PresenceOut),
        (&masked_recipient, PrivacyStanzaKind::PresenceIn),
    ] {
        let route = &candidate.route;
        replace_privacy_list(
            &fixture.db.pool,
            route.account_id,
            &PrivacyList {
                name: "quiet".into(),
                items: vec![PrivacyItem {
                    order: 1,
                    action: PrivacyAction::Deny,
                    match_type: None,
                    match_value: None,
                    message: false,
                    iq: false,
                    presence_in: kind == PrivacyStanzaKind::PresenceIn,
                    presence_out: kind == PrivacyStanzaKind::PresenceOut,
                }],
            },
        )
        .await
        .unwrap();
        assert!(set_active_privacy_list(
            &fixture.db.pool,
            route.account_id,
            route.connection_id,
            Some("quiet"),
        )
        .await
        .unwrap());
    }
    fixture.routes.extend([masked_source, masked_recipient]);
    fixture
        .apply(BlockingMutation::Block(vec![jid(BARE)]))
        .await;
    let restore = fixture.apply(BlockingMutation::UnblockAll).await;
    assert_eq!(restore.contacts.len(), 4);
    for candidate in restore.contacts {
        assert!(candidate.covered_before && !candidate.covered_after);
        assert_eq!(
            candidate.other_policy_allows,
            candidate.route.source.full_jid == SOURCE
                && candidate.route.recipient.unwrap().full_jid == FULL,
        );
    }
    fixture.db.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn directed_revocation_is_confined_to_the_granting_source_and_exact_peer() {
    let mut fixture = Fixture::new().await;
    let mut sibling = fixture.routes[0].clone();
    sibling.route.full_jid = "alice@example.test/Laptop".into();
    sibling.route.connection_id = Uuid::new_v4();
    let other_recipient = route(&fixture.bob, "bob@example.test/Tablet");
    fixture.routes.extend([sibling, other_recipient]);
    fixture.routes[0].directed.push(FULL.into());
    block_jids(&fixture.db.pool, fixture.bob.id, &[SOURCE.into()])
        .await
        .unwrap();

    let change = fixture
        .apply(BlockingMutation::Block(vec![jid(BARE)]))
        .await;
    assert_eq!(change.contacts.len(), 1);
    let contact = &change.contacts[0];
    assert!(!contact.covered_before && contact.covered_after && !contact.other_policy_allows);
    assert_eq!(contact.route.source, fixture.routes[0].route);
    assert_eq!(contact.route.directed.as_deref(), Some(FULL));
    assert_eq!(
        contact.route.recipient.as_ref(),
        Some(&fixture.routes[1].route)
    );
    fixture.db.finish().await;
}
