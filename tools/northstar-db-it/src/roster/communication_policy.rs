use super::presence_service::IsolatedDatabase;
use northstar_auth_postgres::users::{create_user, User};
use northstar_roster_application::{
    CommunicationDecision, CommunicationDecision::*, CommunicationPolicyQuery,
    CommunicationPolicyReader, PolicyDirection, PolicySubject,
};
use northstar_roster_postgres::{
    privacy::{
        read_communication_policies, replace_privacy_list, set_active_privacy_list,
        set_default_privacy_list, PostgresPrivacyRepository, ReplacePrivacyListOutcome,
    },
    roster::{block_jids, unblock_jids, BlockJidsUpdate, UnblockJidsUpdate},
};
use northstar_workflows::roster::{transition_local_presence_subscription, upsert_roster};
use northstar_xep_0016::{
    PrivacyAction, PrivacyItem, PrivacyList, PrivacyMatchType, PrivacyStanzaKind,
};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

const OWNER_BARE: &str = "bob@example.test";
const PEER_BARE: &str = "alice@example.test";
const PEER: &str = "alice@example.test/Phone";

struct Fixture {
    database: IsolatedDatabase,
    owner: User,
    peer: User,
    policies: PostgresPrivacyRepository,
}

impl Fixture {
    async fn new() -> Self {
        let database = IsolatedDatabase::create("communication_policy").await;
        let owner = test_user(&database.pool, "bob").await;
        let peer = test_user(&database.pool, "alice").await;
        let policies = PostgresPrivacyRepository::new(database.pool.clone());
        Self {
            database,
            owner,
            peer,
            policies,
        }
    }

    fn query(&self, peer: &str) -> CommunicationPolicyQuery {
        CommunicationPolicyQuery {
            account_id: self.owner.id,
            expected_auth_generation: Some(self.owner.auth_generation),
            subject: PolicySubject::AccountDefault,
            peer: peer.to_owned(),
            kind: PrivacyStanzaKind::Message,
            direction: PolicyDirection::Inbound,
            check_owner_block: true,
            check_peer_block: false,
        }
    }

    async fn decision(&self, query: &CommunicationPolicyQuery) -> CommunicationDecision {
        self.policies
            .read_communication_policy(query)
            .await
            .unwrap()
    }

    async fn store_list(&self, name: &str, items: Vec<PrivacyItem>) {
        assert_eq!(
            replace_privacy_list(
                &self.database.pool,
                self.owner.id,
                &PrivacyList {
                    name: name.to_owned(),
                    items,
                },
            )
            .await
            .unwrap(),
            ReplacePrivacyListOutcome::Stored
        );
    }

    async fn set_default(&self, name: &str) {
        assert!(
            set_default_privacy_list(&self.database.pool, self.owner.id, Some(name))
                .await
                .unwrap()
        );
    }
}

async fn test_user(pool: &PgPool, username: &str) -> User {
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

fn rule(
    order: u32,
    action: PrivacyAction,
    matcher: Option<(PrivacyMatchType, &str)>,
) -> PrivacyItem {
    PrivacyItem {
        order,
        action,
        match_type: matcher.map(|(kind, _)| kind),
        match_value: matcher.map(|(_, value)| value.to_owned()),
        message: false,
        iq: false,
        presence_in: false,
        presence_out: false,
    }
}

async fn add_block(pool: &PgPool, account: Uuid, jid: &str) {
    let jids = vec![jid.to_owned()];
    assert_eq!(
        block_jids(pool, account, &jids).await.unwrap(),
        BlockJidsUpdate::Changed(jids)
    );
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn block_scope_and_account_precedence() {
    let fixture = Fixture::new().await;
    let pool = &fixture.database.pool;
    let mut query = fixture.query(PEER);
    assert_eq!(fixture.decision(&query).await, Allow);

    for (pattern, bare_decision) in [
        (PEER_BARE, OwnerBlocks),
        ("example.test", OwnerBlocks),
        (PEER, Allow),
    ] {
        add_block(pool, fixture.owner.id, pattern).await;
        assert_eq!(fixture.decision(&query).await, OwnerBlocks, "{pattern}");
        assert_eq!(
            fixture.decision(&fixture.query(PEER_BARE)).await,
            bare_decision
        );
        let removed = vec![pattern.to_owned()];
        assert_eq!(
            unblock_jids(pool, fixture.owner.id, Some(&removed))
                .await
                .unwrap(),
            UnblockJidsUpdate::Changed(removed)
        );
    }
    add_block(pool, fixture.owner.id, "example.test/Phone").await;
    assert_eq!(fixture.decision(&query).await, Allow);
    assert_eq!(
        fixture.decision(&fixture.query("example.test/Phone")).await,
        OwnerBlocks
    );

    add_block(pool, fixture.peer.id, OWNER_BARE).await;
    assert_eq!(fixture.decision(&query).await, Allow);
    query.check_peer_block = true;
    assert_eq!(fixture.decision(&query).await, PeerBlocks);
    assert_eq!(
        fixture
            .decision(&fixture.query("alice@remote.test/Phone"))
            .await,
        Allow
    );

    fixture
        .store_list("deny", vec![rule(10, PrivacyAction::Deny, None)])
        .await;
    fixture.set_default("deny").await;
    assert_eq!(fixture.decision(&query).await, PeerBlocks);
    add_block(pool, fixture.owner.id, PEER).await;
    assert_eq!(fixture.decision(&query).await, OwnerBlocks);
    query.expected_auth_generation = Some(fixture.owner.auth_generation + 1);
    assert_eq!(fixture.decision(&query).await, StaleAccount);

    let disabled: bool = sqlx::query_scalar("SELECT northstar_user_quiesce_deletion($1,$2)")
        .bind(fixture.owner.id)
        .bind(fixture.owner.auth_generation)
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(disabled);
    query.expected_auth_generation = None;
    assert_eq!(fixture.decision(&query).await, StaleAccount);
    assert!(set_default_privacy_list(pool, fixture.owner.id, None)
        .await
        .unwrap());
    let deleted: bool = sqlx::query_scalar("SELECT northstar_user_delete_quiesced($1,$2)")
        .bind(fixture.owner.id)
        .bind(&fixture.owner.username)
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(deleted);
    assert_eq!(fixture.decision(&query).await, StaleAccount);
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn privacy_rules_and_selection_fallback() {
    let fixture = Fixture::new().await;
    let pool = &fixture.database.pool;
    let owner = fixture.owner.id;
    let peer = fixture.peer.id;
    let group_member = "colleague@remote.test";
    let jid_match = "locked@remote.test/Phone";
    let allowed_group_jid = "colleague@remote.test/Allowed";
    upsert_roster(pool, owner, group_member, None, &["work".to_owned()])
        .await
        .unwrap();
    for (actor, from, target, to, kind) in [
        (owner, OWNER_BARE, peer, PEER_BARE, "subscribe"),
        (peer, PEER_BARE, owner, OWNER_BARE, "subscribed"),
    ] {
        let stanza = format!("<presence from='{from}' to='{to}' type='{kind}'/>");
        assert!(transition_local_presence_subscription(
            pool, actor, from, target, to, kind, &stanza
        )
        .await
        .unwrap()
        .is_some());
    }
    fixture
        .store_list(
            "restricted",
            vec![
                rule(
                    10,
                    PrivacyAction::Deny,
                    Some((PrivacyMatchType::Jid, jid_match)),
                ),
                rule(
                    20,
                    PrivacyAction::Deny,
                    Some((PrivacyMatchType::Group, "work")),
                ),
                rule(
                    30,
                    PrivacyAction::Deny,
                    Some((PrivacyMatchType::Subscription, "to")),
                ),
                rule(
                    5,
                    PrivacyAction::Allow,
                    Some((PrivacyMatchType::Jid, allowed_group_jid)),
                ),
            ],
        )
        .await;
    fixture.set_default("restricted").await;
    for (peer, expected) in [
        (jid_match, PrivacyDenies),
        ("locked@remote.test/Desk", Allow),
        ("colleague@remote.test/Phone", PrivacyDenies),
        (allowed_group_jid, Allow),
        (PEER, PrivacyDenies),
        ("not-in-roster@remote.test", Allow),
    ] {
        assert_eq!(
            fixture.decision(&fixture.query(peer)).await,
            expected,
            "{peer}"
        );
    }

    let connection_id = Uuid::new_v4();
    let mut query = fixture.query(jid_match);
    query.subject = PolicySubject::Connection {
        connection_id,
        expects_active: false,
    };
    assert_eq!(fixture.decision(&query).await, PrivacyDenies);
    fixture
        .store_list("allow", vec![rule(10, PrivacyAction::Allow, None)])
        .await;
    fixture.set_default("allow").await;
    assert_eq!(fixture.decision(&query).await, Allow);

    query.subject = PolicySubject::Connection {
        connection_id,
        expects_active: true,
    };
    assert_eq!(fixture.decision(&query).await, PrivacyDenies);
    fixture.set_default("restricted").await;
    assert!(
        set_active_privacy_list(pool, owner, connection_id, Some("allow"))
            .await
            .unwrap()
    );
    assert_eq!(fixture.decision(&query).await, Allow);
    assert_eq!(
        fixture.decision(&fixture.query(jid_match)).await,
        PrivacyDenies
    );

    fixture.set_default("allow").await;
    sqlx::query(
        "UPDATE privacy_active_sessions SET expires_at=statement_timestamp()-INTERVAL '1 second'
          WHERE owner_id=$1 AND connection_id=$2",
    )
    .bind(owner)
    .bind(connection_id)
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(fixture.decision(&query).await, PrivacyDenies);
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn mixed_batch_preserves_order_and_presence_masks() {
    let fixture = Fixture::new().await;
    let pool = &fixture.database.pool;
    let mut presence_out = rule(10, PrivacyAction::Deny, None);
    presence_out.presence_out = true;
    fixture.store_list("outbound", vec![presence_out]).await;
    fixture.set_default("outbound").await;
    add_block(pool, fixture.owner.id, PEER).await;
    add_block(pool, fixture.peer.id, "example.test").await;
    let owner_blocks = fixture.query(PEER);
    let peer_blocks = CommunicationPolicyQuery {
        check_owner_block: false,
        check_peer_block: true,
        ..owner_blocks.clone()
    };
    let inbound = CommunicationPolicyQuery {
        kind: PrivacyStanzaKind::PresenceIn,
        ..fixture.query("remote.test")
    };
    let outbound = CommunicationPolicyQuery {
        kind: PrivacyStanzaKind::PresenceOut,
        direction: PolicyDirection::Outbound,
        ..inbound.clone()
    };
    let stale = CommunicationPolicyQuery {
        account_id: Uuid::new_v4(),
        ..owner_blocks.clone()
    };
    let queries = [
        inbound.clone(),
        owner_blocks,
        stale,
        outbound,
        peer_blocks,
        inbound,
    ];
    assert_eq!(
        fixture
            .policies
            .read_communication_policies(&queries)
            .await
            .unwrap(),
        [
            Allow,
            OwnerBlocks,
            StaleAccount,
            PrivacyDenies,
            PeerBlocks,
            Allow
        ]
    );
    assert!(fixture
        .policies
        .read_communication_policies(&[])
        .await
        .unwrap()
        .is_empty());
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn policy_swap_uses_one_statement_snapshot() {
    let fixture = Fixture::new().await;
    let pool = &fixture.database.pool;
    let owner = fixture.owner.id;
    let query = fixture.query(PEER);
    fixture
        .store_list("swap", vec![rule(10, PrivacyAction::Allow, None)])
        .await;
    fixture.set_default("swap").await;
    add_block(pool, owner, PEER).await;
    assert_eq!(fixture.decision(&query).await, OwnerBlocks);

    let mut writer = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE privacy_list_items IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *writer)
        .await
        .unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    let mut reader = pool.acquire().await.unwrap();
    let reader_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *reader)
        .await
        .unwrap();
    let request = query.clone();
    let operation =
        tokio::spawn(async move { read_communication_policies(&mut *reader, &[request]).await });
    assert_eq!(
        crate::support::blocked_backend(pool, blocker).await,
        reader_pid
    );
    // A split reader waiting on the privacy table would have no block lookup
    // in its active statement. Check both the waiting relation and query text.
    let joint_read: bool = sqlx::query_scalar(
        "SELECT position('blocked_jids' IN activity.query)>0 AND EXISTS (
             SELECT 1 FROM pg_locks
              WHERE pid=activity.pid AND relation='privacy_list_items'::regclass AND NOT granted)
           FROM pg_stat_activity activity WHERE activity.pid=$1",
    )
    .bind(reader_pid)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(joint_read);

    // Both changes must commit together while the reader is waiting.
    let removed = sqlx::query("DELETE FROM blocked_jids WHERE owner_id=$1 AND blocked_jid=$2")
        .bind(owner)
        .bind(PEER)
        .execute(&mut *writer)
        .await
        .unwrap();
    assert_eq!(removed.rows_affected(), 1);
    let updated = sqlx::query(
        "UPDATE privacy_list_items SET action='deny' WHERE owner_id=$1 AND list_name='swap'",
    )
    .bind(owner)
    .execute(&mut *writer)
    .await
    .unwrap();
    assert_eq!(updated.rows_affected(), 1);
    writer.commit().await.unwrap();

    let decisions = operation.await.unwrap().unwrap();
    assert!(matches!(
        decisions.as_slice(),
        [OwnerBlocks | PrivacyDenies]
    ));
    assert_eq!(fixture.decision(&query).await, PrivacyDenies);
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn policy_read_leaves_lease_and_locks_untouched() {
    let fixture = Fixture::new().await;
    let pool = &fixture.database.pool;
    let connection_id = Uuid::new_v4();
    let mut query = fixture.query(PEER);
    query.subject = PolicySubject::Connection {
        connection_id,
        expects_active: true,
    };
    fixture
        .store_list("allow", vec![rule(10, PrivacyAction::Allow, None)])
        .await;
    assert!(
        set_active_privacy_list(pool, fixture.owner.id, connection_id, Some("allow"))
            .await
            .unwrap()
    );
    let lease_sql = "SELECT updated_at::text,expires_at::text FROM privacy_active_sessions
                      WHERE owner_id=$1 AND connection_id=$2";
    let before: (String, String) = sqlx::query_as(lease_sql)
        .bind(fixture.owner.id)
        .bind(connection_id)
        .fetch_one(pool)
        .await
        .unwrap();
    let mut writer = pool.begin().await.unwrap();
    sqlx::query(
        "SELECT owner_id FROM privacy_active_sessions WHERE owner_id=$1 AND connection_id=$2 FOR UPDATE",
    )
    .bind(fixture.owner.id)
    .bind(connection_id)
    .fetch_one(&mut *writer)
    .await
    .unwrap();
    let mut reader = pool.acquire().await.unwrap();
    let reader_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *reader)
        .await
        .unwrap();
    let decisions = tokio::time::timeout(
        Duration::from_secs(5),
        read_communication_policies(&mut *reader, std::slice::from_ref(&query)),
    )
    .await
    .expect("communication policy waited for a lease row lock")
    .unwrap();
    assert_eq!(decisions, [Allow]);
    let has_locks: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid=$1)")
        .bind(reader_pid)
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(!has_locks);

    // Confirm PostgreSQL permits the statement in a read-only transaction.
    let mut read_only = pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *read_only)
        .await
        .unwrap();
    assert_eq!(
        read_communication_policies(&mut *read_only, std::slice::from_ref(&query))
            .await
            .unwrap(),
        [Allow]
    );
    let policy_locks: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid()
           AND (locktype IN ('tuple','advisory') OR (locktype='relation' AND mode<>'AccessShareLock')))",
    )
    .fetch_one(&mut *read_only)
    .await
    .unwrap();
    assert!(!policy_locks);
    read_only.commit().await.unwrap();
    writer.rollback().await.unwrap();
    drop(reader);
    let after: (String, String) = sqlx::query_as(lease_sql)
        .bind(fixture.owner.id)
        .bind(connection_id)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(before, after);
    fixture.database.finish().await;
}
