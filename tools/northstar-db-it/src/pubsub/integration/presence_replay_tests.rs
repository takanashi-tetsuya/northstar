//! Generic presence replay through the workflow's PostgreSQL ports.

use super::*;
use northstar_pubsub_application::{
    PresenceReplayAdmissionOutcome, PresenceReplayAdmissionRequest, ReplayDigestIntent,
    ReplayDigestOutcome,
};
use northstar_pubsub_core::{
    PresenceReplayCandidate, PresenceReplayPage, PresenceReplayQuery, PubSubAddress, PubSubBareJid,
};
use northstar_roster_postgres::privacy::{self, PrivacyAction, PrivacyItem, PrivacyList};
use northstar_workflows::pubsub_repository::test_pubsub_service;

const DOMAIN: &str = "example.test";
const SERVICE: &str = "pubsub.example.test";
const SUBID: &str = "selected";

const FREQUENCY: i32 = 1_000;

/// SubIDs are unique across nodes, so each fixture node gets its own.
fn subid(name: &str) -> String {
    format!("{SUBID}-{name}")
}

struct Fixture {
    recipient_id: Uuid,
    username: String,
    bare: String,
    recipient: String,
    owner: String,
}

impl Fixture {
    async fn new(pool: &PgPool) -> Self {
        let recipient_id = Uuid::new_v4();
        let username = format!("replay-reader-{}", recipient_id.simple());
        let bare = format!("{username}@{DOMAIN}");
        let recipient = format!("{bare}/mobile");
        let owner = format!("replay-owner-{}@{DOMAIN}", recipient_id.simple());
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(recipient_id)
            .bind(&username)
            .execute(pool)
            .await
            .unwrap();
        Self {
            recipient_id,
            username,
            bare,
            recipient,
            owner,
        }
    }

    fn query(&self, active_privacy_list: Option<&str>) -> PresenceReplayQuery {
        PresenceReplayQuery {
            recipient: PubSubAddress::parse(&self.recipient).unwrap(),
            recipient_id: self.recipient_id,
            active_privacy_list: active_privacy_list.map(str::to_owned),
            service: PubSubBareJid::parse(SERVICE).unwrap(),
            show: "online".into(),
            after: None,
            limit: 0,
        }
    }

    async fn node(&self, pool: &PgPool, name: &str, subscriber: &str, digest: bool) -> PubSubNode {
        let node_name = format!("{}-{name}", self.username);
        let node = create_default_test_node(pool, &node_name, &self.owner).await;
        sqlx::query(
            "INSERT INTO pubsub_subscriptions(node_id,jid,state,subid,digest,digest_frequency)
             VALUES($1,$2,'subscribed',$3,$4,$5)",
        )
        .bind(node.id)
        .bind(subscriber)
        .bind(subid(name))
        .bind(digest)
        .bind(FREQUENCY)
        .execute(pool)
        .await
        .unwrap();
        self.insert_item(pool, node.id, "old", 60).await;
        node
    }

    async fn insert_item<'e>(
        &self,
        executor: impl sqlx::Executor<'e, Database = sqlx::Postgres>,
        node_id: Uuid,
        item_id: &str,
        age_seconds: i32,
    ) {
        sqlx::query(
            "INSERT INTO pubsub_items(id,node_id,item_id,publisher_jid,xml_payload,created_at)
             VALUES($1,$2,$3,$4,$5,NOW() - $6::INTEGER * INTERVAL '1 second')",
        )
        .bind(Uuid::new_v4())
        .bind(node_id)
        .bind(item_id)
        .bind(&self.owner)
        .bind(format!("<item id='{item_id}'/>"))
        .bind(age_seconds)
        .execute(executor)
        .await
        .unwrap();
    }

    async fn activate_privacy(&self, pool: &PgPool, name: &str, action: PrivacyAction) -> Uuid {
        let list = PrivacyList {
            name: name.into(),
            items: vec![PrivacyItem {
                order: 1,
                action,
                match_type: None,
                match_value: None,
                message: true,
                iq: false,
                presence_in: false,
                presence_out: false,
            }],
        };
        assert_eq!(
            privacy::replace_privacy_list(pool, self.recipient_id, &list)
                .await
                .unwrap(),
            privacy::ReplacePrivacyListOutcome::Stored,
        );
        let connection_id = Uuid::new_v4();
        assert!(privacy::set_active_privacy_list(
            pool,
            self.recipient_id,
            connection_id,
            Some(name)
        )
        .await
        .unwrap());
        connection_id
    }

    async fn lease_expiry(&self, pool: &PgPool, connection_id: Uuid) -> DateTime<Utc> {
        sqlx::query_scalar(
            "SELECT expires_at FROM privacy_active_sessions WHERE owner_id=$1 AND connection_id=$2",
        )
        .bind(self.recipient_id)
        .bind(connection_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }
}

fn candidates(page: PresenceReplayPage, expected_scanned: usize) -> Vec<PresenceReplayCandidate> {
    let PresenceReplayPage::Candidates {
        candidates,
        next,
        scanned,
    } = page
    else {
        panic!("replay page denied");
    };
    assert_eq!(scanned, expected_scanned);
    assert_eq!(next, None);
    candidates
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn presence_replay_page_reads_candidates_from_one_snapshot() {
    let (url, pool) = integration_pool(2).await;
    let fixture = Fixture::new(&pool).await;
    let first = fixture.node(&pool, "first", &fixture.bare, false).await;
    let second = fixture
        .node(&pool, "second", &fixture.recipient, false)
        .await;
    let application = format!("presence-replay-{}", fixture.recipient_id.simple());
    let reader_pool = named_single_connection_pool(&url, &application).await;
    let pubsub = test_pubsub_service(reader_pool.clone(), DOMAIN);
    let query = fixture.query(None);
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE pubsub_items IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let read = tokio::spawn({
        let pubsub = pubsub.clone();
        let query = query.clone();
        async move { pubsub.presence_replay_page(&query).await.unwrap() }
    });
    wait_for_named_session_lock(&pool, &application).await;

    sqlx::query("DELETE FROM pubsub_subscriptions WHERE node_id=$1 AND jid=$2")
        .bind(first.id)
        .bind(&fixture.bare)
        .execute(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("INSERT INTO pubsub_affiliations(node_id,jid,affiliation) VALUES($1,$2,'outcast')")
        .bind(second.id)
        .bind(&fixture.bare)
        .execute(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("UPDATE pubsub_nodes SET deliver_payloads=false WHERE id=$1")
        .bind(second.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    for node_id in [first.id, second.id] {
        fixture.insert_item(&mut *blocker, node_id, "new", 0).await;
    }
    blocker.commit().await.unwrap();

    // A split read delivers the newer first item with the revoked SubID,
    // then drops the second row when its late ACL lookup sees the outcast.
    let page = candidates(read.await.unwrap(), 2);
    assert_eq!(page.len(), 2);
    for (candidate, (node, name)) in page.iter().zip([(first, "first"), (second, "second")]) {
        assert_eq!(candidate.node_id, node.id);
        assert_eq!(candidate.node, node.node);
        assert_eq!(candidate.subscription.subid, subid(name));
        assert!(candidate.deliver_payloads);
        assert_eq!(candidate.item.item_id, "old");
    }
    let after = pubsub.presence_replay_page(&query).await.unwrap();
    assert!(candidates(after, 1).is_empty());
    reader_pool.close().await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn presence_replay_page_succeeds_on_read_only_connections() {
    let (url, pool) = integration_pool(2).await;
    let fixture = Fixture::new(&pool).await;
    let node = fixture
        .node(&pool, "read-only", &fixture.recipient, false)
        .await;
    let connection_id = fixture
        .activate_privacy(&pool, "allow", PrivacyAction::Allow)
        .await;
    let original_expiry = fixture.lease_expiry(&pool, connection_id).await;
    let read_pool = read_only_disco::read_only_pool(&url).await;
    let read_only: String = sqlx::query_scalar("SHOW default_transaction_read_only")
        .fetch_one(&read_pool)
        .await
        .unwrap();
    assert_eq!(read_only, "on");

    let pubsub = test_pubsub_service(read_pool.clone(), DOMAIN);
    let page = pubsub
        .presence_replay_page(&fixture.query(Some("allow")))
        .await
        .unwrap();
    let accepted = candidates(page, 1);
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].node_id, node.id);
    assert_eq!(accepted[0].subscription.jid, fixture.recipient);
    assert_eq!(accepted[0].subscription.subid, subid("read-only"));
    assert_eq!(accepted[0].item.item_id, "old");
    assert_eq!(
        fixture.lease_expiry(&pool, connection_id).await,
        original_expiry
    );
    read_pool.close().await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn replay_digest_enqueue_rejects_a_changed_subscription_or_newer_item() {
    let (url, pool) = integration_pool(2).await;
    let fixture = Fixture::new(&pool).await;
    let application = format!("replay-digest-{}", fixture.recipient_id.simple());
    let writer_pool = named_single_connection_pool(&url, &application).await;
    let pubsub = test_pubsub_service(writer_pool.clone(), DOMAIN);
    for (change, expected) in [
        ("subid", ReplayDigestOutcome::Stale),
        ("frequency", ReplayDigestOutcome::Stale),
        ("newer-item", ReplayDigestOutcome::Stale),
        ("disabled", ReplayDigestOutcome::NotDigest),
        ("unchanged", ReplayDigestOutcome::Enqueued),
    ] {
        let node = fixture.node(&pool, change, &fixture.bare, true).await;
        let mut accepted = candidates(
            pubsub
                .presence_replay_page(&fixture.query(None))
                .await
                .unwrap(),
            1,
        );
        let candidate = accepted.pop().unwrap();
        assert_eq!(candidate.node_id, node.id);
        let intent = ReplayDigestIntent {
            node_id: candidate.node_id,
            subid: candidate.subscription.subid,
            subscriber_jid: PubSubAddress::parse(&candidate.subscription.jid).unwrap(),
            digest_frequency: candidate.subscription.digest_frequency,
            item_id: candidate.item.item_id,
            children: "<event/>".into(),
        };

        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 3))")
            .bind(&fixture.bare)
            .execute(&mut *blocker)
            .await
            .unwrap();
        let enqueue = tokio::spawn({
            let pubsub = pubsub.clone();
            async move { pubsub.enqueue_replay_digest(intent).await.unwrap() }
        });
        wait_for_named_session_lock(&pool, &application).await;
        if change == "newer-item" {
            fixture.insert_item(&mut *blocker, node.id, "new", 0).await;
        } else if change != "unchanged" {
            let update = match change {
                "subid" => "UPDATE pubsub_subscriptions SET subid='replacement' WHERE node_id=$1 AND jid=$2",
                "frequency" => "UPDATE pubsub_subscriptions SET digest_frequency=2000 WHERE node_id=$1 AND jid=$2",
                "disabled" => "UPDATE pubsub_subscriptions SET digest=false WHERE node_id=$1 AND jid=$2",
                _ => unreachable!(),
            };
            sqlx::query(update)
                .bind(node.id)
                .bind(&fixture.bare)
                .execute(&mut *blocker)
                .await
                .unwrap();
        }
        blocker.commit().await.unwrap();

        assert_eq!(enqueue.await.unwrap(), expected, "{change}");
        let queued: Vec<(String, String, bool)> = sqlx::query_as(
            "SELECT subscriber_jid, event_xml,
                    source_delivery_id IS NULL AND show_values IS NULL
                    AND deliver_after = created_at + INTERVAL '1 second'
               FROM pubsub_digest_queue WHERE subscription_node_id=$1",
        )
        .bind(node.id)
        .fetch_all(&pool)
        .await
        .unwrap();
        if expected == ReplayDigestOutcome::Enqueued {
            assert_eq!(
                queued,
                [(fixture.bare.clone(), "<event/>".to_owned(), true)]
            );
            sqlx::query("DELETE FROM pubsub_digest_queue WHERE subscription_node_id=$1")
                .bind(node.id)
                .execute(&pool)
                .await
                .unwrap();
        } else {
            assert!(queued.is_empty(), "{change}");
        }
        sqlx::query("DELETE FROM pubsub_nodes WHERE id=$1")
            .bind(node.id)
            .execute(&pool)
            .await
            .unwrap();
    }
    writer_pool.close().await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn presence_replay_admission_refreshes_lease_only_when_not_blocked() {
    let (_, pool) = integration_pool(2).await;
    let fixture = Fixture::new(&pool).await;
    let connection_id = fixture
        .activate_privacy(&pool, "deny", PrivacyAction::Deny)
        .await;
    let old_expiry: DateTime<Utc> = sqlx::query_scalar(
        "UPDATE privacy_active_sessions SET expires_at=NOW() - INTERVAL '1 hour'
          WHERE owner_id=$1 AND connection_id=$2 RETURNING expires_at",
    )
    .bind(fixture.recipient_id)
    .bind(connection_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let request = PresenceReplayAdmissionRequest {
        recipient_id: fixture.recipient_id,
        active_privacy_list: Some("deny".into()),
        connection_id,
        service: PubSubBareJid::parse(SERVICE).unwrap(),
    };
    sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,$2)")
        .bind(fixture.recipient_id)
        .bind(SERVICE)
        .execute(&pool)
        .await
        .unwrap();
    let pubsub = test_pubsub_service(pool.clone(), DOMAIN);
    assert_eq!(
        pubsub.admit_presence_replay(request.clone()).await.unwrap(),
        PresenceReplayAdmissionOutcome::Blocked,
    );
    assert_eq!(fixture.lease_expiry(&pool, connection_id).await, old_expiry);
    assert!(matches!(
        pubsub
            .presence_replay_page(&fixture.query(None))
            .await
            .unwrap(),
        PresenceReplayPage::Denied
    ));
    sqlx::query("DELETE FROM blocked_jids WHERE owner_id=$1 AND blocked_jid=$2")
        .bind(fixture.recipient_id)
        .bind(SERVICE)
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(
        pubsub.admit_presence_replay(request).await.unwrap(),
        PresenceReplayAdmissionOutcome::Admitted,
    );
    assert!(fixture.lease_expiry(&pool, connection_id).await > old_expiry);
    assert!(matches!(
        pubsub
            .presence_replay_page(&fixture.query(Some("deny")))
            .await
            .unwrap(),
        PresenceReplayPage::Denied
    ));
    pool.close().await;
}
