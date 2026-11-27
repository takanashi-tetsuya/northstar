use super::*;
use northstar_pubsub_core::{PresenceReplayCursor, PubSubItem};
use northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission;
use std::collections::VecDeque;
use std::future::ready;
use std::sync::{Arc, Mutex};

struct FakeReplayRepository(Arc<FakeReplayState>);

#[derive(Default)]
struct FakeReplayState {
    pages: Mutex<VecDeque<PresenceReplayPage>>,
    queries: Mutex<Vec<PresenceReplayQuery>>,
    digest_outcomes: Mutex<VecDeque<ReplayDigestOutcome>>,
    digests: Mutex<Vec<ReplayDigestIntent>>,
}

impl PubSubPresenceReplayQueryRepository for FakeReplayRepository {
    async fn presence_replay_page(
        &self,
        query: &PresenceReplayQuery,
    ) -> Result<PresenceReplayPage> {
        self.0.queries.lock().unwrap().push(query.clone());
        Ok(self
            .0
            .pages
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected page read"))
    }
}

impl PubSubReplayDigestRepository for FakeReplayRepository {
    async fn enqueue_replay_digest(
        &self,
        intent: ReplayDigestIntent,
    ) -> Result<ReplayDigestOutcome> {
        self.0.digests.lock().unwrap().push(intent);
        Ok(self
            .0
            .digest_outcomes
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected digest enqueue"))
    }
}

fn service(
    pages: Vec<PresenceReplayPage>,
    digest_outcomes: Vec<ReplayDigestOutcome>,
) -> (PubSubService<FakeReplayRepository>, Arc<FakeReplayState>) {
    let state = Arc::new(FakeReplayState {
        pages: Mutex::new(pages.into()),
        digest_outcomes: Mutex::new(digest_outcomes.into()),
        ..Default::default()
    });
    let pubsub = PubSubService::new_with_durable_outbox_database_admission(
        FakeReplayRepository(Arc::clone(&state)),
        2,
        DurableOutboxDatabaseAdmission::for_primary_pool(2),
    );
    (pubsub, state)
}

fn query(limit: usize) -> PresenceReplayQuery {
    PresenceReplayQuery {
        expected_auth_generation: None,
        connection_id: Uuid::nil(),
        recipient: PubSubAddress::parse("reader@example.test/mobile").unwrap(),
        recipient_id: Uuid::nil(),
        active_privacy_list: None,
        service: PubSubBareJid::parse("pubsub.example.test").unwrap(),
        show: "online".into(),
        after: None,
        limit,
    }
}

fn candidate(subid: &str, digest: bool) -> PresenceReplayCandidate {
    PresenceReplayCandidate {
        subscription: PubSubSubscription {
            node: "news".into(),
            jid: "reader@example.test".into(),
            state: "subscribed".into(),
            subid: subid.into(),
            deliver: true,
            digest,
            digest_frequency: 1_000,
            expire: None,
            include_body: false,
            show_values: vec!["online".into()],
            subscription_type: "items".into(),
            subscription_depth: Some(1),
        },
        node_id: Uuid::from_u128(1),
        node: "news".into(),
        deliver_payloads: true,
        item: PubSubItem {
            item_id: "latest".into(),
            xml_payload: "<item id='latest'/>".into(),
            created_at: DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
        },
    }
}

fn page(
    candidates: Vec<PresenceReplayCandidate>,
    scanned: usize,
    next: Option<PresenceReplayCursor>,
) -> PresenceReplayPage {
    PresenceReplayPage::Candidates {
        candidates,
        next,
        scanned,
    }
}

async fn sent(
    pubsub: &PubSubService<FakeReplayRepository>,
    query: PresenceReplayQuery,
) -> Vec<String> {
    let mut sent = Vec::new();
    pubsub
        .replay_presence_pages(
            query,
            |candidate| Ok(candidate.subscription.subid.clone()),
            |children| {
                sent.push(children);
                ready(Ok(true))
            },
        )
        .await
        .unwrap();
    sent
}

#[tokio::test]
async fn replay_pages_continue_past_filtered_rows_and_stop_on_short_scan() {
    let cursor = PresenceReplayCursor {
        node: "news".into(),
        jid: "reader@example.test".into(),
    };
    let (pubsub, state) = service(
        vec![
            page(vec![], 2, Some(cursor.clone())),
            page(vec![candidate("direct", false)], 1, Some(cursor.clone())),
        ],
        vec![],
    );
    assert_eq!(sent(&pubsub, query(2)).await, ["direct"]);
    let queries = state.queries.lock().unwrap();
    assert_eq!(queries.len(), 2);
    assert_eq!(queries[0].after, None);
    assert_eq!(queries[1].after, Some(cursor));
}

#[tokio::test]
async fn denied_page_stops_the_replay() {
    let cursor = PresenceReplayCursor {
        node: "news".into(),
        jid: "reader@example.test".into(),
    };
    let (pubsub, state) = service(
        vec![page(vec![], 100, Some(cursor)), PresenceReplayPage::Denied],
        vec![],
    );
    assert!(sent(&pubsub, query(0)).await.is_empty());
    let queries = state.queries.lock().unwrap();
    assert_eq!(queries.len(), 2);
    assert!(queries.iter().all(|query| query.limit == 100));
}

#[tokio::test]
async fn stale_digest_is_skipped_and_replay_continues() {
    let (pubsub, state) = service(
        vec![page(
            vec![candidate("stale", true), candidate("direct", false)],
            2,
            None,
        )],
        vec![ReplayDigestOutcome::Stale],
    );
    assert_eq!(sent(&pubsub, query(100)).await, ["direct"]);
    let digests = state.digests.lock().unwrap();
    assert_eq!(digests.len(), 1);
    assert_eq!(digests[0].subid, "stale");
    assert_eq!(digests[0].item_id, "latest");
}

#[tokio::test]
async fn digest_disabled_falls_back_to_direct_delivery() {
    let (pubsub, state) = service(
        vec![page(
            vec![candidate("enqueued", true), candidate("disabled", true)],
            2,
            None,
        )],
        vec![
            ReplayDigestOutcome::Enqueued,
            ReplayDigestOutcome::NotDigest,
        ],
    );
    assert_eq!(sent(&pubsub, query(100)).await, ["disabled"]);
    assert_eq!(state.digests.lock().unwrap().len(), 2);
}
