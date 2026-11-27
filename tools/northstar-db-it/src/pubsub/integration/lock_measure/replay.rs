use super::super::create_default_test_node;
use super::{subscribe, Scenario, DOMAIN, STORAGE_LIMIT};
use anyhow::{ensure, Result};
use northstar_pubsub_application::PubSubService;
use northstar_pubsub_core::{
    PresenceReplayPage, PresenceReplayQuery, PubSubAddress, PubSubBareJid,
};
use northstar_pubsub_postgres::{publish_items, PublishItemsOutcome, SubscribeOutcome};
use northstar_workflows::pubsub_repository::{test_pubsub_service, PostgresPubSubRepository};
use uuid::Uuid;

const PAGE_SIZE: usize = 100;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn measure_presence_replay_reads() {
    let scenario = Scenario::new("presence_replay_reads", 1).await;
    let pool = &scenario.pool;
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("measure-replay-reader-{suffix}");
    let requester = format!("{username}@{DOMAIN}");
    let account = northstar_auth_postgres::users::create_user(
        pool,
        &username,
        "Initial password for test!42",
        false,
        true,
        4096,
        false,
    )
    .await
    .unwrap();
    let subscriber = format!("{requester}/desktop");
    let items = [("latest".to_owned(), "<item id='latest'/>".to_owned())];
    let pubsub = test_pubsub_service(pool.clone(), DOMAIN);
    for index in 0..PAGE_SIZE {
        let owner = format!("measure-replay-owner-{suffix}-{index}@{DOMAIN}");
        let name = format!("measure-replay-leaf-{suffix}-{index}");
        let subid = format!("measure-replay-{suffix}-{index}");
        let node = create_default_test_node(pool, &name, &owner).await;
        assert_eq!(
            publish_items(pool, &node, &owner, &items, false, STORAGE_LIMIT)
                .await
                .unwrap(),
            PublishItemsOutcome::Published
        );
        assert!(matches!(
            subscribe(pool, &node, &requester, &subscriber, &subid)
                .await
                .unwrap(),
            SubscribeOutcome::Subscribed(_)
        ));
        assert!(
            node.send_last_published_item == "on_sub_and_presence"
                && pubsub.can_retrieve_node(&node, &requester).await.unwrap(),
            "replay is denied for {}",
            node.node
        );
    }

    let query = PresenceReplayQuery {
        recipient: PubSubAddress::parse(&subscriber).unwrap(),
        recipient_id: account.id,
        expected_auth_generation: Some(account.auth_generation),
        connection_id: Uuid::new_v4(),
        active_privacy_list: None,
        service: PubSubBareJid::parse(&format!("pubsub.{DOMAIN}")).unwrap(),
        show: "online".to_owned(),
        after: None,
        limit: PAGE_SIZE,
    };
    scenario
        .run(
            "generic_replay_page",
            1,
            20,
            move |_, _| {
                let pubsub = pubsub.clone();
                let query = query.clone();
                async move { read_replay_page(&pubsub, &query).await }
            },
            |&()| true,
        )
        .await;

    scenario.close().await;
}

// Read exactly one page via the same service method as the available-presence
// handler. All fixture subscriptions should reach the latest-item read.
async fn read_replay_page(
    pubsub: &PubSubService<PostgresPubSubRepository>,
    query: &PresenceReplayQuery,
) -> Result<()> {
    let PresenceReplayPage::Candidates {
        candidates,
        scanned,
        next,
    } = pubsub.presence_replay_page(query).await?
    else {
        anyhow::bail!("replay page is denied");
    };
    ensure!(
        scanned == PAGE_SIZE && next.is_some(),
        "incomplete replay page"
    );
    ensure!(
        candidates.len() == PAGE_SIZE,
        "replay candidates were filtered"
    );
    for candidate in candidates {
        let subscription = &candidate.subscription;
        ensure!(
            subscription.state == "subscribed"
                && subscription.deliver
                && subscription
                    .show_values
                    .iter()
                    .any(|value| value == &query.show),
            "subscription is ineligible for replay: {subscription:?}"
        );
        ensure!(
            candidate.item.item_id == "latest",
            "latest item is missing for {}",
            candidate.node
        );
    }
    Ok(())
}
