use super::super::create_default_test_node;
use super::{subscribe, Scenario, DOMAIN, STORAGE_LIMIT};
use anyhow::{ensure, Context, Result};
use northstar_pubsub_application::PubSubService;
use northstar_pubsub_postgres::{publish_items, PublishItemsOutcome, SubscribeOutcome};
use northstar_workflows::pubsub_repository::{test_pubsub_service, PostgresPubSubRepository};
use uuid::Uuid;

const PAGE_SIZE: i64 = 100;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn measure_presence_replay_reads() {
    let scenario = Scenario::new("presence_replay_reads", 1).await;
    let pool = &scenario.pool;
    let suffix = Uuid::new_v4().simple().to_string();
    let requester = format!("measure-replay-reader-{suffix}@{DOMAIN}");
    let subscriber = format!("{requester}/desktop");
    let items = [("latest".to_owned(), "<item id='latest'/>".to_owned())];
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
    }

    let pubsub = test_pubsub_service(pool.clone(), DOMAIN);
    scenario
        .run(
            "generic_replay_page",
            1,
            20,
            move |_, _| {
                let pubsub = pubsub.clone();
                let requester = requester.clone();
                let subscriber = subscriber.clone();
                async move { read_replay_page(&pubsub, &requester, &subscriber).await }
            },
            |&()| true,
        )
        .await;

    scenario.close().await;
}

// Read exactly one page via the same service methods as the available-presence
// handler. All fixture subscriptions should reach the latest-item read.
async fn read_replay_page(
    pubsub: &PubSubService<PostgresPubSubRepository>,
    requester: &str,
    subscriber: &str,
) -> Result<()> {
    let page = pubsub
        .subscriptions_addressing_jid_page(subscriber, None, PAGE_SIZE)
        .await?;
    ensure!(page.len() == PAGE_SIZE as usize, "incomplete replay page");
    for subscription in page {
        ensure!(
            subscription.state == "subscribed"
                && subscription.deliver
                && subscription
                    .show_values
                    .iter()
                    .any(|value| value == "online"),
            "subscription is ineligible for replay: {subscription:?}"
        );
        let node = pubsub
            .get_node(&subscription.node)
            .await?
            .context("replay node is missing")?;
        ensure!(
            node.send_last_published_item == "on_sub_and_presence"
                && pubsub.can_retrieve_node(&node, requester).await?,
            "replay is denied for {}",
            subscription.node
        );
        let items = pubsub.get_items(node.id, &[], 1).await?;
        ensure!(
            items.first().is_some_and(|item| item.item_id == "latest"),
            "latest item is missing for {}",
            subscription.node
        );
    }
    Ok(())
}
