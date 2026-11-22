use super::super::create_default_test_node;
use super::{subscribe, Scenario, DOMAIN, STORAGE_LIMIT};
use northstar_pubsub_postgres::{
    publish_items, retract_items, PublishItemsOutcome, RetractItemsOutcome, SubscribeOutcome,
};
use uuid::Uuid;

const WORKERS: usize = 16;
const ITEMS_PER_WORKER: usize = 5;

fn concurrent_item_id(worker: usize, index: usize) -> String {
    format!("concurrent-{worker}-{index}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn measure_item_publish_and_retract_contention() {
    let scenario = Scenario::new("item_publish_and_retract_contention", WORKERS as u32).await;
    let pool = &scenario.pool;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("measure-items-owner-{suffix}@{DOMAIN}");
    let node = create_default_test_node(pool, &format!("measure-items-{suffix}"), &owner).await;
    for index in 0..50 {
        let subscriber = format!("measure-items-reader-{suffix}-{index}@{DOMAIN}");
        let subid = format!("measure-items-{suffix}-{index}");
        assert!(matches!(
            subscribe(pool, &node, &subscriber, &subscriber, &subid)
                .await
                .unwrap(),
            SubscribeOutcome::Subscribed(_)
        ));
    }

    for (phase, concurrency, ops_per_worker) in [
        ("publish_serial", 1, 20),
        ("publish_concurrent", WORKERS, ITEMS_PER_WORKER),
    ] {
        let pool = pool.clone();
        let node = node.clone();
        let owner = owner.clone();
        scenario
            .run(
                phase,
                concurrency,
                ops_per_worker,
                move |worker, index| {
                    let pool = pool.clone();
                    let node = node.clone();
                    let owner = owner.clone();
                    let id = if concurrency == 1 {
                        format!("serial-{index}")
                    } else {
                        concurrent_item_id(worker, index)
                    };
                    let items = [(id.clone(), format!("<item id='{id}'/>"))];
                    async move {
                        publish_items(&pool, &node, &owner, &items, false, STORAGE_LIMIT).await
                    }
                },
                |outcome| *outcome == PublishItemsOutcome::Published,
            )
            .await;
    }

    let pool = pool.clone();
    scenario
        .run(
            "retract_concurrent",
            WORKERS,
            1,
            move |worker, _| {
                let pool = pool.clone();
                let owner = owner.clone();
                let node_id = node.id;
                let item_ids: Vec<_> = (0..ITEMS_PER_WORKER)
                    .map(|index| concurrent_item_id(worker, index))
                    .collect();
                async move { retract_items(&pool, node_id, &item_ids, &owner, true).await }
            },
            |outcome| *outcome == RetractItemsOutcome::Retracted,
        )
        .await;

    scenario.close().await;
}
