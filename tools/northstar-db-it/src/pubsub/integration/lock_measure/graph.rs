use super::{Scenario, DOMAIN};
use northstar_pubsub_postgres::{
    associate_collection_child, create_node, dissociate_collection_child, get_node_by_id,
    CollectionUpdateOutcome, CreateNodeOutcome, PubSubNodeConfig,
};
use std::sync::Arc;
use uuid::Uuid;

const LEAVES: usize = 16;
const COLLECTIONS: usize = 4;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn measure_collection_graph_contention() {
    let scenario = Scenario::new("collection_graph_contention", LEAVES as u32).await;
    let pool = &scenario.pool;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("measure-graph-owner-{suffix}@{DOMAIN}");
    let config = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        persist_items: false,
        ..PubSubNodeConfig::default()
    };
    let mut collections = Vec::new();
    let mut leaves = Vec::new();
    for (count, config, nodes) in [
        (COLLECTIONS, config, &mut collections),
        (LEAVES, PubSubNodeConfig::default(), &mut leaves),
    ] {
        for index in 0..count {
            let name = format!("measure-graph-{}-{suffix}-{index}", config.node_type);
            let id = match create_node(pool, &name, &owner, &config, 100)
                .await
                .unwrap()
            {
                CreateNodeOutcome::Created(id) => id,
                other => panic!("unexpected graph node create outcome: {other:?}"),
            };
            nodes.push(get_node_by_id(pool, id).await.unwrap().unwrap());
        }
    }
    let collections = Arc::new(collections);
    let leaves = Arc::new(leaves);

    for (phase, concurrency, ops_per_worker) in [
        ("edges_concurrent", LEAVES, 2),
        ("edges_serial", 1, LEAVES * 2),
    ] {
        let pool = pool.clone();
        let owner = owner.clone();
        let collections = Arc::clone(&collections);
        let leaves = Arc::clone(&leaves);
        scenario
            .run(
                phase,
                concurrency,
                ops_per_worker,
                move |worker, index| {
                    let pool = pool.clone();
                    let owner = owner.clone();
                    let edge = worker * (ops_per_worker / 2) + index / 2;
                    let collection = collections[edge % COLLECTIONS].clone();
                    let leaf = leaves[edge].clone();
                    async move {
                        if index.is_multiple_of(2) {
                            associate_collection_child(&pool, &collection, &leaf, &owner).await
                        } else {
                            dissociate_collection_child(&pool, &collection, &leaf, &owner).await
                        }
                    }
                },
                |outcome| *outcome == CollectionUpdateOutcome::Updated,
            )
            .await;
    }

    scenario.close().await;
}
