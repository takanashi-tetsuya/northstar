use super::{Scenario, DOMAIN, STORAGE_LIMIT};
use northstar_pubsub_postgres::{
    create_node_and_publish_items_with_renderer, AutoCreatePublishOutcome,
    NoopMutationOutboxRenderer, PubSubNodeConfig,
};
use uuid::Uuid;

const WORKERS: usize = 16;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn measure_auto_create_contention() {
    let scenario = Scenario::new("auto_create_contention", WORKERS as u32).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("measure-auto-create-owner-{suffix}@{DOMAIN}");
    let config = PubSubNodeConfig::default();
    for (phase, same_name) in [("same_name", true), ("distinct_names", false)] {
        let pool = scenario.pool.clone();
        let owner = owner.clone();
        let config = config.clone();
        let name = format!("measure-auto-create-{suffix}-{phase}");
        scenario
            .run(
                phase,
                WORKERS,
                1,
                move |worker, _| {
                    let pool = pool.clone();
                    let owner = owner.clone();
                    let config = config.clone();
                    let node = if same_name {
                        name.clone()
                    } else {
                        format!("{name}-{worker}")
                    };
                    let id = format!("item-{worker}");
                    let items = [(id.clone(), format!("<item id='{id}'/>"))];
                    async move {
                        create_node_and_publish_items_with_renderer(
                            &pool,
                            &node,
                            &owner,
                            &config,
                            20,
                            &items,
                            STORAGE_LIMIT,
                            &NoopMutationOutboxRenderer,
                        )
                        .await
                    }
                },
                move |outcome| {
                    *outcome == AutoCreatePublishOutcome::Published
                        || same_name && *outcome == AutoCreatePublishOutcome::NodeExists
                },
            )
            .await;
    }

    scenario.close().await;
}
