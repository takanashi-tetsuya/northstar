use super::super::create_default_test_node;
use super::{subscribe, Scenario, DOMAIN};
use northstar_pubsub_postgres::{
    unsubscribe_checked_with_outbox, update_subscription_options_checked,
    PubSubSubscriptionOptions, SubscribeOutcome, SubscriptionOptionsOutcome, UnsubscribeOutcome,
};
use uuid::Uuid;

const WORKERS: usize = 32;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn measure_subscription_contention() {
    let scenario = Scenario::new("subscription_contention", WORKERS as u32).await;
    let pool = scenario.pool.clone();
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("measure-subscriptions-owner-{suffix}@{DOMAIN}");
    let node =
        create_default_test_node(&pool, &format!("measure-subscriptions-{suffix}"), &owner).await;
    let identity = move |worker| {
        let subid = format!("measure-subscriptions-{suffix}-{worker}");
        let jid = format!("{subid}@{DOMAIN}");
        (jid, subid)
    };
    let node_id = node.id;
    let options = PubSubSubscriptionOptions {
        deliver: false,
        ..PubSubSubscriptionOptions::for_node_type(&node.node_type)
    };

    scenario
        .run(
            "subscribe_concurrent",
            WORKERS,
            1,
            {
                let pool = pool.clone();
                let identity = identity.clone();
                move |worker, _| {
                    let pool = pool.clone();
                    let node = node.clone();
                    let (jid, subid) = identity(worker);
                    async move { subscribe(&pool, &node, &jid, &jid, &subid).await }
                }
            },
            |outcome| matches!(outcome, SubscribeOutcome::Subscribed(_)),
        )
        .await;

    scenario
        .run(
            "options_concurrent",
            WORKERS,
            1,
            {
                let pool = pool.clone();
                let identity = identity.clone();
                move |worker, _| {
                    let pool = pool.clone();
                    let (jid, subid) = identity(worker);
                    let options = options.clone();
                    async move {
                        update_subscription_options_checked(
                            &pool,
                            DOMAIN,
                            node_id,
                            &jid,
                            &jid,
                            Some(&subid),
                            &options,
                        )
                        .await
                    }
                }
            },
            |outcome| *outcome == SubscriptionOptionsOutcome::Updated,
        )
        .await;

    scenario
        .run(
            "unsubscribe_concurrent",
            WORKERS,
            1,
            move |worker, _| {
                let pool = pool.clone();
                let (jid, subid) = identity(worker);
                async move {
                    unsubscribe_checked_with_outbox(&pool, node_id, &jid, &jid, &subid, &[]).await
                }
            },
            |outcome| *outcome == UnsubscribeOutcome::Unsubscribed,
        )
        .await;

    scenario.close().await;
}
