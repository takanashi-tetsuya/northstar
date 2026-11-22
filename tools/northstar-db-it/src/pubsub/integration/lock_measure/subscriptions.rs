use super::super::create_default_test_node;
use super::{Scenario, DOMAIN};
use northstar_pubsub_core::{
    PubSubAddress, PubSubNodeId, PubSubSubscribeOutcome, PubSubTimeSources,
    PubSubUnsubscribeOutcome, RequestedSubId, SubscriptionOptionsPatch,
};
use northstar_pubsub_postgres::{
    patch_subscription_options_checked, subscribe_checked_with_renderer,
    unsubscribe_current_with_renderer, NoopMutationOutboxRenderer, SubscriptionOptionsOutcome,
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
    let node_id = PubSubNodeId::new(node.id);
    let patch = SubscriptionOptionsPatch {
        deliver: Some(false),
        ..SubscriptionOptionsPatch::default()
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
                    let (jid, subid) = identity(worker);
                    async move {
                        let subscriber = PubSubAddress::parse(&jid)?;
                        subscribe_checked_with_renderer(
                            &pool,
                            DOMAIN,
                            node_id,
                            &subscriber.bare(),
                            &subscriber,
                            1_000,
                            Some(&SubscriptionOptionsPatch::default()),
                            &subid,
                            &PubSubTimeSources::default(),
                            &NoopMutationOutboxRenderer,
                        )
                        .await
                    }
                }
            },
            |outcome| matches!(outcome, PubSubSubscribeOutcome::Subscribed(_)),
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
                    let patch = patch.clone();
                    async move {
                        let subscriber = PubSubAddress::parse(&jid)?;
                        patch_subscription_options_checked(
                            &pool,
                            DOMAIN,
                            node_id,
                            &subscriber.bare(),
                            &subscriber,
                            Some(&subid),
                            &patch,
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
                    let subscriber = PubSubAddress::parse(&jid)?;
                    unsubscribe_current_with_renderer(
                        &pool,
                        node_id,
                        &subscriber.bare(),
                        &subscriber,
                        RequestedSubId(Some(&subid)),
                        &PubSubTimeSources::default(),
                        &NoopMutationOutboxRenderer,
                    )
                    .await
                }
            },
            |outcome| {
                matches!(
                    outcome,
                    PubSubUnsubscribeOutcome::Unsubscribed { subid: Some(_) }
                )
            },
        )
        .await;

    scenario.close().await;
}
