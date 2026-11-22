//! PEP publication checks its explicit options against the locked node row.

use super::*;
use northstar_pubsub_application::{PepPublishItemsCommand, PepPublishItemsOutcome};
use northstar_pubsub_core::{
    requested_pep_publish_config, PepConfigPatch, PepPublishWrite, PepQuotas, PubSubAccount,
};
use northstar_workflows::pubsub_repository::test_pubsub_service;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn pep_explicit_options_are_checked_against_the_locked_node() {
    const NODE: &str = "urn:example:pep:locked-options";
    let (url, pool) = integration_pool(8).await;
    let owner_id = Uuid::new_v4();
    let username = format!("pepoptions{}", &owner_id.simple().to_string()[..10]);
    let auth_generation = sqlx::query_scalar(
        "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test') RETURNING auth_generation",
    )
    .bind(owner_id)
    .bind(&username)
    .fetch_one(&pool)
    .await
    .unwrap();
    let owner = PubSubAccount {
        id: owner_id,
        username,
        auth_generation,
    };
    let requested = requested_pep_publish_config(NODE, Some(&PepConfigPatch::default())).unwrap();
    let config = PepNodeConfig::from(&requested.config);
    assert_eq!(
        create_pep_node(&pool, &owner, NODE, &config, 10)
            .await
            .unwrap(),
        PepCreateOutcome::Created
    );

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM pep_nodes WHERE owner_id=$1 AND node=$2 FOR UPDATE")
        .bind(owner_id)
        .bind(NODE)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let application = format!("ps-pep-options-{}", &owner_id.simple().to_string()[..8]);
    let publish_pool = named_single_connection_pool(&url, &application).await;
    let service = test_pubsub_service(publish_pool.clone(), "example.test");
    let publish = tokio::spawn(async move {
        let stored = service.pep_node(owner.id, NODE).await.unwrap();
        assert_eq!(stored.as_ref(), Some(&requested.config));
        let items = [(
            "item",
            "<item id='item'><entry xmlns='urn:example:entry'/></item>",
        )];
        service
            .publish_pep_items(
                PepPublishItemsCommand::new(
                    PepPublishWrite {
                        user_id: owner.id,
                        username: &owner.username,
                        auth_generation: owner.auth_generation,
                        connection_id: Uuid::new_v4(),
                        node: NODE,
                        requested: &requested.config,
                        enforce_preconditions: requested.explicit,
                        items: &items,
                        quotas: PepQuotas {
                            max_nodes: 10,
                            max_storage_bytes: 1_000_000,
                        },
                    },
                    false,
                ),
                &|audience: &PepAudienceSnapshot| {
                    let jid = &audience.owner_bare_jid;
                    Ok(vec![(
                        jid.clone(),
                        format!("<message xmlns='jabber:client' from='{jid}' to='{jid}'/>"),
                    )])
                },
            )
            .await
    });
    wait_for_named_session_lock(&pool, &application).await;
    assert_eq!(
        sqlx::query("UPDATE pep_nodes SET max_items=2 WHERE owner_id=$1 AND node=$2")
            .bind(owner_id)
            .bind(NODE)
            .execute(&mut *blocker)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    blocker.commit().await.unwrap();

    let result = publish.await.unwrap().unwrap();
    assert_eq!(result.outcome, PepPublishItemsOutcome::PreconditionFailed);
    assert!(!result.content_changed);
    assert!(pep_items(&pool, owner_id, NODE, None, 10)
        .await
        .unwrap()
        .is_empty());
    let outbox_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pubsub_event_outbox WHERE pep_sender_account_id=$1 AND source_node=$2",
    )
    .bind(owner_id)
    .bind(NODE)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(outbox_count, 0);

    publish_pool.close().await;
    pool.close().await;
}
