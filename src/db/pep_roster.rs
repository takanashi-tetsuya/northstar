//! PEP's reads of the roster context's tables: roster-group access and the owners whose roster grants a
//! subscriber presence. They stay in the root crate until the roster context provides them through a port.

use anyhow::Result;
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub async fn roster_group_allowed(
    pool: &PgPool,
    owner_id: Uuid,
    jid: &str,
    groups: &[String],
) -> Result<bool> {
    if groups.is_empty() {
        return Ok(false);
    }
    let jid = northstar_xmpp_types::jid::canonical_bare_key(jid)?;
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM roster_items r, jsonb_array_elements_text(r.groups) g(name) WHERE r.owner_id=$1 AND r.contact_jid=$2 AND g.name = ANY($3))")
        .bind(owner_id).bind(&jid).bind(groups).fetch_one(pool).await.map_err(Into::into)
}

/// Returns local PEP owners whose roster grants presence visibility to the
/// supplied subscriber. The caller still applies node-level access and block
/// checks; this query only bounds the candidate owner set.
pub async fn pep_owner_usernames_for_presence_subscriber(
    pool: &PgPool,
    subscriber_bare: &str,
) -> Result<Vec<String>> {
    let subscriber_bare = northstar_xmpp_types::jid::canonical_bare_key(subscriber_bare)?;
    let rows = sqlx::query(
        "SELECT u.username FROM roster_items r JOIN users u ON u.id=r.owner_id WHERE r.contact_jid=$1 AND r.subscription IN ('from','both') ORDER BY u.username LIMIT 10000",
    )
    .bind(&subscriber_bare)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(|row| row.get("username")).collect())
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::db;
    use northstar_pubsub_postgres::*;

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn pep_node_subscription_and_item_transitions_are_atomic() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let suffix = Uuid::new_v4().simple().to_string();
        let first_owner = Uuid::new_v4();
        let second_owner = Uuid::new_v4();
        for (id, username) in [
            (first_owner, format!("pep-a-{}", &suffix[..12])),
            (second_owner, format!("pep-b-{}", &suffix[..12])),
        ] {
            sqlx::query(
                "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'integration-test')",
            )
            .bind(id)
            .bind(username)
            .execute(&pool)
            .await
            .unwrap();
        }

        let config = default_pep_node_config("urn:example:pep");
        let (left, right) = tokio::join!(
            create_pep_node(&pool, first_owner, "urn:example:first", &config, 1),
            create_pep_node(&pool, first_owner, "urn:example:second", &config, 1),
        );
        let outcomes = [left.unwrap(), right.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == PepCreateOutcome::Created)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == PepCreateOutcome::QuotaExceeded)
                .count(),
            1
        );
        let first_node = if outcomes[0] == PepCreateOutcome::Created {
            "urn:example:first"
        } else {
            "urn:example:second"
        };
        assert_eq!(
            create_pep_node(&pool, second_owner, "urn:example:other", &config, 10)
                .await
                .unwrap(),
            PepCreateOutcome::Created
        );

        let subscriber = format!("remote-{suffix}@remote.test/phone");
        let first = subscribe_pep_node(&pool, first_owner, first_node, &subscriber, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.jid, subscriber);
        let available = pep_subscriptions_for_available_resource(&pool, &subscriber)
            .await
            .unwrap();
        assert_eq!(available.len(), 1);
        assert_eq!(available[0].owner_id, first_owner);
        assert_eq!(available[0].node, first_node);
        assert!(pep_subscriptions_for_available_resource(
            &pool,
            &format!("remote-{suffix}@remote.test/tablet"),
        )
        .await
        .unwrap()
        .is_empty());
        assert!(subscribe_pep_node(
            &pool,
            second_owner,
            "urn:example:other",
            &format!("remote-{suffix}@remote.test/tablet"),
            1,
        )
        .await
        .unwrap()
        .is_none());

        let subscriber_bare = northstar_xmpp_types::jid_text::bare_jid(&subscriber).to_owned();
        db::update_subscription(&pool, first_owner, &subscriber_bare, "from", None)
            .await
            .unwrap();
        db::update_subscription(&pool, first_owner, &subscriber_bare, "none", None)
            .await
            .unwrap();
        assert!(pep_subscribers(&pool, first_owner, first_node)
            .await
            .unwrap()
            .is_empty());

        let mut roster_config = config.clone();
        roster_config.access_model = "roster".to_owned();
        roster_config.roster_groups_allowed = vec!["friends".to_owned()];
        assert!(
            update_pep_node_config(&pool, second_owner, "urn:example:other", &roster_config,)
                .await
                .unwrap()
        );
        db::update_subscription(&pool, second_owner, &subscriber_bare, "from", None)
            .await
            .unwrap();
        db::upsert_roster(
            &pool,
            second_owner,
            &subscriber_bare,
            None,
            &["friends".to_owned()],
        )
        .await
        .unwrap();
        assert!(
            subscribe_pep_node(&pool, second_owner, "urn:example:other", &subscriber, 1,)
                .await
                .unwrap()
                .is_some()
        );
        db::upsert_roster(
            &pool,
            second_owner,
            &subscriber_bare,
            None,
            &["coworkers".to_owned()],
        )
        .await
        .unwrap();
        assert!(pep_subscribers(&pool, second_owner, "urn:example:other")
            .await
            .unwrap()
            .is_empty());

        db::update_subscription(&pool, first_owner, &subscriber_bare, "from", None)
            .await
            .unwrap();
        assert!(
            subscribe_pep_node(&pool, first_owner, first_node, &subscriber, 1)
                .await
                .unwrap()
                .is_some()
        );
        db::delete_roster(&pool, first_owner, &subscriber_bare)
            .await
            .unwrap();
        assert!(pep_subscribers(&pool, first_owner, first_node)
            .await
            .unwrap()
            .is_empty());

        let batch_a = format!("batch-a-{suffix}@remote.test/phone");
        let batch_b = format!("batch-b-{suffix}@remote.test/tablet");
        let batch_a_sub = subscribe_pep_node(&pool, first_owner, first_node, &batch_a, 10)
            .await
            .unwrap()
            .unwrap();
        let batch_b_sub = subscribe_pep_node(&pool, first_owner, first_node, &batch_b, 10)
            .await
            .unwrap()
            .unwrap();
        assert!(!unsubscribe_pep_nodes_batch(
            &pool,
            first_owner,
            first_node,
            &[
                (batch_a.clone(), Some(batch_a_sub.subid.clone())),
                (batch_b.clone(), Some("stale-subid".to_owned())),
            ],
        )
        .await
        .unwrap());
        let still_subscribed = pep_subscribers(&pool, first_owner, first_node)
            .await
            .unwrap();
        assert!(still_subscribed.iter().any(|sub| sub.jid == batch_a));
        assert!(still_subscribed.iter().any(|sub| sub.jid == batch_b));
        assert!(unsubscribe_pep_nodes_batch(
            &pool,
            first_owner,
            first_node,
            &[
                (batch_a, Some(batch_a_sub.subid)),
                (batch_b, Some(batch_b_sub.subid)),
            ],
        )
        .await
        .unwrap());

        assert_eq!(
            publish_pep_items(
                &pool,
                first_owner,
                first_node,
                config.clone(),
                true,
                &[(
                    "one",
                    "<item id='one'><value xmlns='urn:example'>1</value></item>"
                )],
                PepQuotas {
                    max_nodes: 1,
                    max_storage_bytes: 1024,
                },
            )
            .await
            .unwrap(),
            PepPublishOutcome::Published
        );
        let mut conflicting = config.clone();
        conflicting.access_model = "open".to_owned();
        assert_eq!(
            publish_pep_items(
                &pool,
                first_owner,
                first_node,
                conflicting,
                true,
                &[("two", "<item id='two'/>")],
                PepQuotas {
                    max_nodes: 1,
                    max_storage_bytes: 1024,
                },
            )
            .await
            .unwrap(),
            PepPublishOutcome::PreconditionFailed
        );
        let mut limited = config.clone();
        limited.max_items = 1;
        assert!(
            update_pep_node_config(&pool, first_owner, first_node, &limited)
                .await
                .unwrap()
        );
        assert_eq!(
            publish_pep_items(
                &pool,
                first_owner,
                first_node,
                config.clone(),
                false,
                &[("two", "<item id='two'/>"), ("three", "<item id='three'/>"),],
                PepQuotas {
                    max_nodes: 1,
                    max_storage_bytes: 1024,
                },
            )
            .await
            .unwrap(),
            PepPublishOutcome::MaxItemsExceeded
        );
        assert_eq!(
            retract_pep_items(&pool, first_owner, first_node, &["one", "missing"])
                .await
                .unwrap(),
            Some(0)
        );
        assert_eq!(
            pep_items(&pool, first_owner, first_node, Some("one"), 1)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(purge_pep_node(&pool, first_owner, first_node)
            .await
            .unwrap());
        assert!(pep_items(&pool, first_owner, first_node, None, 10)
            .await
            .unwrap()
            .is_empty());
        assert!(delete_pep_node(&pool, first_owner, first_node)
            .await
            .unwrap());
        assert!(pep_subscribers(&pool, first_owner, first_node)
            .await
            .unwrap()
            .is_empty());

        sqlx::query("DELETE FROM users WHERE id=ANY($1)")
            .bind(vec![first_owner, second_owner])
            .execute(&pool)
            .await
            .unwrap();
    }
}
