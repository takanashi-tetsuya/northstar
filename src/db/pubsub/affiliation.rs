//! PubSub affiliation persistence.

use super::*;

pub async fn get_node_affiliation(
    pool: &PgPool,
    node_id: Uuid,
    jid: &str,
) -> Result<Option<String>> {
    let jid = northstar_xmpp_types::jid::canonical_bare_key(jid)?;
    let row =
        sqlx::query("SELECT affiliation FROM pubsub_affiliations WHERE node_id = $1 AND jid = $2")
            .bind(node_id)
            .bind(jid)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|row| row.get("affiliation")))
}

pub async fn affiliations_for_jid(
    pool: &PgPool,
    jid: &str,
    node: Option<&str>,
) -> Result<Vec<PubSubAffiliation>> {
    let jid = northstar_xmpp_types::jid::canonical_bare_key(jid)?;
    let rows = sqlx::query("SELECT n.node, a.jid, a.affiliation FROM pubsub_affiliations a JOIN pubsub_nodes n ON n.id = a.node_id WHERE a.jid = $1 AND a.affiliation <> 'none' AND ($2::TEXT IS NULL OR n.node = $2) ORDER BY n.node")
        .bind(jid)
        .bind(node)
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(row_to_affiliation).collect())
}

#[cfg(test)]
pub async fn set_affiliations(
    pool: &PgPool,
    node_id: Uuid,
    changes: &[(String, String)],
) -> Result<SetAffiliationsOutcome> {
    let requester: String = sqlx::query_scalar(
        "SELECT jid FROM pubsub_affiliations WHERE node_id = $1 AND affiliation = 'owner' ORDER BY jid LIMIT 1",
    )
    .bind(node_id)
    .fetch_one(pool)
    .await?;
    set_affiliations_with_outbox(pool, node_id, &requester, changes, None, None, &[]).await
}

pub async fn set_affiliations_with_renderer(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    changes: &[(String, String)],
    expected_revoked: Option<&[(String, String)]>,
    expected_approved: Option<&[(String, String)]>,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<SetAffiliationsOutcome> {
    let requester = northstar_xmpp_types::jid::canonical_bare_key(requester)?;
    let mut seen = std::collections::BTreeSet::new();
    let changes = changes
        .iter()
        .map(|(jid, affiliation)| {
            let jid = northstar_xmpp_types::jid::canonical_bare_key(jid)?;
            if !seen.insert(jid.clone()) {
                anyhow::bail!(
                    "PubSub affiliation batch contains canonically equivalent duplicate {jid}"
                );
            }
            Ok((jid, affiliation.as_str()))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    let node_exists =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM pubsub_nodes WHERE id = $1 FOR UPDATE")
            .bind(node_id)
            .fetch_optional(&mut *transaction)
            .await?;
    if node_exists.is_none() {
        transaction.rollback().await?;
        return Ok(SetAffiliationsOutcome::NotFound);
    }
    if !requester_is_owner(&mut transaction, node_id, &requester).await? {
        transaction.rollback().await?;
        return Ok(SetAffiliationsOutcome::Forbidden);
    }
    let node = get_node_by_id_in_transaction(&mut transaction, node_id)
        .await?
        .expect("locked PubSub node disappeared during affiliation update");
    let event_time = locked_event_time(&mut transaction).await?;
    let mut revoked_subscriptions = Vec::new();
    let mut approved_subscriptions = Vec::new();
    let mut revoked_details = Vec::new();
    let mut approved_details = Vec::new();
    let mut affiliation_transitions = Vec::new();
    for (jid, affiliation) in &changes {
        let previous: Option<String> = sqlx::query_scalar(
            "SELECT affiliation FROM pubsub_affiliations WHERE node_id=$1 AND jid=$2",
        )
        .bind(node_id)
        .bind(jid)
        .fetch_optional(&mut *transaction)
        .await?;
        let affected = sqlx::query("SELECT n.node,s.jid,s.state,s.subid,s.deliver,s.digest,s.digest_frequency,s.expire,s.include_body,s.show_values,s.subscription_type,s.subscription_depth FROM pubsub_subscriptions s JOIN pubsub_nodes n ON n.id=s.node_id WHERE s.node_id=$1 AND split_part(s.jid, '/', 1)=$2 ORDER BY s.jid FOR UPDATE")
            .bind(node_id)
            .bind(jid)
            .fetch_all(&mut *transaction)
            .await?;
        let affiliation_changed = if *affiliation == "none" {
            previous.as_deref().is_some_and(|value| value != "none")
        } else {
            previous.as_deref() != Some(*affiliation)
        };
        if affiliation_changed {
            if *affiliation == "none" {
                sqlx::query("DELETE FROM pubsub_affiliations WHERE node_id = $1 AND jid = $2")
                    .bind(node_id)
                    .bind(jid)
                    .execute(&mut *transaction)
                    .await?;
            } else {
                sqlx::query("INSERT INTO pubsub_affiliations (node_id, jid, affiliation) VALUES ($1, $2, $3) ON CONFLICT (node_id, jid) DO UPDATE SET affiliation = EXCLUDED.affiliation")
                    .bind(node_id)
                    .bind(jid)
                    .bind(affiliation)
                    .execute(&mut *transaction)
                    .await?;
            }
            affiliation_transitions.push((jid.clone(), (*affiliation).to_owned()));
        }
        if matches!(*affiliation, "outcast" | "publish-only") {
            for subscription in &affected {
                let mut subscription = row_to_subscription(subscription);
                revoked_subscriptions.push((subscription.jid.clone(), subscription.subid.clone()));
                subscription.state = "none".to_owned();
                revoked_details.push(subscription);
            }
            sqlx::query("DELETE FROM pubsub_digest_queue WHERE subscription_node_id = $1 AND split_part(subscriber_jid, '/', 1) = $2")
                .bind(node_id)
                .bind(jid)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("DELETE FROM pubsub_subscriptions WHERE node_id = $1 AND split_part(jid, '/', 1) = $2")
                .bind(node_id)
                .bind(jid)
                .execute(&mut *transaction)
                .await?;
        } else if matches!(*affiliation, "owner" | "publisher") {
            let subscriptions = sqlx::query(
                "UPDATE pubsub_subscriptions
                    SET state='subscribed', updated_at=$3
                  WHERE node_id=$1 AND split_part(jid, '/', 1)=$2 AND state='pending'
                    AND (expire IS NULL OR expire>$3)
                  RETURNING jid, subid",
            )
            .bind(node_id)
            .bind(jid)
            .bind(event_time)
            .fetch_all(&mut *transaction)
            .await?;
            approved_subscriptions.extend(
                subscriptions
                    .iter()
                    .map(|row| (row.get("jid"), row.get("subid"))),
            );
            approved_details.extend(affected.iter().filter_map(|row| {
                let mut subscription = row_to_subscription(row);
                if subscription.state != "pending"
                    || subscription
                        .expire
                        .is_some_and(|expire| expire <= event_time)
                {
                    return None;
                }
                subscription.state = "subscribed".to_owned();
                Some(subscription)
            }));
        }
    }
    let owner_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pubsub_affiliations WHERE node_id = $1 AND affiliation = 'owner'",
    )
    .bind(node_id)
    .fetch_one(&mut *transaction)
    .await?;
    if owner_count == 0 {
        transaction.rollback().await?;
        return Ok(SetAffiliationsOutcome::LastOwner);
    }
    if expected_revoked.is_some_and(|expected| expected != revoked_subscriptions)
        || expected_approved.is_some_and(|expected| expected != approved_subscriptions)
    {
        transaction.rollback().await?;
        anyhow::bail!("PubSub affiliation notification snapshot changed concurrently");
    }
    let last_item = if !approved_details.is_empty() && node.send_last_published_item != "never" {
        latest_item_in_transaction(&mut transaction, node.id).await?
    } else {
        None
    };
    let mut outbox = Vec::new();
    for (jid, affiliation) in &affiliation_transitions {
        outbox.extend(renderer.render_affiliation_transition(
            &node,
            jid,
            affiliation,
            Uuid::new_v4(),
            event_time,
        )?);
    }
    for subscription in &revoked_details {
        outbox.extend(renderer.render_subscription_transition(
            &node,
            subscription,
            std::slice::from_ref(&subscription.jid),
            &[],
            None,
            Uuid::new_v4(),
            event_time,
        )?);
    }
    for subscription in &approved_details {
        outbox.extend(renderer.render_subscription_transition(
            &node,
            subscription,
            std::slice::from_ref(&subscription.jid),
            &[],
            last_item.as_ref(),
            Uuid::new_v4(),
            event_time,
        )?);
    }
    enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
    transaction.commit().await?;
    Ok(SetAffiliationsOutcome::Updated {
        revoked_subscriptions,
        approved_subscriptions,
    })
}
