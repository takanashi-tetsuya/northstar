//! Generic subscription commands evaluated under the node and subscription locks.

use super::{subscription::SUBSCRIPTION_ROW_SQL, *};
use northstar_pubsub_core::{
    pubsub_subscribe_policy, subscription_options_match_node_policy, PubSubAddress, PubSubBareJid,
    PubSubNodeId, PubSubSubscribeDecision, PubSubSubscribeOutcome, PubSubSubscribePolicy,
    PubSubSubscription as CoreSubscription, PubSubSubscriptionOptions as CoreOptions,
    PubSubTimeSources, PubSubUnsubscribeOutcome, RequestedSubId, SubscriptionLeasePatch,
    SubscriptionOptionsPatch,
};
use northstar_xep_0060::subscription_show_values_allowed;

async fn lock_subscription_node(
    transaction: &mut Transaction<'_, Postgres>,
    node_id: Uuid,
) -> Result<Option<PubSubNode>> {
    let locked =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM pubsub_nodes WHERE id=$1 FOR UPDATE")
            .bind(node_id)
            .fetch_optional(&mut **transaction)
            .await?;
    if locked.is_none() {
        return Ok(None);
    }
    get_node_by_id_in_transaction(transaction, node_id).await
}

async fn lock_subscription_row(
    transaction: &mut Transaction<'_, Postgres>,
    node_id: Uuid,
    jid: &str,
) -> Result<Option<PubSubSubscription>> {
    let sql = format!("{SUBSCRIPTION_ROW_SQL} FOR UPDATE OF s");
    let row = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
        .bind(node_id)
        .bind(jid)
        .fetch_optional(&mut **transaction)
        .await?;
    Ok(row.as_ref().map(row_to_subscription))
}

async fn write_subscription_options(
    transaction: &mut Transaction<'_, Postgres>,
    node_id: Uuid,
    jid: &str,
    subid: &str,
    options: &CoreOptions,
    event_time: DateTime<Utc>,
) -> Result<bool> {
    let result = sqlx::query("UPDATE pubsub_subscriptions SET deliver = $3, digest = $4, digest_frequency = $5, expire = $6, include_body = $7, show_values = $8, subscription_type = $9, subscription_depth = $10, updated_at = $12 WHERE node_id = $1 AND jid = $2 AND subid = $11")
        .bind(node_id)
        .bind(jid)
        .bind(options.deliver)
        .bind(options.digest)
        .bind(options.digest_frequency)
        .bind(options.expire)
        .bind(options.include_body)
        .bind(&options.show_values)
        .bind(&options.subscription_type)
        .bind(options.subscription_depth)
        .bind(subid)
        .bind(event_time)
        .execute(&mut **transaction)
        .await?;
    Ok(result.rows_affected() == 1)
}

/// Merge the submitted fields into the options of the locked subscription.
pub async fn patch_subscription_options_checked(
    pool: &PgPool,
    local_domain: &str,
    node_id: PubSubNodeId,
    requester: &PubSubBareJid,
    subscriber: &PubSubAddress,
    expected_subid: Option<&str>,
    patch: &SubscriptionOptionsPatch,
) -> Result<SubscriptionOptionsOutcome> {
    if subscriber.bare() != *requester {
        return Ok(SubscriptionOptionsOutcome::Forbidden);
    }
    let node_id = node_id.get();
    let jid = subscriber.to_string();
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    let Some(node) = lock_subscription_node(&mut transaction, node_id).await? else {
        transaction.rollback().await?;
        return Ok(SubscriptionOptionsOutcome::NotFound);
    };
    let current = lock_subscription_row(&mut transaction, node_id, &jid).await?;
    let event_time = locked_event_time(&mut transaction).await?;
    let Some(current) = current.filter(|row| row.expire.is_none_or(|expire| expire > event_time))
    else {
        transaction.rollback().await?;
        return Ok(SubscriptionOptionsOutcome::NotFound);
    };
    if expected_subid.is_some_and(|expected| expected != current.subid) {
        transaction.rollback().await?;
        return Ok(SubscriptionOptionsOutcome::InvalidSubid);
    }
    let base = CoreOptions {
        deliver: current.deliver,
        digest: current.digest,
        digest_frequency: current.digest_frequency,
        expire: current.expire,
        include_body: current.include_body,
        show_values: current.show_values,
        subscription_type: current.subscription_type,
        subscription_depth: current.subscription_depth,
    };
    let merged = patch.apply_to(&base);
    if !subscription_options_match_node_policy(
        &node.node_type,
        node.payload_type.as_deref(),
        base.subscription_depth,
        &merged,
    ) || !subscription_show_values_allowed(
        requester.canonical().domainpart(),
        local_domain,
        &merged.show_values,
    ) {
        transaction.rollback().await?;
        return Ok(SubscriptionOptionsOutcome::InvalidOptions);
    }
    if !patch.is_empty()
        && !write_subscription_options(
            &mut transaction,
            node_id,
            &jid,
            &current.subid,
            &merged,
            event_time,
        )
        .await?
    {
        transaction.rollback().await?;
        return Ok(SubscriptionOptionsOutcome::InvalidSubid);
    }
    transaction.commit().await?;
    Ok(SubscriptionOptionsOutcome::Updated)
}

/// Compatibility entry point for callers supplying a complete options image.
pub async fn update_subscription_options_checked(
    pool: &PgPool,
    local_domain: &str,
    node_id: Uuid,
    requester: &str,
    subscriber_jid: &str,
    expected_subid: Option<&str>,
    options: &PubSubSubscriptionOptions,
) -> Result<SubscriptionOptionsOutcome> {
    let patch = SubscriptionOptionsPatch {
        deliver: Some(options.deliver),
        digest: Some(options.digest),
        digest_frequency: Some(options.digest_frequency),
        include_body: Some(options.include_body),
        show_values: Some(options.show_values.clone()),
        subscription_type: Some(options.subscription_type.clone()),
        subscription_depth: Some(options.subscription_depth),
        expire: Some(
            options
                .expire
                .map_or(SubscriptionLeasePatch::Clear, SubscriptionLeasePatch::Until),
        ),
    };
    patch_subscription_options_checked(
        pool,
        local_domain,
        PubSubNodeId::new(node_id),
        &PubSubAddress::parse(requester)?.bare(),
        &PubSubAddress::parse(subscriber_jid)?,
        expected_subid,
        &patch,
    )
    .await
}

/// Subscribe using the state and policy protected by the mutation locks.
#[allow(clippy::too_many_arguments)]
pub async fn subscribe_checked_with_renderer(
    pool: &PgPool,
    local_domain: &str,
    node_id: PubSubNodeId,
    requester: &PubSubBareJid,
    subscriber: &PubSubAddress,
    max_subscriptions: i64,
    patch: Option<&SubscriptionOptionsPatch>,
    planned_subid: &str,
    time: &PubSubTimeSources,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<PubSubSubscribeOutcome> {
    subscribe_locked(
        pool,
        local_domain,
        node_id,
        requester,
        subscriber,
        max_subscriptions,
        SubscribeInput::Patch(patch),
        planned_subid,
        time,
        renderer,
    )
    .await
}

enum SubscribeInput<'a> {
    Patch(Option<&'a SubscriptionOptionsPatch>),
    Checked {
        state: &'a str,
        node_type: &'a str,
        access_model: &'a str,
        options: Option<&'a PubSubSubscriptionOptions>,
    },
}

/// Compatibility entry point for callers supplying the old write preconditions.
#[allow(clippy::too_many_arguments)]
pub async fn set_subscription_limited_with_options_and_renderer(
    pool: &PgPool,
    local_domain: &str,
    node_id: Uuid,
    requester: &str,
    jid: &str,
    state: &str,
    expected_node_type: &str,
    expected_access_model: &str,
    max_subscriptions: i64,
    options: Option<&PubSubSubscriptionOptions>,
    requested_subid: &str,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<SubscribeOutcome> {
    let outcome = subscribe_locked(
        pool,
        local_domain,
        PubSubNodeId::new(node_id),
        &PubSubAddress::parse(requester)?.bare(),
        &PubSubAddress::parse(jid)?,
        max_subscriptions,
        SubscribeInput::Checked {
            state,
            node_type: expected_node_type,
            access_model: expected_access_model,
            options,
        },
        requested_subid,
        &PubSubTimeSources::default(),
        renderer,
    )
    .await?;
    Ok(match outcome {
        PubSubSubscribeOutcome::Subscribed(row) => SubscribeOutcome::Subscribed((&row).into()),
        PubSubSubscribeOutcome::NotFound => SubscribeOutcome::NotFound,
        PubSubSubscribeOutcome::Forbidden => SubscribeOutcome::Forbidden,
        PubSubSubscribeOutcome::ClosedNode => SubscribeOutcome::ClosedNode,
        PubSubSubscribeOutcome::LimitExceeded => SubscribeOutcome::LimitExceeded,
        PubSubSubscribeOutcome::InvalidOptions => SubscribeOutcome::InvalidOptions,
        PubSubSubscribeOutcome::PreconditionFailed
        | PubSubSubscribeOutcome::PendingSubscription
        | PubSubSubscribeOutcome::ExistingActive(_) => SubscribeOutcome::PreconditionFailed,
    })
}

#[allow(clippy::too_many_arguments)]
async fn subscribe_locked(
    pool: &PgPool,
    local_domain: &str,
    node_id: PubSubNodeId,
    requester: &PubSubBareJid,
    subscriber: &PubSubAddress,
    max_subscriptions: i64,
    input: SubscribeInput<'_>,
    planned_subid: &str,
    time: &PubSubTimeSources,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<PubSubSubscribeOutcome> {
    if subscriber.bare() != *requester {
        return Ok(PubSubSubscribeOutcome::Forbidden);
    }
    let node_id = node_id.get();
    let jid = subscriber.to_string();
    let bare = requester.to_string();
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    let Some(node) = lock_subscription_node(&mut transaction, node_id).await? else {
        transaction.rollback().await?;
        return Ok(PubSubSubscribeOutcome::NotFound);
    };
    if matches!(
        &input,
        SubscribeInput::Checked { node_type, access_model, .. }
            if node.node_type != *node_type || node.access_model != *access_model
    ) {
        transaction.rollback().await?;
        return Ok(PubSubSubscribeOutcome::PreconditionFailed);
    }
    let affiliation: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM pubsub_affiliations WHERE node_id = $1 AND jid = $2",
    )
    .bind(node_id)
    .bind(&bare)
    .fetch_optional(&mut *transaction)
    .await?;
    let policy = pubsub_subscribe_policy(&node.access_model, affiliation.as_deref());
    if let SubscribeInput::Checked { state, .. } = &input {
        let authorized_state = match policy {
            PubSubSubscribePolicy::Subscribed => "subscribed",
            PubSubSubscribePolicy::Pending => "pending",
            PubSubSubscribePolicy::ClosedNode => {
                transaction.rollback().await?;
                return Ok(PubSubSubscribeOutcome::ClosedNode);
            }
            PubSubSubscribePolicy::Forbidden => {
                transaction.rollback().await?;
                return Ok(PubSubSubscribeOutcome::Forbidden);
            }
        };
        if *state != authorized_state {
            transaction.rollback().await?;
            return Ok(PubSubSubscribeOutcome::PreconditionFailed);
        }
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 2))")
        .bind(&jid)
        .execute(&mut *transaction)
        .await?;
    let existing: Option<CoreSubscription> = lock_subscription_row(&mut transaction, node_id, &jid)
        .await?
        .map(Into::into);
    let event_time = locked_event_time(&mut transaction).await?;
    let expired = existing
        .as_ref()
        .is_some_and(|row| row.is_expired_at(event_time));
    let live = existing.as_ref().filter(|_| !expired);
    let (state, subid, options) = match input {
        SubscribeInput::Patch(patch) => {
            let state = match policy.subscription_decision(
                existing.as_ref(),
                patch.is_some(),
                event_time,
            ) {
                PubSubSubscribeDecision::Write(state) => state,
                PubSubSubscribeDecision::Reply(outcome) => {
                    transaction.rollback().await?;
                    return Ok(outcome);
                }
            };
            if node.node_type != "collection"
                && patch.is_some_and(|patch| patch.subscription_depth.is_some())
            {
                transaction.rollback().await?;
                return Ok(PubSubSubscribeOutcome::InvalidOptions);
            }
            let defaults = CoreOptions::for_node_type(&node.node_type);
            let options = match patch {
                Some(patch) => patch.apply_to(&defaults),
                None => defaults,
            };
            let subid = existing
                .as_ref()
                .map_or(planned_subid, |row| row.subid.as_str());
            (state, subid, Some(options))
        }
        SubscribeInput::Checked { state, options, .. } => {
            if live.is_some_and(|row| row.state == "pending") {
                transaction.rollback().await?;
                return Ok(PubSubSubscribeOutcome::PreconditionFailed);
            }
            let subid = live.map_or(planned_subid, |row| row.subid.as_str());
            (state, subid, options.cloned().map(CoreOptions::from))
        }
    };
    if let Some(options) = &options {
        if !subscription_options_match_node_policy(
            &node.node_type,
            node.payload_type.as_deref(),
            Some(1),
            options,
        ) || !subscription_show_values_allowed(
            requester.canonical().domainpart(),
            local_domain,
            &options.show_values,
        ) {
            transaction.rollback().await?;
            return Ok(PubSubSubscribeOutcome::InvalidOptions);
        }
    }
    if expired {
        delete_legacy_subscription_digests(&mut transaction, node_id, &jid).await?;
        sqlx::query("DELETE FROM pubsub_subscriptions WHERE node_id = $1 AND jid = $2")
            .bind(node_id)
            .bind(&jid)
            .execute(&mut *transaction)
            .await?;
    }
    let state_changed = live.is_none_or(|row| row.state != state);
    if live.is_none() {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pubsub_subscriptions WHERE split_part(jid, '/', 1) = $1 AND (expire IS NULL OR expire > $2)",
        )
        .bind(&bare)
        .bind(event_time)
        .fetch_one(&mut *transaction)
        .await?;
        if count >= max_subscriptions {
            transaction.rollback().await?;
            return Ok(PubSubSubscribeOutcome::LimitExceeded);
        }
    }
    sqlx::query("INSERT INTO pubsub_subscriptions (node_id, jid, state, subid, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $5) ON CONFLICT (node_id, jid) DO UPDATE SET state = EXCLUDED.state, updated_at = EXCLUDED.updated_at")
        .bind(node_id)
        .bind(&jid)
        .bind(state)
        .bind(subid)
        .bind(event_time)
        .execute(&mut *transaction)
        .await?;
    if let Some(options) = &options {
        anyhow::ensure!(
            write_subscription_options(&mut transaction, node_id, &jid, subid, options, event_time)
                .await?,
            "PubSub subscription identity changed during atomic notification projection"
        );
    }
    let row = sqlx::query(SUBSCRIPTION_ROW_SQL)
        .bind(node_id)
        .bind(&jid)
        .fetch_one(&mut *transaction)
        .await?;
    let subscription = row_to_subscription(&row);
    anyhow::ensure!(
        subscription.subid == subid,
        "PubSub subscription identity changed during atomic notification projection"
    );
    if state_changed {
        let owners = if node.notify_sub || subscription.state == "pending" {
            owner_jids_in_transaction(&mut transaction, node.id).await?
        } else {
            Vec::new()
        };
        let notify_recipients = if node.notify_sub {
            owners.as_slice()
        } else {
            &[]
        };
        let authorization_recipients = if subscription.state == "pending" {
            owners.as_slice()
        } else {
            &[]
        };
        let last_item =
            if subscription.state == "subscribed" && node.send_last_published_item != "never" {
                latest_item_in_transaction(&mut transaction, node.id).await?
            } else {
                None
            };
        let outbox = renderer.render_subscription_transition(
            &node,
            &subscription,
            notify_recipients,
            authorization_recipients,
            last_item.as_ref(),
            time.new_uuid(),
            event_time,
        )?;
        enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
    }
    transaction.commit().await?;
    Ok(PubSubSubscribeOutcome::Subscribed(subscription.into()))
}

async fn delete_legacy_subscription_digests(
    transaction: &mut Transaction<'_, Postgres>,
    node_id: Uuid,
    jid: &str,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM pubsub_digest_queue
          WHERE subscription_node_id = $1
            AND subscriber_jid = $2
            AND source_delivery_id IS NULL",
    )
    .bind(node_id)
    .bind(jid)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Remove the locked current subscription, fenced by the echo when supplied.
pub async fn unsubscribe_current_with_renderer(
    pool: &PgPool,
    node_id: PubSubNodeId,
    requester: &PubSubBareJid,
    subscriber: &PubSubAddress,
    requested_subid: RequestedSubId<'_>,
    time: &PubSubTimeSources,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<PubSubUnsubscribeOutcome> {
    if subscriber.bare() != *requester {
        return Ok(PubSubUnsubscribeOutcome::Forbidden);
    }
    let node_id = node_id.get();
    let jid = subscriber.to_string();
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    let Some(node) = lock_subscription_node(&mut transaction, node_id).await? else {
        transaction.rollback().await?;
        return Ok(PubSubUnsubscribeOutcome::NotSubscribed);
    };
    let current = lock_subscription_row(&mut transaction, node_id, &jid).await?;
    let event_time = locked_event_time(&mut transaction).await?;
    let Some(mut subscription) =
        current.filter(|row| row.expire.is_none_or(|expire| expire > event_time))
    else {
        transaction.rollback().await?;
        return Ok(PubSubUnsubscribeOutcome::NotSubscribed);
    };
    if !requested_subid.matches(&subscription.subid) {
        transaction.rollback().await?;
        return Ok(PubSubUnsubscribeOutcome::InvalidSubid);
    }
    delete_legacy_subscription_digests(&mut transaction, node_id, &jid).await?;
    sqlx::query(
        "DELETE FROM pubsub_subscriptions
          WHERE node_id = $1 AND jid = $2 AND subid = $3",
    )
    .bind(node_id)
    .bind(&jid)
    .bind(&subscription.subid)
    .execute(&mut *transaction)
    .await?;
    subscription.state = "none".to_owned();
    let owners = if node.notify_sub {
        owner_jids_in_transaction(&mut transaction, node.id).await?
    } else {
        Vec::new()
    };
    let outbox = renderer.render_subscription_transition(
        &node,
        &subscription,
        &owners,
        &[],
        None,
        time.new_uuid(),
        event_time,
    )?;
    enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
    transaction.commit().await?;
    Ok(PubSubUnsubscribeOutcome::Unsubscribed {
        subid: Some(subscription.subid),
    })
}

/// Compatibility entry point requiring a SubID for every removal.
pub async fn unsubscribe_checked_with_renderer(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    subscriber_jid: &str,
    expected_subid: &str,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<UnsubscribeOutcome> {
    let outcome = unsubscribe_current_with_renderer(
        pool,
        PubSubNodeId::new(node_id),
        &PubSubAddress::parse(requester)?.bare(),
        &PubSubAddress::parse(subscriber_jid)?,
        RequestedSubId(Some(expected_subid)),
        &PubSubTimeSources::default(),
        renderer,
    )
    .await?;
    Ok(match outcome {
        PubSubUnsubscribeOutcome::Unsubscribed { .. } => UnsubscribeOutcome::Unsubscribed,
        PubSubUnsubscribeOutcome::NotFound | PubSubUnsubscribeOutcome::NotSubscribed => {
            UnsubscribeOutcome::NotFound
        }
        PubSubUnsubscribeOutcome::InvalidSubid => UnsubscribeOutcome::InvalidSubid,
        PubSubUnsubscribeOutcome::Forbidden => UnsubscribeOutcome::Forbidden,
    })
}
