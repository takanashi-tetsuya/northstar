//! Complete PostgreSQL PubSub/PEP operations and locked audience snapshots.
use crate::{db, services::pubsub::*};
use anyhow::{Context, Result};
use northstar_pubsub_core::PubSubRootDiscoPage;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, HashMap, HashSet};
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresPubSubRepository {
    pool: PgPool,
    domain: String,
    renderer: PubSubEventRenderer,
}
impl PostgresPubSubRepository {
    pub(crate) fn new(pool: PgPool, domain: &str) -> Self {
        Self {
            pool,
            domain: domain.to_owned(),
            renderer: PubSubEventRenderer::new(domain),
        }
    }
    async fn lock_pep_subscription_principal(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner: &PubSubAccount,
        actor: &PepSubscriptionActor<'_>,
        subscriber_jid: &str,
    ) -> Result<Option<LockedPepSubscriptionPrincipal>> {
        let actor_jid = crate::jid::CanonicalJid::parse(actor.jid)?;
        let subscriber = crate::jid::CanonicalJid::parse(subscriber_jid)?;
        if actor_jid.bare() != subscriber.bare()
            || subscriber.resourcepart().is_some()
                && actor_jid.to_string() != subscriber.to_string()
        {
            return Ok(None);
        }
        let actor_is_local = actor_jid.domainpart() == self.domain.as_str();
        let local_subscriber_id = match (actor_is_local, actor.local_account) {
            (true, Some(account)) if actor_jid.localpart() == Some(account.username.as_str()) => {
                Some(account.id)
            }
            (false, None) => None,
            _ => return Ok(None),
        };
        let owner_bare =
            crate::jid::CanonicalJid::parse_bare(&format!("{}@{}", owner.username, self.domain))?
                .to_string();

        // Node configuration/deletion takes the owner advisory first. Account
        // rows follow in UUID order, then subscriber/node advisories and block
        // policy locks. This order is shared with publication and revocation.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
            .bind(owner.id.to_string())
            .execute(&mut **transaction)
            .await?;
        let mut account_ids = vec![owner.id];
        if let Some(id) = local_subscriber_id {
            account_ids.push(id);
        }
        account_ids.sort_unstable();
        account_ids.dedup();
        let rows = sqlx::query(
            "SELECT id,username,auth_generation,is_disabled FROM users
              WHERE id=ANY($1) ORDER BY id FOR SHARE",
        )
        .bind(&account_ids)
        .fetch_all(&mut **transaction)
        .await?;
        if rows.len() != account_ids.len() {
            return Ok(None);
        }
        let mut accounts = HashMap::with_capacity(rows.len());
        for row in rows {
            accounts.insert(
                row.try_get::<Uuid, _>("id")?,
                (
                    row.try_get::<String, _>("username")?,
                    row.try_get::<i64, _>("auth_generation")?,
                    row.try_get::<bool, _>("is_disabled")?,
                ),
            );
        }
        if !accounts
            .get(&owner.id)
            .is_some_and(|(username, generation, disabled)| {
                username == &owner.username && *generation == owner.auth_generation && !*disabled
            })
        {
            return Ok(None);
        }
        if let Some(account) = actor.local_account {
            if !accounts
                .get(&account.id)
                .is_some_and(|(username, generation, disabled)| {
                    username == &account.username
                        && *generation == account.auth_generation
                        && !*disabled
                })
            {
                return Ok(None);
            }
        }
        Ok(Some(LockedPepSubscriptionPrincipal {
            subscriber_jid: subscriber.to_string(),
            subscriber_bare: subscriber.bare(),
            owner_bare,
            local_subscriber_id,
        }))
    }
    async fn direct_pep_outbox(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        sender_connection_id: Option<Uuid>,
        event_kind: PepOutboxEventKind,
        snapshot: &PepDirectStateSnapshot,
        factory: &dyn PepDirectOutboxFactory,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        let authorized = snapshot
            .transitions
            .iter()
            .map(|transition| transition.recipient_jid().to_owned())
            .collect::<HashSet<_>>();
        let deliveries = factory.build(snapshot)?;
        anyhow::ensure!(
            deliveries.iter().all(|(recipient, _)| {
                crate::jid::canonicalize(recipient)
                    .is_ok_and(|recipient| authorized.contains(&recipient))
            }),
            "PEP direct-state renderer escaped the transaction-owned recipients"
        );
        let mut localparts = authorized
            .iter()
            .filter_map(|jid| crate::jid::CanonicalJid::parse(jid).ok())
            .filter(|jid| jid.domainpart() == self.domain)
            .filter_map(|jid| jid.localpart().map(str::to_owned))
            .collect::<Vec<_>>();
        localparts.sort_unstable();
        localparts.dedup();
        let rows = sqlx::query(
            "SELECT id,username FROM users
              WHERE username=ANY($1) AND NOT is_disabled
              ORDER BY id
              FOR SHARE",
        )
        .bind(&localparts)
        .fetch_all(&mut **transaction)
        .await?;
        let mut local_accounts = HashMap::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.try_get("id")?;
            let username: String = row.try_get("username")?;
            let bare =
                crate::jid::CanonicalJid::parse_bare(&format!("{username}@{}", self.domain))?
                    .to_string();
            local_accounts.insert(bare, id);
        }
        let event_id = Uuid::new_v4();
        let created_at = chrono::Utc::now();
        let mut seen = HashSet::new();
        let mut outbox = Vec::new();
        for (recipient, payload) in deliveries {
            let recipient = crate::jid::canonicalize(&recipient)?;
            if !seen.insert(recipient.clone()) {
                continue;
            }
            let recipient_bare = crate::jid::canonical_bare_key(&recipient)?;
            let recipient_account_id = if recipient_bare == snapshot.owner_bare_jid {
                Some(owner_id)
            } else {
                local_accounts.get(&recipient_bare).copied()
            };
            if crate::jid::CanonicalJid::parse(&recipient)?.domainpart() == self.domain
                && recipient_account_id.is_none()
            {
                // Account deletion/disable committed before this mutation's
                // lock snapshot. There is no valid local delivery subject.
                continue;
            }
            outbox.push(db::PubSubOutboxInsert::new_pep_stanza(
                event_id,
                owner_id,
                &snapshot.owner_bare_jid,
                sender_connection_id,
                recipient,
                recipient_account_id,
                event_kind,
                PepOutboxAuthorizationMode::CausalAudience,
                payload,
                &snapshot.node,
                &self.domain,
                created_at,
            )?);
        }
        Ok(outbox)
    }
    async fn store_pep_node_config(
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        node: &str,
        config: &PepNodeConfig,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE pep_nodes
                SET access_model=$3,max_items=$4,persist_items=$5,
                    send_last_published_item=$6,deliver_notifications=$7,
                    roster_groups_allowed=$8,access_whitelist=$9,
                    updated_at=clock_timestamp()
              WHERE owner_id=$1 AND node=$2",
        )
        .bind(owner_id)
        .bind(node)
        .bind(&config.access_model)
        .bind(config.max_items)
        .bind(config.persist_items)
        .bind(&config.send_last_published_item)
        .bind(config.deliver_notifications)
        .bind(&config.roster_groups_allowed)
        .bind(&config.access_whitelist)
        .execute(&mut **transaction)
        .await?;
        if config.persist_items {
            sqlx::query(
                "DELETE FROM pep_items
                  WHERE owner_id=$1 AND node=$2
                    AND item_id NOT IN (
                        SELECT item_id FROM pep_items
                         WHERE owner_id=$1 AND node=$2
                         ORDER BY updated_at DESC,item_id DESC LIMIT $3
                    )",
            )
            .bind(owner_id)
            .bind(node)
            .bind(config.max_items)
            .execute(&mut **transaction)
            .await?;
        } else {
            sqlx::query("DELETE FROM pep_items WHERE owner_id=$1 AND node=$2")
                .bind(owner_id)
                .bind(node)
                .execute(&mut **transaction)
                .await?;
        }
        Ok(())
    }
    async fn begin_mutation(&self) -> Result<Transaction<'_, Postgres>> {
        db::pubsub::begin_bounded_pubsub_mutation(&self.pool).await
    }
    #[allow(clippy::too_many_arguments)]
    async fn exact_pep_outbox(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        owner_username: &str,
        sender_connection_id: Option<Uuid>,
        node: &str,
        event_kind: PepOutboxEventKind,
        authorization_mode: PepOutboxAuthorizationMode,
        factory: &dyn PepOutboxFactory,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        let owner_bare_jid =
            crate::jid::CanonicalJid::parse_bare(&format!("{owner_username}@{}", self.domain))?
                .to_string();
        let policy = sqlx::query(
            "SELECT access_model,deliver_notifications,roster_groups_allowed,access_whitelist
               FROM pep_nodes
              WHERE owner_id=$1 AND node=$2
              FOR SHARE",
        )
        .bind(owner_id)
        .bind(node)
        .fetch_one(&mut **transaction)
        .await?;
        let deliver_notifications: bool = policy.try_get("deliver_notifications")?;
        if !deliver_notifications {
            return Ok(Vec::new());
        }
        let access_model: String = policy.try_get("access_model")?;
        let roster_groups_allowed: Vec<String> = policy.try_get("roster_groups_allowed")?;
        let access_whitelist = policy
            .try_get::<Vec<String>, _>("access_whitelist")?
            .into_iter()
            .map(|jid| crate::jid::canonical_bare_key(&jid))
            .collect::<Result<HashSet<_>>>()?;

        // The owner users row is held FOR SHARE by the caller. Production
        // roster mutations take it FOR UPDATE, so rows and groups below cannot
        // change until this event has been projected.
        let roster_rows = sqlx::query(
            "SELECT contact_jid,subscription,groups
               FROM roster_items
              WHERE owner_id=$1
              ORDER BY contact_jid
              FOR SHARE",
        )
        .bind(owner_id)
        .fetch_all(&mut **transaction)
        .await?;
        let mut roster = BTreeMap::new();
        for row in roster_rows {
            let jid = crate::jid::canonicalize_bare(&row.try_get::<String, _>("contact_jid")?)?;
            roster.insert(
                jid,
                PepRosterAudienceEntry {
                    subscription: row.try_get("subscription")?,
                    groups: serde_json::from_value(row.try_get("groups")?)
                        .context("stored PEP roster groups are not a string array")?,
                },
            );
        }

        // Subscribe/unsubscribe and roster-driven cancellation serialize on
        // this node advisory. FOR SHARE also protects direct legacy cleanup.
        let explicit = sqlx::query_scalar::<_, String>(
            "SELECT subscriber_jid FROM pep_subscriptions
              WHERE owner_id=$1 AND node=$2 AND state='subscribed'
              ORDER BY subscriber_jid
              FOR SHARE",
        )
        .bind(owner_id)
        .bind(node)
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|jid| crate::jid::canonicalize(&jid))
        .collect::<Result<Vec<_>>>()?;

        let mut localparts = roster
            .keys()
            .chain(explicit.iter())
            .filter_map(|jid| crate::jid::CanonicalJid::parse(jid).ok())
            .filter(|jid| jid.domainpart() == self.domain.as_str())
            .filter_map(|jid| jid.localpart().map(str::to_owned))
            .collect::<Vec<_>>();
        localparts.sort_unstable();
        localparts.dedup();
        let local_rows = sqlx::query(
            "SELECT id,username FROM users
              WHERE username=ANY($1) AND NOT is_disabled",
        )
        .bind(&localparts)
        .fetch_all(&mut **transaction)
        .await?;
        let mut local_accounts = HashMap::with_capacity(local_rows.len());
        let mut block_owners = vec![owner_id];
        for row in local_rows {
            let id: Uuid = row.try_get("id")?;
            let username: String = row.try_get("username")?;
            let bare =
                crate::jid::CanonicalJid::parse_bare(&format!("{username}@{}", self.domain))?
                    .to_string();
            local_accounts.insert(bare, id);
            block_owners.push(id);
        }
        block_owners.sort_unstable();
        block_owners.dedup();
        for block_owner in &block_owners {
            lock_pep_block_policy(transaction, *block_owner).await?;
        }
        let block_rows = sqlx::query(
            "SELECT owner_id,blocked_jid FROM blocked_jids
              WHERE owner_id=ANY($1)
              ORDER BY owner_id,blocked_jid",
        )
        .bind(&block_owners)
        .fetch_all(&mut **transaction)
        .await?;
        let mut blocks: HashMap<Uuid, Vec<String>> = HashMap::new();
        for row in block_rows {
            blocks
                .entry(row.try_get("owner_id")?)
                .or_default()
                .push(row.try_get("blocked_jid")?);
        }

        let authorized = |jid: &str,
                          roster_entry: Option<&PepRosterAudienceEntry>|
         -> Result<bool> {
            let bare = crate::jid::canonical_bare_key(jid)?;
            if bare == owner_bare_jid {
                return Ok(true);
            }
            let parsed = crate::jid::CanonicalJid::parse(jid)?;
            if parsed.domainpart() == self.domain && !local_accounts.contains_key(&bare) {
                return Ok(false);
            }
            if blocks.get(&owner_id).is_some_and(|patterns| {
                patterns
                    .iter()
                    .any(|pattern| db::roster::blocked_jid_matches(pattern, jid))
            }) {
                return Ok(false);
            }
            if let Some(recipient_id) = local_accounts.get(&bare) {
                if blocks.get(recipient_id).is_some_and(|patterns| {
                    patterns
                        .iter()
                        .any(|pattern| db::roster::blocked_jid_matches(pattern, &owner_bare_jid))
                }) {
                    return Ok(false);
                }
            }
            Ok(match access_model.as_str() {
                "open" => true,
                "whitelist" => access_whitelist.contains(&bare),
                "presence" => roster_entry
                    .is_some_and(|entry| matches!(entry.subscription.as_str(), "from" | "both")),
                "roster" => roster_entry.is_some_and(|entry| {
                    entry
                        .groups
                        .iter()
                        .any(|group| roster_groups_allowed.contains(group))
                }),
                _ => false,
            })
        };

        let mut roster_jids = Vec::new();
        for (jid, entry) in &roster {
            if matches!(entry.subscription.as_str(), "from" | "both")
                && authorized(jid, Some(entry))?
            {
                roster_jids.push(jid.clone());
            }
        }
        let mut explicit_jids = Vec::new();
        for jid in explicit {
            let bare = crate::jid::canonical_bare_key(&jid)?;
            if authorized(&jid, roster.get(&bare))? {
                explicit_jids.push(jid);
            }
        }
        let audience = PepAudienceSnapshot {
            owner_bare_jid: owner_bare_jid.clone(),
            roster_jids,
            explicit_jids,
        };
        let deliveries = factory.build(&audience)?;
        anyhow::ensure!(
            deliveries
                .iter()
                .all(|(recipient, _)| audience.authorizes_routed_jid(recipient)),
            "PEP renderer escaped the transaction-owned audience"
        );
        let event_id = Uuid::new_v4();
        let created_at = chrono::Utc::now();
        let mut seen = HashSet::new();
        deliveries
            .into_iter()
            .filter_map(|(recipient, payload)| {
                let recipient = crate::jid::canonicalize(&recipient).ok()?;
                seen.insert(recipient.clone())
                    .then_some((recipient, payload))
            })
            .map(|(recipient, payload)| {
                let recipient_bare = crate::jid::canonical_bare_key(&recipient)?;
                let recipient_account_id = if recipient_bare == owner_bare_jid {
                    Some(owner_id)
                } else {
                    local_accounts.get(&recipient_bare).copied()
                };
                db::PubSubOutboxInsert::new_pep_stanza(
                    event_id,
                    owner_id,
                    &owner_bare_jid,
                    sender_connection_id,
                    recipient,
                    recipient_account_id,
                    event_kind,
                    authorization_mode,
                    payload,
                    node,
                    &self.domain,
                    created_at,
                )
            })
            .collect()
    }
    async fn begin_authorized_pep_owner_mutation(
        &self,
        owner: &PubSubAccount,
        node: &str,
    ) -> Result<Option<(Transaction<'_, Postgres>, String)>> {
        let mut transaction = self.begin_mutation().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
            .bind(owner.id.to_string())
            .execute(&mut *transaction)
            .await?;
        let username = sqlx::query_scalar::<_, String>(
            "SELECT username FROM users
              WHERE id=$1 AND username=$2 AND auth_generation=$3 AND NOT is_disabled
              FOR SHARE",
        )
        .bind(owner.id)
        .bind(&owner.username)
        .bind(owner.auth_generation)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(username) = username else {
            transaction.rollback().await?;
            return Ok(None);
        };
        lock_pep_audience(&mut transaction, owner.id, node).await?;
        let owner_bare_jid =
            crate::jid::CanonicalJid::parse_bare(&format!("{username}@{}", self.domain))?
                .to_string();
        Ok(Some((transaction, owner_bare_jid)))
    }
    async fn locked_pep_node_config(
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        node: &str,
    ) -> Result<Option<PepNodeConfig>> {
        let row = sqlx::query(
            "SELECT access_model,max_items,persist_items,send_last_published_item,
                    deliver_notifications,roster_groups_allowed,access_whitelist
               FROM pep_nodes
              WHERE owner_id=$1 AND node=$2
              FOR UPDATE",
        )
        .bind(owner_id)
        .bind(node)
        .fetch_optional(&mut **transaction)
        .await?;
        row.map(|row| {
            Ok(PepNodeConfig {
                access_model: row.try_get("access_model")?,
                max_items: row.try_get("max_items")?,
                persist_items: row.try_get("persist_items")?,
                send_last_published_item: row.try_get("send_last_published_item")?,
                deliver_notifications: row.try_get("deliver_notifications")?,
                roster_groups_allowed: row.try_get("roster_groups_allowed")?,
                access_whitelist: row.try_get("access_whitelist")?,
            })
        })
        .transpose()
    }
}
impl From<db::CreateNodeOutcome> for CreateNodeOutcome {
    fn from(value: db::CreateNodeOutcome) -> Self {
        match value {
            db::CreateNodeOutcome::Created(_) => Self::Created,
            db::CreateNodeOutcome::Conflict => Self::Conflict,
            db::CreateNodeOutcome::QuotaExceeded => Self::QuotaExceeded,
            db::CreateNodeOutcome::InvalidOptions => Self::InvalidOptions,
            db::CreateNodeOutcome::Forbidden => Self::Forbidden,
            db::CreateNodeOutcome::CollectionLimitExceeded => Self::CollectionLimitExceeded,
            db::CreateNodeOutcome::Cycle => Self::Cycle,
        }
    }
}

impl From<db::PublishItemsOutcome> for PublishItemsOutcome {
    fn from(value: db::PublishItemsOutcome) -> Self {
        match value {
            db::PublishItemsOutcome::Published => Self::Published,
            db::PublishItemsOutcome::Conflict => Self::Conflict,
            db::PublishItemsOutcome::QuotaExceeded => Self::QuotaExceeded,
            db::PublishItemsOutcome::Forbidden => Self::Forbidden,
            db::PublishItemsOutcome::PreconditionFailed => Self::PreconditionFailed,
        }
    }
}

impl From<db::RetractItemsOutcome> for RetractItemsOutcome {
    fn from(value: db::RetractItemsOutcome) -> Self {
        match value {
            db::RetractItemsOutcome::Retracted => Self::Retracted,
            db::RetractItemsOutcome::NotFound => Self::NotFound,
            db::RetractItemsOutcome::Forbidden => Self::Forbidden,
        }
    }
}

impl From<db::CollectionUpdateOutcome> for CollectionUpdateOutcome {
    fn from(value: db::CollectionUpdateOutcome) -> Self {
        match value {
            db::CollectionUpdateOutcome::Updated => Self::Updated,
            db::CollectionUpdateOutcome::NotFound => Self::NotFound,
            db::CollectionUpdateOutcome::NotAssociated => Self::NotAssociated,
            db::CollectionUpdateOutcome::NotCollection => Self::NotCollection,
            db::CollectionUpdateOutcome::Forbidden => Self::Forbidden,
            db::CollectionUpdateOutcome::LimitExceeded => Self::LimitExceeded,
            db::CollectionUpdateOutcome::DepthExceeded => Self::DepthExceeded,
            db::CollectionUpdateOutcome::Cycle => Self::Cycle,
        }
    }
}

impl From<db::PubSubConfigOutcome> for PubSubConfigOutcome {
    fn from(value: db::PubSubConfigOutcome) -> Self {
        match value {
            db::PubSubConfigOutcome::Updated => Self::Updated,
            db::PubSubConfigOutcome::Conflict => Self::Conflict,
            db::PubSubConfigOutcome::NotFound => Self::NotFound,
            db::PubSubConfigOutcome::InvalidOptions => Self::InvalidOptions,
            db::PubSubConfigOutcome::Forbidden => Self::Forbidden,
            db::PubSubConfigOutcome::LimitExceeded => Self::LimitExceeded,
            db::PubSubConfigOutcome::Cycle => Self::Cycle,
        }
    }
}

impl From<db::SetSubscriptionsOutcome> for SetSubscriptionsOutcome {
    fn from(value: db::SetSubscriptionsOutcome) -> Self {
        match value {
            db::SetSubscriptionsOutcome::Updated(transitions) => Self::Updated(transitions),
            db::SetSubscriptionsOutcome::LimitExceeded => Self::LimitExceeded,
            db::SetSubscriptionsOutcome::InvalidSubid => Self::InvalidSubid,
            db::SetSubscriptionsOutcome::NotFound => Self::NotFound,
            db::SetSubscriptionsOutcome::Forbidden => Self::Forbidden,
        }
    }
}

impl From<db::SetAffiliationsOutcome> for SetAffiliationsOutcome {
    fn from(value: db::SetAffiliationsOutcome) -> Self {
        match value {
            db::SetAffiliationsOutcome::Updated {
                revoked_subscriptions,
                approved_subscriptions,
            } => Self::Updated {
                revoked_subscriptions,
                approved_subscriptions,
            },
            db::SetAffiliationsOutcome::LastOwner => Self::LastOwner,
            db::SetAffiliationsOutcome::NotFound => Self::NotFound,
            db::SetAffiliationsOutcome::Forbidden => Self::Forbidden,
        }
    }
}

impl From<db::OwnerMutationOutcome> for OwnerMutationOutcome {
    fn from(value: db::OwnerMutationOutcome) -> Self {
        match value {
            db::OwnerMutationOutcome::Applied => Self::Applied,
            db::OwnerMutationOutcome::NotFound => Self::NotFound,
            db::OwnerMutationOutcome::Forbidden => Self::Forbidden,
            db::OwnerMutationOutcome::Invalid => Self::Invalid,
        }
    }
}

impl From<db::SubscribeOutcome> for SubscribeOutcome {
    fn from(value: db::SubscribeOutcome) -> Self {
        match value {
            db::SubscribeOutcome::Subscribed(subscription) => Self::Subscribed(subscription.into()),
            db::SubscribeOutcome::LimitExceeded => Self::LimitExceeded,
            db::SubscribeOutcome::NotFound => Self::NotFound,
            db::SubscribeOutcome::Forbidden => Self::Forbidden,
            db::SubscribeOutcome::ClosedNode => Self::ClosedNode,
            db::SubscribeOutcome::PreconditionFailed => Self::PreconditionFailed,
        }
    }
}

impl From<db::UnsubscribeOutcome> for UnsubscribeOutcome {
    fn from(value: db::UnsubscribeOutcome) -> Self {
        match value {
            db::UnsubscribeOutcome::Unsubscribed => Self::Unsubscribed,
            db::UnsubscribeOutcome::NotFound => Self::NotFound,
            db::UnsubscribeOutcome::InvalidSubid => Self::InvalidSubid,
            db::UnsubscribeOutcome::Forbidden => Self::Forbidden,
        }
    }
}

impl From<db::SubscriptionOptionsOutcome> for SubscriptionOptionsOutcome {
    fn from(value: db::SubscriptionOptionsOutcome) -> Self {
        match value {
            db::SubscriptionOptionsOutcome::Updated => Self::Updated,
            db::SubscriptionOptionsOutcome::NotFound => Self::NotFound,
            db::SubscriptionOptionsOutcome::InvalidSubid => Self::InvalidSubid,
            db::SubscriptionOptionsOutcome::Forbidden => Self::Forbidden,
        }
    }
}

impl From<db::PepNodeConfig> for PepNodeConfig {
    fn from(value: db::PepNodeConfig) -> Self {
        Self {
            access_model: value.access_model,
            max_items: value.max_items,
            persist_items: value.persist_items,
            send_last_published_item: value.send_last_published_item,
            deliver_notifications: value.deliver_notifications,
            roster_groups_allowed: value.roster_groups_allowed,
            access_whitelist: value.access_whitelist,
        }
    }
}

impl From<&PepNodeConfig> for db::PepNodeConfig {
    fn from(value: &PepNodeConfig) -> Self {
        Self {
            access_model: value.access_model.clone(),
            max_items: value.max_items,
            persist_items: value.persist_items,
            send_last_published_item: value.send_last_published_item.clone(),
            deliver_notifications: value.deliver_notifications,
            roster_groups_allowed: value.roster_groups_allowed.clone(),
            access_whitelist: value.access_whitelist.clone(),
        }
    }
}

impl From<PepQuotas> for db::PepQuotas {
    fn from(value: PepQuotas) -> Self {
        Self {
            max_nodes: value.max_nodes,
            max_storage_bytes: value.max_storage_bytes,
        }
    }
}

impl From<db::PepCreateOutcome> for PepCreateOutcome {
    fn from(value: db::PepCreateOutcome) -> Self {
        match value {
            db::PepCreateOutcome::Created => Self::Created,
            db::PepCreateOutcome::Conflict => Self::Conflict,
            db::PepCreateOutcome::QuotaExceeded => Self::QuotaExceeded,
        }
    }
}

impl From<db::PepPublishOutcome> for PepPublishOutcome {
    fn from(value: db::PepPublishOutcome) -> Self {
        match value {
            db::PepPublishOutcome::Published => Self::Published,
            db::PepPublishOutcome::PreconditionFailed => Self::PreconditionFailed,
            db::PepPublishOutcome::MaxItemsExceeded => Self::MaxItemsExceeded,
            db::PepPublishOutcome::QuotaExceeded => Self::QuotaExceeded,
        }
    }
}

impl From<db::PepSubscription> for PepSubscription {
    fn from(value: db::PepSubscription) -> Self {
        Self {
            jid: value.jid,
            subid: value.subid,
        }
    }
}

impl From<db::PepPresenceSubscription> for PepPresenceSubscription {
    fn from(value: db::PepPresenceSubscription) -> Self {
        Self {
            owner_id: value.owner_id,
            owner_username: value.owner_username,
            node: value.node,
        }
    }
}

impl From<db::PepItem> for PepItem {
    fn from(value: db::PepItem) -> Self {
        Self {
            item_id: value.item_id,
            payload: value.payload,
            updated_at: value.updated_at,
        }
    }
}

impl From<db::PubSubItem> for PubSubItem {
    fn from(value: db::PubSubItem) -> Self {
        Self {
            item_id: value.item_id,
            xml_payload: value.xml_payload,
            created_at: value.created_at,
        }
    }
}

impl From<db::CollectionVisibleItem> for CollectionVisibleItem {
    fn from(value: db::CollectionVisibleItem) -> Self {
        Self {
            node: value.node,
            xml_payload: value.xml_payload,
        }
    }
}

impl From<db::PubSubSubscription> for PubSubSubscription {
    fn from(value: db::PubSubSubscription) -> Self {
        Self {
            node: value.node,
            jid: value.jid,
            state: value.state,
            subid: value.subid,
            deliver: value.deliver,
            digest: value.digest,
            digest_frequency: value.digest_frequency,
            expire: value.expire,
            include_body: value.include_body,
            show_values: value.show_values,
            subscription_type: value.subscription_type,
            subscription_depth: value.subscription_depth,
        }
    }
}

impl From<&PubSubSubscription> for db::PubSubSubscription {
    fn from(value: &PubSubSubscription) -> Self {
        Self {
            node: value.node.clone(),
            jid: value.jid.clone(),
            state: value.state.clone(),
            subid: value.subid.clone(),
            deliver: value.deliver,
            digest: value.digest,
            digest_frequency: value.digest_frequency,
            expire: value.expire,
            include_body: value.include_body,
            show_values: value.show_values.clone(),
            subscription_type: value.subscription_type.clone(),
            subscription_depth: value.subscription_depth,
        }
    }
}

impl From<db::PubSubSubscriptionOptions> for PubSubSubscriptionOptions {
    fn from(value: db::PubSubSubscriptionOptions) -> Self {
        Self {
            deliver: value.deliver,
            digest: value.digest,
            digest_frequency: value.digest_frequency,
            expire: value.expire,
            include_body: value.include_body,
            show_values: value.show_values,
            subscription_type: value.subscription_type,
            subscription_depth: value.subscription_depth,
        }
    }
}

impl From<&PubSubSubscriptionOptions> for db::PubSubSubscriptionOptions {
    fn from(value: &PubSubSubscriptionOptions) -> Self {
        Self {
            deliver: value.deliver,
            digest: value.digest,
            digest_frequency: value.digest_frequency,
            expire: value.expire,
            include_body: value.include_body,
            show_values: value.show_values.clone(),
            subscription_type: value.subscription_type.clone(),
            subscription_depth: value.subscription_depth,
        }
    }
}

impl From<db::PubSubAffiliation> for PubSubAffiliation {
    fn from(value: db::PubSubAffiliation) -> Self {
        Self {
            node: value.node,
            jid: value.jid,
            affiliation: value.affiliation,
        }
    }
}

impl From<db::SubscriptionAuthorizationOutcome> for SubscriptionAuthorizationOutcome {
    fn from(value: db::SubscriptionAuthorizationOutcome) -> Self {
        match value {
            db::SubscriptionAuthorizationOutcome::Applied => Self::Applied,
            db::SubscriptionAuthorizationOutcome::NotFound => Self::NotFound,
            db::SubscriptionAuthorizationOutcome::Forbidden => Self::Forbidden,
            db::SubscriptionAuthorizationOutcome::Stale => Self::Stale,
        }
    }
}

impl From<db::DuePubSubDigest> for DuePubSubDigest {
    fn from(value: db::DuePubSubDigest) -> Self {
        Self {
            ids: value.ids,
            subscription_node_id: value.subscription_node_id,
            subscriber_jid: value.subscriber_jid,
            event_xml: value.event_xml,
            show_values: value.show_values,
        }
    }
}

struct PepRosterAudienceEntry {
    subscription: String,
    groups: Vec<String>,
}

async fn lock_pep_audience(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    node: &str,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 5))")
        .bind(format!("{owner_id}:{node}"))
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn lock_pep_block_policy(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 0))")
        .bind(owner_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

struct LockedPepSubscriptionPrincipal {
    subscriber_jid: String,
    subscriber_bare: String,
    owner_bare: String,
    local_subscriber_id: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PepOutboxAuthorizationLockPlan {
    BlockPolicyOnly,
    AudienceThenBlockPolicy,
}

pub(crate) fn pep_outbox_authorization_lock_plan(
    authorization_mode: PepOutboxAuthorizationMode,
) -> PepOutboxAuthorizationLockPlan {
    if authorization_mode == PepOutboxAuthorizationMode::LiveNodeAccess {
        PepOutboxAuthorizationLockPlan::AudienceThenBlockPolicy
    } else {
        PepOutboxAuthorizationLockPlan::BlockPolicyOnly
    }
}

pub(crate) fn db_outbox(entries: &[PubSubOutboxInsert]) -> Vec<db::PubSubOutboxInsert> {
    entries.to_vec()
}
fn map_database_busy(error: anyhow::Error) -> anyhow::Error {
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<db::pubsub::PubSubMutationBusy>()
            .is_some()
            || cause
                .downcast_ref::<sqlx::Error>()
                .is_some_and(|error| match error {
                    sqlx::Error::PoolTimedOut => true,
                    sqlx::Error::Database(error) => error
                        .code()
                        .is_some_and(|code| matches!(code.as_ref(), "55P03" | "57014")),
                    _ => false,
                })
    }) {
        error.context(northstar_pubsub_application::PubSubMutationBusy)
    } else {
        error
    }
}
impl db::PubSubMutationOutboxRenderer for PubSubEventRenderer {
    fn render_create(
        &self,
        node: &db::PubSubNode,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_create(
            self,
            node,
            &audience
                .iter()
                .map(|delivery| PubSubNotificationDelivery {
                    subscription_node_id: delivery.subscription_node_id,
                    subscription: delivery.subscription.clone().into(),
                    collection: delivery.collection.clone(),
                })
                .collect::<Vec<_>>(),
            event_id,
            created_at,
        )
    }
    fn render_items(
        &self,
        node: &db::PubSubNode,
        items: &[(String, String)],
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_items(
            self,
            node,
            items,
            &audience
                .iter()
                .map(|delivery| PubSubNotificationDelivery {
                    subscription_node_id: delivery.subscription_node_id,
                    subscription: delivery.subscription.clone().into(),
                    collection: delivery.collection.clone(),
                })
                .collect::<Vec<_>>(),
            event_id,
            created_at,
        )
    }
    fn render_purge(
        &self,
        node: &db::PubSubNode,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_purge(
            self,
            node,
            &audience
                .iter()
                .map(|delivery| PubSubNotificationDelivery {
                    subscription_node_id: delivery.subscription_node_id,
                    subscription: delivery.subscription.clone().into(),
                    collection: delivery.collection.clone(),
                })
                .collect::<Vec<_>>(),
            event_id,
            created_at,
        )
    }
    fn render_retract(
        &self,
        node: &db::PubSubNode,
        item_ids: &[String],
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_retract(
            self,
            node,
            item_ids,
            &audience
                .iter()
                .map(|delivery| PubSubNotificationDelivery {
                    subscription_node_id: delivery.subscription_node_id,
                    subscription: delivery.subscription.clone().into(),
                    collection: delivery.collection.clone(),
                })
                .collect::<Vec<_>>(),
            event_id,
            created_at,
        )
    }
    fn render_delete(
        &self,
        node: &db::PubSubNode,
        redirect: Option<&str>,
        audience: &[db::PubSubNotificationDelivery],
        nonactive_recipients: &[String],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_delete(
            self,
            node,
            redirect,
            &audience
                .iter()
                .map(|delivery| PubSubNotificationDelivery {
                    subscription_node_id: delivery.subscription_node_id,
                    subscription: delivery.subscription.clone().into(),
                    collection: delivery.collection.clone(),
                })
                .collect::<Vec<_>>(),
            nonactive_recipients,
            event_id,
            created_at,
        )
    }
    fn render_configuration(
        &self,
        node: &db::PubSubNode,
        config: &db::PubSubNodeConfig,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_configuration(
            self,
            node,
            config,
            &audience
                .iter()
                .map(|delivery| PubSubNotificationDelivery {
                    subscription_node_id: delivery.subscription_node_id,
                    subscription: delivery.subscription.clone().into(),
                    collection: delivery.collection.clone(),
                })
                .collect::<Vec<_>>(),
            event_id,
            created_at,
        )
    }
    fn render_collection_edge(
        &self,
        source: &db::PubSubNode,
        action: &str,
        target_node: &str,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_collection_edge(
            self,
            source,
            action,
            target_node,
            &audience
                .iter()
                .map(|delivery| PubSubNotificationDelivery {
                    subscription_node_id: delivery.subscription_node_id,
                    subscription: delivery.subscription.clone().into(),
                    collection: delivery.collection.clone(),
                })
                .collect::<Vec<_>>(),
            event_id,
            created_at,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn render_subscription_transition(
        &self,
        node: &db::PubSubNode,
        subscription: &db::PubSubSubscription,
        notify_recipients: &[String],
        authorization_recipients: &[String],
        last_item: Option<&db::PubSubItem>,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_subscription_transition(
            self,
            node,
            &subscription.clone().into(),
            notify_recipients,
            authorization_recipients,
            last_item.cloned().map(Into::into).as_ref(),
            event_id,
            created_at,
        )
    }
    fn render_affiliation_transition(
        &self,
        node: &db::PubSubNode,
        jid: &str,
        affiliation: &str,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        PubSubEventRenderer::render_affiliation_transition(
            self,
            node,
            jid,
            affiliation,
            event_id,
            created_at,
        )
    }
}
#[cfg(test)]
impl db::PubSubMutationOutboxRenderer for PubSubService<PostgresPubSubRepository> {
    fn render_create(
        &self,
        node: &db::PubSubNode,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_create(
            &self.repository_for_tests().renderer,
            node,
            audience,
            event_id,
            created_at,
        )
    }
    fn render_items(
        &self,
        node: &db::PubSubNode,
        items: &[(String, String)],
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_items(
            &self.repository_for_tests().renderer,
            node,
            items,
            audience,
            event_id,
            created_at,
        )
    }
    fn render_purge(
        &self,
        node: &db::PubSubNode,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_purge(
            &self.repository_for_tests().renderer,
            node,
            audience,
            event_id,
            created_at,
        )
    }
    fn render_retract(
        &self,
        node: &db::PubSubNode,
        item_ids: &[String],
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_retract(
            &self.repository_for_tests().renderer,
            node,
            item_ids,
            audience,
            event_id,
            created_at,
        )
    }
    fn render_delete(
        &self,
        node: &db::PubSubNode,
        redirect: Option<&str>,
        audience: &[db::PubSubNotificationDelivery],
        nonactive_recipients: &[String],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_delete(
            &self.repository_for_tests().renderer,
            node,
            redirect,
            audience,
            nonactive_recipients,
            event_id,
            created_at,
        )
    }
    fn render_configuration(
        &self,
        node: &db::PubSubNode,
        config: &db::PubSubNodeConfig,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_configuration(
            &self.repository_for_tests().renderer,
            node,
            config,
            audience,
            event_id,
            created_at,
        )
    }
    fn render_collection_edge(
        &self,
        source: &db::PubSubNode,
        action: &str,
        target_node: &str,
        audience: &[db::PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_collection_edge(
            &self.repository_for_tests().renderer,
            source,
            action,
            target_node,
            audience,
            event_id,
            created_at,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn render_subscription_transition(
        &self,
        node: &db::PubSubNode,
        subscription: &db::PubSubSubscription,
        notify_recipients: &[String],
        authorization_recipients: &[String],
        last_item: Option<&db::PubSubItem>,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_subscription_transition(
            &self.repository_for_tests().renderer,
            node,
            subscription,
            notify_recipients,
            authorization_recipients,
            last_item,
            event_id,
            created_at,
        )
    }
    fn render_affiliation_transition(
        &self,
        node: &db::PubSubNode,
        jid: &str,
        affiliation: &str,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        db::PubSubMutationOutboxRenderer::render_affiliation_transition(
            &self.repository_for_tests().renderer,
            node,
            jid,
            affiliation,
            event_id,
            created_at,
        )
    }
}
impl PubSubNodeMutationRepository for PostgresPubSubRepository {
    async fn delete_node_as_owner_with_redirect_and_outbox(
        &self,
        node_id: Uuid,
        requester: &str,
        redirect: Option<&str>,
    ) -> Result<OwnerMutationOutcome> {
        let outcome: Result<_> = async {
            Ok(db::delete_node_as_owner_with_redirect_and_outbox(
                &self.pool,
                node_id,
                requester,
                redirect,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }

    async fn update_node_config_and_graph_with_outbox(
        &self,
        node: &PubSubNode,
        requester: &str,
        expected: &PubSubNodeConfig,
        config: &PubSubNodeConfig,
    ) -> Result<PubSubConfigOutcome> {
        let outcome: Result<_> = async {
            Ok(db::update_node_config_and_graph_with_outbox(
                &self.pool,
                node,
                requester,
                expected,
                config,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }

    async fn create_node(
        &self,
        node: &str,
        creator_jid: &str,
        config: &PubSubNodeConfig,
        max_nodes_per_owner: i64,
    ) -> Result<CreateNodeOutcome> {
        let outcome: Result<_> = async {
            Ok(db::create_node_with_renderer(
                &self.pool,
                node,
                creator_jid,
                config,
                max_nodes_per_owner,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn associate_collection_child(
        &self,
        collection: &PubSubNode,
        child: &PubSubNode,
        requester: &str,
    ) -> Result<CollectionUpdateOutcome> {
        let outcome: Result<_> = async {
            Ok(db::associate_collection_child_with_renderer(
                &self.pool,
                collection,
                child,
                requester,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn dissociate_collection_child(
        &self,
        collection: &PubSubNode,
        child: &PubSubNode,
        requester: &str,
    ) -> Result<CollectionUpdateOutcome> {
        let outcome: Result<_> = async {
            Ok(db::dissociate_collection_child_with_renderer(
                &self.pool,
                collection,
                child,
                requester,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PubSubNodeQueryRepository for PostgresPubSubRepository {
    async fn get_node(&self, node: &str) -> Result<Option<PubSubNode>> {
        db::get_node(&self.pool, node)
            .await
            .map_err(map_database_busy)
    }
    async fn node_redirect(&self, node: &str) -> Result<Option<String>> {
        let outcome: Result<_> = async { db::node_redirect(&self.pool, node).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn collection_parents(&self, child_id: Uuid) -> Result<Vec<PubSubNode>> {
        db::collection_parents(&self.pool, child_id)
            .await
            .map_err(map_database_busy)
    }
    async fn collection_children(&self, collection_id: Uuid) -> Result<Vec<PubSubNode>> {
        db::collection_children(&self.pool, collection_id)
            .await
            .map_err(map_database_busy)
    }
    async fn is_owner(&self, node_id: Uuid, requester: &str) -> Result<bool> {
        let outcome: Result<_> = async {
            Ok(db::get_node_affiliation(&self.pool, node_id, requester)
                .await?
                .as_deref()
                == Some("owner"))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn node_metadata(&self, node_id: Uuid) -> Result<PubSubNodeMetadata> {
        db::node_metadata(&self.pool, node_id)
            .await
            .map_err(map_database_busy)
    }
}
impl PubSubRootDiscoveryQueryRepository for PostgresPubSubRepository {
    async fn root_disco_page(
        &self,
        requester: &str,
        cursor: Option<&str>,
        backwards: bool,
        limit: i64,
    ) -> Result<PubSubRootDiscoPage> {
        db::root_disco_page(&self.pool, requester, cursor, backwards, limit)
            .await
            .map_err(map_database_busy)
    }
}
impl PubSubItemQueryRepository for PostgresPubSubRepository {
    async fn leaf_disco_snapshot(
        &self,
        node: &str,
        requester: &str,
    ) -> Result<Option<PubSubLeafDiscoSnapshot>> {
        let snapshot = db::leaf_disco_snapshot(&self.pool, node, requester)
            .await
            .map_err(map_database_busy)?;
        Ok(snapshot.map(|snapshot| PubSubLeafDiscoSnapshot {
            node_type: snapshot.node_type,
            access_model: snapshot.access_model,
            affiliation: snapshot.affiliation,
            subscribed: snapshot.subscribed,
            item_ids: snapshot.item_ids,
        }))
    }
    async fn get_items(
        &self,
        node_id: Uuid,
        item_ids: &[String],
        limit: i64,
    ) -> Result<Vec<PubSubItem>> {
        let outcome: Result<_> = async {
            Ok(db::get_items(&self.pool, node_id, item_ids, limit)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn collection_visible_items(
        &self,
        collection_id: Uuid,
        requester: &str,
        global_item_limit: i64,
        xml_byte_limit: i64,
    ) -> Result<Vec<CollectionVisibleItem>> {
        let outcome: Result<_> = async {
            Ok(db::collection_visible_items(
                &self.pool,
                collection_id,
                requester,
                global_item_limit,
                xml_byte_limit,
            )
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn can_publish(&self, node: &PubSubNode, requester: &str) -> Result<bool> {
        let outcome: Result<_> = async {
            let (affiliation, subscribed) =
                db::publish_authorization_facts(&self.pool, node.id, requester).await?;
            let affiliation = affiliation
                .as_deref()
                .map(str::parse::<northstar_xep_0060::Affiliation>)
                .transpose()
                .map_err(|error| anyhow::anyhow!("invalid stored PubSub affiliation: {error}"))?;
            let publish_model = node
                .publish_model
                .parse::<northstar_xep_0060::PublishModel>()
                .map_err(|error| anyhow::anyhow!("invalid stored PubSub publish model: {error}"))?;
            let access_model = node
                .access_model
                .parse::<northstar_xep_0060::AccessModel>()
                .map_err(|error| anyhow::anyhow!("invalid stored PubSub access model: {error}"))?;
            Ok(northstar_xep_0060::can_publish_pure(
                publish_model,
                access_model,
                affiliation,
                subscribed,
            ))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PubSubItemMutationRepository for PostgresPubSubRepository {
    async fn purge_node_as_owner_with_outbox(
        &self,
        node_id: Uuid,
        requester: &str,
    ) -> Result<OwnerMutationOutcome> {
        let outcome: Result<_> = async {
            Ok(
                db::purge_node_as_owner_with_outbox(&self.pool, node_id, requester, &self.renderer)
                    .await?
                    .into(),
            )
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn publish_items(
        &self,
        node: &PubSubNode,
        publisher_jid: &str,
        items: &[(String, String)],
        max_storage_bytes_per_owner: i64,
    ) -> Result<PublishItemsOutcome> {
        let outcome: Result<_> = async {
            Ok(db::publish_items_with_renderer(
                &self.pool,
                node,
                publisher_jid,
                items,
                false,
                max_storage_bytes_per_owner,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn retract_items(
        &self,
        node_id: Uuid,
        item_ids: &[String],
        publisher_jid: &str,
        force_notification: bool,
    ) -> Result<RetractItemsOutcome> {
        let outcome: Result<_> = async {
            Ok(db::retract_items_with_renderer(
                &self.pool,
                node_id,
                item_ids,
                publisher_jid,
                force_notification,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PubSubSubscriptionQueryRepository for PostgresPubSubRepository {
    async fn is_subscribed(&self, node_id: Uuid, jid: &str) -> Result<bool> {
        let outcome: Result<_> = async { db::is_subscribed(&self.pool, node_id, jid).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn subscriptions_for_jid(
        &self,
        jid: &str,
        node: Option<&str>,
    ) -> Result<Vec<PubSubSubscription>> {
        let outcome: Result<_> = async {
            Ok(db::subscriptions_for_jid(&self.pool, jid, node)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn subscriptions_addressing_jid_page(
        &self,
        jid: &str,
        after: Option<(&str, &str)>,
        limit: i64,
    ) -> Result<Vec<PubSubSubscription>> {
        let outcome: Result<_> = async {
            Ok(
                db::subscriptions_addressing_jid_page(&self.pool, jid, after, limit)
                    .await?
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            )
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn node_subscriptions(&self, node_id: Uuid) -> Result<Vec<PubSubSubscription>> {
        let outcome: Result<_> = async {
            Ok(db::node_subscriptions(&self.pool, node_id)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn get_subscription(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> Result<Option<PubSubSubscription>> {
        let outcome: Result<_> = async {
            Ok(db::get_subscription(&self.pool, node_id, jid)
                .await?
                .map(Into::into))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PubSubSubscriptionMutationRepository for PostgresPubSubRepository {
    async fn update_subscription_options_checked(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: Option<&str>,
        options: &PubSubSubscriptionOptions,
    ) -> Result<SubscriptionOptionsOutcome> {
        let outcome: Result<_> = async {
            let options = db::PubSubSubscriptionOptions::from(options);
            Ok(db::update_subscription_options_checked(
                &self.pool,
                node_id,
                requester,
                subscriber_jid,
                expected_subid,
                &options,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    #[allow(clippy::too_many_arguments)]
    async fn set_subscription_limited_with_options(
        &self,
        node_id: Uuid,
        requester: &str,
        jid: &str,
        state: &str,
        expected_node_type: &str,
        expected_access_model: &str,
        max_subscriptions: i64,
        options: Option<&PubSubSubscriptionOptions>,
        requested_subid: &str,
    ) -> Result<SubscribeOutcome> {
        let outcome: Result<_> = async {
            let options = options.map(db::PubSubSubscriptionOptions::from);
            Ok(db::set_subscription_limited_with_options_and_renderer(
                &self.pool,
                node_id,
                requester,
                jid,
                state,
                expected_node_type,
                expected_access_model,
                max_subscriptions,
                options.as_ref(),
                requested_subid,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn unsubscribe_checked(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: &str,
    ) -> Result<UnsubscribeOutcome> {
        let outcome: Result<_> = async {
            Ok(db::unsubscribe_checked_with_renderer(
                &self.pool,
                node_id,
                requester,
                subscriber_jid,
                expected_subid,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn set_subscriptions(
        &self,
        node_id: Uuid,
        requester: &str,
        changes: &[(String, String, Option<String>)],
    ) -> Result<SetSubscriptionsOutcome> {
        let outcome: Result<_> = async {
            Ok(db::set_subscriptions_with_renderer(
                &self.pool,
                node_id,
                requester,
                changes,
                None,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn resolve_pending_subscription(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: &str,
        allow: bool,
    ) -> Result<SubscriptionAuthorizationOutcome> {
        let outcome: Result<_> = async {
            Ok(db::resolve_pending_subscription_with_renderer(
                &self.pool,
                node_id,
                requester,
                subscriber_jid,
                expected_subid,
                allow,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PubSubAffiliationQueryRepository for PostgresPubSubRepository {
    async fn get_node_affiliation(&self, node_id: Uuid, jid: &str) -> Result<Option<String>> {
        let outcome: Result<_> =
            async { db::get_node_affiliation(&self.pool, node_id, jid).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn affiliations_for_jid(
        &self,
        jid: &str,
        node: Option<&str>,
    ) -> Result<Vec<PubSubAffiliation>> {
        let outcome: Result<_> = async {
            Ok(db::affiliations_for_jid(&self.pool, jid, node)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn node_affiliations(&self, node_id: Uuid) -> Result<Vec<PubSubAffiliation>> {
        let outcome: Result<_> = async {
            Ok(db::node_affiliations(&self.pool, node_id)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PubSubAffiliationMutationRepository for PostgresPubSubRepository {
    async fn set_affiliations(
        &self,
        node_id: Uuid,
        requester: &str,
        changes: &[(String, String)],
    ) -> Result<SetAffiliationsOutcome> {
        let outcome: Result<_> = async {
            Ok(db::set_affiliations_with_renderer(
                &self.pool,
                node_id,
                requester,
                changes,
                None,
                None,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PubSubOutboxRepository for PostgresPubSubRepository {
    async fn cleanup_idle_pubsub_event_streams(&self, limit: i64) -> Result<u64> {
        let outcome: Result<_> =
            async { db::cleanup_idle_pubsub_event_streams(&self.pool, limit).await }.await;
        outcome.map_err(map_database_busy)
    }

    async fn cleanup_pubsub_dead_letters(&self, limit: i64) -> Result<u64> {
        let outcome: Result<_> =
            async { db::cleanup_pubsub_dead_letters(&self.pool, limit).await }.await;
        outcome.map_err(map_database_busy)
    }

    async fn outbox_get_subscription(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> Result<Option<PubSubSubscription>> {
        let outcome: Result<_> = async {
            Ok(db::get_subscription(&self.pool, node_id, jid)
                .await?
                .map(Into::into))
        }
        .await;
        outcome.map_err(map_database_busy)
    }

    async fn local_account_blocks_pubsub(&self, username: &str, service: &str) -> Result<bool> {
        let outcome: Result<_> = async {
            let Some(user) = db::find_enabled_user(&self.pool, username).await? else {
                return Ok(false);
            };
            db::is_blocked(&self.pool, user.id, service).await
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn presence_delivery_denied(
        &self,
        recipient_id: Uuid,
        active_privacy_list: Option<&str>,
        connection_id: Uuid,
        service: &str,
    ) -> Result<bool> {
        let outcome: Result<_> = async {
            if db::is_blocked(&self.pool, recipient_id, service).await? {
                return Ok(true);
            }
            if active_privacy_list.is_some() {
                db::refresh_active_privacy_session(&self.pool, recipient_id, connection_id).await?;
            }
            db::privacy_denies(
                &self.pool,
                recipient_id,
                active_privacy_list,
                service,
                db::PrivacyStanzaKind::Message,
            )
            .await
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn authorize_pep_outbox_delivery(
        &self,
        item: &ClaimedPubSubOutboxDelivery,
    ) -> Result<PepOutboxAuthorizationOutcome> {
        let outcome: Result<_> = async {
            let drop_unverifiable = || {
                db::record_unverifiable_pep_drop();
                PepOutboxAuthorizationOutcome::Drop(PepOutboxDropReason::UnverifiableIdentity)
            };
            if item.delivery_kind != PubSubOutboxDeliveryKind::PepStanza
                || item.source != PubSubOutboxSource::Pep
                || item.legacy_unverifiable
            {
                return Ok(drop_unverifiable());
            }
            let Some(subject) = item.pep_subject.as_ref() else {
                return Ok(drop_unverifiable());
            };
            if subject.sender_account_id.is_nil()
                || subject
                    .sender_connection_id
                    .is_some_and(|connection_id| connection_id.is_nil())
                || subject
                    .recipient_account_id
                    .is_some_and(|recipient_id| recipient_id.is_nil())
                || (subject.event_kind.requires_causal_authorization()
                    && subject.authorization_mode != PepOutboxAuthorizationMode::CausalAudience)
                || item.security_sensitive != db::security_sensitive_pep_node(&item.source_node)
                || (item.security_sensitive
                    && matches!(
                        subject.event_kind,
                        PepOutboxEventKind::Publish | PepOutboxEventKind::LastItem
                    )
                    && subject.authorization_mode != PepOutboxAuthorizationMode::LiveNodeAccess)
            {
                return Ok(drop_unverifiable());
            }

            let Ok(sender) = crate::jid::CanonicalJid::parse_bare(&subject.sender_bare_jid) else {
                return Ok(drop_unverifiable());
            };
            let Ok(recipient) = crate::jid::CanonicalJid::parse(&item.recipient_jid) else {
                return Ok(drop_unverifiable());
            };
            if sender.to_string() != subject.sender_bare_jid
                || sender.domainpart() != self.domain
                || sender.localpart().is_none()
                || recipient.to_string() != item.recipient_jid
                || recipient.domainpart() != item.target_domain
            {
                return Ok(drop_unverifiable());
            }
            let recipient_is_local = recipient.domainpart() == self.domain;
            if recipient_is_local != subject.recipient_is_local
                || subject.recipient_is_local != subject.recipient_account_id.is_some()
                || recipient_is_local && recipient.localpart().is_none()
            {
                return Ok(drop_unverifiable());
            }

            let mut transaction = self.begin_mutation().await?;
            let mut account_ids = vec![subject.sender_account_id];
            if let Some(recipient_id) = subject.recipient_account_id {
                account_ids.push(recipient_id);
            }
            account_ids.sort_unstable();
            account_ids.dedup();
            let rows = sqlx::query(
                "SELECT id,username,is_disabled FROM users
              WHERE id=ANY($1)
              ORDER BY id
              FOR SHARE",
            )
            .bind(&account_ids)
            .fetch_all(&mut *transaction)
            .await?;
            let accounts = rows
                .into_iter()
                .map(|row| {
                    Ok::<_, sqlx::Error>((
                        row.try_get::<Uuid, _>("id")?,
                        (
                            row.try_get::<String, _>("username")?,
                            row.try_get::<bool, _>("is_disabled")?,
                        ),
                    ))
                })
                .collect::<std::result::Result<HashMap<_, _>, _>>()?;
            let sender_matches =
                accounts
                    .get(&subject.sender_account_id)
                    .is_some_and(|(username, disabled)| {
                        !*disabled
                            && crate::jid::CanonicalJid::parse_bare(&format!(
                                "{username}@{}",
                                self.domain
                            ))
                            .is_ok_and(|jid| jid.to_string() == subject.sender_bare_jid)
                    });
            if !sender_matches {
                transaction.rollback().await?;
                return Ok(PepOutboxAuthorizationOutcome::Drop(
                    PepOutboxDropReason::SenderUnavailable,
                ));
            }
            if let Some(recipient_id) = subject.recipient_account_id {
                let recipient_matches =
                    accounts
                        .get(&recipient_id)
                        .is_some_and(|(username, disabled)| {
                            !*disabled
                                && recipient.localpart() == Some(username.as_str())
                                && recipient.domainpart() == self.domain
                        });
                if !recipient_matches {
                    transaction.rollback().await?;
                    return Ok(PepOutboxAuthorizationOutcome::Drop(
                        PepOutboxDropReason::RecipientUnavailable,
                    ));
                }
            }

            // A publication holds the per-node audience lock while it derives
            // the causal delivery set, and subsequently takes the block-policy
            // locks for that same set.  A live authorization must take those
            // shared authorities in exactly that order.  Taking block policy
            // first here creates an advisory-lock cycle with a simultaneous
            // security-sensitive publication: publish owns audience and waits for
            // block policy while delivery owns block policy and waits for
            // audience.  Causal-audience events do not consult a live node policy
            // and therefore intentionally do not take the audience lock.
            let lock_plan = pep_outbox_authorization_lock_plan(subject.authorization_mode);
            if lock_plan == PepOutboxAuthorizationLockPlan::AudienceThenBlockPolicy {
                lock_pep_audience(
                    &mut transaction,
                    subject.sender_account_id,
                    &item.source_node,
                )
                .await?;
            }
            for owner_id in &account_ids {
                lock_pep_block_policy(&mut transaction, *owner_id).await?;
            }
            let block_rows = sqlx::query(
                "SELECT owner_id,blocked_jid FROM blocked_jids
              WHERE owner_id=ANY($1)
              ORDER BY owner_id,blocked_jid
              FOR SHARE",
            )
            .bind(&account_ids)
            .fetch_all(&mut *transaction)
            .await?;
            let mut blocks: HashMap<Uuid, Vec<String>> = HashMap::new();
            for row in block_rows {
                blocks
                    .entry(row.try_get("owner_id")?)
                    .or_default()
                    .push(row.try_get("blocked_jid")?);
            }
            let same_account = subject.recipient_account_id == Some(subject.sender_account_id);
            let sender_blocks_recipient = !same_account
                && blocks
                    .get(&subject.sender_account_id)
                    .is_some_and(|patterns| {
                        patterns.iter().any(|pattern| {
                            db::roster::blocked_jid_matches(pattern, &item.recipient_jid)
                        })
                    });
            let recipient_blocks_sender = !same_account
                && subject.recipient_account_id.is_some_and(|recipient_id| {
                    blocks.get(&recipient_id).is_some_and(|patterns| {
                        patterns.iter().any(|pattern| {
                            db::roster::blocked_jid_matches(pattern, &subject.sender_bare_jid)
                        })
                    })
                });
            if sender_blocks_recipient || recipient_blocks_sender {
                transaction.rollback().await?;
                return Ok(PepOutboxAuthorizationOutcome::Drop(
                    PepOutboxDropReason::Blocked,
                ));
            }

            if !same_account
                && db::privacy::privacy_denies_in_transaction(
                    &mut transaction,
                    subject.sender_account_id,
                    subject.sender_connection_id,
                    &item.recipient_jid,
                    db::PrivacyStanzaKind::Message,
                )
                .await?
            {
                transaction.rollback().await?;
                return Ok(PepOutboxAuthorizationOutcome::Drop(
                    PepOutboxDropReason::PrivacyDenied,
                ));
            }
            if !same_account {
                if let Some(recipient_id) = subject.recipient_account_id {
                    if db::privacy::privacy_denies_in_transaction(
                        &mut transaction,
                        recipient_id,
                        None,
                        &subject.sender_bare_jid,
                        db::PrivacyStanzaKind::Message,
                    )
                    .await?
                    {
                        transaction.rollback().await?;
                        return Ok(PepOutboxAuthorizationOutcome::Drop(
                            PepOutboxDropReason::PrivacyDenied,
                        ));
                    }
                }
            }

            if lock_plan == PepOutboxAuthorizationLockPlan::AudienceThenBlockPolicy {
                let policy = sqlx::query(
                "SELECT access_model,deliver_notifications,roster_groups_allowed,access_whitelist
                   FROM pep_nodes
                  WHERE owner_id=$1 AND node=$2
                  FOR SHARE",
            )
            .bind(subject.sender_account_id)
            .bind(&item.source_node)
            .fetch_optional(&mut *transaction)
            .await?;
                let Some(policy) = policy else {
                    transaction.rollback().await?;
                    return Ok(PepOutboxAuthorizationOutcome::Drop(
                        PepOutboxDropReason::NodeAccessRevoked,
                    ));
                };
                if !policy.try_get::<bool, _>("deliver_notifications")? {
                    transaction.rollback().await?;
                    return Ok(PepOutboxAuthorizationOutcome::Drop(
                        PepOutboxDropReason::NodeAccessRevoked,
                    ));
                }
                let recipient_bare = recipient.bare();
                if recipient_bare != subject.sender_bare_jid {
                    let roster = sqlx::query(
                        "SELECT subscription,groups FROM roster_items
                      WHERE owner_id=$1 AND contact_jid=$2
                      FOR SHARE",
                    )
                    .bind(subject.sender_account_id)
                    .bind(&recipient_bare)
                    .fetch_optional(&mut *transaction)
                    .await?;
                    let automatic = roster
                        .as_ref()
                        .map(|row| row.try_get::<String, _>("subscription"))
                        .transpose()?
                        .is_some_and(|subscription| {
                            matches!(subscription.as_str(), "from" | "both")
                        });
                    let access_model: String = policy.try_get("access_model")?;
                    let access_allowed = match access_model.as_str() {
                        // The causal audience was already captured while the
                        // publication transaction held the node locks. `open`
                        // therefore remains open at delivery time; the live check
                        // detects a later restrictive policy without inventing a
                        // subscription requirement XEP-0060 does not impose.
                        "open" => true,
                        "whitelist" => policy
                            .try_get::<Vec<String>, _>("access_whitelist")?
                            .iter()
                            .any(|jid| {
                                crate::jid::canonical_bare_key(jid)
                                    .is_ok_and(|jid| jid == recipient_bare)
                            }),
                        "presence" => automatic,
                        "roster" => match roster.as_ref() {
                            Some(row) => {
                                let groups = serde_json::from_value::<Vec<String>>(
                                    row.try_get::<serde_json::Value, _>("groups")?,
                                )
                                .context("stored PEP roster groups are not a string array")?;
                                let allowed: Vec<String> =
                                    policy.try_get("roster_groups_allowed")?;
                                automatic && groups.iter().any(|group| allowed.contains(group))
                            }
                            None => false,
                        },
                        _ => false,
                    };
                    if !access_allowed {
                        transaction.rollback().await?;
                        return Ok(PepOutboxAuthorizationOutcome::Drop(
                            PepOutboxDropReason::NodeAccessRevoked,
                        ));
                    }
                }
            }
            transaction.commit().await?;
            Ok(PepOutboxAuthorizationOutcome::Deliver)
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn claim_pubsub_outbox(&self, limit: i64) -> Result<Vec<ClaimedPubSubOutboxDelivery>> {
        let outcome: Result<_> = async { db::claim_pubsub_outbox(&self.pool, limit).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn acknowledge_pubsub_outbox(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        let outcome: Result<_> =
            async { db::acknowledge_pubsub_outbox(&self.pool, delivery_id, lease_token).await }
                .await;
        outcome.map_err(map_database_busy)
    }
    async fn renew_pubsub_outbox_lease(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        let outcome: Result<_> =
            async { db::renew_pubsub_outbox_lease(&self.pool, delivery_id, lease_token).await }
                .await;
        outcome.map_err(map_database_busy)
    }
    async fn retry_pubsub_outbox(
        &self,
        item: &ClaimedPubSubOutboxDelivery,
        error: &str,
    ) -> Result<PubSubOutboxFailureDisposition> {
        let outcome: Result<_> =
            async { db::retry_pubsub_outbox(&self.pool, item, error).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn dead_letter_pubsub_outbox(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        reason: &str,
        error: &str,
    ) -> Result<PubSubOutboxFailureDisposition> {
        let outcome: Result<_> = async {
            db::dead_letter_pubsub_outbox(&self.pool, delivery_id, lease_token, reason, error).await
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn expire_pubsub_outbox(&self, limit: i64) -> Result<u64> {
        let outcome: Result<_> = async { db::expire_pubsub_outbox(&self.pool, limit).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn pubsub_outbox_snapshot(&self) -> Result<PubSubOutboxSnapshot> {
        let outcome: Result<_> = async { db::pubsub_outbox_snapshot(&self.pool).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn enqueue_pubsub_digest_snapshot(
        &self,
        source_delivery_id: Uuid,
        node_id: Uuid,
        subscriber_jid: &str,
        event_xml: &str,
        frequency_ms: i32,
        show_values: &[String],
    ) -> Result<()> {
        let outcome: Result<_> = async {
            // This is a projection of an already-committed outbox row, not a
            // client mutation. It must not occupy the foreground PubSub mutation
            // admission while delivery workers recover under a small pool.

            db::enqueue_pubsub_digest_snapshot(
                &self.pool,
                source_delivery_id,
                node_id,
                subscriber_jid,
                event_xml,
                frequency_ms,
                show_values,
            )
            .await
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn enqueue_pubsub_digest(
        &self,
        node_id: Uuid,
        subscriber_jid: &str,
        event_xml: &str,
        frequency_ms: i32,
    ) -> Result<bool> {
        let outcome: Result<_> = async {
            db::enqueue_pubsub_digest(&self.pool, node_id, subscriber_jid, event_xml, frequency_ms)
                .await
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn claim_due_pubsub_digests(&self, limit: i64) -> Result<Vec<DuePubSubDigest>> {
        let outcome: Result<_> = async {
            Ok(db::claim_due_pubsub_digests(&self.pool, limit)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn release_pubsub_digests(&self, ids: &[Uuid]) -> Result<()> {
        let outcome: Result<_> = async { db::release_pubsub_digests(&self.pool, ids).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn acknowledge_pubsub_digests(&self, ids: &[Uuid]) -> Result<()> {
        let outcome: Result<_> =
            async { db::acknowledge_pubsub_digests(&self.pool, ids).await }.await;
        outcome.map_err(map_database_busy)
    }
}
impl PepNodeQueryRepository for PostgresPubSubRepository {
    async fn roster_item(
        &self,
        owner_id: Uuid,
        jid: &str,
    ) -> Result<Option<(String, Option<String>, String, Option<String>)>> {
        let outcome: Result<_> = async { db::roster_item(&self.pool, owner_id, jid).await }.await;
        outcome.map_err(map_database_busy)
    }

    async fn pep_node(&self, owner_id: Uuid, node: &str) -> Result<Option<PepNodeConfig>> {
        let outcome: Result<_> = async {
            Ok(db::pep_node(&self.pool, owner_id, node)
                .await?
                .map(Into::into))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn pep_nodes(&self, owner_id: Uuid) -> Result<Vec<String>> {
        let outcome: Result<_> = async { db::pep_nodes(&self.pool, owner_id).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn find_enabled_user(&self, username: &str) -> Result<Option<PubSubAccount>> {
        let outcome: Result<_> = async {
            Ok(db::find_enabled_user(&self.pool, username)
                .await?
                .map(|user| PubSubAccount {
                    id: user.id,
                    username: user.username,
                    auth_generation: user.auth_generation,
                }))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn roster(
        &self,
        owner_id: Uuid,
    ) -> Result<Vec<(String, Option<String>, String, Option<String>)>> {
        let outcome: Result<_> = async { db::roster(&self.pool, owner_id).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn is_blocked(&self, owner_id: Uuid, candidate: &str) -> Result<bool> {
        let outcome: Result<_> =
            async { db::is_blocked(&self.pool, owner_id, candidate).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn roster_group_allowed(
        &self,
        owner_id: Uuid,
        jid: &str,
        groups: &[String],
    ) -> Result<bool> {
        let outcome: Result<_> =
            async { db::roster_group_allowed(&self.pool, owner_id, jid, groups).await }.await;
        outcome.map_err(map_database_busy)
    }
}
impl PepNodeMutationRepository for PostgresPubSubRepository {
    async fn create_pep_node(
        &self,
        owner_id: Uuid,
        node: &str,
        config: &PepNodeConfig,
        max_nodes: i64,
    ) -> Result<PepCreateOutcome> {
        let outcome: Result<_> = async {
            let config = db::PepNodeConfig::from(config);
            Ok(
                db::create_pep_node(&self.pool, owner_id, node, &config, max_nodes)
                    .await?
                    .into(),
            )
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn update_pep_node_config(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        expected: &PepNodeConfig,
        config: &PepNodeConfig,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let outcome: Result<_> = async {
            let Some((mut transaction, _)) = self
                .begin_authorized_pep_owner_mutation(owner, node)
                .await?
            else {
                return Ok(PepOwnerMutationOutcome::Forbidden);
            };
            let Some(current) =
                Self::locked_pep_node_config(&mut transaction, owner.id, node).await?
            else {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotFound);
            };
            if &current != expected {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::Stale);
            }
            let outbox = self
                .exact_pep_outbox(
                    &mut transaction,
                    owner.id,
                    &owner.username,
                    Some(sender_connection_id),
                    node,
                    PepOutboxEventKind::Configuration,
                    PepOutboxAuthorizationMode::CausalAudience,
                    factory,
                )
                .await?;
            Self::store_pep_node_config(&mut transaction, owner.id, node, config).await?;
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            transaction.commit().await?;
            Ok(PepOwnerMutationOutcome::Applied(0))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn purge_pep_node(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let outcome: Result<_> = async {
            let Some((mut transaction, _)) = self
                .begin_authorized_pep_owner_mutation(owner, node)
                .await?
            else {
                return Ok(PepOwnerMutationOutcome::Forbidden);
            };
            if Self::locked_pep_node_config(&mut transaction, owner.id, node)
                .await?
                .is_none()
            {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotFound);
            }
            let outbox = self
                .exact_pep_outbox(
                    &mut transaction,
                    owner.id,
                    &owner.username,
                    Some(sender_connection_id),
                    node,
                    PepOutboxEventKind::Purge,
                    PepOutboxAuthorizationMode::CausalAudience,
                    factory,
                )
                .await?;
            sqlx::query("DELETE FROM pep_items WHERE owner_id=$1 AND node=$2")
                .bind(owner.id)
                .bind(node)
                .execute(&mut *transaction)
                .await?;
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            transaction.commit().await?;
            Ok(PepOwnerMutationOutcome::Applied(0))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn delete_pep_node(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let outcome: Result<_> = async {
            let Some((mut transaction, _)) = self
                .begin_authorized_pep_owner_mutation(owner, node)
                .await?
            else {
                return Ok(PepOwnerMutationOutcome::Forbidden);
            };
            if Self::locked_pep_node_config(&mut transaction, owner.id, node)
                .await?
                .is_none()
            {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotFound);
            }
            let outbox = self
                .exact_pep_outbox(
                    &mut transaction,
                    owner.id,
                    &owner.username,
                    Some(sender_connection_id),
                    node,
                    PepOutboxEventKind::Delete,
                    PepOutboxAuthorizationMode::CausalAudience,
                    factory,
                )
                .await?;
            sqlx::query("DELETE FROM pep_nodes WHERE owner_id=$1 AND node=$2")
                .bind(owner.id)
                .bind(node)
                .execute(&mut *transaction)
                .await?;
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            transaction.commit().await?;
            Ok(PepOwnerMutationOutcome::Applied(0))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PepItemQueryRepository for PostgresPubSubRepository {
    async fn pep_items(
        &self,
        owner_id: Uuid,
        node: &str,
        item_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<(String, String)>> {
        let outcome: Result<_> =
            async { db::pep_items(&self.pool, owner_id, node, item_id, limit).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn pep_items_by_ids(
        &self,
        owner_id: Uuid,
        node: &str,
        item_ids: &[&str],
        limit: i64,
    ) -> Result<Vec<(String, String)>> {
        let outcome: Result<_> =
            async { db::pep_items_by_ids(&self.pool, owner_id, node, item_ids, limit).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn pep_items_with_timestamp(
        &self,
        owner_id: Uuid,
        node: &str,
        limit: i64,
    ) -> Result<Vec<PepItem>> {
        let outcome: Result<_> = async {
            Ok(
                db::pep_items_with_timestamp(&self.pool, owner_id, node, limit)
                    .await?
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            )
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PepItemMutationRepository for PostgresPubSubRepository {
    async fn retract_pep_items(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        item_ids: &[&str],
        notify: bool,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let outcome: Result<_> = async {
            let Some((mut transaction, _)) = self
                .begin_authorized_pep_owner_mutation(owner, node)
                .await?
            else {
                return Ok(PepOwnerMutationOutcome::Forbidden);
            };
            if Self::locked_pep_node_config(&mut transaction, owner.id, node)
                .await?
                .is_none()
            {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotFound);
            }
            let matched: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pep_items
              WHERE owner_id=$1 AND node=$2 AND item_id=ANY($3)",
            )
            .bind(owner.id)
            .bind(node)
            .bind(item_ids)
            .fetch_one(&mut *transaction)
            .await?;
            if matched != i64::try_from(item_ids.len())? {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotFound);
            }
            let outbox = if notify {
                self.exact_pep_outbox(
                    &mut transaction,
                    owner.id,
                    &owner.username,
                    Some(sender_connection_id),
                    node,
                    PepOutboxEventKind::Retract,
                    PepOutboxAuthorizationMode::CausalAudience,
                    factory,
                )
                .await?
            } else {
                Vec::new()
            };
            let removed = sqlx::query(
                "DELETE FROM pep_items WHERE owner_id=$1 AND node=$2 AND item_id=ANY($3)",
            )
            .bind(owner.id)
            .bind(node)
            .bind(item_ids)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            transaction.commit().await?;
            Ok(PepOwnerMutationOutcome::Applied(removed))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    #[allow(clippy::too_many_arguments)]
    async fn commit_legacy_bookmarks(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        private_xml: &str,
        items: &mut [(String, String)],
        expected_previous_items: &[(String, String)],
        max_private_bytes: i64,
        quotas: PepQuotas,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepBookmarkMutationOutcome> {
        const LEGACY_BOOKMARKS: &str = "storage:bookmarks";
        const BOOKMARKS2: &str = "urn:xmpp:bookmarks:1";
        let outcome: Result<_> = async {
            let Some((mut transaction, _)) = self
                .begin_authorized_pep_owner_mutation(owner, BOOKMARKS2)
                .await?
            else {
                return Ok(PepBookmarkMutationOutcome::Forbidden);
            };
            db::private::lock_private_xml_owner(&mut transaction, owner.id).await?;
            let previous_items = sqlx::query(
                "SELECT item_id,payload FROM pep_items
              WHERE owner_id=$1 AND node=$2
              ORDER BY item_id
              FOR UPDATE",
            )
            .bind(owner.id)
            .bind(BOOKMARKS2)
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .map(|row| Ok::<_, sqlx::Error>((row.try_get("item_id")?, row.try_get("payload")?)))
            .collect::<std::result::Result<Vec<(String, String)>, _>>()?;
            if previous_items != expected_previous_items {
                transaction.rollback().await?;
                return Ok(PepBookmarkMutationOutcome::ConcurrentChange);
            }
            let borrowed = items
                .iter()
                .map(|(item_id, payload)| (item_id.as_str(), payload.as_str()))
                .collect::<Vec<_>>();
            let config = db::default_pep_node_config(BOOKMARKS2);
            let pep_outcome = db::pep::replace_pep_items_in_transaction(
                &mut transaction,
                owner.id,
                BOOKMARKS2,
                &config,
                &borrowed,
                quotas.into(),
            )
            .await?;
            if pep_outcome != db::PepPublishOutcome::Published {
                transaction.rollback().await?;
                return Ok(PepBookmarkMutationOutcome::ResourceConstraint);
            }
            let private_outcome = db::private::set_private_xml_batch_in_transaction(
                &mut transaction,
                owner.id,
                &[db::PrivateXmlEntry {
                    element_name: "storage",
                    element_ns: LEGACY_BOOKMARKS,
                    xml_data: private_xml,
                }],
                max_private_bytes,
            )
            .await?;
            if private_outcome != db::PrivateXmlWriteOutcome::Stored {
                transaction.rollback().await?;
                return Ok(PepBookmarkMutationOutcome::ResourceConstraint);
            }
            let outbox = self
                .exact_pep_outbox(
                    &mut transaction,
                    owner.id,
                    &owner.username,
                    Some(sender_connection_id),
                    BOOKMARKS2,
                    PepOutboxEventKind::Publish,
                    PepOutboxAuthorizationMode::CausalAudience,
                    factory,
                )
                .await?;
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            transaction.commit().await?;
            Ok(PepBookmarkMutationOutcome::Stored)
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn publish_pep_items(
        &self,
        command: PepPublishItemsCommand<'_>,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepPublishItemsResult> {
        let outcome: Result<_> = async {
            let write = command.write;

            let mut transaction = self.begin_mutation().await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
                .bind(write.user_id.to_string())
                .execute(&mut *transaction)
                .await?;
            let owner_username = sqlx::query_scalar::<_, String>(
                "SELECT username FROM users
              WHERE id=$1 AND username=$2 AND auth_generation=$3 AND NOT is_disabled
              FOR SHARE",
            )
            .bind(write.user_id)
            .bind(write.username)
            .bind(write.auth_generation)
            .fetch_optional(&mut *transaction)
            .await?;
            let Some(owner_username) = owner_username else {
                transaction.rollback().await?;
                return Ok(PepPublishItemsResult {
                    outcome: PepPublishItemsOutcome::Unauthorized,
                    content_changed: false,
                });
            };
            lock_pep_audience(&mut transaction, write.user_id, write.node).await?;

            let item_ids = write
                .items
                .iter()
                .map(|(item_id, _)| *item_id)
                .collect::<Vec<_>>();
            let previous = sqlx::query(
                "SELECT item_id,payload FROM pep_items
              WHERE owner_id=$1 AND node=$2 AND item_id=ANY($3)
              FOR UPDATE",
            )
            .bind(write.user_id)
            .bind(write.node)
            .bind(&item_ids)
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .map(|row| {
                Ok::<_, sqlx::Error>((
                    row.try_get::<String, _>("item_id")?,
                    row.try_get::<String, _>("payload")?,
                ))
            })
            .collect::<std::result::Result<HashMap<_, _>, _>>()?;
            let changed = previous.len() != write.items.len()
                || write.items.iter().any(|(item_id, payload)| {
                    previous.get(*item_id).map(String::as_str) != Some(*payload)
                });
            let requested = db::PepNodeConfig::from(write.requested);
            let outcome = db::pep::publish_pep_items_in_transaction(
                &mut transaction,
                write.user_id,
                write.node,
                &requested,
                write.enforce_preconditions,
                write.items,
                write.quotas.into(),
            )
            .await?;
            if outcome != db::PepPublishOutcome::Published {
                transaction.rollback().await?;
                return Ok(PepPublishItemsResult {
                    outcome: PepPublishItemsOutcome::from(PepPublishOutcome::from(outcome)),
                    content_changed: false,
                });
            }
            if changed || !command.require_content_change {
                let outbox = self
                    .exact_pep_outbox(
                        &mut transaction,
                        write.user_id,
                        &owner_username,
                        Some(write.connection_id),
                        write.node,
                        PepOutboxEventKind::Publish,
                        PepOutboxAuthorizationMode::CausalAudience,
                        factory,
                    )
                    .await?;
                db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            }
            transaction.commit().await?;
            Ok(PepPublishItemsResult {
                outcome: PepPublishItemsOutcome::Published,
                content_changed: changed,
            })
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PepSubscriptionQueryRepository for PostgresPubSubRepository {
    async fn pep_subscribers(&self, owner_id: Uuid, node: &str) -> Result<Vec<PepSubscription>> {
        let outcome: Result<_> = async {
            Ok(db::pep_subscribers(&self.pool, owner_id, node)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn pep_subscriptions_for_available_resource(
        &self,
        subscriber_jid: &str,
    ) -> Result<Vec<PepPresenceSubscription>> {
        let outcome: Result<_> = async {
            Ok(
                db::pep_subscriptions_for_available_resource(&self.pool, subscriber_jid)
                    .await?
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            )
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn pep_owner_usernames_for_presence_subscriber(
        &self,
        subscriber_bare: &str,
    ) -> Result<Vec<String>> {
        let outcome: Result<_> = async {
            db::pep_owner_usernames_for_presence_subscriber(&self.pool, subscriber_bare).await
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PepSubscriptionMutationRepository for PostgresPubSubRepository {
    async fn subscribe_pep_node(
        &self,
        command: PepSubscribeCommand<'_>,
        factory: &dyn PepSubscribeOutboxFactory,
    ) -> Result<PepSubscribeResult> {
        let outcome: Result<_> = async {
        let write = command.write;

        let mut transaction = self.begin_mutation().await?;
        let Some(principal) = self
            .lock_pep_subscription_principal(
                &mut transaction,
                write.owner,
                &write.actor,
                write.subscriber_jid,
            )
            .await?
        else {
            transaction.rollback().await?;
            return Ok(PepSubscribeResult::from(PepSubscribeOutcome::Forbidden));
        };

        // Per-bare-JID quota first, then per-node serialization. All callers
        // use this order, so concurrent subscriptions cannot deadlock by
        // choosing different nodes for the same subscriber.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 4))")
            .bind(&principal.subscriber_bare)
            .execute(&mut *transaction)
            .await?;
        lock_pep_audience(&mut transaction, write.owner.id, write.node).await?;

        let policy = sqlx::query(
            "SELECT access_model,send_last_published_item,deliver_notifications,
                    roster_groups_allowed,access_whitelist
               FROM pep_nodes
              WHERE owner_id=$1 AND node=$2
              FOR SHARE",
        )
        .bind(write.owner.id)
        .bind(write.node)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(policy) = policy else {
            transaction.rollback().await?;
            return Ok(PepSubscribeResult::from(PepSubscribeOutcome::NotFound));
        };

        let mut block_owners = vec![write.owner.id];
        if let Some(subscriber_id) = principal.local_subscriber_id {
            block_owners.push(subscriber_id);
        }
        block_owners.sort_unstable();
        block_owners.dedup();
        for block_owner in &block_owners {
            lock_pep_block_policy(&mut transaction, *block_owner).await?;
        }
        let block_rows = sqlx::query(
            "SELECT owner_id,blocked_jid FROM blocked_jids
              WHERE owner_id=ANY($1)
              ORDER BY owner_id,blocked_jid
              FOR SHARE",
        )
        .bind(&block_owners)
        .fetch_all(&mut *transaction)
        .await?;
        let mut blocks: HashMap<Uuid, Vec<String>> = HashMap::new();
        for row in block_rows {
            blocks
                .entry(row.try_get("owner_id")?)
                .or_default()
                .push(row.try_get("blocked_jid")?);
        }

        let owner_blocks_subscriber = blocks.get(&write.owner.id).is_some_and(|patterns| {
            patterns
                .iter()
                .any(|pattern| db::roster::blocked_jid_matches(pattern, &principal.subscriber_jid))
        });
        let subscriber_blocks_owner = principal.local_subscriber_id.is_some_and(|subscriber_id| {
            blocks.get(&subscriber_id).is_some_and(|patterns| {
                patterns
                    .iter()
                    .any(|pattern| db::roster::blocked_jid_matches(pattern, &principal.owner_bare))
            })
        });

        let roster = sqlx::query("SELECT subscription,groups FROM roster_items WHERE owner_id=$1 AND contact_jid=$2 FOR SHARE")
            .bind(write.owner.id)
            .bind(&principal.subscriber_bare)
            .fetch_optional(&mut *transaction)
            .await?
            .map(|row| {
                Ok::<PepRosterAudienceEntry, anyhow::Error>(PepRosterAudienceEntry {
                    subscription: row.try_get("subscription")?,
                    groups: serde_json::from_value(row.try_get("groups")?)
                        .context("stored PEP roster groups are not a string array")?,
                })
            })
            .transpose()?;
        let access_model: String = policy.try_get("access_model")?;
        let authorized = if principal.subscriber_bare == principal.owner_bare {
            true
        } else if owner_blocks_subscriber || subscriber_blocks_owner {
            false
        } else {
            match access_model.as_str() {
                "open" => true,
                "whitelist" => {
                    let whitelist: Vec<String> = policy.try_get("access_whitelist")?;
                    whitelist.iter().any(|jid| {
                        crate::jid::canonical_bare_key(jid)
                            .is_ok_and(|jid| jid == principal.subscriber_bare)
                    })
                }
                "presence" => roster
                    .as_ref()
                    .is_some_and(|entry| matches!(entry.subscription.as_str(), "from" | "both")),
                "roster" => {
                    let allowed: Vec<String> = policy.try_get("roster_groups_allowed")?;
                    roster.as_ref().is_some_and(|entry| {
                        entry.groups.iter().any(|group| allowed.contains(group))
                    })
                }
                _ => false,
            }
        };
        if !authorized {
            transaction.rollback().await?;
            return Ok(PepSubscribeResult::from(
                PepSubscribeOutcome::NotAuthorized(access_model),
            ));
        }

        let existing = sqlx::query_scalar::<_, String>(
            "SELECT subid FROM pep_subscriptions
              WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3
              FOR UPDATE",
        )
        .bind(write.owner.id)
        .bind(write.node)
        .bind(&principal.subscriber_jid)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(subid) = existing {
            transaction.commit().await?;
            return Ok(PepSubscribeResult::from(PepSubscribeOutcome::Subscribed(
                PepSubscription {
                    jid: principal.subscriber_jid,
                    subid,
                },
            )));
        }

        let subscriber_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pep_subscriptions
              WHERE split_part(subscriber_jid, '/', 1)=$1",
        )
        .bind(&principal.subscriber_bare)
        .fetch_one(&mut *transaction)
        .await?;
        let node_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pep_subscriptions WHERE owner_id=$1 AND node=$2",
        )
        .bind(write.owner.id)
        .bind(write.node)
        .fetch_one(&mut *transaction)
        .await?;
        if write.max_subscriptions <= 0
            || subscriber_count >= write.max_subscriptions
            || node_count >= db::PEP_MAX_SUBSCRIBERS_PER_NODE
        {
            transaction.rollback().await?;
            return Ok(PepSubscribeResult::from(PepSubscribeOutcome::LimitExceeded));
        }

        let last_item = if policy.try_get::<bool, _>("deliver_notifications")?
            && policy.try_get::<String, _>("send_last_published_item")? != "never"
        {
            sqlx::query(
                "SELECT item_id,payload,updated_at FROM pep_items
                  WHERE owner_id=$1 AND node=$2
                  ORDER BY updated_at DESC,item_id DESC LIMIT 1
                  FOR SHARE",
            )
            .bind(write.owner.id)
            .bind(write.node)
            .fetch_optional(&mut *transaction)
            .await?
            .map(|row| {
                Ok::<PepItem, sqlx::Error>(PepItem {
                    item_id: row.try_get("item_id")?,
                    payload: row.try_get("payload")?,
                    updated_at: row.try_get("updated_at")?,
                })
            })
            .transpose()?
        } else {
            None
        };
        sqlx::query(
            "INSERT INTO pep_subscriptions(owner_id,node,subscriber_jid,subid)
             VALUES($1,$2,$3,$4)",
        )
        .bind(write.owner.id)
        .bind(write.node)
        .bind(&principal.subscriber_jid)
        .bind(write.requested_subid)
        .execute(&mut *transaction)
        .await?;
        let snapshot = PepSubscribeSnapshot {
            owner_id: write.owner.id,
            owner_bare_jid: principal.owner_bare,
            node: write.node.to_owned(),
            subscriber_jid: principal.subscriber_jid.clone(),
            subscriber_account_id: principal.local_subscriber_id,
            local_domain: self.domain.clone(),
            last_item,
        };
        let outbox = db_outbox(&factory.build(&snapshot)?);
        anyhow::ensure!(
            outbox.iter().all(|entry| {
                entry.source == db::PubSubOutboxSource::Pep
                    && entry.delivery_kind == db::PubSubOutboxDeliveryKind::PepStanza
                    && entry.source_node == write.node
                    && entry.recipient_jid == principal.subscriber_jid
            }),
            "PEP subscription renderer escaped the transaction-owned recipient"
        );
        db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
        transaction.commit().await?;
        Ok(PepSubscribeResult::from(PepSubscribeOutcome::Subscribed(
            PepSubscription {
                jid: principal.subscriber_jid,
                subid: write.requested_subid.to_owned(),
            },
        )))
    }.await;
        outcome.map_err(map_database_busy)
    }
    async fn unsubscribe_pep_node(
        &self,
        command: PepUnsubscribeCommand<'_>,
    ) -> Result<PepUnsubscribeResult> {
        let outcome: Result<_> = async {
            let write = command.write;

            let mut transaction = self.begin_mutation().await?;
            let Some(principal) = self
                .lock_pep_subscription_principal(
                    &mut transaction,
                    write.owner,
                    &write.actor,
                    write.subscriber_jid,
                )
                .await?
            else {
                transaction.rollback().await?;
                return Ok(PepUnsubscribeResult::from(PepUnsubscribeOutcome::Forbidden));
            };
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 4))")
                .bind(&principal.subscriber_bare)
                .execute(&mut *transaction)
                .await?;
            lock_pep_audience(&mut transaction, write.owner.id, write.node).await?;
            let exists = sqlx::query_scalar::<_, bool>(
                "SELECT TRUE FROM pep_nodes WHERE owner_id=$1 AND node=$2 FOR SHARE",
            )
            .bind(write.owner.id)
            .bind(write.node)
            .fetch_optional(&mut *transaction)
            .await?;
            if exists.is_none() {
                transaction.rollback().await?;
                return Ok(PepUnsubscribeResult::from(PepUnsubscribeOutcome::NotFound));
            }
            let existing = sqlx::query_scalar::<_, String>(
                "SELECT subid FROM pep_subscriptions
              WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3
              FOR UPDATE",
            )
            .bind(write.owner.id)
            .bind(write.node)
            .bind(&principal.subscriber_jid)
            .fetch_optional(&mut *transaction)
            .await?;
            let Some(existing) = existing else {
                transaction.commit().await?;
                return Ok(PepUnsubscribeResult::from(
                    PepUnsubscribeOutcome::Unsubscribed(None),
                ));
            };
            if write.subid.is_some_and(|subid| subid != existing.as_str()) {
                transaction.rollback().await?;
                return Ok(PepUnsubscribeResult::from(
                    PepUnsubscribeOutcome::InvalidSubid,
                ));
            }
            sqlx::query(
                "DELETE FROM pep_subscriptions
              WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3 AND subid=$4",
            )
            .bind(write.owner.id)
            .bind(write.node)
            .bind(&principal.subscriber_jid)
            .bind(&existing)
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            Ok(PepUnsubscribeResult::from(
                PepUnsubscribeOutcome::Unsubscribed(Some(existing)),
            ))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn unsubscribe_pep_nodes_batch(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        changes: &[(String, Option<String>)],
        factory: &dyn PepDirectOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let outcome: Result<_> = async {
            let Some((mut transaction, owner_bare_jid)) = self
                .begin_authorized_pep_owner_mutation(owner, node)
                .await?
            else {
                return Ok(PepOwnerMutationOutcome::Forbidden);
            };
            if Self::locked_pep_node_config(&mut transaction, owner.id, node)
                .await?
                .is_none()
            {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotFound);
            }
            let mut canonical = Vec::with_capacity(changes.len());
            let mut unique = HashSet::new();
            for (jid, requested_subid) in changes {
                let jid = crate::jid::canonicalize(jid)?;
                if !unique.insert((jid.clone(), requested_subid.clone())) {
                    transaction.rollback().await?;
                    return Ok(PepOwnerMutationOutcome::NotSubscribed);
                }
                let stored = sqlx::query_scalar::<_, String>(
                    "SELECT subid FROM pep_subscriptions
                  WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3
                  FOR UPDATE",
                )
                .bind(owner.id)
                .bind(node)
                .bind(&jid)
                .fetch_optional(&mut *transaction)
                .await?;
                let Some(stored) = stored.filter(|stored| {
                    requested_subid
                        .as_ref()
                        .is_none_or(|requested| requested == stored)
                }) else {
                    transaction.rollback().await?;
                    return Ok(PepOwnerMutationOutcome::NotSubscribed);
                };
                canonical.push((jid, stored));
            }
            if canonical.is_empty() {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotSubscribed);
            }
            let snapshot = PepDirectStateSnapshot {
                owner_bare_jid,
                node: node.to_owned(),
                transitions: canonical
                    .iter()
                    .map(
                        |(recipient_jid, subid)| PepDirectStateTransition::Subscription {
                            recipient_jid: recipient_jid.clone(),
                            subid: subid.clone(),
                            state: "none".to_owned(),
                        },
                    )
                    .collect(),
            };
            let outbox = self
                .direct_pep_outbox(
                    &mut transaction,
                    owner.id,
                    Some(sender_connection_id),
                    PepOutboxEventKind::SubscriptionState,
                    &snapshot,
                    factory,
                )
                .await?;
            for (jid, subid) in &canonical {
                sqlx::query(
                    "DELETE FROM pep_subscriptions
                  WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3 AND subid=$4",
                )
                .bind(owner.id)
                .bind(node)
                .bind(jid)
                .bind(subid)
                .execute(&mut *transaction)
                .await?;
            }
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            transaction.commit().await?;
            Ok(PepOwnerMutationOutcome::Applied(u64::try_from(
                canonical.len(),
            )?))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PepAffiliationRepository for PostgresPubSubRepository {
    async fn update_pep_affiliations(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        expected: &PepNodeConfig,
        changes: &[(String, String)],
        factory: &dyn PepDirectOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let outcome: Result<_> = async {
            let Some((mut transaction, owner_bare_jid)) = self
                .begin_authorized_pep_owner_mutation(owner, node)
                .await?
            else {
                return Ok(PepOwnerMutationOutcome::Forbidden);
            };
            let Some(mut current) =
                Self::locked_pep_node_config(&mut transaction, owner.id, node).await?
            else {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotFound);
            };
            if &current != expected {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::Stale);
            }
            let mut whitelist = current
                .access_whitelist
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            let mut transitions = Vec::with_capacity(changes.len());
            let mut seen = HashSet::new();
            for (jid, affiliation) in changes {
                let jid = crate::jid::canonicalize_bare(jid)?;
                if jid == owner_bare_jid
                    || !matches!(affiliation.as_str(), "member" | "none")
                    || !seen.insert(jid.clone())
                {
                    transaction.rollback().await?;
                    return Ok(PepOwnerMutationOutcome::Forbidden);
                }
                if affiliation == "member" {
                    whitelist.insert(jid.clone());
                } else {
                    whitelist.remove(&jid);
                }
                transitions.push(PepDirectStateTransition::Affiliation {
                    recipient_jid: jid,
                    affiliation: affiliation.clone(),
                });
            }
            if transitions.is_empty() || whitelist.len() > 10_000 {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::Forbidden);
            }
            current.access_whitelist = whitelist.into_iter().collect();
            current.access_whitelist.sort_unstable();
            let snapshot = PepDirectStateSnapshot {
                owner_bare_jid,
                node: node.to_owned(),
                transitions,
            };
            let outbox = self
                .direct_pep_outbox(
                    &mut transaction,
                    owner.id,
                    Some(sender_connection_id),
                    PepOutboxEventKind::AffiliationState,
                    &snapshot,
                    factory,
                )
                .await?;
            Self::store_pep_node_config(&mut transaction, owner.id, node, &current).await?;
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            transaction.commit().await?;
            Ok(PepOwnerMutationOutcome::Applied(0))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
#[cfg(test)]
impl PubSubService<PostgresPubSubRepository> {
    pub(crate) fn new(pool: PgPool, domain: &str) -> Self {
        let capacity = pool.options().get_max_connections();
        Self::new_with_durable_outbox_database_admission(
            PostgresPubSubRepository::new(pool, domain),
            capacity,
            crate::services::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(
                capacity,
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_pressure_is_retryable_without_hiding_other_failures() {
        for error in [
            anyhow::Error::from(sqlx::Error::PoolTimedOut),
            anyhow::Error::from(db::pubsub::PubSubMutationBusy),
        ] {
            assert!(is_pubsub_mutation_busy(&map_database_busy(error)));
        }
        let closed = map_database_busy(sqlx::Error::PoolClosed.into());
        assert!(!is_pubsub_mutation_busy(&closed));
        assert!(closed.downcast_ref::<sqlx::Error>().is_some());
        let integrity = map_database_busy(anyhow::anyhow!("stored audience is corrupt"));
        assert!(!is_pubsub_mutation_busy(&integrity));
        assert_eq!(integrity.to_string(), "stored audience is corrupt");
    }
}
