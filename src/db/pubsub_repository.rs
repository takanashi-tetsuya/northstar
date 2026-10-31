//! Complete PostgreSQL PubSub/PEP operations and locked audience snapshots.
use crate::db;
use anyhow::{Context, Result};
#[cfg(test)]
use northstar_pubsub_application::PubSubService;
use northstar_pubsub_application::{
    service::PubSubEventRenderer, PepAffiliationRepository, PepCommitLegacyBookmarksCommand,
    PepCommitLegacyBookmarksResult, PepItemMutationRepository, PepItemQueryRepository,
    PepNodeMutationRepository, PepNodeQueryRepository, PepPublishItemsCommand,
    PepPublishItemsOutcome, PepPublishItemsResult, PepSubscribeCommand, PepSubscribeResult,
    PepSubscriptionMutationRepository, PepSubscriptionQueryRepository, PepUnsubscribeCommand,
    PepUnsubscribeResult, PubSubAffiliationMutationRepository, PubSubAffiliationQueryRepository,
    PubSubCollectionDiscoChild, PubSubCollectionDiscoSnapshot, PubSubItemMutationRepository,
    PubSubItemQueryRepository, PubSubLeafDiscoSnapshot, PubSubNodeMutationRepository,
    PubSubNodeQueryRepository, PubSubOutboxRepository, PubSubOwnerRead, PubSubOwnerReadKind,
    PubSubRootDiscoveryQueryRepository, PubSubSubscriptionMutationRepository,
    PubSubSubscriptionQueryRepository,
};
use northstar_pubsub_core::PubSubRootDiscoPage;
use northstar_pubsub_core::{
    ClaimedPubSubOutboxDelivery, CollectionUpdateOutcome, CollectionVisibleItem, CreateNodeOutcome,
    DuePubSubDigest, OwnerMutationOutcome, PepAudienceSnapshot, PepBookmarkMutationOutcome,
    PepCreateOutcome, PepDirectOutboxFactory, PepDirectStateSnapshot, PepDirectStateTransition,
    PepItem, PepNodeConfig, PepOutboxAuthorizationMode, PepOutboxAuthorizationOutcome,
    PepOutboxDropReason, PepOutboxEventKind, PepOutboxFactory, PepOwnerMutationOutcome,
    PepPresenceSubscription, PepPublishOutcome, PepQuotas, PepSubscribeOutboxFactory,
    PepSubscribeOutcome, PepSubscribeSnapshot, PepSubscription, PepSubscriptionActor,
    PepUnsubscribeOutcome, PubSubAccount, PubSubAffiliation, PubSubConfigOutcome, PubSubItem,
    PubSubNode, PubSubNodeConfig, PubSubNodeMetadata, PubSubNotificationDelivery,
    PubSubOutboxDeliveryKind, PubSubOutboxFailureDisposition, PubSubOutboxInsert,
    PubSubOutboxSnapshot, PubSubOutboxSource, PubSubSubscription, PubSubSubscriptionOptions,
    PublishItemsOutcome, RetractItemsOutcome, SetAffiliationsOutcome, SetSubscriptionsOutcome,
    SubscribeOutcome, SubscriptionAuthorizationOutcome, SubscriptionOptionsOutcome,
    UnsubscribeOutcome,
};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, HashMap, HashSet};
use uuid::Uuid;

mod conversions;
mod outbox_rendering;
mod pep_ports;
mod pubsub_outbox;
mod pubsub_ports;

const BOOKMARKS2: &str = "urn:xmpp:bookmarks:1";

struct PepBookmarkReplacementOutbox<'a> {
    factory: &'a dyn PepOutboxFactory,
    current: Vec<(&'a str, &'a str)>,
    previous: Vec<(&'a str, &'a str)>,
}

impl PepOutboxFactory for PepBookmarkReplacementOutbox<'_> {
    fn build(&self, audience: &PepAudienceSnapshot) -> Result<Vec<(String, String)>> {
        self.factory
            .build_replaced(audience, &self.current, &self.previous)
    }
}

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
        let actor_jid = northstar_xmpp_types::jid::CanonicalJid::parse(actor.jid)?;
        let subscriber = northstar_xmpp_types::jid::CanonicalJid::parse(subscriber_jid)?;
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
        let owner_bare = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&format!(
            "{}@{}",
            owner.username, self.domain
        ))?
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
                northstar_xmpp_types::jid::canonicalize(recipient)
                    .is_ok_and(|recipient| authorized.contains(&recipient))
            }),
            "PEP direct-state renderer escaped the transaction-owned recipients"
        );
        let mut localparts = authorized
            .iter()
            .filter_map(|jid| northstar_xmpp_types::jid::CanonicalJid::parse(jid).ok())
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
            let bare = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&format!(
                "{username}@{}",
                self.domain
            ))?
            .to_string();
            local_accounts.insert(bare, id);
        }
        let event_id = Uuid::new_v4();
        let created_at = chrono::Utc::now();
        let mut seen = HashSet::new();
        let mut outbox = Vec::new();
        for (recipient, payload) in deliveries {
            let recipient = northstar_xmpp_types::jid::canonicalize(&recipient)?;
            if !seen.insert(recipient.clone()) {
                continue;
            }
            let recipient_bare = northstar_xmpp_types::jid::canonical_bare_key(&recipient)?;
            let recipient_account_id = if recipient_bare == snapshot.owner_bare_jid {
                Some(owner_id)
            } else {
                local_accounts.get(&recipient_bare).copied()
            };
            if northstar_xmpp_types::jid::CanonicalJid::parse(&recipient)?.domainpart()
                == self.domain
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
        published_items: Option<&[(&str, &str)]>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        let owner_bare_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&format!(
            "{owner_username}@{}",
            self.domain
        ))?
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
            .map(|jid| northstar_xmpp_types::jid::canonical_bare_key(&jid))
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
            let jid = northstar_xmpp_types::jid::canonicalize_bare(
                &row.try_get::<String, _>("contact_jid")?,
            )?;
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
        .map(|jid| northstar_xmpp_types::jid::canonicalize(&jid))
        .collect::<Result<Vec<_>>>()?;

        let mut localparts = roster
            .keys()
            .chain(explicit.iter())
            .filter_map(|jid| northstar_xmpp_types::jid::CanonicalJid::parse(jid).ok())
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
            let bare = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&format!(
                "{username}@{}",
                self.domain
            ))?
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
            let bare = northstar_xmpp_types::jid::canonical_bare_key(jid)?;
            if bare == owner_bare_jid {
                return Ok(true);
            }
            let parsed = northstar_xmpp_types::jid::CanonicalJid::parse(jid)?;
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
            let bare = northstar_xmpp_types::jid::canonical_bare_key(&jid)?;
            if authorized(&jid, roster.get(&bare))? {
                explicit_jids.push(jid);
            }
        }
        let audience = PepAudienceSnapshot {
            owner_bare_jid: owner_bare_jid.clone(),
            roster_jids,
            explicit_jids,
        };
        let deliveries = match published_items {
            Some(items) => factory.build_published(&audience, items)?,
            None => factory.build(&audience)?,
        };
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
                let recipient = northstar_xmpp_types::jid::canonicalize(&recipient).ok()?;
                seen.insert(recipient.clone())
                    .then_some((recipient, payload))
            })
            .map(|(recipient, payload)| {
                let recipient_bare = northstar_xmpp_types::jid::canonical_bare_key(&recipient)?;
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
        let owner_bare_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&format!(
            "{username}@{}",
            self.domain
        ))?
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
#[cfg(test)]
pub(crate) fn test_pubsub_service(
    pool: PgPool,
    domain: &str,
) -> PubSubService<PostgresPubSubRepository> {
    let capacity = pool.options().get_max_connections();
    PubSubService::new_with_durable_outbox_database_admission(
        PostgresPubSubRepository::new(pool, domain),
        capacity,
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(
            capacity,
        ),
    )
}

#[cfg(test)]
mod service_tests;
#[cfg(test)]
mod tests;
