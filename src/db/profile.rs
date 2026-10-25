//! PostgreSQL profile snapshots, avatar projection and durable publication.

use crate::{db, services::profile::*, xmpp::xml_builder::XmlElement};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

pub(crate) struct PostgresProfileRepository {
    pool: PgPool,
    domain: String,
}
impl PostgresProfileRepository {
    pub(crate) fn new(pool: PgPool, domain: String) -> Self {
        Self { pool, domain }
    }
    async fn exact_profile_outbox(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
        owner_username: &str,
        connection_id: Uuid,
        node: &str,
        factory: &dyn ProfileOutboxFactory,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        let owner_bare_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&format!(
            "{owner_username}@{}",
            self.domain
        ))?
        .to_string();
        let policy = stored_profile_node_policy(transaction, user_id, node).await?;
        anyhow::ensure!(
            policy.deliver_notifications,
            "profile outbox requested for a notification-disabled node"
        );

        // Existing roster rows are locked so unsubscribe/removal cannot commit
        // between authorization and the outbox projection. A newly-added row
        // is intentionally absent from this event-time snapshot.
        let roster_rows = sqlx::query(
            "SELECT contact_jid,subscription,groups
               FROM roster_items
              WHERE owner_id=$1 AND subscription IN ('from','both')
              ORDER BY contact_jid
              FOR SHARE",
        )
        .bind(user_id)
        .fetch_all(&mut **transaction)
        .await?;
        let mut roster = HashMap::with_capacity(roster_rows.len());
        for row in roster_rows {
            let jid: String = row.try_get("contact_jid")?;
            let jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&jid)?.to_string();
            let groups = serde_json::from_value::<Vec<String>>(row.try_get("groups")?)
                .context("stored roster groups are not a string array")?;
            roster.insert(
                jid,
                RosterAudienceEntry {
                    subscription: row.try_get("subscription")?,
                    groups,
                },
            );
        }

        // Node lock is already held. FOR SHARE additionally serializes legacy
        // roster-driven cancellation code which deletes rows without taking
        // that advisory lock.
        let explicit_rows = sqlx::query_scalar::<_, String>(
            "SELECT subscriber_jid FROM pep_subscriptions
              WHERE owner_id=$1 AND node=$2 AND state='subscribed'
              ORDER BY subscriber_jid
              FOR SHARE",
        )
        .bind(user_id)
        .bind(node)
        .fetch_all(&mut **transaction)
        .await?;
        let explicit = explicit_rows
            .into_iter()
            .map(|jid| northstar_xmpp_types::jid::canonicalize(&jid))
            .collect::<Result<Vec<_>>>()?;

        // XEP-0191 writes use the same seed-0 account locks. Take every local
        // participant lock in UUID order so owner/recipient block changes
        // cannot interleave with the snapshot and concurrent profile fan-out
        // cannot introduce a lock cycle.
        let mut localparts = roster
            .keys()
            .chain(explicit.iter())
            .filter_map(|jid| northstar_xmpp_types::jid::CanonicalJid::parse(jid).ok())
            .filter(|jid| jid.domainpart() == self.domain)
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
        let mut block_owners = vec![user_id];
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
        for owner_id in &block_owners {
            lock_profile_block_policy(transaction, *owner_id).await?;
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
        let privacy = owner_privacy_policy(transaction, user_id, connection_id).await?;

        let authorized = |jid: &str, roster_entry: Option<&RosterAudienceEntry>| -> Result<bool> {
            let bare = northstar_xmpp_types::jid::canonical_bare_key(jid)?;
            let parsed = northstar_xmpp_types::jid::CanonicalJid::parse(jid)?;
            if bare != owner_bare_jid
                && parsed.domainpart() == self.domain
                && !local_accounts.contains_key(&bare)
            {
                return Ok(false);
            }
            if blocks
                .get(&user_id)
                .is_some_and(|patterns| blocked_by_any(patterns, jid))
            {
                return Ok(false);
            }
            if let Some(recipient_id) = local_accounts.get(&bare) {
                if blocks
                    .get(recipient_id)
                    .is_some_and(|patterns| blocked_by_any(patterns, &owner_bare_jid))
                {
                    return Ok(false);
                }
            }
            if !profile_access_allowed(&policy, &bare, roster_entry)? {
                return Ok(false);
            }
            Ok(!privacy
                .as_ref()
                .is_some_and(|privacy| privacy_denies_message(privacy, jid, roster_entry)))
        };

        let mut roster_jids = Vec::new();
        for (jid, entry) in &roster {
            if authorized(jid, Some(entry))? {
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
        let audience = ProfileAudienceSnapshot {
            owner_bare_jid: owner_bare_jid.clone(),
            roster_jids,
            explicit_jids,
        };
        let mut deliveries = factory.build(&audience)?;
        anyhow::ensure!(
            deliveries
                .iter()
                .all(|(recipient, _)| audience.authorizes_routed_jid(recipient)),
            "profile renderer escaped the transaction-owned audience"
        );
        let mut seen = HashSet::new();
        deliveries.retain(|(recipient, _)| seen.insert(recipient.clone()));
        profile_outbox(
            user_id,
            &owner_bare_jid,
            Some(connection_id),
            node,
            &self.domain,
            &local_accounts,
            &deliveries,
        )
    }

    async fn begin_authorized_profile_mutation(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
    ) -> Result<Option<(Transaction<'_, Postgres>, String)>> {
        let mut transaction = crate::db::pubsub::begin_bounded_pubsub_mutation(&self.pool).await?;
        lock_profile_account(&mut transaction, user_id).await?;
        let owner_username = sqlx::query_scalar::<_, String>(
            "SELECT username FROM users
              WHERE id=$1 AND auth_generation=$2 AND NOT is_disabled
              FOR SHARE",
        )
        .bind(user_id)
        .bind(expected_auth_generation)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(owner_username) = owner_username else {
            transaction.rollback().await?;
            return Ok(None);
        };
        Ok(Some((transaction, owner_username)))
    }
}
impl ProfileRepository for PostgresProfileRepository {
    async fn public_vcard(&self, username: &str) -> Result<PublicVCard> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let row = sqlx::query(
            "SELECT v.user_id AS profile_account_id,v.payload
               FROM users u
               LEFT JOIN vcards v ON v.user_id=u.id
              WHERE u.username=$1 AND NOT u.is_disabled",
        )
        .bind(username)
        .fetch_optional(&mut *transaction)
        .await?;
        transaction.commit().await?;
        match row {
            Some(row) => Ok(PublicVCard::Profile(
                if row
                    .try_get::<Option<Uuid>, _>("profile_account_id")?
                    .is_some()
                {
                    Some(row.try_get("payload")?)
                } else {
                    None
                },
            )),
            None => Ok(PublicVCard::MissingAccount),
        }
    }

    async fn set_legacy_vcard(
        &self,
        write: LegacyVCardWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
    ) -> Result<ProfilePublishResult> {
        let Some((mut transaction, owner_username)) = self
            .begin_authorized_profile_mutation(write.user_id, write.auth_generation)
            .await?
        else {
            return Ok(ProfilePublishResult::rejected(
                ProfilePublishStatus::Unauthorized,
            ));
        };
        let previous = vcard_in_transaction(&mut transaction, write.user_id, true).await?;
        let previous_hash = previous.avatar_hash.as_deref();
        let pep_matches = converted_avatar_items_match(
            &mut transaction,
            write.user_id,
            write.data_item,
            write.metadata_item,
        )
        .await?;
        if previous_hash == write.avatar_hash && pep_matches {
            upsert_vcard_in_transaction(
                &mut transaction,
                write.user_id,
                write.payload,
                write.avatar_hash,
            )
            .await?;
            transaction.commit().await?;
            return Ok(ProfilePublishResult {
                status: ProfilePublishStatus::Published,
                content_changed: false,
                avatar_presence: AvatarPresenceUpdate::Unchanged,
            });
        }

        lock_profile_audience(&mut transaction, write.user_id, AVATAR_METADATA).await?;
        if !avatar_node_compatible(&mut transaction, write.user_id, AVATAR_DATA, false).await?
            || !avatar_node_compatible(&mut transaction, write.user_id, AVATAR_METADATA, true)
                .await?
        {
            transaction.rollback().await?;
            return Ok(ProfilePublishResult::rejected(
                ProfilePublishStatus::PreconditionFailed,
            ));
        }
        let quotas = db::PepQuotas {
            max_nodes: write.max_nodes,
            max_storage_bytes: write.max_storage_bytes,
        };
        if let Some(data_item) = write.data_item {
            let data_config = db::default_pep_node_config(AVATAR_DATA);
            let outcome = db::pep::publish_pep_items_in_transaction(
                &mut transaction,
                write.user_id,
                AVATAR_DATA,
                &data_config,
                false,
                &[data_item],
                quotas,
            )
            .await?;
            if outcome != db::PepPublishOutcome::Published {
                transaction.rollback().await?;
                return Ok(ProfilePublishResult::rejected(outcome.into()));
            }
        }
        let metadata_config = db::default_pep_node_config(AVATAR_METADATA);
        let outcome = db::pep::publish_pep_items_in_transaction(
            &mut transaction,
            write.user_id,
            AVATAR_METADATA,
            &metadata_config,
            false,
            &[write.metadata_item],
            quotas,
        )
        .await?;
        if outcome != db::PepPublishOutcome::Published {
            transaction.rollback().await?;
            return Ok(ProfilePublishResult::rejected(outcome.into()));
        }
        upsert_vcard_in_transaction(
            &mut transaction,
            write.user_id,
            write.payload,
            write.avatar_hash,
        )
        .await?;
        if profile_node_delivers_notifications(&mut transaction, write.user_id, AVATAR_METADATA)
            .await?
        {
            let outbox = self
                .exact_profile_outbox(
                    &mut transaction,
                    write.user_id,
                    &owner_username,
                    write.connection_id,
                    AVATAR_METADATA,
                    explicit_factory,
                )
                .await?;
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
        }
        transaction.commit().await?;
        Ok(ProfilePublishResult {
            status: ProfilePublishStatus::Published,
            content_changed: true,
            avatar_presence: if previous_hash == write.avatar_hash {
                AvatarPresenceUpdate::Unchanged
            } else {
                AvatarPresenceUpdate::Changed(write.avatar_hash.map(str::to_owned))
            },
        })
    }

    async fn publish_profile_items(
        &self,
        write: ProfilePepWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
        require_content_change: bool,
    ) -> Result<ProfilePublishResult> {
        let Some((mut transaction, owner_username)) = self
            .begin_authorized_profile_mutation(write.user_id, write.auth_generation)
            .await?
        else {
            return Ok(ProfilePublishResult::rejected(
                ProfilePublishStatus::Unauthorized,
            ));
        };
        lock_profile_audience(&mut transaction, write.user_id, write.node).await?;
        let changed = requested_items_changed(
            &mut transaction,
            write.user_id,
            write.node,
            write.items,
            false,
        )
        .await?;
        let outcome = db::pep::publish_pep_items_in_transaction(
            &mut transaction,
            write.user_id,
            write.node,
            &db::PepNodeConfig::from(write.requested),
            write.enforce_preconditions,
            write.items,
            db::PepQuotas {
                max_nodes: write.max_nodes,
                max_storage_bytes: write.max_storage_bytes,
            },
        )
        .await?;
        if outcome != db::PepPublishOutcome::Published {
            transaction.rollback().await?;
            return Ok(ProfilePublishResult::rejected(outcome.into()));
        }
        if (changed || !require_content_change)
            && profile_node_delivers_notifications(&mut transaction, write.user_id, write.node)
                .await?
        {
            let outbox = self
                .exact_profile_outbox(
                    &mut transaction,
                    write.user_id,
                    &owner_username,
                    write.connection_id,
                    write.node,
                    explicit_factory,
                )
                .await?;
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
        }
        transaction.commit().await?;
        Ok(ProfilePublishResult {
            status: ProfilePublishStatus::Published,
            content_changed: changed,
            avatar_presence: AvatarPresenceUpdate::Unchanged,
        })
    }

    async fn publish_avatar_metadata(
        &self,
        write: ProfilePepWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
    ) -> Result<ProfilePublishResult> {
        let Some((mut transaction, owner_username)) = self
            .begin_authorized_profile_mutation(write.user_id, write.auth_generation)
            .await?
        else {
            return Ok(ProfilePublishResult::rejected(
                ProfilePublishStatus::Unauthorized,
            ));
        };
        lock_profile_audience(&mut transaction, write.user_id, AVATAR_METADATA).await?;
        if !avatar_node_compatible(&mut transaction, write.user_id, AVATAR_DATA, false).await?
            || !avatar_node_compatible(&mut transaction, write.user_id, AVATAR_METADATA, true)
                .await?
        {
            transaction.rollback().await?;
            return Ok(ProfilePublishResult::rejected(
                ProfilePublishStatus::PreconditionFailed,
            ));
        }
        let previous = vcard_in_transaction(&mut transaction, write.user_id, true).await?;
        let projection = match avatar_projection_in_transaction(
            &mut transaction,
            write.user_id,
            previous.payload.as_deref(),
            write.items,
        )
        .await
        {
            Ok(projection) => projection,
            Err(error) => {
                tracing::debug!(?error, "avatar metadata projection rejected");
                transaction.rollback().await?;
                return Ok(ProfilePublishResult::rejected(
                    ProfilePublishStatus::InvalidAvatar,
                ));
            }
        };
        let changed = requested_items_changed(
            &mut transaction,
            write.user_id,
            AVATAR_METADATA,
            write.items,
            true,
        )
        .await?;
        let outcome = db::pep::publish_pep_items_in_transaction(
            &mut transaction,
            write.user_id,
            AVATAR_METADATA,
            &db::PepNodeConfig::from(write.requested),
            write.enforce_preconditions,
            write.items,
            db::PepQuotas {
                max_nodes: write.max_nodes,
                max_storage_bytes: write.max_storage_bytes,
            },
        )
        .await?;
        if outcome != db::PepPublishOutcome::Published {
            transaction.rollback().await?;
            return Ok(ProfilePublishResult::rejected(outcome.into()));
        }
        let avatar_presence = if let Some(projection) = projection {
            upsert_vcard_in_transaction(
                &mut transaction,
                write.user_id,
                &projection.vcard_payload,
                projection.avatar_hash.as_deref(),
            )
            .await?;
            if previous.avatar_hash == projection.avatar_hash {
                AvatarPresenceUpdate::Unchanged
            } else {
                AvatarPresenceUpdate::Changed(projection.avatar_hash)
            }
        } else {
            AvatarPresenceUpdate::Unchanged
        };
        if changed
            && profile_node_delivers_notifications(&mut transaction, write.user_id, AVATAR_METADATA)
                .await?
        {
            let outbox = self
                .exact_profile_outbox(
                    &mut transaction,
                    write.user_id,
                    &owner_username,
                    write.connection_id,
                    AVATAR_METADATA,
                    explicit_factory,
                )
                .await?;
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
        }
        transaction.commit().await?;
        Ok(ProfilePublishResult {
            status: ProfilePublishStatus::Published,
            content_changed: changed,
            avatar_presence,
        })
    }
}

impl From<db::PepPublishOutcome> for ProfilePublishStatus {
    fn from(value: db::PepPublishOutcome) -> Self {
        match value {
            db::PepPublishOutcome::Published => Self::Published,
            db::PepPublishOutcome::PreconditionFailed => Self::PreconditionFailed,
            db::PepPublishOutcome::MaxItemsExceeded => Self::MaxItemsExceeded,
            db::PepPublishOutcome::QuotaExceeded => Self::QuotaExceeded,
        }
    }
}

struct StoredVCard {
    payload: Option<String>,
    avatar_hash: Option<String>,
}

struct RosterAudienceEntry {
    subscription: String,
    groups: Vec<String>,
}

struct StoredProfileNodePolicy {
    access_model: String,
    roster_groups_allowed: Vec<String>,
    access_whitelist: Vec<String>,
    deliver_notifications: bool,
}

struct StoredPrivacyPolicy {
    items: Vec<StoredPrivacyItem>,
}

struct StoredPrivacyItem {
    deny: bool,
    match_type: Option<String>,
    match_value: Option<String>,
    message: bool,
    iq: bool,
    presence_in: bool,
    presence_out: bool,
}

struct AvatarProjection {
    vcard_payload: String,
    avatar_hash: Option<String>,
}

async fn lock_profile_account(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
        .bind(user_id.to_string())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn lock_profile_audience(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    node: &str,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 5))")
        .bind(format!("{user_id}:{node}"))
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn lock_profile_block_policy(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(user_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn vcard_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    lock: bool,
) -> Result<StoredVCard> {
    let sql = if lock {
        "SELECT payload,avatar_hash FROM vcards WHERE user_id=$1 FOR UPDATE"
    } else {
        "SELECT payload,avatar_hash FROM vcards WHERE user_id=$1"
    };
    let row = sqlx::query(sql)
        .bind(user_id)
        .fetch_optional(&mut **transaction)
        .await?;
    match row {
        Some(row) => Ok(StoredVCard {
            payload: Some(row.try_get("payload")?),
            avatar_hash: row.try_get("avatar_hash")?,
        }),
        None => Ok(StoredVCard {
            payload: None,
            avatar_hash: None,
        }),
    }
}

async fn upsert_vcard_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    payload: &str,
    avatar_hash: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO vcards(user_id,payload,avatar_hash) VALUES($1,$2,$3)
         ON CONFLICT(user_id) DO UPDATE
            SET payload=EXCLUDED.payload,
                avatar_hash=EXCLUDED.avatar_hash,
                updated_at=clock_timestamp()",
    )
    .bind(user_id)
    .bind(payload)
    .bind(avatar_hash)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn avatar_node_compatible(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    node: &str,
    require_single_item: bool,
) -> Result<bool> {
    let row = sqlx::query(
        "SELECT access_model,persist_items,max_items
           FROM pep_nodes
          WHERE owner_id=$1 AND node=$2
          FOR UPDATE",
    )
    .bind(user_id)
    .bind(node)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row.is_none_or(|row| {
        row.get::<String, _>("access_model") == "open"
            && row.get::<bool, _>("persist_items")
            && (!require_single_item || row.get::<i32, _>("max_items") == 1)
    }))
}

async fn requested_items_changed(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    node: &str,
    items: &[(&str, &str)],
    compare_whole_node: bool,
) -> Result<bool> {
    let item_ids = items.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    let rows = if compare_whole_node {
        sqlx::query(
            "SELECT item_id,payload FROM pep_items
              WHERE owner_id=$1 AND node=$2
              FOR UPDATE",
        )
        .bind(user_id)
        .bind(node)
        .fetch_all(&mut **transaction)
        .await?
    } else {
        sqlx::query(
            "SELECT item_id,payload FROM pep_items
              WHERE owner_id=$1 AND node=$2 AND item_id=ANY($3)
              FOR UPDATE",
        )
        .bind(user_id)
        .bind(node)
        .bind(&item_ids)
        .fetch_all(&mut **transaction)
        .await?
    };
    let previous = rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("item_id")?,
                row.try_get::<String, _>("payload")?,
            ))
        })
        .collect::<std::result::Result<HashMap<_, _>, sqlx::Error>>()?;
    Ok(previous.len() != items.len()
        || items
            .iter()
            .any(|(id, payload)| previous.get(*id).map(String::as_str) != Some(*payload)))
}

async fn converted_avatar_items_match(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    data_item: Option<(&str, &str)>,
    metadata_item: (&str, &str),
) -> Result<bool> {
    let metadata_matches = !requested_items_changed(
        transaction,
        user_id,
        AVATAR_METADATA,
        &[metadata_item],
        true,
    )
    .await?;
    if !metadata_matches {
        return Ok(false);
    }
    let Some((item_id, payload)) = data_item else {
        return Ok(true);
    };
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pep_items
          WHERE owner_id=$1 AND node=$2 AND item_id=$3 AND payload=$4)",
    )
    .bind(user_id)
    .bind(AVATAR_DATA)
    .bind(item_id)
    .bind(payload)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn profile_node_delivers_notifications(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    node: &str,
) -> Result<bool> {
    sqlx::query_scalar(
        "SELECT deliver_notifications FROM pep_nodes
          WHERE owner_id=$1 AND node=$2",
    )
    .bind(user_id)
    .bind(node)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn stored_profile_node_policy(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    node: &str,
) -> Result<StoredProfileNodePolicy> {
    let row = sqlx::query(
        "SELECT access_model,roster_groups_allowed,access_whitelist,deliver_notifications
           FROM pep_nodes
          WHERE owner_id=$1 AND node=$2
          FOR SHARE",
    )
    .bind(user_id)
    .bind(node)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(StoredProfileNodePolicy {
        access_model: row.try_get("access_model")?,
        roster_groups_allowed: row.try_get("roster_groups_allowed")?,
        access_whitelist: row.try_get("access_whitelist")?,
        deliver_notifications: row.try_get("deliver_notifications")?,
    })
}

async fn owner_privacy_policy(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    connection_id: Uuid,
) -> Result<Option<StoredPrivacyPolicy>> {
    let active = sqlx::query_scalar::<_, String>(
        "SELECT list_name FROM privacy_active_sessions
          WHERE owner_id=$1 AND connection_id=$2 AND expires_at>NOW()
          FOR SHARE",
    )
    .bind(owner_id)
    .bind(connection_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let selected = match active {
        Some(active) => Some(active),
        None => {
            sqlx::query_scalar::<_, String>(
                "SELECT list_name FROM privacy_default_lists
                  WHERE owner_id=$1
                  FOR SHARE",
            )
            .bind(owner_id)
            .fetch_optional(&mut **transaction)
            .await?
        }
    };
    let Some(selected) = selected else {
        return Ok(None);
    };
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM privacy_lists WHERE owner_id=$1 AND name=$2)",
    )
    .bind(owner_id)
    .bind(&selected)
    .fetch_one(&mut **transaction)
    .await?;
    anyhow::ensure!(exists, "selected profile privacy list is missing");
    let rows = sqlx::query(
        "SELECT action,match_type,match_value,filter_message,filter_iq,
                filter_presence_in,filter_presence_out
           FROM privacy_list_items
          WHERE owner_id=$1 AND list_name=$2
          ORDER BY item_order
          FOR SHARE",
    )
    .bind(owner_id)
    .bind(&selected)
    .fetch_all(&mut **transaction)
    .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let action: String = row.try_get("action")?;
        anyhow::ensure!(
            matches!(action.as_str(), "allow" | "deny"),
            "invalid privacy action"
        );
        let match_type: Option<String> = row.try_get("match_type")?;
        anyhow::ensure!(
            match_type
                .as_deref()
                .is_none_or(|kind| matches!(kind, "jid" | "group" | "subscription")),
            "invalid privacy match type"
        );
        let match_value: Option<String> = row.try_get("match_value")?;
        anyhow::ensure!(
            match_type.is_some() == match_value.is_some(),
            "incomplete privacy matcher"
        );
        items.push(StoredPrivacyItem {
            deny: action == "deny",
            match_type,
            match_value,
            message: row.try_get("filter_message")?,
            iq: row.try_get("filter_iq")?,
            presence_in: row.try_get("filter_presence_in")?,
            presence_out: row.try_get("filter_presence_out")?,
        });
    }
    Ok(Some(StoredPrivacyPolicy { items }))
}

fn profile_access_allowed(
    policy: &StoredProfileNodePolicy,
    candidate_bare: &str,
    roster: Option<&RosterAudienceEntry>,
) -> Result<bool> {
    match policy.access_model.as_str() {
        "open" => Ok(true),
        "presence" => {
            Ok(roster.is_some_and(|entry| matches!(entry.subscription.as_str(), "from" | "both")))
        }
        "roster" => Ok(roster.is_some_and(|entry| {
            matches!(entry.subscription.as_str(), "from" | "both")
                && entry.groups.iter().any(|group| {
                    policy
                        .roster_groups_allowed
                        .iter()
                        .any(|allowed| allowed == group)
                })
        })),
        "whitelist" => {
            for allowed in &policy.access_whitelist {
                if northstar_xmpp_types::jid::canonical_bare_key(allowed)? == candidate_bare {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}

fn blocked_by_any(patterns: &[String], candidate: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| db::roster::blocked_jid_matches(pattern, candidate))
}

fn privacy_denies_message(
    policy: &StoredPrivacyPolicy,
    candidate: &str,
    roster: Option<&RosterAudienceEntry>,
) -> bool {
    for item in &policy.items {
        let has_filter = item.message || item.iq || item.presence_in || item.presence_out;
        if has_filter && !item.message {
            continue;
        }
        let entity_matches = match (item.match_type.as_deref(), item.match_value.as_deref()) {
            (None, None) => true,
            (Some("jid"), Some(value)) => db::roster::blocked_jid_matches(value, candidate),
            (Some("group"), Some(value)) => {
                roster.is_some_and(|entry| entry.groups.iter().any(|group| group == value))
            }
            (Some("subscription"), Some(value)) => {
                roster.map_or(value == "none", |entry| entry.subscription == value)
            }
            _ => false,
        };
        if entity_matches {
            return item.deny;
        }
    }
    false
}

fn profile_outbox(
    user_id: Uuid,
    owner_bare_jid: &str,
    sender_connection_id: Option<Uuid>,
    node: &str,
    local_domain: &str,
    local_accounts: &HashMap<String, Uuid>,
    deliveries: &[(String, String)],
) -> Result<Vec<db::PubSubOutboxInsert>> {
    let event_id = Uuid::new_v4();
    let created_at = chrono::Utc::now();
    deliveries
        .iter()
        .map(|(recipient, message)| {
            let recipient_bare = northstar_xmpp_types::jid::canonical_bare_key(recipient)?;
            let recipient_account_id = if recipient_bare == owner_bare_jid {
                Some(user_id)
            } else {
                local_accounts.get(&recipient_bare).copied()
            };
            db::PubSubOutboxInsert::new_pep_stanza(
                event_id,
                user_id,
                owner_bare_jid,
                sender_connection_id,
                recipient.clone(),
                recipient_account_id,
                db::PepOutboxEventKind::Publish,
                db::PepOutboxAuthorizationMode::CausalAudience,
                message.clone(),
                node,
                local_domain,
                created_at,
            )
        })
        .collect()
}

async fn avatar_projection_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    current_vcard: Option<&str>,
    items: &[(&str, &str)],
) -> Result<Option<AvatarProjection>> {
    let [(_, metadata_item)] = items else {
        bail!("avatar metadata publication must contain exactly one item");
    };
    let document = roxmltree::Document::parse(metadata_item)?;
    let metadata = document
        .root_element()
        .children()
        .find(|child| {
            child.is_element()
                && child.tag_name().name() == "metadata"
                && child.tag_name().namespace() == Some(AVATAR_METADATA)
        })
        .context("missing avatar metadata payload")?;
    let empty_vcard = XmlElement::namespaced("vCard", "vcard-temp").finish();
    let current = current_vcard.unwrap_or(&empty_vcard);
    let elements = metadata
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if elements.is_empty() {
        return Ok(Some(AvatarProjection {
            vcard_payload: replace_vcard_temp_photo(current, None, None),
            avatar_hash: None,
        }));
    }
    let infos = elements
        .iter()
        .copied()
        .filter(|child| {
            child.tag_name().name() == "info"
                && child.tag_name().namespace() == Some(AVATAR_METADATA)
                && child.attribute("url").is_none()
        })
        .collect::<Vec<_>>();
    let Some(info) = infos
        .iter()
        .find(|info| {
            info.attribute("type")
                .is_some_and(|media_type| media_type.eq_ignore_ascii_case("image/png"))
        })
        .copied()
        .or_else(|| infos.first().copied())
    else {
        // URL-only representations have no non-external legacy projection.
        return Ok(None);
    };
    let data_node = sqlx::query(
        "SELECT access_model,persist_items FROM pep_nodes
          WHERE owner_id=$1 AND node=$2
          FOR UPDATE",
    )
    .bind(user_id)
    .bind(AVATAR_DATA)
    .fetch_optional(&mut **transaction)
    .await?;
    if data_node.as_ref().is_none_or(|node| {
        node.get::<String, _>("access_model") != "open" || !node.get::<bool, _>("persist_items")
    }) {
        bail!("avatar data node is not publicly retrievable");
    }
    let hash = info
        .attribute("id")
        .context("avatar metadata has no hash")?;
    let media_type = info
        .attribute("type")
        .context("avatar metadata has no media type")?;
    let declared_bytes = info
        .attribute("bytes")
        .and_then(|value| value.parse::<usize>().ok())
        .context("avatar metadata has no valid byte length")?;
    let item_xml = sqlx::query_scalar::<_, String>(
        "SELECT payload FROM pep_items
          WHERE owner_id=$1 AND node=$2 AND item_id=$3
          FOR UPDATE",
    )
    .bind(user_id)
    .bind(AVATAR_DATA)
    .bind(hash)
    .fetch_optional(&mut **transaction)
    .await?
    .context("avatar data item does not exist")?;
    let data_document = roxmltree::Document::parse(&item_xml)?;
    let data = data_document
        .root_element()
        .children()
        .find(|child| {
            child.is_element()
                && child.tag_name().name() == "data"
                && child.tag_name().namespace() == Some(AVATAR_DATA)
        })
        .context("avatar data item has no data payload")?;
    let encoded = data
        .children()
        .filter_map(|child| child.text())
        .collect::<String>()
        .replace(char::is_whitespace, "");
    let bytes = BASE64
        .decode(&encoded)
        .context("avatar data is not valid base64")?;
    anyhow::ensure!(
        !bytes.is_empty()
            && bytes.len() <= 256 * 1024
            && bytes.len() == declared_bytes
            && sha1_hex(&bytes).eq_ignore_ascii_case(hash)
            && detected_media_type(&bytes)
                .is_some_and(|actual| actual.eq_ignore_ascii_case(media_type))
            && (!media_type.eq_ignore_ascii_case("image/png") || valid_png_image(&bytes)),
        "avatar data no longer matches metadata"
    );
    Ok(Some(AvatarProjection {
        vcard_payload: replace_vcard_temp_photo(current, Some(media_type), Some(&encoded)),
        avatar_hash: Some(hash.to_ascii_lowercase()),
    }))
}

#[cfg(test)]
mod tests;
