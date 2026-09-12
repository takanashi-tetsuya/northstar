use crate::{db, xmpp::xml_builder::XmlElement};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sha1::{Digest, Sha1};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) const AVATAR_DATA: &str = "urn:xmpp:avatar:data";
pub(crate) const AVATAR_METADATA: &str = "urn:xmpp:avatar:metadata";
pub(crate) const VCARD4: &str = "urn:xmpp:vcard4";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PublicVCard {
    MissingAccount,
    Profile(Option<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AvatarPresenceUpdate {
    Unchanged,
    Changed(Option<String>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfilePublishStatus {
    Published,
    Unauthorized,
    PreconditionFailed,
    MaxItemsExceeded,
    QuotaExceeded,
    InvalidAvatar,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProfilePublishResult {
    pub(crate) status: ProfilePublishStatus,
    pub(crate) content_changed: bool,
    pub(crate) avatar_presence: AvatarPresenceUpdate,
}

impl ProfilePublishResult {
    fn rejected(status: ProfilePublishStatus) -> Self {
        Self {
            status,
            content_changed: false,
            avatar_presence: AvatarPresenceUpdate::Unchanged,
        }
    }
}

pub(crate) struct LegacyVCardWrite<'a> {
    pub(crate) user_id: Uuid,
    pub(crate) auth_generation: i64,
    pub(crate) connection_id: Uuid,
    pub(crate) payload: &'a str,
    pub(crate) avatar_hash: Option<&'a str>,
    pub(crate) data_item: Option<(&'a str, &'a str)>,
    pub(crate) metadata_item: (&'a str, &'a str),
    pub(crate) max_nodes: i64,
    pub(crate) max_storage_bytes: i64,
}

pub(crate) struct ProfilePepWrite<'a> {
    pub(crate) user_id: Uuid,
    pub(crate) auth_generation: i64,
    pub(crate) connection_id: Uuid,
    pub(crate) node: &'a str,
    pub(crate) requested: &'a db::PepNodeConfig,
    pub(crate) enforce_preconditions: bool,
    pub(crate) items: &'a [(&'a str, &'a str)],
    pub(crate) max_nodes: i64,
    pub(crate) max_storage_bytes: i64,
}

/// Exact durable authorization snapshot captured while the profile account,
/// PEP node and audience-policy locks are held. Online resources/caps remain
/// soft routing hints, but they can only narrow these authorized principals.
pub(crate) struct ProfileAudienceSnapshot {
    pub(crate) owner_bare_jid: String,
    pub(crate) roster_jids: Vec<String>,
    pub(crate) explicit_jids: Vec<String>,
}

impl ProfileAudienceSnapshot {
    fn authorizes_routed_jid(&self, recipient: &str) -> bool {
        let Ok(recipient) = crate::jid::CanonicalJid::parse(recipient) else {
            return false;
        };
        let recipient_full = recipient.to_string();
        let recipient_bare = recipient.bare();
        if recipient_bare == self.owner_bare_jid
            || self.roster_jids.iter().any(|jid| jid == &recipient_bare)
        {
            return true;
        }
        self.explicit_jids.iter().any(|jid| {
            crate::jid::CanonicalJid::parse(jid).is_ok_and(|explicit| {
                if explicit.resourcepart().is_some() {
                    explicit.to_string() == recipient_full
                } else {
                    explicit.bare() == recipient_bare
                }
            })
        })
    }
}

/// Synchronously renders a transaction-owned profile audience. The callback
/// must not perform I/O: keeping it synchronous prevents a PostgreSQL
/// transaction from spanning a network operation or a second pool wait.
pub(crate) trait ProfileOutboxFactory: Send + Sync {
    fn build(&self, audience: &ProfileAudienceSnapshot) -> Result<Vec<(String, String)>>;
}

impl<F> ProfileOutboxFactory for F
where
    F: Fn(&ProfileAudienceSnapshot) -> Result<Vec<(String, String)>> + Send + Sync,
{
    fn build(&self, audience: &ProfileAudienceSnapshot) -> Result<Vec<(String, String)>> {
        self(audience)
    }
}

pub(crate) struct ProfileService {
    pool: PgPool,
    domain: String,
    mutation_admission: Arc<crate::services::pubsub::PubSubMutationAdmission>,
}

impl ProfileService {
    #[cfg(test)]
    pub(crate) fn new(pool: PgPool, domain: String) -> Self {
        let mutation_admission = Arc::new(crate::services::pubsub::PubSubMutationAdmission::new(
            pool.options().get_max_connections() as usize,
        ));
        Self {
            pool,
            domain,
            mutation_admission,
        }
    }

    pub(crate) fn with_mutation_admission(
        pool: PgPool,
        domain: String,
        mutation_admission: Arc<crate::services::pubsub::PubSubMutationAdmission>,
    ) -> Self {
        Self {
            pool,
            domain,
            mutation_admission,
        }
    }

    /// Resolve account existence and its public legacy profile from one
    /// repeatable-read snapshot. No credential-bearing `db::User` crosses the
    /// service boundary.
    pub(crate) async fn public_vcard(&self, username: &str) -> Result<PublicVCard> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let row = sqlx::query(
            "SELECT v.payload
               FROM users u
               LEFT JOIN vcards v ON v.user_id=u.id
              WHERE u.username=$1",
        )
        .bind(username)
        .fetch_optional(&mut *transaction)
        .await?;
        transaction.commit().await?;
        match row {
            Some(row) => Ok(PublicVCard::Profile(row.try_get("payload")?)),
            None => Ok(PublicVCard::MissingAccount),
        }
    }

    /// Apply a legacy vCard-temp write and, when its avatar changes, the
    /// converted XEP-0084 data/metadata items plus their durable event outbox.
    /// The prior hash comparison is deliberately inside the account lock.
    pub(crate) async fn set_legacy_vcard(
        &self,
        write: LegacyVCardWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
    ) -> Result<ProfilePublishResult> {
        let owner_key = write.user_id.to_string();
        let _permit = self
            .mutation_admission
            .acquire(&[&owner_key], false)
            .await?;
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

    /// Publish vCard4 or avatar data under the same account lock used by the
    /// vCard-temp/metadata projection. Authorization, comparison, mutation and
    /// outbox insertion share one transaction.
    pub(crate) async fn publish_profile_items(
        &self,
        write: ProfilePepWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
        require_content_change: bool,
    ) -> Result<ProfilePublishResult> {
        anyhow::ensure!(
            matches!(write.node, AVATAR_DATA | VCARD4),
            "generic profile publish supports only avatar data and vCard4"
        );
        let owner_key = write.user_id.to_string();
        let _permit = self
            .mutation_admission
            .acquire(&[&owner_key, write.node], false)
            .await?;
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
            write.requested,
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

    /// Atomically publish avatar metadata and derive the legacy vCard fallback
    /// from the exact vCard, node and data item read after taking the profile
    /// account lock. No prepared projection can overwrite a concurrent profile
    /// write.
    pub(crate) async fn publish_avatar_metadata(
        &self,
        write: ProfilePepWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
    ) -> Result<ProfilePublishResult> {
        anyhow::ensure!(
            write.node == AVATAR_METADATA,
            "avatar metadata publication used the wrong node"
        );
        let owner_key = write.user_id.to_string();
        let _permit = self
            .mutation_admission
            .acquire(&[&owner_key, write.node], false)
            .await?;
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
            write.requested,
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

    /// Capture every durable fan-out authorization input in the mutation
    /// transaction. The protocol callback may consult online caps/resources,
    /// but cannot add a principal which is absent from this snapshot.
    async fn exact_profile_outbox(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
        owner_username: &str,
        connection_id: Uuid,
        node: &str,
        factory: &dyn ProfileOutboxFactory,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        let owner_bare_jid =
            crate::jid::CanonicalJid::parse_bare(&format!("{owner_username}@{}", self.domain))?
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
            let jid = crate::jid::CanonicalJid::parse_bare(&jid)?.to_string();
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
            .map(|jid| crate::jid::canonicalize(&jid))
            .collect::<Result<Vec<_>>>()?;

        // XEP-0191 writes use the same seed-0 account locks. Take every local
        // participant lock in UUID order so owner/recipient block changes
        // cannot interleave with the snapshot and concurrent profile fan-out
        // cannot introduce a lock cycle.
        let mut localparts = roster
            .keys()
            .chain(explicit.iter())
            .filter_map(|jid| crate::jid::CanonicalJid::parse(jid).ok())
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
            let bare =
                crate::jid::CanonicalJid::parse_bare(&format!("{username}@{}", self.domain))?
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
            let bare = crate::jid::canonical_bare_key(jid)?;
            let parsed = crate::jid::CanonicalJid::parse(jid)?;
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
            let bare = crate::jid::canonical_bare_key(&jid)?;
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
                if crate::jid::canonical_bare_key(allowed)? == candidate_bare {
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
            let recipient_bare = crate::jid::canonical_bare_key(recipient)?;
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

pub(crate) fn sha1_hex(bytes: &[u8]) -> String {
    Sha1::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn detected_media_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.starts_with(b"BM") {
        Some("image/bmp")
    } else if bytes.starts_with(b"II*\0") || bytes.starts_with(b"MM\0*") {
        Some("image/tiff")
    } else if bytes.starts_with(&[0, 0, 1, 0]) {
        Some("image/vnd.microsoft.icon")
    } else if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        match &bytes[8..12] {
            b"avif" | b"avis" => Some("image/avif"),
            b"heic" | b"heix" | b"hevc" | b"hevx" => Some("image/heic"),
            b"mif1" | b"msf1" => Some("image/heif"),
            _ => None,
        }
    } else {
        None
    }
}

pub(crate) fn replace_vcard_temp_photo(
    existing: &str,
    media_type: Option<&str>,
    encoded: Option<&str>,
) -> String {
    let Ok(document) = roxmltree::Document::parse(existing) else {
        return empty_vcard_with_photo(media_type, encoded, None);
    };
    let root = document.root_element();
    if root.tag_name().name() != "vCard" || root.tag_name().namespace() != Some("vcard-temp") {
        return empty_vcard_with_photo(media_type, encoded, None);
    }
    let version = root.attribute("version").map(str::to_owned);
    let mut ranges = root
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == "PHOTO"
                && child.tag_name().namespace() == Some("vcard-temp")
        })
        .map(|child| child.range())
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut output = existing.to_owned();
    for range in ranges {
        output.replace_range(range, "");
    }
    let photo = serialized_photo(media_type, encoded);
    if let Some(end) = output.rfind("</") {
        output.insert_str(end, &photo);
        output
    } else if output.trim_end().ends_with("/>") {
        empty_vcard_with_photo(media_type, encoded, version.as_deref())
    } else {
        empty_vcard_with_photo(media_type, encoded, None)
    }
}

fn serialized_photo(media_type: Option<&str>, encoded: Option<&str>) -> String {
    match (media_type, encoded) {
        (Some(media_type), Some(encoded)) => XmlElement::new("PHOTO")
            .child(XmlElement::new("TYPE").text(media_type))
            .child(XmlElement::new("BINVAL").text(encoded))
            .finish(),
        _ => String::new(),
    }
}

fn empty_vcard_with_photo(
    media_type: Option<&str>,
    encoded: Option<&str>,
    version: Option<&str>,
) -> String {
    let mut vcard = XmlElement::namespaced("vCard", "vcard-temp").optional_attr("version", version);
    if let (Some(media_type), Some(encoded)) = (media_type, encoded) {
        vcard.push_child(
            XmlElement::new("PHOTO")
                .child(XmlElement::new("TYPE").text(media_type))
                .child(XmlElement::new("BINVAL").text(encoded)),
        );
    }
    vcard.finish()
}

/// Strict enough to reject truncated, reordered, CRC-corrupted or trailing
/// PNG containers used as a metadata hash oracle.
pub(crate) fn valid_png_image(bytes: &[u8]) -> bool {
    const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if !bytes.starts_with(SIGNATURE) {
        return false;
    }
    let mut offset = SIGNATURE.len();
    let mut saw_ihdr = false;
    let mut saw_plte = false;
    let mut saw_idat = false;
    let mut left_idat_run = false;
    let mut color_type = 0_u8;
    while offset < bytes.len() {
        let Some(header_end) = offset.checked_add(8) else {
            return false;
        };
        if header_end > bytes.len() {
            return false;
        }
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let chunk_type = &bytes[offset + 4..header_end];
        let Some(data_end) = header_end.checked_add(length) else {
            return false;
        };
        let Some(chunk_end) = data_end.checked_add(4) else {
            return false;
        };
        if chunk_end > bytes.len()
            || !chunk_type.iter().all(u8::is_ascii_alphabetic)
            || png_crc32(&bytes[offset + 4..data_end])
                != u32::from_be_bytes(bytes[data_end..chunk_end].try_into().unwrap())
        {
            return false;
        }
        match chunk_type {
            b"IHDR" => {
                if saw_ihdr || offset != SIGNATURE.len() || length != 13 {
                    return false;
                }
                let data = &bytes[header_end..data_end];
                let width = u32::from_be_bytes(data[0..4].try_into().unwrap());
                let height = u32::from_be_bytes(data[4..8].try_into().unwrap());
                let bit_depth = data[8];
                color_type = data[9];
                let valid_depth = match color_type {
                    0 => matches!(bit_depth, 1 | 2 | 4 | 8 | 16),
                    2 | 4 | 6 => matches!(bit_depth, 8 | 16),
                    3 => matches!(bit_depth, 1 | 2 | 4 | 8),
                    _ => false,
                };
                if width == 0
                    || height == 0
                    || !valid_depth
                    || data[10] != 0
                    || data[11] != 0
                    || data[12] > 1
                {
                    return false;
                }
                saw_ihdr = true;
            }
            b"PLTE" => {
                if !saw_ihdr
                    || saw_plte
                    || saw_idat
                    || matches!(color_type, 0 | 4)
                    || length == 0
                    || length > 768
                    || !length.is_multiple_of(3)
                {
                    return false;
                }
                saw_plte = true;
            }
            b"IDAT" => {
                if !saw_ihdr || left_idat_run || color_type == 3 && !saw_plte {
                    return false;
                }
                saw_idat = true;
            }
            b"IEND" => {
                return saw_ihdr && saw_idat && length == 0 && chunk_end == bytes.len();
            }
            _ if chunk_type[0].is_ascii_uppercase() => return false,
            _ => {
                if !saw_ihdr {
                    return false;
                }
            }
        }
        if saw_idat && chunk_type != b"IDAT" {
            left_idat_run = true;
        }
        offset = chunk_end;
    }
    false
}

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    struct IsolatedDatabase {
        admin: PgPool,
        pool: PgPool,
        schema: String,
    }

    impl IsolatedDatabase {
        async fn create(label: &str) -> Self {
            let url = std::env::var("TEST_DATABASE_URL")
                .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
            let admin = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await
                .unwrap();
            let schema = format!("profile_{label}_{}", Uuid::new_v4().simple());
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .unwrap();
            let connection_schema = schema.clone();
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(8)
                .after_connect(move |connection, _| {
                    let statement = format!("SET search_path TO {connection_schema}");
                    Box::pin(async move {
                        sqlx::query(&statement).execute(connection).await?;
                        Ok(())
                    })
                })
                .connect(&url)
                .await
                .unwrap();
            crate::db::migrate(&pool).await.unwrap();
            Self {
                admin,
                pool,
                schema,
            }
        }

        async fn finish(self) {
            self.pool.close().await;
            sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
                .execute(&self.admin)
                .await
                .unwrap();
            self.admin.close().await;
        }
    }

    async fn insert_user(pool: &PgPool, prefix: &str) -> (Uuid, String, i64) {
        let id = Uuid::new_v4();
        let username = format!("{prefix}{}", &id.simple().to_string()[..10]);
        let generation = sqlx::query_scalar::<_, i64>(
            "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')
             RETURNING auth_generation",
        )
        .bind(id)
        .bind(&username)
        .fetch_one(pool)
        .await
        .unwrap();
        (id, username, generation)
    }

    fn vcard4_item(id: &str, value: &str) -> String {
        format!(
            "<item id='{id}'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn><text>{value}</text></fn></vcard></item>"
        )
    }

    fn direct_snapshot_deliveries(
        audience: &ProfileAudienceSnapshot,
    ) -> Result<Vec<(String, String)>> {
        Ok(audience
            .roster_jids
            .iter()
            .chain(audience.explicit_jids.iter())
            .map(|jid| {
                (
                    jid.clone(),
                    format!("<message xmlns='jabber:client' to='{jid}'/>"),
                )
            })
            .collect())
    }

    #[test]
    fn vcard_photo_projection_preserves_non_photo_profile_fields() {
        let existing = "<vCard xmlns='vcard-temp'><FN>Alice &amp; Bob</FN><PHOTO><BINVAL>old</BINVAL></PHOTO><NICKNAME>a</NICKNAME></vCard>";
        let replaced = replace_vcard_temp_photo(existing, Some("image/png"), Some("new"));
        assert!(replaced.contains("<FN>Alice &amp; Bob</FN>"));
        assert!(replaced.contains("<NICKNAME>a</NICKNAME>"));
        assert!(!replaced.contains("old"));
        assert!(replaced.contains("<BINVAL>new</BINVAL>"));
        let cleared = replace_vcard_temp_photo(&replaced, None, None);
        assert!(cleared.contains("<FN>Alice &amp; Bob</FN>"));
        assert!(!cleared.contains("<PHOTO>"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
    async fn profile_publish_uses_exact_subscribe_and_block_snapshot() {
        let database = IsolatedDatabase::create("audience").await;
        let (owner_id, _, auth_generation) = insert_user(&database.pool, "owner").await;
        let config = db::default_pep_node_config(VCARD4);
        assert!(matches!(
            db::create_pep_node(&database.pool, owner_id, VCARD4, &config, 10)
                .await
                .unwrap(),
            db::PepCreateOutcome::Created
        ));
        let unsubscribed = format!("unsub{}@remote.test/phone", Uuid::new_v4().simple());
        let blocked = format!("blocked{}@remote.test/tablet", Uuid::new_v4().simple());
        let unsubscribed_record =
            db::subscribe_pep_node(&database.pool, owner_id, VCARD4, &unsubscribed, 100)
                .await
                .unwrap()
                .unwrap();
        db::subscribe_pep_node(&database.pool, owner_id, VCARD4, &blocked, 100)
            .await
            .unwrap()
            .unwrap();

        let service = Arc::new(ProfileService::new(
            database.pool.clone(),
            "example.test".to_owned(),
        ));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let factory_gate = Arc::clone(&gate);
        let (snapshot_tx, mut snapshot_rx) = tokio::sync::mpsc::unbounded_channel();
        let publish_service = Arc::clone(&service);
        let publish = tokio::spawn(async move {
            let config = db::default_pep_node_config(VCARD4);
            let payload = vcard4_item("profile", "one");
            let items = [("profile", payload.as_str())];
            let factory = move |audience: &ProfileAudienceSnapshot| {
                snapshot_tx
                    .send((audience.roster_jids.clone(), audience.explicit_jids.clone()))
                    .map_err(|_| anyhow::anyhow!("profile snapshot observer closed"))?;
                let (released, wake) = &*factory_gate;
                let mut released = released.lock().expect("profile gate poisoned");
                while !*released {
                    released = wake.wait(released).expect("profile gate poisoned");
                }
                direct_snapshot_deliveries(audience)
            };
            publish_service
                .publish_profile_items(
                    ProfilePepWrite {
                        user_id: owner_id,
                        auth_generation,
                        connection_id: Uuid::new_v4(),
                        node: VCARD4,
                        requested: &config,
                        enforce_preconditions: false,
                        items: &items,
                        max_nodes: 10,
                        max_storage_bytes: 1_000_000,
                    },
                    &factory,
                    true,
                )
                .await
        });
        let (_, mut explicit) = tokio::time::timeout(Duration::from_secs(3), snapshot_rx.recv())
            .await
            .expect("publication never reached the audience snapshot")
            .expect("profile snapshot observer closed");
        explicit.sort_unstable();
        let mut expected = vec![unsubscribed.clone(), blocked.clone()];
        expected.sort_unstable();
        assert_eq!(explicit, expected);

        let unsubscribe_pool = database.pool.clone();
        let unsubscribe_jid = unsubscribed.clone();
        let unsubscribe_subid = unsubscribed_record.subid.clone();
        let mut unsubscribe = tokio::spawn(async move {
            db::unsubscribe_pep_node(
                &unsubscribe_pool,
                owner_id,
                VCARD4,
                &unsubscribe_jid,
                Some(&unsubscribe_subid),
            )
            .await
        });
        let block_pool = database.pool.clone();
        let blocked_for_task = blocked.clone();
        let mut block = tokio::spawn(async move {
            db::block_jids(&block_pool, owner_id, &[blocked_for_task]).await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut unsubscribe)
                .await
                .is_err(),
            "unsubscribe bypassed the profile node lock"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut block)
                .await
                .is_err(),
            "block mutation bypassed the profile audience lock"
        );
        {
            let (released, wake) = &*gate;
            *released.lock().expect("profile gate poisoned") = true;
            wake.notify_all();
        }
        assert_eq!(
            publish.await.unwrap().unwrap().status,
            ProfilePublishStatus::Published
        );
        unsubscribe.await.unwrap().unwrap().unwrap();
        assert!(matches!(
            block.await.unwrap().unwrap(),
            db::BlockJidsUpdate::Changed(_)
        ));

        let second_payload = vcard4_item("profile", "two");
        let second_items = [("profile", second_payload.as_str())];
        let (second_tx, mut second_rx) = tokio::sync::mpsc::unbounded_channel();
        let second = service
            .publish_profile_items(
                ProfilePepWrite {
                    user_id: owner_id,
                    auth_generation,
                    connection_id: Uuid::new_v4(),
                    node: VCARD4,
                    requested: &config,
                    enforce_preconditions: false,
                    items: &second_items,
                    max_nodes: 10,
                    max_storage_bytes: 1_000_000,
                },
                &|audience: &ProfileAudienceSnapshot| {
                    second_tx
                        .send(audience.explicit_jids.clone())
                        .map_err(|_| anyhow::anyhow!("second observer closed"))?;
                    direct_snapshot_deliveries(audience)
                },
                true,
            )
            .await
            .unwrap();
        assert_eq!(second.status, ProfilePublishStatus::Published);
        assert!(second_rx.recv().await.unwrap().is_empty());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pep_subscriptions
                  WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3",
            )
            .bind(owner_id)
            .bind(VCARD4)
            .bind(&blocked)
            .fetch_one(&database.pool)
            .await
            .unwrap(),
            1,
            "blocking filters delivery without silently deleting subscription authority"
        );
        database.finish().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
    async fn first_profile_publish_snapshots_roster_privacy_and_rolls_back_atomically() {
        let database = IsolatedDatabase::create("first_publish").await;
        let (owner_id, _, auth_generation) = insert_user(&database.pool, "owner").await;
        let (_, allowed_name, _) = insert_user(&database.pool, "allowed").await;
        let allowed = format!("{allowed_name}@example.test");
        let denied = format!("denied{}@remote.test", Uuid::new_v4().simple());
        for contact in [&allowed, &denied] {
            sqlx::query(
                "INSERT INTO roster_items(owner_id,contact_jid,subscription,groups)
                 VALUES($1,$2,'from','[\"friends\"]'::jsonb)",
            )
            .bind(owner_id)
            .bind(contact)
            .execute(&database.pool)
            .await
            .unwrap();
        }
        let privacy = db::PrivacyList {
            name: "profile-policy".to_owned(),
            items: vec![
                db::PrivacyItem {
                    order: 1,
                    action: db::PrivacyAction::Deny,
                    match_type: Some(db::PrivacyMatchType::Jid),
                    match_value: Some(denied.clone()),
                    message: true,
                    iq: false,
                    presence_in: false,
                    presence_out: false,
                },
                db::PrivacyItem {
                    order: 2,
                    action: db::PrivacyAction::Allow,
                    match_type: None,
                    match_value: None,
                    message: false,
                    iq: false,
                    presence_in: false,
                    presence_out: false,
                },
            ],
        };
        assert_eq!(
            db::replace_privacy_list(&database.pool, owner_id, &privacy)
                .await
                .unwrap(),
            db::ReplacePrivacyListOutcome::Stored
        );
        assert!(
            db::set_default_privacy_list(&database.pool, owner_id, Some(&privacy.name))
                .await
                .unwrap()
        );
        sqlx::query(
            "CREATE FUNCTION fail_profile_outbox() RETURNS trigger
             LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced profile outbox failure'; END $$",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER fail_profile_outbox BEFORE INSERT ON pubsub_event_outbox
             FOR EACH ROW EXECUTE FUNCTION fail_profile_outbox()",
        )
        .execute(&database.pool)
        .await
        .unwrap();

        let service = ProfileService::new(database.pool.clone(), "example.test".to_owned());
        let config = db::default_pep_node_config(VCARD4);
        let payload = vcard4_item("profile", "atomic");
        let items = [("profile", payload.as_str())];
        let (audience_tx, mut audience_rx) = tokio::sync::mpsc::unbounded_channel();
        let failed = service
            .publish_profile_items(
                ProfilePepWrite {
                    user_id: owner_id,
                    auth_generation,
                    connection_id: Uuid::new_v4(),
                    node: VCARD4,
                    requested: &config,
                    enforce_preconditions: false,
                    items: &items,
                    max_nodes: 10,
                    max_storage_bytes: 1_000_000,
                },
                &|audience: &ProfileAudienceSnapshot| {
                    audience_tx
                        .send(audience.roster_jids.clone())
                        .map_err(|_| anyhow::anyhow!("first-publish observer closed"))?;
                    direct_snapshot_deliveries(audience)
                },
                true,
            )
            .await;
        assert!(failed.is_err());
        assert_eq!(audience_rx.recv().await.unwrap(), vec![allowed.clone()]);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pep_nodes WHERE owner_id=$1 AND node=$2",
            )
            .bind(owner_id)
            .bind(VCARD4)
            .fetch_one(&database.pool)
            .await
            .unwrap(),
            0
        );
        sqlx::query("DROP TRIGGER fail_profile_outbox ON pubsub_event_outbox")
            .execute(&database.pool)
            .await
            .unwrap();
        sqlx::query("DROP FUNCTION fail_profile_outbox()")
            .execute(&database.pool)
            .await
            .unwrap();

        let result = service
            .publish_profile_items(
                ProfilePepWrite {
                    user_id: owner_id,
                    auth_generation,
                    connection_id: Uuid::new_v4(),
                    node: VCARD4,
                    requested: &config,
                    enforce_preconditions: false,
                    items: &items,
                    max_nodes: 10,
                    max_storage_bytes: 1_000_000,
                },
                &direct_snapshot_deliveries,
                true,
            )
            .await
            .unwrap();
        assert_eq!(result.status, ProfilePublishStatus::Published);
        assert_eq!(
            sqlx::query_scalar::<_, Vec<String>>(
                "SELECT COALESCE(ARRAY_AGG(recipient_jid ORDER BY recipient_jid),ARRAY[]::TEXT[])
                   FROM pubsub_event_outbox WHERE source_node=$1",
            )
            .bind(VCARD4)
            .fetch_one(&database.pool)
            .await
            .unwrap(),
            vec![allowed]
        );
        database.finish().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
    async fn legacy_and_metadata_race_never_restores_a_stale_vcard_baseline() {
        let database = IsolatedDatabase::create("legacy_metadata").await;
        let (owner_id, _, auth_generation) = insert_user(&database.pool, "owner").await;
        let service = Arc::new(ProfileService::new(
            database.pool.clone(),
            "example.test".to_owned(),
        ));
        let png = BASE64
            .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
            .unwrap();
        assert!(valid_png_image(&png));
        let hash = sha1_hex(&png);
        let encoded = BASE64.encode(&png);
        let data_item =
            format!("<item id='{hash}'><data xmlns='{AVATAR_DATA}'>{encoded}</data></item>");
        let metadata_item = format!(
            "<item id='{hash}'><metadata xmlns='{AVATAR_METADATA}'><info bytes='{}' id='{hash}' type='image/png'/></metadata></item>",
            png.len()
        );
        let initial = service
            .set_legacy_vcard(
                LegacyVCardWrite {
                    user_id: owner_id,
                    auth_generation,
                    connection_id: Uuid::new_v4(),
                    payload: "<vCard xmlns='vcard-temp'><FN>Initial</FN></vCard>",
                    avatar_hash: Some(&hash),
                    data_item: Some((&hash, &data_item)),
                    metadata_item: (&hash, &metadata_item),
                    max_nodes: 10,
                    max_storage_bytes: 1_000_000,
                },
                &direct_snapshot_deliveries,
            )
            .await
            .unwrap();
        assert_eq!(initial.status, ProfilePublishStatus::Published);

        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let legacy_service = Arc::clone(&service);
        let legacy_barrier = Arc::clone(&barrier);
        let legacy = tokio::spawn(async move {
            legacy_barrier.wait().await;
            legacy_service
                .set_legacy_vcard(
                    LegacyVCardWrite {
                        user_id: owner_id,
                        auth_generation,
                        connection_id: Uuid::new_v4(),
                        payload: "<vCard xmlns='vcard-temp'><FN>Legacy Latest</FN></vCard>",
                        avatar_hash: None,
                        data_item: None,
                        metadata_item: (
                            "current",
                            "<item id='current'><metadata xmlns='urn:xmpp:avatar:metadata'/></item>",
                        ),
                        max_nodes: 10,
                        max_storage_bytes: 1_000_000,
                    },
                    &direct_snapshot_deliveries,
                )
                .await
        });
        let metadata_service = Arc::clone(&service);
        let metadata_barrier = Arc::clone(&barrier);
        let metadata_hash = hash.clone();
        let metadata_xml = metadata_item.clone();
        let metadata = tokio::spawn(async move {
            metadata_barrier.wait().await;
            let config = db::default_pep_node_config(AVATAR_METADATA);
            let items = [(metadata_hash.as_str(), metadata_xml.as_str())];
            metadata_service
                .publish_avatar_metadata(
                    ProfilePepWrite {
                        user_id: owner_id,
                        auth_generation,
                        connection_id: Uuid::new_v4(),
                        node: AVATAR_METADATA,
                        requested: &config,
                        enforce_preconditions: false,
                        items: &items,
                        max_nodes: 10,
                        max_storage_bytes: 1_000_000,
                    },
                    &direct_snapshot_deliveries,
                )
                .await
        });
        barrier.wait().await;
        assert_eq!(
            legacy.await.unwrap().unwrap().status,
            ProfilePublishStatus::Published
        );
        assert_eq!(
            metadata.await.unwrap().unwrap().status,
            ProfilePublishStatus::Published
        );
        let record = db::get_vcard(&database.pool, owner_id).await.unwrap();
        let payload = record.payload_vcard_temp.unwrap();
        assert!(payload.contains("<FN>Legacy Latest</FN>"));
        if record.avatar_hash.is_some() {
            assert!(payload.contains("<PHOTO>"));
        } else {
            assert!(!payload.contains("<PHOTO>"));
        }
        database.finish().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
    async fn deleted_account_incarnation_and_corrupt_vcard_fail_closed() {
        let database = IsolatedDatabase::create("identity_decode").await;
        let (old_id, username, auth_generation) = insert_user(&database.pool, "owner").await;
        let mut blocker = database.pool.begin().await.unwrap();
        lock_profile_account(&mut blocker, old_id).await.unwrap();
        let service = Arc::new(ProfileService::new(
            database.pool.clone(),
            "example.test".to_owned(),
        ));
        let stale_service = Arc::clone(&service);
        let stale = tokio::spawn(async move {
            let config = db::default_pep_node_config(VCARD4);
            let payload = vcard4_item("stale", "stale");
            let items = [("stale", payload.as_str())];
            stale_service
                .publish_profile_items(
                    ProfilePepWrite {
                        user_id: old_id,
                        auth_generation,
                        connection_id: Uuid::new_v4(),
                        node: VCARD4,
                        requested: &config,
                        enforce_preconditions: false,
                        items: &items,
                        max_nodes: 10,
                        max_storage_bytes: 1_000_000,
                    },
                    &direct_snapshot_deliveries,
                    true,
                )
                .await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(old_id)
            .execute(&database.pool)
            .await
            .unwrap();
        let new_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(new_id)
            .bind(&username)
            .execute(&database.pool)
            .await
            .unwrap();
        blocker.commit().await.unwrap();
        assert_eq!(
            stale.await.unwrap().unwrap().status,
            ProfilePublishStatus::Unauthorized
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pep_nodes WHERE owner_id=$1")
                .bind(new_id)
                .fetch_one(&database.pool)
                .await
                .unwrap(),
            0
        );

        sqlx::query("ALTER TABLE vcards ALTER COLUMN payload DROP NOT NULL")
            .execute(&database.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO vcards(user_id,payload) VALUES($1,NULL)")
            .bind(new_id)
            .execute(&database.pool)
            .await
            .unwrap();
        assert!(db::get_vcard(&database.pool, new_id).await.is_err());
        database.finish().await;
    }
}
