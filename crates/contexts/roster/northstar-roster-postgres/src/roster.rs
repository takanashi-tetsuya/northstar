use anyhow::Result;
use sqlx::Row;
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::HashMap;
use std::collections::HashSet;
use uuid::Uuid;

use crate::RosterTransactionEffects;
use northstar_roster_application::{
    RosterGetCommand, RosterRemovalRoute, RosterRemoveCommand, RosterRepository,
    RosterUpsertCommand, S2sOutboxPolicy,
};
use northstar_roster_core::RosterAuthorization;

mod blocking;
mod persistence;
mod presence;

pub use self::blocking::*;
pub use self::persistence::*;
pub use self::presence::*;

#[derive(Clone)]
pub struct PostgresRosterRepository<E> {
    pool: PgPool,
    effects: E,
}

impl<E> PostgresRosterRepository<E> {
    pub fn new(pool: PgPool, effects: E) -> Self {
        Self { pool, effects }
    }
}

impl<E: RosterTransactionEffects> RosterRepository for PostgresRosterRepository<E> {
    type Error = anyhow::Error;

    async fn get_roster(
        &self,
        command: &RosterGetCommand,
    ) -> Result<RosterAuthorization<RosterReadSnapshot>> {
        Ok(
            match roster_read_snapshot(
                &self.effects,
                &self.pool,
                command.owner_id,
                command.expected_auth_generation,
                command.requested_version,
                command.annotations_requested,
            )
            .await?
            {
                Some(snapshot) => RosterAuthorization::Authorized(snapshot),
                None => RosterAuthorization::Unauthorized,
            },
        )
    }

    async fn upsert_item(
        &self,
        command: &RosterUpsertCommand,
    ) -> Result<RosterAuthorization<RosterChange>> {
        Ok(
            match upsert_roster_authorized(
                &self.effects,
                &self.pool,
                command.owner_id,
                command.expected_auth_generation,
                &command.jid,
                command.name.as_deref(),
                &command.groups,
            )
            .await?
            {
                Some(change) => RosterAuthorization::Authorized(change),
                None => RosterAuthorization::Unauthorized,
            },
        )
    }

    async fn remove_item(
        &self,
        command: &RosterRemoveCommand<'_>,
    ) -> Result<RosterAuthorization<Option<RosterRemovalTransition>>> {
        Ok(
            match remove_roster_item_authorized(
                &self.effects,
                &self.pool,
                command.owner_id,
                command.expected_auth_generation,
                command.jid,
                command.route,
            )
            .await?
            {
                AuthorizedRosterRemoval::Unauthorized => RosterAuthorization::Unauthorized,
                AuthorizedRosterRemoval::Missing => RosterAuthorization::Authorized(None),
                AuthorizedRosterRemoval::Removed(transition) => {
                    RosterAuthorization::Authorized(Some(*transition))
                }
            },
        )
    }
}

pub use northstar_roster_core::{
    AuthorizedLocalPresence, AuthorizedLocalPresenceTransition, AuthorizedRosterRemoval,
    LocalPresenceEffect, LocalPresenceTransition, LocalRosterContact, PresenceAccount,
    PresencePolicyDenial, RosterChange, RosterReadSnapshot, RosterRemovalTransition,
};

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub struct RosterSnapshot {
    pub version: i64,
    pub items: Vec<RosterChange>,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub struct PendingPresence {
    pub requester: String,
    pub stanza: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RemotePresenceTransition {
    pub subscription: String,
    pub change: Option<RosterChange>,
    pub routed: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AuthorizedRemotePresenceTransition {
    Unauthorized,
    PolicyDenied(PresencePolicyDenial),
    Transition(Box<AuthorizedRemotePresence>),
}

#[derive(Debug, Eq, PartialEq)]
pub struct AuthorizedRemotePresence {
    pub actor: PresenceAccount,
    pub transition: RemotePresenceTransition,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AuthorizedInboundRemotePresenceTransition {
    /// The exact addressed local account incarnation disappeared or was
    /// disabled before the recipient policy transaction acquired its lock.
    Missing,
    /// The recipient's account-wide inbound privacy/block authority denied
    /// the remote subscription stanza.
    PolicyDenied(PresencePolicyDenial),
    Transition(Box<AuthorizedInboundRemotePresence>),
}

#[derive(Debug, Eq, PartialEq)]
pub struct AuthorizedInboundRemotePresence {
    pub recipient: PresenceAccount,
    pub transition: InboundRemotePresenceTransition,
}

pub use northstar_roster_core::InboundRemotePresenceEffect;

#[derive(Debug, Eq, PartialEq)]
pub struct InboundRemotePresenceTransition {
    pub effect: InboundRemotePresenceEffect,
    pub subscription: String,
    pub change: Option<RosterChange>,
    /// A server acknowledgement required by this transition. It is separate
    /// from `effect` because an inbound unsubscribe can both be delivered to
    /// interested resources and acknowledged automatically.
    pub auto_reply: Option<&'static str>,
    /// Removing a real `from` subscription requires the contact's stale
    /// availability to be withdrawn from interested local resources.
    pub send_unavailable: bool,
}

#[cfg(any(test, feature = "test-support"))]
pub async fn roster_snapshot(pool: &PgPool, owner_id: Uuid) -> Result<RosterSnapshot> {
    // One statement gives the token and every item from the same MVCC
    // snapshot. Separate queries can label a newer body with an older token.
    let rows = sqlx::query(
        "SELECT u.roster_version AS version, r.contact_jid, r.display_name, r.subscription, r.ask, r.groups, r.approved FROM users u LEFT JOIN roster_items r ON r.owner_id=u.id WHERE u.id=$1 ORDER BY r.contact_jid NULLS FIRST",
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await?;
    let version = rows
        .first()
        .map(|row| row.get("version"))
        .ok_or_else(|| anyhow::anyhow!("roster owner no longer exists"))?;
    let items = rows
        .iter()
        .filter_map(|row| {
            row.get::<Option<String>, _>("contact_jid")
                .map(|contact_jid| (row, contact_jid))
        })
        .map(|(row, contact_jid)| {
            Ok(RosterChange {
                version,
                contact_jid,
                display_name: row.get("display_name"),
                subscription: row.get("subscription"),
                ask: row.get("ask"),
                groups: serde_json::from_value(row.get("groups"))?,
                approved: row.get("approved"),
                removed: false,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(RosterSnapshot { version, items })
}

/// Read the complete roster, an optional XEP-0237 delta, and XEP-0405 PAM
/// annotations in one MVCC snapshot.  The transaction is deliberately short
/// and read-only; no network work is performed while it is open.
pub async fn roster_read_snapshot<E: RosterTransactionEffects>(
    effects: &E,
    pool: &PgPool,
    owner_id: Uuid,
    expected_auth_generation: i64,
    requested_version: Option<i64>,
    annotations_requested: bool,
) -> Result<Option<RosterReadSnapshot>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;

    let rows = sqlx::query(
        "SELECT u.roster_version AS version, r.contact_jid, r.display_name, r.subscription, r.ask, r.groups, r.approved FROM users u LEFT JOIN roster_items r ON r.owner_id=u.id WHERE u.id=$1 AND u.auth_generation=$2 AND NOT u.is_disabled ORDER BY r.contact_jid NULLS FIRST",
    )
    .bind(owner_id)
    .bind(expected_auth_generation)
    .fetch_all(&mut *transaction)
    .await?;
    let Some(first) = rows.first() else {
        transaction.rollback().await?;
        return Ok(None);
    };
    let version = first.try_get("version")?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let Some(contact_jid) = row.try_get::<Option<String>, _>("contact_jid")? else {
            continue;
        };
        items.push(RosterChange {
            version,
            contact_jid,
            display_name: row.try_get("display_name")?,
            subscription: row.try_get("subscription")?,
            ask: row.try_get("ask")?,
            groups: serde_json::from_value(row.try_get("groups")?)?,
            approved: row.try_get("approved")?,
            removed: false,
        });
    }

    let mix_participants = if annotations_requested {
        effects.mix_participants(&mut transaction, owner_id).await?
    } else {
        HashMap::new()
    };

    // An annotated request must be complete because a version-only response
    // cannot retrofit annotations onto the client's cached roster.
    let changes = if annotations_requested {
        None
    } else if let Some(requested_version) = requested_version {
        roster_changes_since_in_transaction(&mut transaction, owner_id, requested_version, version)
            .await?
    } else {
        None
    };
    transaction.commit().await?;
    Ok(Some(RosterReadSnapshot {
        version,
        items,
        changes,
        mix_participants,
    }))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn upsert_roster<E: RosterTransactionEffects>(
    effects: &E,
    pool: &PgPool,
    owner_id: Uuid,
    jid: &str,
    name: Option<&str>,
    groups: &[String],
) -> Result<RosterChange> {
    let mut transaction = pool.begin().await?;
    let change =
        upsert_roster_in_transaction(effects, &mut transaction, owner_id, jid, name, groups)
            .await?;
    transaction.commit().await?;
    Ok(change)
}

/// Removes a roster item and atomically settles every subscription direction.
///
/// RFC 6121 section 2.5.2 requires an `unsubscribe` when the owner subscribed
/// to the contact and an `unsubscribed` when the contact subscribed to the
/// owner. Pending requests are cancelled too: otherwise deleting the item
/// would remove the local `ask` state while leaving the peer's durable request
/// alive. A retry after COMMIT observes no roster row, returns `None`, and
/// therefore cannot enqueue or deliver duplicate cancellation stanzas.
#[cfg(any(test, feature = "test-support"))]
pub async fn remove_roster_item<E: RosterTransactionEffects>(
    effects: &E,
    pool: &PgPool,
    owner_id: Uuid,
    jid: &str,
    route: RosterRemovalRoute<'_>,
) -> Result<Option<RosterRemovalTransition>> {
    let transaction = pool.begin().await?;
    Ok(
        match remove_roster_item_in_transaction(effects, transaction, owner_id, None, jid, route)
            .await?
        {
            AuthorizedRosterRemoval::Removed(transition) => Some(*transition),
            AuthorizedRosterRemoval::Missing | AuthorizedRosterRemoval::Unauthorized => None,
        },
    )
}

#[cfg(any(test, feature = "test-support"))]
pub async fn delete_roster<E: RosterTransactionEffects>(
    effects: &E,
    pool: &PgPool,
    owner_id: Uuid,
    jid: &str,
) -> Result<Option<RosterChange>> {
    remove_roster_item(
        effects,
        pool,
        owner_id,
        jid,
        RosterRemovalRoute::Local {
            owner_jid: "test-owner@example.invalid",
            contact_username: None,
        },
    )
    .await
    .map(|transition| transition.map(|transition| transition.owner_change))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn update_subscription<E: RosterTransactionEffects>(
    effects: &E,
    pool: &PgPool,
    owner_id: Uuid,
    jid: &str,
    subscription: &str,
    ask: Option<&str>,
) -> Result<RosterChange> {
    update_subscription_with_approval(effects, pool, owner_id, jid, subscription, ask, None).await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn update_subscription_with_approval<E: RosterTransactionEffects>(
    effects: &E,
    pool: &PgPool,
    owner_id: Uuid,
    jid: &str,
    subscription: &str,
    ask: Option<&str>,
    approved: Option<bool>,
) -> Result<RosterChange> {
    let mut transaction = pool.begin().await?;
    let change = update_subscription_in_transaction(
        effects,
        &mut transaction,
        owner_id,
        jid,
        subscription,
        ask,
        approved,
    )
    .await?;
    transaction.commit().await?;
    Ok(change)
}

/// Applies both sides of a local RFC 6121 presence-subscription transition,
/// including pre-approval and pending-request bookkeeping, in one transaction.
/// Locking both user rows in UUID order serializes simultaneous inverse
/// transitions and prevents a partially committed one-sided roster.
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::too_many_arguments)]
pub async fn transition_local_presence_subscription<E: RosterTransactionEffects>(
    effects: &E,
    pool: &PgPool,
    actor_id: Uuid,
    actor_jid: &str,
    target_id: Uuid,
    target_jid: &str,
    kind: &str,
    stamped_stanza: &str,
) -> Result<Option<LocalPresenceTransition>> {
    if !matches!(
        kind,
        "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
    ) {
        return Ok(None);
    }
    let actor_jid = northstar_xmpp_types::jid::canonicalize_bare(actor_jid)?;
    let target_jid = northstar_xmpp_types::jid::canonicalize_bare(target_jid)?;
    let mut transaction = pool.begin().await?;
    let locked = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM users WHERE id=ANY($1) ORDER BY id FOR UPDATE",
    )
    .bind(vec![actor_id, target_id])
    .fetch_all(&mut *transaction)
    .await?;
    let expected_locks = if actor_id == target_id { 1 } else { 2 };
    if locked.len() != expected_locks {
        transaction.rollback().await?;
        return Ok(None);
    }
    if actor_id == target_id {
        transaction.commit().await?;
        return Ok(Some(suppressed_local_presence_transition()));
    }
    let transition = transition_local_presence_subscription_in_transaction(
        effects,
        &mut transaction,
        actor_id,
        &actor_jid,
        target_id,
        &target_jid,
        kind,
        stamped_stanza,
    )
    .await?;
    transaction.commit().await?;
    Ok(Some(transition))
}

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::too_many_arguments)]
pub async fn transition_local_presence_subscription_authorized_test_hook<
    E: RosterTransactionEffects,
    F,
    Fut,
>(
    effects: &E,
    pool: &PgPool,
    actor_id: Uuid,
    expected_auth_generation: i64,
    connection_id: Uuid,
    actor_domain: &str,
    target_username: &str,
    kind: &str,
    stamped_stanza: &str,
    after_target_resolution: F,
) -> Result<AuthorizedLocalPresenceTransition>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    transition_local_presence_subscription_authorized_with_hook(
        effects,
        pool,
        actor_id,
        expected_auth_generation,
        connection_id,
        actor_domain,
        target_username,
        kind,
        stamped_stanza,
        after_target_resolution,
    )
    .await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn pending_presence_subscriptions(
    pool: &PgPool,
    recipient_id: Uuid,
) -> Result<Vec<PendingPresence>> {
    let rows = sqlx::query(
        "SELECT u.username,p.stanza FROM pending_presence_subscriptions p JOIN users u ON u.id = p.requester_id WHERE p.recipient_id = $1 ORDER BY p.created_at",
    )
    .bind(recipient_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|row| PendingPresence {
            requester: row.get("username"),
            stanza: row.get("stanza"),
        })
        .collect())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn add_federated_presence_pending_with_stanza(
    pool: &PgPool,
    recipient_id: Uuid,
    from_jid: &str,
    stanza: Option<&str>,
) -> Result<()> {
    if stanza.is_some_and(|stanza| stanza.is_empty() || stanza.len() > 65_536) {
        anyhow::bail!("federated presence subscription stanza exceeds the persistence limit");
    }
    let from_jid = northstar_xmpp_types::jid::canonicalize_bare(from_jid)?;
    sqlx::query(
        "INSERT INTO federated_presence_pending (recipient_id, from_jid, stanza) VALUES ($1, $2, $3) ON CONFLICT (recipient_id, from_jid) DO UPDATE SET stanza=COALESCE(EXCLUDED.stanza,federated_presence_pending.stanza),created_at=NOW()",
    )
    .bind(recipient_id)
    .bind(from_jid)
    .bind(stanza)
    .execute(pool)
    .await?;
    Ok(())
}

/// Applies a federated subscription transition and consumes its pending row in
/// one transaction. This prevents a committed roster authorization from being
/// paired with stale pending state (or the reverse) after a database failure.
#[cfg(any(test, feature = "test-support"))]
pub async fn transition_remote_presence_subscription<E: RosterTransactionEffects>(
    effects: &E,
    pool: &PgPool,
    recipient_id: Uuid,
    from_jid: &str,
    kind: &str,
) -> Result<Option<RemotePresenceTransition>> {
    let mut transaction = pool.begin().await?;
    let transition = transition_remote_presence_subscription_in_transaction(
        effects,
        &mut transaction,
        recipient_id,
        from_jid,
        kind,
        None,
    )
    .await?;
    if transition.is_some() {
        transaction.commit().await?;
    } else {
        transaction.rollback().await?;
    }
    Ok(transition)
}

/// Atomically applies the local side of an outbound federated subscription
/// transition and admits the matching stanza to the durable S2S outbox.  A
/// successful return therefore means both effects committed; quota errors,
/// injected database failures, and process termination before COMMIT leave
/// neither effect visible.
#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "test-support"))]
pub async fn transition_remote_presence_subscription_with_outbox<E: RosterTransactionEffects>(
    effects: &E,
    pool: &PgPool,
    recipient_id: Uuid,
    from_jid: &str,
    kind: &str,
    target_domain: &str,
    stanza: &str,
    bounce_to: Option<&str>,
    policy: S2sOutboxPolicy,
) -> Result<Option<RemotePresenceTransition>> {
    let mut transaction = pool.begin().await?;
    let transition = transition_remote_presence_subscription_in_transaction(
        effects,
        &mut transaction,
        recipient_id,
        from_jid,
        kind,
        Some((target_domain, stanza, bounce_to, policy)),
    )
    .await?;
    if transition.is_some() {
        transaction.commit().await?;
    } else {
        transaction.rollback().await?;
    }
    Ok(transition)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn federated_presence_pending(
    pool: &PgPool,
    recipient_id: Uuid,
) -> Result<Vec<PendingPresence>> {
    let rows = sqlx::query(
        "SELECT from_jid,stanza FROM federated_presence_pending WHERE recipient_id = $1 ORDER BY created_at",
    )
    .bind(recipient_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|row| PendingPresence {
            requester: row.get("from_jid"),
            stanza: row.get("stanza"),
        })
        .collect())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn get_roster_version(pool: &PgPool, owner_id: Uuid) -> Result<i64> {
    let row = sqlx::query("SELECT roster_version FROM users WHERE id = $1")
        .bind(owner_id)
        .fetch_one(pool)
        .await?;
    Ok(row.get("roster_version"))
}

/// Returns `None` when the requested version predates the retained journal and
/// the caller must fall back to a complete roster. XEP-0237 requires one
/// interim push per modified item containing that item's final result, not all
/// intermediate edits to the same item. The selected final versions remain
/// unique and are emitted in ascending order.
#[cfg(any(test, feature = "test-support"))]
pub async fn roster_changes_since(
    pool: &PgPool,
    owner_id: Uuid,
    requested_version: i64,
    current_version: i64,
) -> Result<Option<Vec<RosterChange>>> {
    let mut transaction = pool.begin().await?;
    let changes = roster_changes_since_in_transaction(
        &mut transaction,
        owner_id,
        requested_version,
        current_version,
    )
    .await?;
    transaction.commit().await?;
    Ok(changes)
}

mod application_repository {
    use anyhow::Result;
    use northstar_roster_application::blocking::*;
    use sqlx::PgPool;
    use uuid::Uuid;
    #[derive(Clone)]
    pub struct PostgresBlockingRepository {
        pool: PgPool,
    }
    impl PostgresBlockingRepository {
        pub fn new(pool: PgPool) -> Self {
            Self { pool }
        }
    }
    impl BlockingRepository for PostgresBlockingRepository {
        async fn blocked_jids(&self, owner: Uuid) -> Result<Vec<String>> {
            super::blocked_jids(&self.pool, owner).await
        }
        async fn roster(&self, owner: Uuid) -> Result<Vec<RosterEntry>> {
            super::roster(&self.pool, owner).await
        }
        async fn block(&self, owner: Uuid, jids: &[String]) -> Result<BlockUpdateOutcome> {
            Ok(match super::block_jids(&self.pool, owner, jids).await? {
                super::BlockJidsUpdate::Changed(changed) => BlockUpdateOutcome::Changed(changed),
                super::BlockJidsUpdate::QuotaExceeded => BlockUpdateOutcome::QuotaExceeded,
                super::BlockJidsUpdate::Unavailable => BlockUpdateOutcome::Unavailable,
            })
        }
        async fn unblock(
            &self,
            owner: Uuid,
            jids: Option<&[String]>,
        ) -> Result<UnblockUpdateOutcome> {
            Ok(match super::unblock_jids(&self.pool, owner, jids).await? {
                super::UnblockJidsUpdate::Changed(changed) => {
                    UnblockUpdateOutcome::Changed(changed)
                }
                super::UnblockJidsUpdate::Unavailable => UnblockUpdateOutcome::Unavailable,
            })
        }
    }
}
pub use application_repository::PostgresBlockingRepository;
