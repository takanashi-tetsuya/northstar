//! The roster context's persistence as the root crate binds it: the steps of a roster transaction that touch other
//! contexts' tables, and the adapter's functions with those steps bound.

use anyhow::Result;
#[cfg(test)]
use northstar_roster_application::RosterRemovalRoute;
use northstar_roster_application::S2sOutboxPolicy;
pub use northstar_roster_postgres::roster::*;
use northstar_roster_postgres::RosterTransactionEffects;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::HashMap;
#[cfg(test)]
use std::collections::HashSet;
use uuid::Uuid;

#[cfg(test)]
mod blocking_match_tests;

/// The roster adapter with the root crate's transaction steps.
pub(crate) type PostgresRosterRepository =
    northstar_roster_postgres::roster::PostgresRosterRepository<RootRosterEffects>;

/// Runs the roster transaction steps over the tables of the contexts still in the root crate.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RootRosterEffects;

impl RosterTransactionEffects for RootRosterEffects {
    async fn cancel_inaccessible_pep_subscriptions(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        contact_jid: &str,
    ) -> Result<()> {
        sqlx::query(
            "DELETE FROM pep_subscriptions ps USING pep_nodes pn
             WHERE ps.owner_id=$1
               AND split_part(ps.subscriber_jid, '/', 1)=$2
               AND pn.owner_id=ps.owner_id
               AND pn.node=ps.node
               AND (
                 (pn.access_model='presence' AND NOT EXISTS (
                    SELECT 1 FROM roster_items r
                     WHERE r.owner_id=$1 AND r.contact_jid=$2
                       AND r.subscription IN ('from','both')
                 ))
                 OR
                 (pn.access_model='roster' AND NOT EXISTS (
                    SELECT 1 FROM roster_items r,
                         jsonb_array_elements_text(r.groups) AS g(name)
                     WHERE r.owner_id=$1 AND r.contact_jid=$2
                       AND r.subscription IN ('from','both')
                       AND g.name=ANY(pn.roster_groups_allowed)
                 ))
               )",
        )
        .bind(owner_id)
        .bind(contact_jid)
        .execute(&mut **transaction)
        .await?;
        Ok(())
    }

    async fn enqueue_federated_stanza(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        target_domain: &str,
        stanza: &str,
        bounce_to: Option<&str>,
        policy: S2sOutboxPolicy,
    ) -> Result<()> {
        super::enqueue_s2s_outbox_in_transaction(
            transaction,
            target_domain,
            stanza,
            bounce_to,
            policy,
        )
        .await?;
        Ok(())
    }

    async fn mix_participants(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
    ) -> Result<HashMap<String, String>> {
        let mut mix_participants = HashMap::new();
        let rows = sqlx::query(
            "SELECT channel_jid, participant_id FROM mix_pam_memberships WHERE user_id=$1 AND state='joined' AND participant_id IS NOT NULL ORDER BY channel_jid",
        )
        .bind(owner_id)
        .fetch_all(&mut **transaction)
        .await?;
        for row in rows {
            let channel_jid: String = row.try_get("channel_jid")?;
            let participant_id: String = row.try_get("participant_id")?;
            if mix_participants
                .insert(channel_jid, participant_id)
                .is_some()
            {
                anyhow::bail!("duplicate PAM roster annotation in one snapshot");
            }
        }
        Ok(mix_participants)
    }
}

#[cfg(test)]
pub async fn delete_roster(
    pool: &PgPool,
    owner_id: Uuid,
    jid: &str,
) -> Result<Option<RosterChange>> {
    northstar_roster_postgres::roster::delete_roster(&RootRosterEffects, pool, owner_id, jid).await
}

#[cfg(test)]
pub async fn remove_roster_item(
    pool: &PgPool,
    owner_id: Uuid,
    jid: &str,
    route: RosterRemovalRoute<'_>,
) -> Result<Option<RosterRemovalTransition>> {
    northstar_roster_postgres::roster::remove_roster_item(
        &RootRosterEffects,
        pool,
        owner_id,
        jid,
        route,
    )
    .await
}

#[cfg(test)]
pub async fn remove_roster_item_authorized(
    pool: &PgPool,
    owner_id: Uuid,
    expected_auth_generation: i64,
    jid: &str,
    route: RosterRemovalRoute<'_>,
) -> Result<AuthorizedRosterRemoval> {
    northstar_roster_postgres::roster::remove_roster_item_authorized(
        &RootRosterEffects,
        pool,
        owner_id,
        expected_auth_generation,
        jid,
        route,
    )
    .await
}

#[cfg(test)]
pub async fn roster_read_snapshot(
    pool: &PgPool,
    owner_id: Uuid,
    expected_auth_generation: i64,
    requested_version: Option<i64>,
    annotations_requested: bool,
) -> Result<Option<RosterReadSnapshot>> {
    northstar_roster_postgres::roster::roster_read_snapshot(
        &RootRosterEffects,
        pool,
        owner_id,
        expected_auth_generation,
        requested_version,
        annotations_requested,
    )
    .await
}

pub async fn transition_inbound_remote_presence_subscription(
    pool: &PgPool,
    recipient_id: Uuid,
    recipient_domain: &str,
    from_jid: &str,
    kind: &str,
    stamped_stanza: &str,
) -> Result<AuthorizedInboundRemotePresenceTransition> {
    northstar_roster_postgres::roster::transition_inbound_remote_presence_subscription(
        &RootRosterEffects,
        pool,
        recipient_id,
        recipient_domain,
        from_jid,
        kind,
        stamped_stanza,
    )
    .await
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub async fn transition_local_presence_subscription(
    pool: &PgPool,
    actor_id: Uuid,
    actor_jid: &str,
    target_id: Uuid,
    target_jid: &str,
    kind: &str,
    stamped_stanza: &str,
) -> Result<Option<LocalPresenceTransition>> {
    northstar_roster_postgres::roster::transition_local_presence_subscription(
        &RootRosterEffects,
        pool,
        actor_id,
        actor_jid,
        target_id,
        target_jid,
        kind,
        stamped_stanza,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn transition_local_presence_subscription_authorized(
    pool: &PgPool,
    actor_id: Uuid,
    expected_auth_generation: i64,
    connection_id: Uuid,
    actor_domain: &str,
    target_username: &str,
    kind: &str,
    stamped_stanza: &str,
) -> Result<AuthorizedLocalPresenceTransition> {
    northstar_roster_postgres::roster::transition_local_presence_subscription_authorized(
        &RootRosterEffects,
        pool,
        actor_id,
        expected_auth_generation,
        connection_id,
        actor_domain,
        target_username,
        kind,
        stamped_stanza,
    )
    .await
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn transition_local_presence_subscription_authorized_test_hook<F, Fut>(
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
    northstar_roster_postgres::roster::transition_local_presence_subscription_authorized_test_hook(
        &RootRosterEffects,
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

#[cfg(test)]
pub async fn transition_remote_presence_subscription(
    pool: &PgPool,
    recipient_id: Uuid,
    from_jid: &str,
    kind: &str,
) -> Result<Option<RemotePresenceTransition>> {
    northstar_roster_postgres::roster::transition_remote_presence_subscription(
        &RootRosterEffects,
        pool,
        recipient_id,
        from_jid,
        kind,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn transition_remote_presence_subscription_authorized(
    pool: &PgPool,
    actor_id: Uuid,
    expected_auth_generation: i64,
    connection_id: Uuid,
    actor_domain: &str,
    contact: &str,
    kind: &str,
) -> Result<AuthorizedRemotePresenceTransition> {
    northstar_roster_postgres::roster::transition_remote_presence_subscription_authorized(
        &RootRosterEffects,
        pool,
        actor_id,
        expected_auth_generation,
        connection_id,
        actor_domain,
        contact,
        kind,
    )
    .await
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub async fn transition_remote_presence_subscription_with_outbox(
    pool: &PgPool,
    recipient_id: Uuid,
    from_jid: &str,
    kind: &str,
    target_domain: &str,
    stanza: &str,
    bounce_to: Option<&str>,
    policy: S2sOutboxPolicy,
) -> Result<Option<RemotePresenceTransition>> {
    northstar_roster_postgres::roster::transition_remote_presence_subscription_with_outbox(
        &RootRosterEffects,
        pool,
        recipient_id,
        from_jid,
        kind,
        target_domain,
        stanza,
        bounce_to,
        policy,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn transition_remote_presence_subscription_with_outbox_authorized(
    pool: &PgPool,
    actor_id: Uuid,
    expected_auth_generation: i64,
    connection_id: Uuid,
    actor_domain: &str,
    contact: &str,
    kind: &str,
    target_domain: &str,
    stanza: &str,
    bounce_to: Option<&str>,
    policy: S2sOutboxPolicy,
) -> Result<AuthorizedRemotePresenceTransition> {
    northstar_roster_postgres::roster::transition_remote_presence_subscription_with_outbox_authorized(&RootRosterEffects, pool, actor_id, expected_auth_generation, connection_id, actor_domain, contact, kind, target_domain, stanza, bounce_to, policy).await
}

#[cfg(test)]
pub async fn update_subscription(
    pool: &PgPool,
    owner_id: Uuid,
    jid: &str,
    subscription: &str,
    ask: Option<&str>,
) -> Result<RosterChange> {
    northstar_roster_postgres::roster::update_subscription(
        &RootRosterEffects,
        pool,
        owner_id,
        jid,
        subscription,
        ask,
    )
    .await
}

pub async fn update_subscription_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    jid: &str,
    subscription: &str,
    ask: Option<&str>,
    approved: Option<bool>,
) -> Result<RosterChange> {
    northstar_roster_postgres::roster::update_subscription_in_transaction(
        &RootRosterEffects,
        transaction,
        owner_id,
        jid,
        subscription,
        ask,
        approved,
    )
    .await
}

#[cfg(test)]
pub async fn update_subscription_with_approval(
    pool: &PgPool,
    owner_id: Uuid,
    jid: &str,
    subscription: &str,
    ask: Option<&str>,
    approved: Option<bool>,
) -> Result<RosterChange> {
    northstar_roster_postgres::roster::update_subscription_with_approval(
        &RootRosterEffects,
        pool,
        owner_id,
        jid,
        subscription,
        ask,
        approved,
    )
    .await
}

#[cfg(test)]
pub async fn upsert_roster(
    pool: &PgPool,
    owner_id: Uuid,
    jid: &str,
    name: Option<&str>,
    groups: &[String],
) -> Result<RosterChange> {
    northstar_roster_postgres::roster::upsert_roster(
        &RootRosterEffects,
        pool,
        owner_id,
        jid,
        name,
        groups,
    )
    .await
}

#[cfg(test)]
pub async fn upsert_roster_authorized(
    pool: &PgPool,
    owner_id: Uuid,
    expected_auth_generation: i64,
    jid: &str,
    name: Option<&str>,
    groups: &[String],
) -> Result<Option<RosterChange>> {
    northstar_roster_postgres::roster::upsert_roster_authorized(
        &RootRosterEffects,
        pool,
        owner_id,
        expected_auth_generation,
        jid,
        name,
        groups,
    )
    .await
}
