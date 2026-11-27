use anyhow::Result;
use northstar_roster_application::privacy::PrivacySelectionOutcome;
use northstar_roster_core::RosterActor;
use northstar_roster_postgres::privacy::{
    renew_active_privacy_selection, set_active_privacy_list_in_transaction,
};
use northstar_session_postgres::capacity::{
    publish_binding_live_session_in_transaction, refresh_live_session_leases,
};
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::HashSet;
use uuid::Uuid;

pub struct PrivacySelectionCheckpoint {
    pub session_id: Uuid,
    pub snapshot: crate::sm::SmSessionSnapshot,
    pub ttl_seconds: u64,
    pub live_lease_seconds: u64,
}

/// Commit a client's explicit select or decline under the account, binding and SM fences.
/// The normal transport checkpoint still owns the inbound counter and queue handoffs.
pub async fn activate_privacy_selection(
    pool: &PgPool,
    actor: &RosterActor,
    name: Option<&str>,
    checkpoint: Option<PrivacySelectionCheckpoint>,
) -> Result<PrivacySelectionOutcome> {
    use PrivacySelectionOutcome::{Conflict, Missing, Updated};

    let Some(mut tx) = northstar_auth_postgres::users::lock_auth_generation(
        pool,
        actor.account_id,
        actor.auth_generation,
    )
    .await?
    else {
        return Ok(Conflict);
    };
    sqlx::query("SELECT pg_advisory_xact_lock(1314079573,pg_catalog.hashtext($1))")
        .bind(&actor.full_jid)
        .execute(&mut *tx)
        .await?;
    if !has_live_binding(&mut tx, actor).await? {
        tx.rollback().await?;
        return Ok(Conflict);
    }
    if let Some(mut checkpoint) = checkpoint {
        let owner = crate::sm::sm_exact_owner_state(
            &mut tx,
            checkpoint.session_id,
            actor.connection_id,
            actor.account_id,
            actor.auth_generation,
        )
        .await?;
        if owner != "active"
            || !crate::privacy::sm_privacy_state_exists(&mut tx, checkpoint.session_id).await?
        {
            tx.rollback().await?;
            return Ok(Conflict);
        }
        checkpoint.snapshot.active_privacy_list = name.map(str::to_owned);
        if !crate::sm::update_privacy_selection_snapshot(
            &mut tx,
            checkpoint.session_id,
            actor.connection_id,
            &checkpoint.snapshot,
            i64::try_from(checkpoint.ttl_seconds)?,
            i64::try_from(checkpoint.live_lease_seconds)?,
            false,
        )
        .await?
        {
            tx.rollback().await?;
            return Ok(Conflict);
        }
    } else if !publish_binding_live_session_in_transaction(
        &mut tx,
        actor.connection_id,
        actor.account_id,
        &actor.full_jid,
        1,
    )
    .await?
    {
        tx.rollback().await?;
        return Ok(Conflict);
    }
    if !set_active_privacy_list_in_transaction(&mut tx, actor.account_id, actor.connection_id, name)
        .await?
    {
        tx.rollback().await?;
        return Ok(Missing);
    }
    if !has_live_binding(&mut tx, actor).await? {
        tx.rollback().await?;
        return Ok(Conflict);
    }
    tx.commit().await?;
    Ok(Updated)
}

async fn has_live_binding(tx: &mut Transaction<'_, Postgres>, actor: &RosterActor) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM deployment_session_leases
          WHERE user_id=$1 AND connection_id=$2 AND full_jid=$3 AND lease_until>clock_timestamp())",
    )
    .bind(actor.account_id)
    .bind(actor.connection_id)
    .bind(&actor.full_jid)
    .fetch_one(&mut **tx)
    .await?)
}

/// Return exact renewed routes only after their existing privacy leases have been renewed or left expired.
pub async fn renew_capacity_and_privacy_leases(
    pool: &PgPool,
    connection_ids: &[Uuid],
    lease_seconds: u64,
) -> Result<HashSet<Uuid>> {
    let mut tx = pool.begin().await?;
    let live = refresh_live_session_leases(&mut *tx, connection_ids, lease_seconds).await?;
    if !live.is_empty() {
        let live_ids = live.iter().copied().collect::<Vec<_>>();
        renew_active_privacy_selection(&mut *tx, &live_ids).await?;
    }
    tx.commit().await?;
    Ok(live)
}
