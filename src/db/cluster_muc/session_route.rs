//! Cluster session route authority and its startup validation.

use super::*;

/// Verify the durable replay-capacity ledger and its trigger authority.  A
/// mismatch is a deterministic safety violation (for example a disabled
/// trigger or out-of-band table write), not a transient Redis condition.
pub async fn validate_cluster_replay_capacity_authority(pool: &PgPool) -> Result<()> {
    let healthy: bool = sqlx::query_scalar("SELECT northstar_cluster_replay_capacity_healthy()")
        .fetch_one(pool)
        .await?;
    anyhow::ensure!(
        healthy,
        "cluster replay capacity authority failed reconciliation"
    );
    Ok(())
}

/// Verify the owner/ACL and row-shape invariants of the exact C2S route
/// authority.  Unlike route expiry, a false result is not recoverable by
/// retrying Redis and must fail the cluster closed.
pub async fn validate_cluster_session_route_authority(pool: &PgPool) -> Result<()> {
    let healthy: bool = sqlx::query_scalar("SELECT northstar_cluster_session_authority_healthy()")
        .fetch_one(pool)
        .await?;
    anyhow::ensure!(
        healthy,
        "cluster session route authority failed reconciliation"
    );
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterSessionRouteAuthority {
    pub owner_node_id: String,
    pub owner_instance_uuid: Uuid,
    pub owner_instance_epoch: i64,
    pub connection_uuid: Uuid,
}

/// Proof that a cluster route is part of an already-authorized C2S bind.
/// Normal binding is revalidated against either the exact live lease or its
/// bounded replacement claim.  SM resumption additionally carries the
/// unguessable, expiring claim capability so PostgreSQL can bind the staged
/// route to the exact durable stream before its lease is transferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClusterSessionRouteClaimProof {
    Binding,
    SmResume { session_id: Uuid, claim_token: Uuid },
}

#[allow(clippy::too_many_arguments)]
pub async fn claim_cluster_session_route(
    pool: &PgPool,
    namespace: &str,
    full_jid: &str,
    bare_jid: &str,
    owner_node_id: &str,
    owner_instance_uuid: Uuid,
    owner_instance_epoch: i64,
    connection_uuid: Uuid,
    proof: ClusterSessionRouteClaimProof,
    lease: Duration,
) -> Result<bool> {
    validate_node_id(owner_node_id)?;
    anyhow::ensure!(
        !owner_instance_uuid.is_nil() && owner_instance_epoch >= 1 && !connection_uuid.is_nil(),
        "invalid cluster session process or connection identity"
    );
    let (sm_session_id, sm_claim_token) = match proof {
        ClusterSessionRouteClaimProof::Binding => (None, None),
        ClusterSessionRouteClaimProof::SmResume {
            session_id,
            claim_token,
        } => {
            anyhow::ensure!(
                !session_id.is_nil() && !claim_token.is_nil(),
                "invalid SM route claim identity"
            );
            (Some(session_id), Some(claim_token))
        }
    };
    let lease_seconds = i32::try_from(lease.as_secs()).context("session lease is too large")?;
    let outcome: String = sqlx::query_scalar(
        "SELECT northstar_claim_cluster_session_route($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(namespace)
    .bind(full_jid)
    .bind(bare_jid)
    .bind(owner_node_id)
    .bind(owner_instance_uuid)
    .bind(owner_instance_epoch)
    .bind(connection_uuid)
    .bind(sm_session_id)
    .bind(sm_claim_token)
    .bind(lease_seconds)
    .fetch_one(pool)
    .await?;
    match outcome.as_str() {
        "claimed" => Ok(true),
        "conflict" => Ok(false),
        _ => anyhow::bail!("cluster session claim returned an unknown outcome"),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn refresh_cluster_session_route(
    pool: &PgPool,
    namespace: &str,
    full_jid: &str,
    owner_node_id: &str,
    owner_instance_uuid: Uuid,
    owner_instance_epoch: i64,
    connection_uuid: Uuid,
    lease: Duration,
) -> Result<bool> {
    let lease_seconds = i32::try_from(lease.as_secs()).context("session lease is too large")?;
    Ok(
        sqlx::query_scalar("SELECT northstar_refresh_cluster_session_route($1,$2,$3,$4,$5,$6,$7)")
            .bind(namespace)
            .bind(full_jid)
            .bind(owner_node_id)
            .bind(owner_instance_uuid)
            .bind(owner_instance_epoch)
            .bind(connection_uuid)
            .bind(lease_seconds)
            .fetch_one(pool)
            .await?,
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn release_cluster_session_route(
    pool: &PgPool,
    namespace: &str,
    full_jid: &str,
    owner_node_id: &str,
    owner_instance_uuid: Uuid,
    owner_instance_epoch: i64,
    connection_uuid: Uuid,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT northstar_release_cluster_session_route($1,$2,$3,$4,$5,$6)")
            .bind(namespace)
            .bind(full_jid)
            .bind(owner_node_id)
            .bind(owner_instance_uuid)
            .bind(owner_instance_epoch)
            .bind(connection_uuid)
            .fetch_one(pool)
            .await?,
    )
}

pub async fn cluster_session_route_authority(
    pool: &PgPool,
    namespace: &str,
    full_jid: &str,
) -> Result<Option<ClusterSessionRouteAuthority>> {
    let row: Option<(String, Uuid, i64, Uuid)> = sqlx::query_as(
        "SELECT owner_node_id,owner_instance_uuid,owner_instance_epoch,connection_uuid
           FROM northstar_cluster_session_route($1,$2)",
    )
    .bind(namespace)
    .bind(full_jid)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(owner_node_id, owner_instance_uuid, owner_instance_epoch, connection_uuid)| {
            ClusterSessionRouteAuthority {
                owner_node_id,
                owner_instance_uuid,
                owner_instance_epoch,
                connection_uuid,
            }
        },
    ))
}

pub async fn cluster_session_nodes_for_bare(
    pool: &PgPool,
    namespace: &str,
    bare_jid: &str,
) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT owner_node_id FROM northstar_cluster_session_nodes_for_bare($1,$2)",
    )
    .bind(namespace)
    .bind(bare_jid)
    .fetch_all(pool)
    .await?)
}

pub async fn cleanup_cluster_session_routes(pool: &PgPool, limit: i32) -> Result<u64> {
    let removed: i64 = sqlx::query_scalar("SELECT northstar_cleanup_cluster_session_routes($1)")
        .bind(limit.clamp(1, 10_000))
        .fetch_one(pool)
        .await?;
    Ok(removed.max(0) as u64)
}
