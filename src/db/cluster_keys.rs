use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use northstar_security::cluster_keys::ClusterKeyDeploymentIdentity;
use northstar_security::cluster_keys::ClusterNodeInstance;
use northstar_security::cluster_keys::ClusterPeerKeyAuthority;
use northstar_security::cluster_keys::ExpectedClusterPeerKey;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

/// The replay function uses PostgreSQL's default PL/pgSQL exception code for
/// both ordinary validation rejections and authority failures. Only the exact
/// source-side validation texts may bypass terminal authority handling.
pub(crate) fn cluster_replay_validation_rejection(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<sqlx::Error>()
        .and_then(sqlx::Error::as_database_error)
        .is_some_and(|database| {
            replay_validation_rejection_fields(database.code().as_deref(), database.message())
        })
}

fn replay_validation_rejection_fields(code: Option<&str>, message: &str) -> bool {
    code == Some("P0001")
        && matches!(
            message,
            "cluster replay identity conflict"
                | "cluster replay source instance is not authoritative"
                | "cluster replay validity window rejected"
        )
}

/// Lock the local signing-key row before the exact live process-instance row.
/// Both locks are held by the caller's transaction through its message commit,
/// serializing key rotation, instance replacement and clean release with the
/// durable message write. PostgreSQL's clock, rather than a cached peer lease,
/// decides whether this process still owns the instance.
pub(crate) async fn fence_direct_message_authority_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    authority: &northstar_security::cluster_keys::ClusterReadinessAuthority,
) -> Result<()> {
    let key: Option<bool> = sqlx::query_scalar(
        "SELECT TRUE FROM cluster_key_deployments
         WHERE xmpp_domain=$1 AND node_id=$2 AND epoch=$3
           AND current_key_id=$4 AND current_public_key_sha256=$5
         FOR SHARE",
    )
    .bind(&authority.key_identity.xmpp_domain)
    .bind(&authority.key_identity.node_id)
    .bind(authority.key_identity.epoch)
    .bind(&authority.key_identity.current_key_id)
    .bind(&authority.key_identity.current_public_key_sha256)
    .fetch_optional(&mut **tx)
    .await?;
    anyhow::ensure!(
        key.is_some(),
        "cluster signing-key authority changed before direct-message commit"
    );

    let instance: Option<bool> = sqlx::query_scalar(
        "SELECT TRUE FROM cluster_node_instances
         WHERE xmpp_domain=$1 AND node_id=$2
           AND instance_uuid=$3 AND instance_epoch=$4
           AND signing_key_id=$5 AND signing_key_epoch=$6
           AND lease_until > clock_timestamp()
         FOR SHARE",
    )
    .bind(&authority.key_identity.xmpp_domain)
    .bind(&authority.instance_node_id)
    .bind(authority.instance_uuid)
    .bind(authority.instance_epoch)
    .bind(&authority.signing_key_id)
    .bind(authority.signing_key_epoch)
    .fetch_optional(&mut **tx)
    .await?;
    anyhow::ensure!(
        instance.is_some(),
        "cluster process instance lease was lost before direct-message commit"
    );
    Ok(())
}

/// Wait behind every direct admission currently holding this process's exact
/// key and instance shared locks. The returned PostgreSQL timestamp is a
/// cutoff for one bounded recovery replay pass, never a claim on live routes.
pub(crate) async fn recovery_replay_cutoff_after_direct_commits(
    pool: &PgPool,
    authority: &northstar_security::cluster_keys::ClusterReadinessAuthority,
) -> Result<DateTime<Utc>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut tx = pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '7s'")
            .execute(&mut *tx)
            .await?;
        let key: Option<bool> = sqlx::query_scalar(
            "SELECT TRUE FROM cluster_key_deployments
             WHERE xmpp_domain=$1 AND node_id=$2 AND epoch=$3
               AND current_key_id=$4 AND current_public_key_sha256=$5
             FOR UPDATE",
        )
        .bind(&authority.key_identity.xmpp_domain)
        .bind(&authority.key_identity.node_id)
        .bind(authority.key_identity.epoch)
        .bind(&authority.key_identity.current_key_id)
        .bind(&authority.key_identity.current_public_key_sha256)
        .fetch_optional(&mut *tx)
        .await?;
        anyhow::ensure!(
            key.is_some(),
            "cluster recovery signing-key authority changed"
        );
        let instance: Option<bool> = sqlx::query_scalar(
            "SELECT TRUE FROM cluster_node_instances
             WHERE xmpp_domain=$1 AND node_id=$2
               AND instance_uuid=$3 AND instance_epoch=$4
               AND signing_key_id=$5 AND signing_key_epoch=$6
               AND lease_until > clock_timestamp()
             FOR UPDATE",
        )
        .bind(&authority.key_identity.xmpp_domain)
        .bind(&authority.instance_node_id)
        .bind(authority.instance_uuid)
        .bind(authority.instance_epoch)
        .bind(&authority.signing_key_id)
        .bind(authority.signing_key_epoch)
        .fetch_optional(&mut *tx)
        .await?;
        anyhow::ensure!(
            instance.is_some(),
            "cluster recovery process instance lease was lost"
        );
        let cutoff: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok::<_, anyhow::Error>(cutoff)
    })
    .await
    .context("cluster recovery authority barrier exceeded ten seconds")?
}

#[allow(clippy::too_many_arguments)]
pub async fn admit_cluster_envelope_replay(
    pool: &PgPool,
    namespace: &str,
    envelope: &northstar_security::cluster_bus::SignedClusterEnvelope,
) -> Result<bool> {
    let event_id = Uuid::parse_str(&envelope.event_id)?;
    let expires_at = chrono::DateTime::<chrono::Utc>::from_timestamp(envelope.expires_at, 0)
        .context("cluster envelope expiry is outside PostgreSQL timestamp range")?;
    Ok(sqlx::query_scalar(
        "SELECT northstar_admit_cluster_envelope_replay($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
    )
    .bind(namespace).bind(&envelope.source_node).bind(envelope.connection_uuid)
    .bind(envelope.connection_epoch).bind(&envelope.key_id).bind(envelope.key_epoch)
    .bind(&envelope.destination_node).bind(envelope.destination_connection_uuid)
    .bind(envelope.destination_connection_epoch).bind(&envelope.destination_key_id)
    .bind(envelope.destination_key_epoch).bind(event_id)
    .bind(Sha256::digest(envelope.channel.as_bytes()).to_vec())
    .bind(&envelope.payload_sha256).bind(expires_at).fetch_one(pool).await?)
}

pub async fn cleanup_cluster_envelope_replays(pool: &PgPool, limit: i32) -> Result<u64> {
    let removed: i64 = sqlx::query_scalar("SELECT northstar_cleanup_cluster_envelope_replays($1)")
        .bind(limit.clamp(1, 10_000))
        .fetch_one(pool)
        .await?;
    Ok(removed.max(0) as u64)
}

#[cfg(test)]
mod replay_schema_tests;

pub(crate) const CLUSTER_KEY_AUTHORITY_LOCK: i64 = 4_741_070_036_074_865_762;
const KEY_ROTATION_GRACE_SECONDS: i64 = 20;

/// Direct spool producers take the shared claim fence before acquiring the
/// key and instance row locks. A replacement instance takes the exclusive
/// lock first, so a committed wake targets either the old or the new stable
/// node slot without an inverse row/advisory lock cycle.
pub(crate) async fn lock_direct_spool_instance_claims_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(CLUSTER_KEY_AUTHORITY_LOCK)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClusterKeyRecord {
    epoch: i64,
    current_key_id: String,
    current_public_key_sha256: String,
    previous_key_id: Option<String>,
    previous_public_key_sha256: Option<String>,
    staged_next_key_id: Option<String>,
    staged_next_public_key_sha256: Option<String>,
}

type ClusterKeyRow = (
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

impl From<ClusterKeyRow> for ClusterKeyRecord {
    fn from(row: ClusterKeyRow) -> Self {
        Self {
            epoch: row.0,
            current_key_id: row.1,
            current_public_key_sha256: row.2,
            previous_key_id: row.3,
            previous_public_key_sha256: row.4,
            staged_next_key_id: row.5,
            staged_next_public_key_sha256: row.6,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reconciliation {
    Compatible,
    Prepare,
    Activate,
    Retire,
}

const MAX_INSTANCE_LEASE_SECONDS: u64 = 3_600;

type ClusterInstanceLeaseRow = (uuid::Uuid, i64, String, i64, chrono::DateTime<chrono::Utc>);
type ClusterKeyDeploymentRow = (
    String,
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);
type ClusterPeerKeyAuthorityRow = (String, i64, String, Option<String>, Option<String>);
#[cfg(test)]
type OptionalKeyMaterial<'a> = Option<(&'a str, &'a str)>;

fn next_instance_epoch(
    existing: Option<ClusterInstanceLeaseRow>,
    requested_uuid: uuid::Uuid,
    requested_signing_key_id: &str,
    requested_signing_key_epoch: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<i64> {
    match existing {
        None => Ok(1),
        Some((
            current_uuid,
            current_epoch,
            current_signing_key_id,
            current_signing_key_epoch,
            lease_until,
        )) => {
            let same_instance = current_uuid == requested_uuid
                && current_signing_key_id == requested_signing_key_id
                && current_signing_key_epoch == requested_signing_key_epoch;
            anyhow::ensure!(
                same_instance || lease_until <= now,
                "another process still owns this cluster node ID until {lease_until}"
            );
            if same_instance {
                Ok(current_epoch)
            } else {
                current_epoch
                    .checked_add(1)
                    .context("cluster instance epoch overflow")
            }
        }
    }
}

pub async fn reconcile_cluster_key_deployment(
    pool: &PgPool,
    identity: &ClusterKeyDeploymentIdentity,
) -> Result<()> {
    reconcile_cluster_key_deployment_inner(pool, identity, true, true).await
}

/// Prepare/bootstrap/activate the local key authority before claiming the
/// process instance. Retirement is intentionally deferred until the new
/// current key owns a live fenced instance and the overlap grace has elapsed.
pub async fn reconcile_cluster_key_deployment_before_instance_claim(
    pool: &PgPool,
    identity: &ClusterKeyDeploymentIdentity,
) -> Result<()> {
    reconcile_cluster_key_deployment_inner(pool, identity, true, false).await
}

pub async fn reconcile_cluster_peer_key_deployment(
    pool: &PgPool,
    identity: &ClusterKeyDeploymentIdentity,
) -> Result<()> {
    reconcile_cluster_key_deployment_inner(pool, identity, false, false).await
}

async fn reconcile_cluster_key_deployment_inner(
    pool: &PgPool,
    identity: &ClusterKeyDeploymentIdentity,
    owns_node: bool,
    permit_retire: bool,
) -> Result<()> {
    validate_identity(identity)?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(CLUSTER_KEY_AUTHORITY_LOCK)
        .execute(&mut *tx)
        .await
        .context("could not lock cluster key authority")?;
    let record = sqlx::query_as::<_, ClusterKeyRow>(
        "SELECT epoch,current_key_id,current_public_key_sha256,
                previous_key_id,previous_public_key_sha256,
                staged_next_key_id,staged_next_public_key_sha256
         FROM cluster_key_deployments
         WHERE xmpp_domain=$1 AND node_id=$2 FOR UPDATE",
    )
    .bind(&identity.xmpp_domain)
    .bind(&identity.node_id)
    .fetch_optional(&mut *tx)
    .await?
    .map(ClusterKeyRecord::from);
    match record {
        None => {
            sqlx::query(
                "INSERT INTO cluster_key_deployments
                 (xmpp_domain,node_id,epoch,current_key_id,current_public_key_sha256,
                  previous_key_id,previous_public_key_sha256,
                  staged_next_key_id,staged_next_public_key_sha256)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind(&identity.xmpp_domain)
            .bind(&identity.node_id)
            .bind(identity.epoch)
            .bind(&identity.current_key_id)
            .bind(&identity.current_public_key_sha256)
            .bind(&identity.previous_key_id)
            .bind(&identity.previous_public_key_sha256)
            .bind(&identity.staged_next_key_id)
            .bind(&identity.staged_next_public_key_sha256)
            .execute(&mut *tx)
            .await?;
        }
        Some(record) => match if owns_node {
            decide_reconciliation(&record, identity)?
        } else {
            match decide_reconciliation(&record, identity) {
                Ok(Reconciliation::Prepare) => Reconciliation::Prepare,
                Ok(Reconciliation::Compatible) => Reconciliation::Compatible,
                Ok(other) if authority_configuration_compatible(&record, identity) => {
                    let _ = other;
                    Reconciliation::Compatible
                }
                Err(_) if authority_configuration_compatible(&record, identity) => {
                    Reconciliation::Compatible
                }
                Ok(other) => other,
                Err(error) => return Err(error),
            }
        } {
            Reconciliation::Compatible => {}
            Reconciliation::Retire if owns_node && !permit_retire => {}
            transition @ (Reconciliation::Prepare
            | Reconciliation::Activate
            | Reconciliation::Retire) => {
                anyhow::ensure!(
                    owns_node || transition == Reconciliation::Prepare,
                    "a peer allowlist cannot activate or retire another node's signing key"
                );
                if transition == Reconciliation::Retire {
                    let safely_activated: bool = sqlx::query_scalar(
                        "SELECT EXISTS(
                           SELECT 1
                           FROM cluster_node_instances AS instance
                           JOIN cluster_key_deployments AS authority
                             ON authority.xmpp_domain=instance.xmpp_domain
                            AND authority.node_id=instance.node_id
                           WHERE instance.xmpp_domain=$1 AND instance.node_id=$2
                             AND instance.lease_until > clock_timestamp()
                             AND instance.signing_key_id=authority.current_key_id
                             AND instance.signing_key_epoch=authority.epoch
                             AND authority.updated_at <= clock_timestamp()
                                 - ($3::bigint * INTERVAL '1 second')
                         )",
                    )
                    .bind(&identity.xmpp_domain)
                    .bind(&identity.node_id)
                    .bind(KEY_ROTATION_GRACE_SECONDS)
                    .fetch_one(&mut *tx)
                    .await?;
                    anyhow::ensure!(
                        safely_activated,
                        "cluster previous key cannot retire until the current key owns an active fenced instance beyond the rotation grace"
                    );
                }
                sqlx::query(
                    "UPDATE cluster_key_deployments
                     SET epoch=$3,current_key_id=$4,current_public_key_sha256=$5,
                         previous_key_id=$6,previous_public_key_sha256=$7,
                         staged_next_key_id=$8,staged_next_public_key_sha256=$9,
                         updated_at=clock_timestamp()
                     WHERE xmpp_domain=$1 AND node_id=$2",
                )
                .bind(&identity.xmpp_domain)
                .bind(&identity.node_id)
                .bind(identity.epoch)
                .bind(&identity.current_key_id)
                .bind(&identity.current_public_key_sha256)
                .bind(&identity.previous_key_id)
                .bind(&identity.previous_public_key_sha256)
                .bind(&identity.staged_next_key_id)
                .bind(&identity.staged_next_public_key_sha256)
                .execute(&mut *tx)
                .await?;
            }
        },
    }
    tx.commit().await?;
    Ok(())
}

pub async fn validate_cluster_key_deployment(
    pool: &PgPool,
    identity: &ClusterKeyDeploymentIdentity,
) -> Result<()> {
    validate_identity(identity)?;
    let record = sqlx::query_as::<_, ClusterKeyRow>(
        "SELECT epoch,current_key_id,current_public_key_sha256,
                previous_key_id,previous_public_key_sha256,
                staged_next_key_id,staged_next_public_key_sha256
         FROM cluster_key_deployments
         WHERE xmpp_domain=$1 AND node_id=$2",
    )
    .bind(&identity.xmpp_domain)
    .bind(&identity.node_id)
    .fetch_optional(pool)
    .await?
    .context("cluster key authority is missing for this node")?;
    let record = ClusterKeyRecord::from(record);
    anyhow::ensure!(
        authority_configuration_compatible(&record, identity),
        "cluster key authority is incompatible with this process"
    );
    Ok(())
}

/// Claim the one active process slot for a stable node ID. PostgreSQL's clock
/// and row lock are authoritative. A still-live different UUID is never
/// pre-empted; an expired row advances the independent instance epoch.
pub async fn claim_cluster_node_instance(
    pool: &PgPool,
    xmpp_domain: &str,
    node_id: &str,
    instance_uuid: uuid::Uuid,
    signing_key_id: &str,
    signing_key_epoch: i64,
    lease: Duration,
) -> Result<ClusterNodeInstance> {
    anyhow::ensure!(
        !instance_uuid.is_nil(),
        "cluster instance UUID must be non-nil"
    );
    let lease_seconds = bounded_lease_seconds(lease)?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(CLUSTER_KEY_AUTHORITY_LOCK)
        .execute(&mut *tx)
        .await?;
    let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let current_key: Option<(i64, String)> = sqlx::query_as(
        "SELECT epoch,current_key_id FROM cluster_key_deployments
         WHERE xmpp_domain=$1 AND node_id=$2 FOR UPDATE",
    )
    .bind(xmpp_domain)
    .bind(node_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (current_key_epoch, current_key_id) =
        current_key.context("cluster signing-key authority is missing for this node")?;
    anyhow::ensure!(
        current_key_epoch == signing_key_epoch && current_key_id == signing_key_id,
        "cluster process may claim an instance lease only with the active current signing key"
    );
    let existing: Option<ClusterInstanceLeaseRow> = sqlx::query_as(
        "SELECT instance_uuid,instance_epoch,signing_key_id,signing_key_epoch,lease_until
         FROM cluster_node_instances
         WHERE xmpp_domain=$1 AND node_id=$2 FOR UPDATE",
    )
    .bind(xmpp_domain)
    .bind(node_id)
    .fetch_optional(&mut *tx)
    .await?;
    let instance_epoch = next_instance_epoch(
        existing,
        instance_uuid,
        signing_key_id,
        signing_key_epoch,
        now,
    )?;
    let lease_until = now + chrono::Duration::seconds(lease_seconds);
    sqlx::query(
        "INSERT INTO cluster_node_instances
         (xmpp_domain,node_id,instance_uuid,instance_epoch,
          signing_key_id,signing_key_epoch,lease_until,updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (xmpp_domain,node_id) DO UPDATE
         SET instance_uuid=EXCLUDED.instance_uuid,
             instance_epoch=EXCLUDED.instance_epoch,
             signing_key_id=EXCLUDED.signing_key_id,
             signing_key_epoch=EXCLUDED.signing_key_epoch,
             lease_until=EXCLUDED.lease_until,updated_at=EXCLUDED.updated_at",
    )
    .bind(xmpp_domain)
    .bind(node_id)
    .bind(instance_uuid)
    .bind(instance_epoch)
    .bind(signing_key_id)
    .bind(signing_key_epoch)
    .bind(lease_until)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    record_instance_history(
        &mut tx,
        xmpp_domain,
        node_id,
        instance_uuid,
        instance_epoch,
        signing_key_id,
        signing_key_epoch,
        lease_until,
        "claim",
    )
    .await?;
    tx.commit().await?;
    Ok(ClusterNodeInstance {
        node_id: node_id.to_owned(),
        instance_uuid,
        instance_epoch,
        signing_key_id: signing_key_id.to_owned(),
        signing_key_epoch,
        lease_remaining: Duration::from_secs(lease_seconds as u64),
    })
}

pub struct ClusterNodeHeartbeat<'a> {
    pub xmpp_domain: &'a str,
    pub node_id: &'a str,
    pub instance_uuid: uuid::Uuid,
    pub instance_epoch: i64,
    pub signing_key_id: &'a str,
    pub signing_key_epoch: i64,
    pub lease: Duration,
}

pub async fn heartbeat_cluster_node_instance(
    pool: &PgPool,
    heartbeat: ClusterNodeHeartbeat<'_>,
) -> Result<ClusterNodeInstance> {
    let ClusterNodeHeartbeat {
        xmpp_domain,
        node_id,
        instance_uuid,
        instance_epoch,
        signing_key_id,
        signing_key_epoch,
        lease,
    } = heartbeat;
    let lease_seconds = bounded_lease_seconds(lease)?;
    let mut tx = pool.begin().await?;
    let row: Option<(chrono::DateTime<chrono::Utc>,)> = sqlx::query_as(
        "UPDATE cluster_node_instances
         SET lease_until=clock_timestamp() + ($7::bigint * INTERVAL '1 second'),
             updated_at=clock_timestamp()
         WHERE xmpp_domain=$1 AND node_id=$2
           AND instance_uuid=$3 AND instance_epoch=$4
           AND signing_key_id=$5 AND signing_key_epoch=$6
           AND lease_until > clock_timestamp()
         RETURNING lease_until",
    )
    .bind(xmpp_domain)
    .bind(node_id)
    .bind(instance_uuid)
    .bind(instance_epoch)
    .bind(signing_key_id)
    .bind(signing_key_epoch)
    .bind(lease_seconds)
    .fetch_optional(&mut *tx)
    .await?;
    let (_lease_until,) = row.context("cluster node instance lease was lost or expired")?;
    tx.commit().await?;
    Ok(ClusterNodeInstance {
        node_id: node_id.to_owned(),
        instance_uuid,
        instance_epoch,
        signing_key_id: signing_key_id.to_owned(),
        signing_key_epoch,
        lease_remaining: Duration::from_secs(lease_seconds as u64),
    })
}

/// A clean release atomically expires the process lease and records the fence.
/// The process must stop cluster publication before calling this function.
/// Receivers bound their cached authority to a short monotonic refresh window.
pub async fn release_cluster_node_instance(
    pool: &PgPool,
    xmpp_domain: &str,
    node_id: &str,
    instance_uuid: uuid::Uuid,
    instance_epoch: i64,
    signing_key_id: &str,
    signing_key_epoch: i64,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let row: Option<(chrono::DateTime<chrono::Utc>,)> = sqlx::query_as(
        "UPDATE cluster_node_instances
         SET lease_until=clock_timestamp(),updated_at=clock_timestamp()
         WHERE xmpp_domain=$1 AND node_id=$2
           AND instance_uuid=$3 AND instance_epoch=$4
           AND signing_key_id=$5 AND signing_key_epoch=$6
         RETURNING lease_until",
    )
    .bind(xmpp_domain)
    .bind(node_id)
    .bind(instance_uuid)
    .bind(instance_epoch)
    .bind(signing_key_id)
    .bind(signing_key_epoch)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((lease_until,)) = row else {
        return Ok(false);
    };
    record_instance_history(
        &mut tx,
        xmpp_domain,
        node_id,
        instance_uuid,
        instance_epoch,
        signing_key_id,
        signing_key_epoch,
        lease_until,
        "release",
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

pub async fn active_cluster_node_instances(
    pool: &PgPool,
    xmpp_domain: &str,
    node_ids: &[String],
) -> Result<Vec<ClusterNodeInstance>> {
    if node_ids.is_empty() {
        return Ok(Vec::new());
    }
    anyhow::ensure!(
        node_ids.len() <= 128,
        "too many cluster nodes in authority refresh"
    );
    let rows: Vec<(String, uuid::Uuid, i64, String, i64, i64)> = sqlx::query_as(
        "SELECT node_id,instance_uuid,instance_epoch,signing_key_id,signing_key_epoch,
                FLOOR(EXTRACT(EPOCH FROM (lease_until - clock_timestamp())))::bigint
         FROM cluster_node_instances
         WHERE xmpp_domain=$1 AND node_id = ANY($2)
           AND lease_until > clock_timestamp()",
    )
    .bind(xmpp_domain)
    .bind(node_ids)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                node_id,
                instance_uuid,
                instance_epoch,
                signing_key_id,
                signing_key_epoch,
                remaining_seconds,
            )| ClusterNodeInstance {
                node_id,
                instance_uuid,
                instance_epoch,
                signing_key_id,
                signing_key_epoch,
                lease_remaining: Duration::from_secs(remaining_seconds.max(0) as u64),
            },
        )
        .collect())
}

pub async fn validate_cluster_peer_key_deployments(
    pool: &PgPool,
    xmpp_domain: &str,
    expected: &[ExpectedClusterPeerKey],
) -> Result<()> {
    if expected.is_empty() {
        return Ok(());
    }
    anyhow::ensure!(expected.len() <= 128, "too many configured cluster peers");
    let node_ids = expected
        .iter()
        .map(|peer| peer.node_id.clone())
        .collect::<Vec<_>>();
    let rows: Vec<ClusterKeyDeploymentRow> = sqlx::query_as(
        "SELECT node_id,epoch,current_key_id,current_public_key_sha256,
                    previous_key_id,previous_public_key_sha256,
                    staged_next_key_id,staged_next_public_key_sha256
             FROM cluster_key_deployments
             WHERE xmpp_domain=$1 AND node_id = ANY($2)",
    )
    .bind(xmpp_domain)
    .bind(&node_ids)
    .fetch_all(pool)
    .await?;
    let actual = rows
        .into_iter()
        .map(|row| (row.0.clone(), row))
        .collect::<std::collections::HashMap<_, _>>();
    for peer in expected {
        let row = actual
            .get(&peer.node_id)
            .with_context(|| format!("cluster peer {} has no key authority", peer.node_id))?;
        let record = ClusterKeyRecord {
            epoch: row.1,
            current_key_id: row.2.clone(),
            current_public_key_sha256: row.3.clone(),
            previous_key_id: row.4.clone(),
            previous_public_key_sha256: row.5.clone(),
            staged_next_key_id: row.6.clone(),
            staged_next_public_key_sha256: row.7.clone(),
        };
        let configured = ClusterKeyDeploymentIdentity {
            xmpp_domain: xmpp_domain.to_owned(),
            node_id: peer.node_id.clone(),
            epoch: peer.epoch,
            current_key_id: peer.current_key_id.clone(),
            current_public_key_sha256: peer.current_public_key_sha256.clone(),
            previous_key_id: peer.previous_key_id.clone(),
            previous_public_key_sha256: peer.previous_public_key_sha256.clone(),
            staged_next_key_id: peer.staged_next_key_id.clone(),
            staged_next_public_key_sha256: peer.staged_next_public_key_sha256.clone(),
        };
        anyhow::ensure!(
            authority_configuration_compatible(&record, &configured),
            "cluster peer {} key authority does not match its allowlist",
            peer.node_id
        );
    }
    Ok(())
}

pub async fn cluster_peer_key_authorities(
    pool: &PgPool,
    xmpp_domain: &str,
    node_ids: &[String],
) -> Result<Vec<ClusterPeerKeyAuthority>> {
    if node_ids.is_empty() {
        return Ok(Vec::new());
    }
    anyhow::ensure!(node_ids.len() <= 128, "too many configured cluster peers");
    let rows: Vec<ClusterPeerKeyAuthorityRow> = sqlx::query_as(
        "SELECT node_id,epoch,current_key_id,previous_key_id,staged_next_key_id
         FROM cluster_key_deployments
         WHERE xmpp_domain=$1 AND node_id = ANY($2)",
    )
    .bind(xmpp_domain)
    .bind(node_ids)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(node_id, epoch, current_key_id, previous_key_id, staged_next_key_id)| {
                ClusterPeerKeyAuthority {
                    node_id,
                    epoch,
                    current_key_id,
                    previous_key_id,
                    staged_next_key_id,
                }
            },
        )
        .collect())
}

fn bounded_lease_seconds(lease: Duration) -> Result<i64> {
    anyhow::ensure!(
        (90..=MAX_INSTANCE_LEASE_SECONDS).contains(&lease.as_secs()),
        "cluster node instance lease must be between 90 and {MAX_INSTANCE_LEASE_SECONDS} seconds"
    );
    i64::try_from(lease.as_secs()).context("cluster instance lease is too large")
}

#[allow(clippy::too_many_arguments)]
async fn record_instance_history(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    xmpp_domain: &str,
    node_id: &str,
    instance_uuid: uuid::Uuid,
    instance_epoch: i64,
    signing_key_id: &str,
    signing_key_epoch: i64,
    lease_until: chrono::DateTime<chrono::Utc>,
    operation: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO cluster_node_instance_history
         (xmpp_domain,node_id,instance_uuid,instance_epoch,
          signing_key_id,signing_key_epoch,lease_until,operation)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(xmpp_domain)
    .bind(node_id)
    .bind(instance_uuid)
    .bind(instance_epoch)
    .bind(signing_key_id)
    .bind(signing_key_epoch)
    .bind(lease_until)
    .bind(operation)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn decide_reconciliation(
    record: &ClusterKeyRecord,
    identity: &ClusterKeyDeploymentIdentity,
) -> Result<Reconciliation> {
    let current_matches = record.current_key_id == identity.current_key_id
        && record.current_public_key_sha256 == identity.current_public_key_sha256;
    let previous_matches = record.previous_key_id == identity.previous_key_id
        && record.previous_public_key_sha256 == identity.previous_public_key_sha256;
    let staged_matches = record.staged_next_key_id == identity.staged_next_key_id
        && record.staged_next_public_key_sha256 == identity.staged_next_public_key_sha256;
    if record.epoch == identity.epoch {
        if current_matches && previous_matches && staged_matches {
            return Ok(Reconciliation::Compatible);
        }
        if current_matches
            && previous_matches
            && record.staged_next_key_id.is_none()
            && identity.staged_next_key_id.is_some()
        {
            return Ok(Reconciliation::Prepare);
        }
        if current_matches
            && staged_matches
            && record.previous_key_id.is_some()
            && identity.previous_key_id.is_none()
        {
            return Ok(Reconciliation::Retire);
        }
        anyhow::bail!("cluster node ID/epoch is already authorized for different key material");
    }
    anyhow::ensure!(
        identity.epoch == record.epoch.saturating_add(1),
        "cluster key epoch must advance by exactly one"
    );
    anyhow::ensure!(
        record.staged_next_key_id.as_deref() == Some(identity.current_key_id.as_str())
            && record.staged_next_public_key_sha256.as_deref()
                == Some(identity.current_public_key_sha256.as_str())
            && identity.previous_key_id.as_deref() == Some(record.current_key_id.as_str())
            && identity.previous_public_key_sha256.as_deref()
                == Some(record.current_public_key_sha256.as_str()),
        "cluster activation must consume staged-next and retain current as previous"
    );
    Ok(Reconciliation::Activate)
}

fn authority_configuration_compatible(
    record: &ClusterKeyRecord,
    identity: &ClusterKeyDeploymentIdentity,
) -> bool {
    let optional_pair_compatible =
        |left_id: &Option<String>,
         left_digest: &Option<String>,
         right_id: &Option<String>,
         right_digest: &Option<String>| {
            left_id.is_none()
                || right_id.is_none()
                || (left_id == right_id && left_digest == right_digest)
        };
    if record.epoch == identity.epoch
        && record.current_key_id == identity.current_key_id
        && record.current_public_key_sha256 == identity.current_public_key_sha256
        && optional_pair_compatible(
            &record.previous_key_id,
            &record.previous_public_key_sha256,
            &identity.previous_key_id,
            &identity.previous_public_key_sha256,
        )
        && optional_pair_compatible(
            &record.staged_next_key_id,
            &record.staged_next_public_key_sha256,
            &identity.staged_next_key_id,
            &identity.staged_next_public_key_sha256,
        )
    {
        return true;
    }
    (record.epoch == identity.epoch.saturating_add(1)
        && record.previous_key_id.as_deref() == Some(identity.current_key_id.as_str())
        && record.previous_public_key_sha256.as_deref()
            == Some(identity.current_public_key_sha256.as_str())
        && identity.staged_next_key_id.as_deref() == Some(record.current_key_id.as_str())
        && identity.staged_next_public_key_sha256.as_deref()
            == Some(record.current_public_key_sha256.as_str()))
        || (identity.epoch == record.epoch.saturating_add(1)
            && identity.previous_key_id.as_deref() == Some(record.current_key_id.as_str())
            && identity.previous_public_key_sha256.as_deref()
                == Some(record.current_public_key_sha256.as_str())
            && record.staged_next_key_id.as_deref() == Some(identity.current_key_id.as_str())
            && record.staged_next_public_key_sha256.as_deref()
                == Some(identity.current_public_key_sha256.as_str()))
}

fn validate_identity(identity: &ClusterKeyDeploymentIdentity) -> Result<()> {
    anyhow::ensure!(identity.epoch >= 1, "cluster key epoch must be positive");
    anyhow::ensure!(
        (1..=128).contains(&identity.node_id.len())
            && identity
                .node_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        "cluster node ID is invalid"
    );
    anyhow::ensure!(
        (identity.previous_key_id.is_none()) == (identity.previous_public_key_sha256.is_none()),
        "cluster previous key ID and fingerprint must be configured together"
    );
    anyhow::ensure!(
        (identity.staged_next_key_id.is_none())
            == (identity.staged_next_public_key_sha256.is_none()),
        "cluster staged-next key ID and fingerprint must be configured together"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
