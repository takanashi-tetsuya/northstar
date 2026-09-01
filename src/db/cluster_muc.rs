//! PostgreSQL authority for experimental clustered MUC.
//!
//! Redis is only a signed wake-up transport.  Every method which changes a
//! room or occupancy locks the room row, checks the current PostgreSQL
//! authorization fact and records one immutable operation plus its exact
//! audience before commit.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::time::Duration;
use uuid::Uuid;

const MAX_NICK_BYTES: usize = 128;
const MAX_PAYLOAD_BYTES: usize = 1_048_576;
const MAX_OPERATION_SNAPSHOT_BYTES: usize = 16 * 1_048_576;
const MAX_OPERATION_AUDIENCE: usize = 10_000;
const MAX_CLAIM_BATCH: i64 = 256;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClusterMucPrincipal {
    Local {
        user_id: Uuid,
        bare_jid: String,
    },
    Federated {
        bare_jid: String,
        authenticated_domain: String,
    },
}

/// Identity whose durable room affiliation is being changed. This is
/// deliberately separate from `ClusterMucPrincipal`: an inviter proves its
/// own authenticated domain, but cannot (and must not pretend to) prove the
/// invited remote account's domain ownership.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClusterMucAffiliationSubject {
    Local { user_id: Uuid, bare_jid: String },
    Federated { bare_jid: String },
}

impl ClusterMucAffiliationSubject {
    fn bare_jid(&self) -> &str {
        match self {
            Self::Local { bare_jid, .. } | Self::Federated { bare_jid } => bare_jid,
        }
    }

    fn validate(&self) -> Result<()> {
        let jid = crate::jid::CanonicalJid::parse_bare(self.bare_jid())?;
        anyhow::ensure!(
            jid.localpart().is_some() && jid.to_string() == self.bare_jid(),
            "cluster MUC affiliation subject must be a canonical user bare JID"
        );
        Ok(())
    }

    fn matches_principal(&self, principal: &ClusterMucPrincipal) -> bool {
        match (self, principal) {
            (
                Self::Local {
                    user_id: subject_id,
                    bare_jid: subject_jid,
                },
                ClusterMucPrincipal::Local { user_id, bare_jid },
            ) => subject_id == user_id && subject_jid == bare_jid,
            (
                Self::Federated {
                    bare_jid: subject_jid,
                },
                ClusterMucPrincipal::Federated { bare_jid, .. },
            ) => subject_jid == bare_jid,
            _ => false,
        }
    }
}

/// Exact authority supplied by a mediated or direct invitation. Mediated
/// invitations bind the actor to an active occupancy incarnation. A local
/// direct invitation may omit that target, but is then authorized only by
/// the authenticated local account's durable affiliation.
#[derive(Clone, Debug)]
pub struct ClusterMucInviteAuthority {
    pub operation_id: Uuid,
    pub expected_room_epoch: Uuid,
    pub expected_config_version: i64,
    pub actor: ClusterMucPrincipal,
    pub actor_full_jid: String,
    pub actor_target: Option<ClusterMucOccupancyTarget>,
    pub subject: ClusterMucAffiliationSubject,
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClusterMucAffiliationMutationOutcome {
    Applied { affiliation_changed: bool },
    Replay { affiliation_changed: bool },
    Conflict,
    Outcast,
    NotAllowed,
    Unauthorized,
    Stale,
    Destroyed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClusterMucRegistrationOutcome {
    Applied { affiliation_changed: bool },
    Replay { affiliation_changed: bool },
    Conflict,
    Outcast,
    NotAllowed,
    Stale,
    Destroyed,
}

#[derive(Clone, Copy, Debug)]
enum ClusterMucAffiliationMutation<'a> {
    SelfRegister { reserved_nick: &'a str },
    SelfUnregister,
    Invitation,
}

impl ClusterMucPrincipal {
    fn bare_jid(&self) -> &str {
        match self {
            Self::Local { bare_jid, .. } | Self::Federated { bare_jid, .. } => bare_jid,
        }
    }

    fn validate(&self) -> Result<()> {
        let jid = crate::jid::CanonicalJid::parse_bare(self.bare_jid())?;
        anyhow::ensure!(
            jid.localpart().is_some(),
            "MUC principal must be a user JID"
        );
        anyhow::ensure!(
            jid.to_string() == self.bare_jid(),
            "MUC principal JID must already be canonical"
        );
        if let Self::Federated {
            authenticated_domain,
            ..
        } = self
        {
            let authenticated_domain = crate::jid::prepare_domainpart(authenticated_domain)?;
            anyhow::ensure!(
                authenticated_domain == jid.domainpart(),
                "federated MUC ownership is not proven by the authenticated S2S domain"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClusterMucOccupancy {
    pub room_id: Uuid,
    pub room_epoch: Uuid,
    pub occupant_incarnation: Uuid,
    pub occupancy_epoch: i64,
    pub config_version: i64,
    pub identity_kind: String,
    pub local_user_id: Option<Uuid>,
    pub bare_jid: String,
    pub full_jid: String,
    pub nick: String,
    pub authenticated_domain: Option<String>,
    pub owner_node_id: String,
    pub connection_uuid: Uuid,
    pub connection_epoch: i64,
    pub sm_session_id: Option<Uuid>,
    pub role: String,
    pub affiliation: String,
    pub state: String,
    pub presence_payload: String,
    pub lease_until: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct ClusterMucJoin<'a> {
    pub operation_id: Uuid,
    pub room_id: Uuid,
    pub expected_room_epoch: Uuid,
    pub expected_config_version: i64,
    pub principal: ClusterMucPrincipal,
    pub full_jid: &'a str,
    pub nick: &'a str,
    pub owner_node_id: &'a str,
    pub connection_uuid: Uuid,
    pub connection_epoch: i64,
    pub sm_session_id: Option<Uuid>,
    pub occupant_incarnation: Uuid,
    pub presence_payload: &'a str,
    pub lease: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClusterMucJoinOutcome {
    Joined(ClusterMucOccupancy),
    Replay(ClusterMucOccupancy),
    RoomMissing,
    RoomDestroyed,
    RoomLocked,
    StaleRoom,
    Outcast,
    MembershipRequired,
    ReservedNickname,
    NicknameConflict,
    FullJidConflict,
    Full,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClusterMucOccupancyTarget {
    pub room_id: Uuid,
    pub room_epoch: Uuid,
    pub occupant_incarnation: Uuid,
    pub occupancy_epoch: i64,
    pub full_jid: String,
    pub nick: String,
    pub connection_uuid: Uuid,
    pub connection_epoch: i64,
}

/// Compact, immutable result of a policy mutation. This deliberately omits
/// `presence_payload`: policy audit data is not a second durable copy of
/// arbitrary user-supplied presence XML.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClusterMucPolicySnapshot {
    pub room_id: Uuid,
    pub room_epoch: Uuid,
    pub occupant_incarnation: Uuid,
    pub occupancy_epoch: i64,
    pub full_jid: String,
    pub bare_jid: String,
    pub nick: String,
    pub connection_uuid: Uuid,
    pub connection_epoch: i64,
    pub sm_session_id: Option<Uuid>,
    pub role: String,
    pub affiliation: String,
    pub state: String,
}

impl From<&ClusterMucOccupancy> for ClusterMucPolicySnapshot {
    fn from(value: &ClusterMucOccupancy) -> Self {
        Self {
            room_id: value.room_id,
            room_epoch: value.room_epoch,
            occupant_incarnation: value.occupant_incarnation,
            occupancy_epoch: value.occupancy_epoch,
            full_jid: value.full_jid.clone(),
            bare_jid: value.bare_jid.clone(),
            nick: value.nick.clone(),
            connection_uuid: value.connection_uuid,
            connection_epoch: value.connection_epoch,
            sm_session_id: value.sm_session_id,
            role: value.role.clone(),
            affiliation: value.affiliation.clone(),
            state: value.state.clone(),
        }
    }
}

impl From<&ClusterMucOccupancy> for ClusterMucOccupancyTarget {
    fn from(value: &ClusterMucOccupancy) -> Self {
        Self {
            room_id: value.room_id,
            room_epoch: value.room_epoch,
            occupant_incarnation: value.occupant_incarnation,
            occupancy_epoch: value.occupancy_epoch,
            full_jid: value.full_jid.clone(),
            nick: value.nick.clone(),
            connection_uuid: value.connection_uuid,
            connection_epoch: value.connection_epoch,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClusterMucTransitionOutcome {
    Applied,
    Replay,
    Stale,
    Destroyed,
    Conflict,
    Unauthorized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClusterMucConfigurationOutcome {
    Applied,
    Replay,
    LockedByAnother,
    Expired,
    Missing,
    Stale,
    Unauthorized,
    Destroyed,
}

#[derive(Clone, Debug)]
pub struct ClusterMucOutboxDelivery {
    pub delivery_id: Uuid,
    pub operation_id: Uuid,
    pub room_id: Uuid,
    pub room_epoch: Uuid,
    pub event_sequence: i64,
    pub event_id: Uuid,
    pub audience_kind: String,
    pub target_node_id: String,
    pub recipient_full_jid: Option<String>,
    pub recipient_nick: Option<String>,
    pub recipient_occupant_incarnation: Option<Uuid>,
    pub recipient_occupancy_epoch: Option<i64>,
    pub recipient_connection_uuid: Option<Uuid>,
    pub recipient_connection_epoch: Option<i64>,
    pub payload: String,
    pub payload_digest: Vec<u8>,
    pub attempt_count: i32,
    pub claim_token: Uuid,
    pub handoff_version: i64,
}

#[derive(Clone, Debug)]
pub struct ClusterMucEventContext {
    pub operation_kind: String,
    pub room_localpart: String,
    pub room_epoch: Uuid,
    pub room_non_anonymous: bool,
    pub occupant_id_secret: Vec<u8>,
    pub actor_full_jid: Option<String>,
    pub actor_affiliation: Option<String>,
    pub details: Value,
    pub target: Option<ClusterMucEventOccupant>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterMucWakeDescriptor {
    pub operation_id: Uuid,
    pub room_id: Uuid,
    pub event_id: Uuid,
    pub event_sequence: i64,
    pub target_nodes: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ClusterMucEventOccupant {
    pub full_jid: String,
    pub bare_jid: String,
    pub nick: String,
    pub affiliation: String,
    pub role: String,
    pub presence_payload: String,
    pub occupant_incarnation: Uuid,
    pub occupancy_epoch: i64,
    pub connection_uuid: Uuid,
    pub connection_epoch: i64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClusterMucOutboxSnapshot {
    pub queued_rows: i64,
    pub expired_rows: i64,
    pub claimed_rows: i64,
    pub dead_letter_rows: i64,
    pub oldest_age_seconds: i64,
}

#[derive(Clone, Debug)]
struct RoomAuthority {
    room_epoch: Uuid,
    config_version: i64,
    configuration_state: String,
    configuration_owner_jid: Option<String>,
    configuration_expired: bool,
    destroyed: bool,
    members_only: bool,
    moderated: bool,
    non_anonymous: bool,
    allow_registration: bool,
    allow_invites: bool,
    allow_subject_change: bool,
    max_occupants: i32,
}

/// Immutable, bounded delivery projection captured at operation commit. It
/// deliberately excludes the potentially 1 MiB presence payload: recipient
/// endpoint reconstruction needs identity/route/role facts, not the
/// recipient's last advertised presence. Keeping this projection in the
/// append-only operation prevents a later resume/rename from rewriting who
/// was in the audience of an already committed event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClusterMucAudienceSnapshot {
    pub room_id: Uuid,
    pub room_epoch: Uuid,
    pub identity_kind: String,
    pub local_user_id: Option<Uuid>,
    pub bare_jid: String,
    pub full_jid: String,
    pub nick: String,
    pub authenticated_domain: Option<String>,
    pub owner_node_id: String,
    pub occupant_incarnation: Uuid,
    pub occupancy_epoch: i64,
    pub connection_uuid: Uuid,
    pub connection_epoch: i64,
    pub sm_session_id: Option<Uuid>,
    pub role: String,
    pub affiliation: String,
}

impl From<&ClusterMucOccupancy> for ClusterMucAudienceSnapshot {
    fn from(value: &ClusterMucOccupancy) -> Self {
        Self {
            room_id: value.room_id,
            room_epoch: value.room_epoch,
            identity_kind: value.identity_kind.clone(),
            local_user_id: value.local_user_id,
            bare_jid: value.bare_jid.clone(),
            full_jid: value.full_jid.clone(),
            nick: value.nick.clone(),
            authenticated_domain: value.authenticated_domain.clone(),
            owner_node_id: value.owner_node_id.clone(),
            occupant_incarnation: value.occupant_incarnation,
            occupancy_epoch: value.occupancy_epoch,
            connection_uuid: value.connection_uuid,
            connection_epoch: value.connection_epoch,
            sm_session_id: value.sm_session_id,
            role: value.role.clone(),
            affiliation: value.affiliation.clone(),
        }
    }
}

fn validate_node_id(node_id: &str) -> Result<()> {
    anyhow::ensure!(
        !node_id.is_empty()
            && node_id.len() <= 128
            && node_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "cluster MUC node ID is invalid"
    );
    Ok(())
}

fn validate_lease(lease: Duration) -> Result<i64> {
    let seconds = i64::try_from(lease.as_secs()).context("MUC lease is too large")?;
    anyhow::ensure!(
        (15..=600).contains(&seconds),
        "cluster MUC occupancy lease must be between 15 and 600 seconds"
    );
    Ok(seconds)
}

fn validate_nick(nick: &str) -> Result<()> {
    anyhow::ensure!(
        !nick.is_empty() && nick.len() <= MAX_NICK_BYTES && !nick.chars().any(char::is_control),
        "MUC nickname is invalid"
    );
    Ok(())
}

fn request_digest(value: &impl Serialize) -> Result<Vec<u8>> {
    Ok(Sha256::digest(
        serde_json::to_vec(value).context("could not serialize MUC operation identity")?,
    )
    .to_vec())
}

fn payload_digest(payload: &str) -> Vec<u8> {
    Sha256::digest(payload.as_bytes()).to_vec()
}

fn bounded_error(value: &str) -> String {
    value.chars().take(4096).collect()
}

fn capacity_shard(delivery_id: Uuid) -> i16 {
    i16::from(delivery_id.as_bytes()[0] & 63)
}

fn occupancy_from_row(row: &sqlx::postgres::PgRow) -> ClusterMucOccupancy {
    ClusterMucOccupancy {
        room_id: row.get("room_id"),
        room_epoch: row.get("room_epoch"),
        occupant_incarnation: row.get("occupant_incarnation"),
        occupancy_epoch: row.get("occupancy_epoch"),
        config_version: row.get("config_version"),
        identity_kind: row.get("identity_kind"),
        local_user_id: row.get("local_user_id"),
        bare_jid: row.get("bare_jid"),
        full_jid: row.get("full_jid"),
        nick: row.get("nick"),
        authenticated_domain: row.get("authenticated_domain"),
        owner_node_id: row.get("owner_node_id"),
        connection_uuid: row.get("connection_uuid"),
        connection_epoch: row.get("connection_epoch"),
        sm_session_id: row.get("sm_session_id"),
        role: row.get("role"),
        affiliation: row.get("affiliation"),
        state: row.get("state"),
        presence_payload: row.get("presence_payload"),
        lease_until: row.get("lease_until"),
    }
}

async fn lock_room(
    tx: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
) -> Result<Option<RoomAuthority>> {
    let row = sqlx::query(
        "SELECT room_epoch,config_version,configuration_state,configuration_owner_jid,
                COALESCE(configuration_expires_at<=clock_timestamp(),FALSE)
                    AS configuration_expired,
                destroyed_at IS NOT NULL AS destroyed,members_only,moderated,
                non_anonymous,allow_registration,allow_invites,allow_subject_change,max_occupants
           FROM muc_rooms WHERE id=$1 FOR UPDATE",
    )
    .bind(room_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.map(|row| RoomAuthority {
        room_epoch: row.get("room_epoch"),
        config_version: row.get("config_version"),
        configuration_state: row.get("configuration_state"),
        configuration_owner_jid: row.get("configuration_owner_jid"),
        configuration_expired: row.get("configuration_expired"),
        destroyed: row.get("destroyed"),
        members_only: row.get("members_only"),
        moderated: row.get("moderated"),
        non_anonymous: row.get("non_anonymous"),
        allow_registration: row.get("allow_registration"),
        allow_invites: row.get("allow_invites"),
        allow_subject_change: row.get("allow_subject_change"),
        max_occupants: row.get("max_occupants"),
    }))
}

pub(super) async fn expire_due_in_room(
    tx: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
) -> Result<u64> {
    let room = sqlx::query(
        "SELECT room_epoch,config_version FROM muc_rooms
          WHERE id=$1 AND destroyed_at IS NULL",
    )
    .bind(room_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(room) = room else {
        return Ok(0);
    };
    let room_epoch: Uuid = room.get("room_epoch");
    let config_version: i64 = room.get("config_version");
    let rows = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND state IN ('active','suspended')
            AND lease_until<=clock_timestamp()
          ORDER BY lease_until,occupancy_epoch
          FOR UPDATE LIMIT 1000",
    )
    .bind(room_id)
    .fetch_all(&mut **tx)
    .await?;
    if rows.is_empty() {
        return Ok(0);
    }
    // All already-expired leases are excluded by active_audience. Each
    // observer receives every departure with its own stable event ID.
    let audience = active_audience(tx, room_id).await?;
    let mut expired = 0_u64;
    for row in rows {
        let occupancy = occupancy_from_row(&row);
        let target = ClusterMucOccupancyTarget::from(&occupancy);
        let operation_id = Uuid::new_v4();
        let digest = request_digest(&json!({
            "target":&target,"lease_until":occupancy.lease_until,
            "transition":"expire","clock":"postgresql",
        }))?;
        let (_unused, event_sequence) = allocate_room_epochs(tx, room_id, false).await?;
        let changed = sqlx::query(
            "UPDATE cluster_muc_occupancies
                SET state='expired',role='none',ended_at=clock_timestamp(),
                    lease_until=clock_timestamp(),updated_at=clock_timestamp()
              WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3
                AND connection_uuid=$4 AND connection_epoch=$5
                AND state IN ('active','suspended') AND lease_until<=clock_timestamp()",
        )
        .bind(room_id)
        .bind(occupancy.occupant_incarnation)
        .bind(occupancy.occupancy_epoch)
        .bind(occupancy.connection_uuid)
        .bind(occupancy.connection_epoch)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        anyhow::ensure!(
            changed == 1,
            "expired MUC lease changed under its room lock"
        );
        let authorization = json!({
            "source":"lease_expiry","clock":"postgresql",
            "lease_until":occupancy.lease_until,
        });
        let details = json!({"state":"expired","status":332});
        insert_operation_and_outbox(
            tx,
            OperationRecord {
                operation_id,
                room_id,
                room_epoch,
                kind: "expire",
                digest: &digest,
                actor_bare_jid: None,
                actor_full_jid: None,
                actor_affiliation: None,
                authorization_source: "system",
                authorization_snapshot: &authorization,
                target: Some(&target),
                config_version_before: config_version,
                config_version_after: config_version,
                event_sequence,
                event_id: operation_id,
                audience: &audience,
                details: &details,
            },
        )
        .await?;
        expired += 1;
    }
    Ok(expired)
}

/// Bounded, multi-node-safe expiry sweep. The room row serializes this with
/// join/rename/moderation and every expired incarnation receives an immutable
/// operation/outbox event before the transaction commits.
pub async fn expire_cluster_muc_occupancies(pool: &PgPool, room_limit: i64) -> Result<u64> {
    let room_ids = sqlx::query_scalar::<_, Uuid>(
        "SELECT DISTINCT room_id FROM cluster_muc_occupancies
          WHERE state IN ('active','suspended') AND lease_until<=clock_timestamp()
          ORDER BY room_id LIMIT $1",
    )
    .bind(room_limit.clamp(1, 100))
    .fetch_all(pool)
    .await?;
    let mut expired = 0_u64;
    for room_id in room_ids {
        let mut tx = pool.begin().await?;
        if lock_room(&mut tx, room_id).await?.is_none() {
            tx.rollback().await?;
            continue;
        }
        expired = expired.saturating_add(expire_due_in_room(&mut tx, room_id).await?);
        tx.commit().await?;
    }
    Ok(expired)
}

async fn existing_operation(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    kind: &str,
    digest: &[u8],
) -> Result<Option<(Uuid, Uuid)>> {
    let row = sqlx::query(
        "SELECT room_id,event_id,operation_kind,request_digest
           FROM cluster_muc_operations WHERE operation_id=$1",
    )
    .bind(operation_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    anyhow::ensure!(
        row.get::<String, _>("operation_kind") == kind
            && row.get::<Vec<u8>, _>("request_digest") == digest,
        "MUC operation UUID was reused with a different kind or payload"
    );
    Ok(Some((row.get("room_id"), row.get("event_id"))))
}

async fn active_audience(
    tx: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
) -> Result<Vec<ClusterMucAudienceSnapshot>> {
    let rows = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND state IN ('active','suspended')
            AND lease_until > clock_timestamp()
          ORDER BY occupancy_epoch
          LIMIT $2",
    )
    .bind(room_id)
    .bind(i64::try_from(MAX_OPERATION_AUDIENCE + 1).unwrap_or(10_001))
    .fetch_all(&mut **tx)
    .await?;
    anyhow::ensure!(
        rows.len() <= MAX_OPERATION_AUDIENCE,
        "MUC immutable audience exceeds the configured operation bound"
    );
    Ok(rows
        .iter()
        .map(occupancy_from_row)
        .map(|occupancy| ClusterMucAudienceSnapshot::from(&occupancy))
        .collect())
}

struct OperationRecord<'a> {
    operation_id: Uuid,
    room_id: Uuid,
    room_epoch: Uuid,
    kind: &'a str,
    digest: &'a [u8],
    actor_bare_jid: Option<&'a str>,
    actor_full_jid: Option<&'a str>,
    actor_affiliation: Option<&'a str>,
    authorization_source: &'a str,
    authorization_snapshot: &'a Value,
    target: Option<&'a ClusterMucOccupancyTarget>,
    config_version_before: i64,
    config_version_after: i64,
    event_sequence: i64,
    event_id: Uuid,
    audience: &'a [ClusterMucAudienceSnapshot],
    details: &'a Value,
}

async fn insert_operation_and_outbox(
    tx: &mut Transaction<'_, Postgres>,
    record: OperationRecord<'_>,
) -> Result<()> {
    let audience_json = serde_json::to_value(record.audience)?;
    anyhow::ensure!(
        serde_json::to_vec(&audience_json)?.len() <= MAX_OPERATION_SNAPSHOT_BYTES,
        "MUC immutable audience snapshot is oversized"
    );
    anyhow::ensure!(
        serde_json::to_vec(record.authorization_snapshot)?.len() <= MAX_PAYLOAD_BYTES,
        "MUC authorization snapshot is oversized"
    );
    anyhow::ensure!(
        serde_json::to_vec(record.details)?.len() <= MAX_OPERATION_SNAPSHOT_BYTES,
        "MUC operation result snapshot is oversized"
    );
    let target = record.target;
    let target_snapshot = if let Some(target) = target {
        let row = sqlx::query(
            "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3",
        )
        .bind(target.room_id)
        .bind(target.occupant_incarnation)
        .bind(target.occupancy_epoch)
        .fetch_optional(&mut **tx)
        .await?;
        Some(serde_json::to_value(
            row.as_ref()
                .map(occupancy_from_row)
                .context("MUC operation target snapshot disappeared")?,
        )?)
    } else {
        None
    };
    sqlx::query(
        "INSERT INTO cluster_muc_operations(
             operation_id,room_id,room_epoch,operation_kind,request_digest,
             actor_bare_jid,actor_full_jid,actor_affiliation,authorization_source,
             actor_authorization_snapshot,target_occupant_incarnation,
             target_occupancy_epoch,target_full_jid,target_nick,
             target_connection_uuid,target_connection_epoch,target_snapshot,
             config_version_before,config_version_after,event_sequence,event_id,
             audience_snapshot,details)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                $17,$18,$19,$20,$21,$22,$23)",
    )
    .bind(record.operation_id)
    .bind(record.room_id)
    .bind(record.room_epoch)
    .bind(record.kind)
    .bind(record.digest)
    .bind(record.actor_bare_jid)
    .bind(record.actor_full_jid)
    .bind(record.actor_affiliation)
    .bind(record.authorization_source)
    .bind(record.authorization_snapshot)
    .bind(target.map(|value| value.occupant_incarnation))
    .bind(target.map(|value| value.occupancy_epoch))
    .bind(target.map(|value| value.full_jid.as_str()))
    .bind(target.map(|value| value.nick.as_str()))
    .bind(target.map(|value| value.connection_uuid))
    .bind(target.map(|value| value.connection_epoch))
    .bind(&target_snapshot)
    .bind(record.config_version_before)
    .bind(record.config_version_after)
    .bind(record.event_sequence)
    .bind(record.event_id)
    .bind(&audience_json)
    .bind(record.details)
    .execute(&mut **tx)
    .await?;

    // Keep the per-delivery payload O(1). The immutable authorization,
    // target and audience/result snapshots live once in the operation row
    // and are re-read by the worker. Copying an O(room-size) policy snapshot
    // into every audience row would create O(N^2) PostgreSQL storage.
    let immutable = json!({
        "schema": "northstar.cluster-muc-event.v1",
        "operation_id": record.operation_id,
        "room_id": record.room_id,
        "room_epoch": record.room_epoch,
        "kind": record.kind,
        "event_id": record.event_id,
        "event_sequence": record.event_sequence,
    });
    let payload = serde_json::to_string(&immutable)?;
    anyhow::ensure!(
        payload.len() <= MAX_PAYLOAD_BYTES,
        "MUC outbox payload is oversized"
    );
    let digest = payload_digest(&payload);
    let mut deliveries = record
        .audience
        .iter()
        .map(|recipient| {
            let delivery_id = Uuid::new_v4();
            (capacity_shard(delivery_id), delivery_id, recipient)
        })
        .collect::<Vec<_>>();
    // Capacity rows are acquired in a total shard/UUID order in every MUC
    // mutation transaction.  Dead-letter moves acquire the outbox row first,
    // then the same capacity shard, then the dead-letter shard.
    deliveries.sort_by_key(|(shard, delivery_id, _)| (*shard, *delivery_id));
    for (shard, delivery_id, recipient) in deliveries {
        sqlx::query(
            "INSERT INTO cluster_muc_event_outbox(
                 delivery_id,operation_id,room_id,room_epoch,event_sequence,event_id,
                 audience_kind,target_node_id,recipient_full_jid,recipient_nick,
                 recipient_occupant_incarnation,recipient_occupancy_epoch,
                 recipient_connection_uuid,recipient_connection_epoch,payload,payload_digest,
                 capacity_shard)
             VALUES($1,$2,$3,$4,$5,$6,'occupant',$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        )
        .bind(delivery_id)
        .bind(record.operation_id)
        .bind(record.room_id)
        .bind(record.room_epoch)
        .bind(record.event_sequence)
        .bind(record.event_id)
        .bind(&recipient.owner_node_id)
        .bind(&recipient.full_jid)
        .bind(&recipient.nick)
        .bind(recipient.occupant_incarnation)
        .bind(recipient.occupancy_epoch)
        .bind(recipient.connection_uuid)
        .bind(recipient.connection_epoch)
        .bind(&payload)
        .bind(&digest)
        .bind(shard)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn allocate_room_epochs(
    tx: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    occupancy: bool,
) -> Result<(Option<i64>, i64)> {
    let row = sqlx::query(
        "UPDATE muc_rooms SET
             next_occupancy_epoch=next_occupancy_epoch + CASE WHEN $2 THEN 1 ELSE 0 END,
             next_event_sequence=next_event_sequence+1
          WHERE id=$1 AND destroyed_at IS NULL
          RETURNING CASE WHEN $2 THEN next_occupancy_epoch-1 ELSE NULL END AS occupancy_epoch,
                    next_event_sequence-1 AS event_sequence",
    )
    .bind(room_id)
    .bind(occupancy)
    .fetch_one(&mut **tx)
    .await?;
    Ok((row.get("occupancy_epoch"), row.get("event_sequence")))
}

async fn affiliation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    principal: &ClusterMucPrincipal,
) -> Result<Option<String>> {
    match principal {
        ClusterMucPrincipal::Local { user_id, .. } => sqlx::query_scalar(
            "SELECT affiliation FROM muc_affiliations
              WHERE room_id=$1 AND user_id=$2 FOR SHARE",
        )
        .bind(room_id)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(Into::into),
        ClusterMucPrincipal::Federated { bare_jid, .. } => sqlx::query_scalar(
            "SELECT affiliation FROM muc_external_affiliations
              WHERE room_id=$1 AND jid=$2 FOR SHARE",
        )
        .bind(room_id)
        .bind(bare_jid)
        .fetch_optional(&mut **tx)
        .await
        .map_err(Into::into),
    }
}

/// Atomically authorizes and claims one nickname/full-JID occupancy.
pub async fn claim_cluster_muc_occupancy(
    pool: &PgPool,
    request: ClusterMucJoin<'_>,
) -> Result<ClusterMucJoinOutcome> {
    request.principal.validate()?;
    validate_node_id(request.owner_node_id)?;
    validate_nick(request.nick)?;
    anyhow::ensure!(
        !request.connection_uuid.is_nil(),
        "MUC connection UUID is nil"
    );
    anyhow::ensure!(
        request.connection_epoch >= 1,
        "MUC connection epoch is invalid"
    );
    anyhow::ensure!(
        !request.occupant_incarnation.is_nil(),
        "MUC occupant incarnation is nil"
    );
    anyhow::ensure!(
        request.presence_payload.len() <= MAX_PAYLOAD_BYTES,
        "MUC presence payload is oversized"
    );
    let full_jid = crate::jid::canonicalize(request.full_jid)?;
    anyhow::ensure!(
        full_jid == request.full_jid,
        "MUC full JID must be canonical"
    );
    anyhow::ensure!(
        crate::jid::canonicalize_bare(&full_jid)? == request.principal.bare_jid(),
        "MUC full JID does not belong to the authorized principal"
    );
    let lease_seconds = validate_lease(request.lease)?;
    let digest = request_digest(&json!({
        "room_id": request.room_id,
        "room_epoch": request.expected_room_epoch,
        "config_version": request.expected_config_version,
        "principal": &request.principal,
        "full_jid": request.full_jid,
        "nick": request.nick,
        "node": request.owner_node_id,
        "connection_uuid": request.connection_uuid,
        "connection_epoch": request.connection_epoch,
        "occupant_incarnation": request.occupant_incarnation,
    }))?;

    let mut tx = pool.begin().await?;
    if let Some((room_id, _)) =
        existing_operation(&mut tx, request.operation_id, "join", &digest).await?
    {
        anyhow::ensure!(room_id == request.room_id, "MUC replay changed rooms");
        let row = sqlx::query(
            "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND occupant_incarnation=$2",
        )
        .bind(request.room_id)
        .bind(request.occupant_incarnation)
        .fetch_one(&mut *tx)
        .await?;
        let occupancy = occupancy_from_row(&row);
        tx.commit().await?;
        return Ok(ClusterMucJoinOutcome::Replay(occupancy));
    }
    let Some(room) = lock_room(&mut tx, request.room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::RoomMissing);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::RoomDestroyed);
    }
    if room.room_epoch != request.expected_room_epoch
        || room.config_version != request.expected_config_version
    {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::StaleRoom);
    }
    expire_due_in_room(&mut tx, request.room_id).await?;
    let affiliation = affiliation_in_tx(&mut tx, request.room_id, &request.principal).await?;
    if affiliation.as_deref() == Some("outcast") {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::Outcast);
    }
    if room.members_only && affiliation.is_none() {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::MembershipRequired);
    }
    if room.configuration_state != "active"
        && !(room.configuration_state == "locked"
            && !room.configuration_expired
            && room.configuration_owner_jid.as_deref() == Some(request.full_jid)
            && affiliation.as_deref() == Some("owner"))
    {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::RoomLocked);
    }
    let reserved_for_other: bool = match &request.principal {
        ClusterMucPrincipal::Local { user_id, .. } => {
            sqlx::query_scalar(
                "SELECT EXISTS(
                 SELECT 1 FROM muc_affiliations
                  WHERE room_id=$1 AND reserved_nick=$2 AND user_id<>$3
                 UNION ALL
                 SELECT 1 FROM muc_external_affiliations
                  WHERE room_id=$1 AND reserved_nick=$2)",
            )
            .bind(request.room_id)
            .bind(request.nick)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?
        }
        ClusterMucPrincipal::Federated { bare_jid, .. } => {
            sqlx::query_scalar(
                "SELECT EXISTS(
                 SELECT 1 FROM muc_affiliations
                  WHERE room_id=$1 AND reserved_nick=$2
                 UNION ALL
                 SELECT 1 FROM muc_external_affiliations
                  WHERE room_id=$1 AND reserved_nick=$2 AND jid<>$3)",
            )
            .bind(request.room_id)
            .bind(request.nick)
            .bind(bare_jid)
            .fetch_one(&mut *tx)
            .await?
        }
    };
    if reserved_for_other {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::ReservedNickname);
    }
    let nick_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM cluster_muc_occupancies
          WHERE room_id=$1 AND nick=$2 AND state IN ('active','suspended'))",
    )
    .bind(request.room_id)
    .bind(request.nick)
    .fetch_one(&mut *tx)
    .await?;
    if nick_exists {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::NicknameConflict);
    }
    let full_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM cluster_muc_occupancies
          WHERE room_id=$1 AND full_jid=$2 AND state IN ('active','suspended'))",
    )
    .bind(request.room_id)
    .bind(request.full_jid)
    .fetch_one(&mut *tx)
    .await?;
    if full_exists {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::FullJidConflict);
    }
    let privileged = matches!(affiliation.as_deref(), Some("owner" | "admin"));
    let capacity = i64::from(room.max_occupants) + if privileged { 10 } else { 0 };
    let occupants: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM cluster_muc_occupancies
          WHERE room_id=$1 AND state IN ('active','suspended')",
    )
    .bind(request.room_id)
    .fetch_one(&mut *tx)
    .await?;
    if occupants >= capacity {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::Full);
    }

    let (occupancy_epoch, event_sequence) =
        allocate_room_epochs(&mut tx, request.room_id, true).await?;
    let occupancy_epoch = occupancy_epoch.context("MUC occupancy epoch was not allocated")?;
    let affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
    let role = if matches!(affiliation.as_str(), "owner" | "admin") {
        "moderator"
    } else if room.moderated && affiliation == "none" {
        "visitor"
    } else {
        "participant"
    };
    let (identity_kind, local_user_id, authenticated_domain) = match &request.principal {
        ClusterMucPrincipal::Local { user_id, .. } => ("local", Some(*user_id), None),
        ClusterMucPrincipal::Federated {
            authenticated_domain,
            ..
        } => ("federated", None, Some(authenticated_domain.as_str())),
    };
    let row = sqlx::query(
        "INSERT INTO cluster_muc_occupancies(
             room_id,room_epoch,occupant_incarnation,occupancy_epoch,config_version,
             identity_kind,local_user_id,bare_jid,full_jid,nick,authenticated_domain,
             owner_node_id,connection_uuid,connection_epoch,sm_session_id,state,role,
             affiliation,presence_payload,lease_until)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
                'active',$16,$17,$18,clock_timestamp()+make_interval(secs=>$19))
         RETURNING *",
    )
    .bind(request.room_id)
    .bind(room.room_epoch)
    .bind(request.occupant_incarnation)
    .bind(occupancy_epoch)
    .bind(room.config_version)
    .bind(identity_kind)
    .bind(local_user_id)
    .bind(request.principal.bare_jid())
    .bind(request.full_jid)
    .bind(request.nick)
    .bind(authenticated_domain)
    .bind(request.owner_node_id)
    .bind(request.connection_uuid)
    .bind(request.connection_epoch)
    .bind(request.sm_session_id)
    .bind(role)
    .bind(&affiliation)
    .bind(request.presence_payload)
    .bind(lease_seconds as f64)
    .fetch_one(&mut *tx)
    .await?;
    let occupancy = occupancy_from_row(&row);
    let target = ClusterMucOccupancyTarget::from(&occupancy);
    let audience = active_audience(&mut tx, request.room_id).await?;
    let authorization = json!({
        "source": if matches!(&request.principal, ClusterMucPrincipal::Local { .. }) {
            "local_database"
        } else {
            "federated_verified"
        },
        "principal": &request.principal,
        "affiliation": affiliation,
        "room_epoch": room.room_epoch,
        "config_version": room.config_version,
    });
    let details = json!({"role": role, "created_occupancy": true});
    // The operation UUID is also the server-authoritative XEP-0359 event ID.
    // Synchronous protocol responses and any at-least-once outbox retry can
    // therefore share one identifier without another post-commit lookup.
    let event_id = request.operation_id;
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id: request.operation_id,
            room_id: request.room_id,
            room_epoch: room.room_epoch,
            kind: "join",
            digest: &digest,
            actor_bare_jid: Some(request.principal.bare_jid()),
            actor_full_jid: Some(request.full_jid),
            actor_affiliation: Some(&affiliation),
            authorization_source: if matches!(&request.principal, ClusterMucPrincipal::Local { .. })
            {
                "local_database"
            } else {
                "federated_verified"
            },
            authorization_snapshot: &authorization,
            target: Some(&target),
            config_version_before: room.config_version,
            config_version_after: room.config_version,
            event_sequence,
            event_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(ClusterMucJoinOutcome::Joined(occupancy))
}

/// Extend an exact live occupancy lease.  A stale node, reused nickname or
/// older connection epoch changes zero rows and therefore loses authority.
pub async fn renew_cluster_muc_occupancy(
    pool: &PgPool,
    target: &ClusterMucOccupancyTarget,
    owner_node_id: &str,
    lease: Duration,
) -> Result<bool> {
    validate_node_id(owner_node_id)?;
    let seconds = validate_lease(lease)?;
    Ok(sqlx::query(
        "UPDATE cluster_muc_occupancies
            SET lease_until=clock_timestamp()+make_interval(secs=>$10),
                updated_at=clock_timestamp()
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND owner_node_id=$9 AND state IN ('active','suspended')
            AND lease_until > clock_timestamp()",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .bind(owner_node_id)
    .bind(seconds as f64)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

/// Refresh bounded ordinary presence soft-state while extending the exact PG
/// lease. This is not an authorization mutation and therefore does not
/// allocate an operation/event sequence.
pub async fn refresh_cluster_muc_presence(
    pool: &PgPool,
    target: &ClusterMucOccupancyTarget,
    owner_node_id: &str,
    presence_payload: &str,
    lease: Duration,
) -> Result<bool> {
    validate_node_id(owner_node_id)?;
    anyhow::ensure!(
        presence_payload.len() <= MAX_PAYLOAD_BYTES,
        "MUC presence payload is oversized"
    );
    let seconds = validate_lease(lease)?;
    Ok(sqlx::query(
        "UPDATE cluster_muc_occupancies SET presence_payload=$10,
             lease_until=clock_timestamp()+make_interval(secs=>$11),updated_at=clock_timestamp()
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8 AND owner_node_id=$9
            AND state='active' AND lease_until>clock_timestamp()",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .bind(owner_node_id)
    .bind(presence_payload)
    .bind(seconds as f64)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn associate_cluster_muc_sm_session(
    pool: &PgPool,
    target: &ClusterMucOccupancyTarget,
    owner_node_id: &str,
    sm_session_id: Uuid,
) -> Result<bool> {
    validate_node_id(owner_node_id)?;
    Ok(sqlx::query(
        "UPDATE cluster_muc_occupancies SET sm_session_id=$10,updated_at=clock_timestamp()
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8 AND owner_node_id=$9
            AND state='active' AND lease_until>clock_timestamp()",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .bind(owner_node_id)
    .bind(sm_session_id)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn suspended_cluster_muc_occupancy(
    pool: &PgPool,
    room_id: Uuid,
    room_epoch: Uuid,
    sm_session_id: Uuid,
    full_jid: &str,
    nick: &str,
) -> Result<Option<ClusterMucOccupancy>> {
    let full_jid = crate::jid::canonicalize(full_jid)?;
    validate_nick(nick)?;
    let row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND sm_session_id=$3
            AND full_jid=$4 AND nick=$5 AND state='suspended'
            AND lease_until>clock_timestamp()",
    )
    .bind(room_id)
    .bind(room_epoch)
    .bind(sm_session_id)
    .bind(full_jid)
    .bind(nick)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| occupancy_from_row(&row)))
}

#[derive(Serialize)]
struct SelfTransitionDigest<'a> {
    room_id: Uuid,
    room_epoch: Uuid,
    occupant_incarnation: Uuid,
    occupancy_epoch: i64,
    full_jid: &'a str,
    nick: &'a str,
    connection_uuid: Uuid,
    connection_epoch: i64,
    transition: &'a str,
    new_connection_uuid: Option<Uuid>,
    new_connection_epoch: Option<i64>,
    sm_session_id: Option<Uuid>,
}

/// Suspend, resume or leave one exact occupant.  Resume preserves the stable
/// occupant incarnation while advancing the connection epoch.
#[allow(clippy::too_many_arguments)]
pub async fn transition_cluster_muc_occupancy(
    pool: &PgPool,
    operation_id: Uuid,
    target: &ClusterMucOccupancyTarget,
    transition: &str,
    owner_node_id: &str,
    new_connection_uuid: Option<Uuid>,
    new_connection_epoch: Option<i64>,
    sm_session_id: Option<Uuid>,
    lease: Duration,
) -> Result<ClusterMucTransitionOutcome> {
    anyhow::ensure!(
        matches!(transition, "suspend" | "resume" | "leave"),
        "unsupported MUC self transition"
    );
    validate_node_id(owner_node_id)?;
    let lease_seconds = validate_lease(lease)?;
    if transition == "resume" {
        anyhow::ensure!(
            new_connection_uuid.is_some_and(|value| !value.is_nil())
                && new_connection_epoch.is_some_and(|value| value > target.connection_epoch)
                && sm_session_id.is_some(),
            "MUC resume requires a newer exact connection and SM session"
        );
    }
    let digest = request_digest(&SelfTransitionDigest {
        room_id: target.room_id,
        room_epoch: target.room_epoch,
        occupant_incarnation: target.occupant_incarnation,
        occupancy_epoch: target.occupancy_epoch,
        full_jid: &target.full_jid,
        nick: &target.nick,
        connection_uuid: target.connection_uuid,
        connection_epoch: target.connection_epoch,
        transition,
        new_connection_uuid,
        new_connection_epoch,
        sm_session_id,
    })?;
    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, transition, &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(ClusterMucTransitionOutcome::Replay);
    }
    let Some(room) = lock_room(&mut tx, target.room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Destroyed);
    }
    if room.room_epoch != target.room_epoch {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    }
    let current = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND (owner_node_id=$9 OR $10='resume') AND state IN ('active','suspended')
          FOR UPDATE",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .bind(owner_node_id)
    .bind(transition)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(current) = current else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    let authorization_source = if current.get::<Option<Uuid>, _>("local_user_id").is_some() {
        "local_database"
    } else {
        "federated_verified"
    };
    let current = occupancy_from_row(&current);
    let expected_state = if transition == "resume" {
        "suspended"
    } else {
        "active"
    };
    if current.state != expected_state {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    }
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, target.room_id, false).await?;
    let new_state = match transition {
        "suspend" => "suspended",
        "resume" => "active",
        "leave" => "left",
        _ => unreachable!(),
    };
    sqlx::query(
        "UPDATE cluster_muc_occupancies SET
             state=$10,
             owner_node_id=CASE WHEN $15 THEN $9 ELSE owner_node_id END,
             connection_uuid=COALESCE($11,connection_uuid),
             connection_epoch=COALESCE($12,connection_epoch),
             sm_session_id=$13,
             lease_until=CASE WHEN $10='left' THEN clock_timestamp()
                              ELSE clock_timestamp()+make_interval(secs=>$14) END,
             ended_at=CASE WHEN $10='left' THEN clock_timestamp() ELSE NULL END,
             updated_at=clock_timestamp()
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND (owner_node_id=$9 OR $10='resume')",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .bind(owner_node_id)
    .bind(new_state)
    .bind(new_connection_uuid)
    .bind(new_connection_epoch)
    .bind(sm_session_id)
    .bind(lease_seconds as f64)
    .bind(transition == "resume")
    .execute(&mut *tx)
    .await?;
    if transition == "resume" {
        sqlx::query("SELECT northstar_transfer_cluster_muc_outbox($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(target.room_id)
            .bind(target.room_epoch)
            .bind(target.occupant_incarnation)
            .bind(target.connection_uuid)
            .bind(target.connection_epoch)
            .bind(new_connection_uuid.expect("resume UUID validated"))
            .bind(new_connection_epoch.expect("resume epoch validated"))
            .bind(owner_node_id)
            .execute(&mut *tx)
            .await?;
    }
    let audience = active_audience(&mut tx, target.room_id).await?;
    let authorization = json!({
        "source": "exact_occupancy",
        "owner_node_id": owner_node_id,
        "occupant_incarnation": target.occupant_incarnation,
        "occupancy_epoch": target.occupancy_epoch,
        "connection_uuid": target.connection_uuid,
        "connection_epoch": target.connection_epoch,
    });
    let details = json!({
        "state": new_state,
        "new_connection_uuid": new_connection_uuid,
        "new_connection_epoch": new_connection_epoch,
        "sm_session_id": sm_session_id,
    });
    let actor_bare_jid = crate::jid::canonicalize_bare(&target.full_jid)?;
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id: target.room_id,
            room_epoch: target.room_epoch,
            kind: transition,
            digest: &digest,
            actor_bare_jid: Some(&actor_bare_jid),
            actor_full_jid: Some(&target.full_jid),
            actor_affiliation: Some(&current.affiliation),
            authorization_source,
            authorization_snapshot: &authorization,
            target: Some(target),
            config_version_before: room.config_version,
            config_version_after: room.config_version,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(ClusterMucTransitionOutcome::Applied)
}

/// Rename only the exact current incarnation. A delayed mutation that names a
/// reused nickname cannot match the replacement occupancy UUID/epoch tuple.
pub async fn rename_cluster_muc_occupancy(
    pool: &PgPool,
    operation_id: Uuid,
    target: &ClusterMucOccupancyTarget,
    owner_node_id: &str,
    new_nick: &str,
) -> Result<ClusterMucTransitionOutcome> {
    validate_node_id(owner_node_id)?;
    validate_nick(new_nick)?;
    let digest = request_digest(&json!({
        "target": target,
        "owner_node_id": owner_node_id,
        "new_nick": new_nick,
    }))?;
    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, "rename", &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(ClusterMucTransitionOutcome::Replay);
    }
    let Some(room) = lock_room(&mut tx, target.room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Destroyed);
    }
    expire_due_in_room(&mut tx, target.room_id).await?;
    let current = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8 AND owner_node_id=$9
            AND state IN ('active','suspended') AND lease_until>clock_timestamp()
          FOR UPDATE",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .bind(owner_node_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(current) = current else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    let local_user_id: Option<Uuid> = current.get("local_user_id");
    let current = occupancy_from_row(&current);
    let conflict: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM cluster_muc_occupancies
          WHERE room_id=$1 AND nick=$2 AND occupant_incarnation<>$3
            AND state IN ('active','suspended'))",
    )
    .bind(target.room_id)
    .bind(new_nick)
    .bind(target.occupant_incarnation)
    .fetch_one(&mut *tx)
    .await?;
    if conflict {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Conflict);
    }
    let reserved: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM muc_affiliations a
              WHERE a.room_id=$1 AND a.reserved_nick=$2
                AND ($3::uuid IS NULL OR a.user_id<>$3)
             UNION ALL
             SELECT 1 FROM muc_external_affiliations e
              WHERE e.room_id=$1 AND e.reserved_nick=$2 AND e.jid<>$4)",
    )
    .bind(target.room_id)
    .bind(new_nick)
    .bind(local_user_id)
    .bind(&current.bare_jid)
    .fetch_one(&mut *tx)
    .await?;
    if reserved {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Conflict);
    }
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, target.room_id, false).await?;
    sqlx::query(
        "UPDATE cluster_muc_occupancies SET nick=$10,updated_at=clock_timestamp()
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8 AND owner_node_id=$9",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .bind(owner_node_id)
    .bind(new_nick)
    .execute(&mut *tx)
    .await?;
    let audience = active_audience(&mut tx, target.room_id).await?;
    let authorization = json!({"source":"exact_occupancy","owner_node_id":owner_node_id});
    let details = json!({"old_nick":target.nick,"new_nick":new_nick});
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id: target.room_id,
            room_epoch: target.room_epoch,
            kind: "rename",
            digest: &digest,
            actor_bare_jid: Some(&current.bare_jid),
            actor_full_jid: Some(&current.full_jid),
            actor_affiliation: Some(&current.affiliation),
            authorization_source: if local_user_id.is_some() {
                "local_database"
            } else {
                "federated_verified"
            },
            authorization_snapshot: &authorization,
            target: Some(target),
            config_version_before: room.config_version,
            config_version_after: room.config_version,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(ClusterMucTransitionOutcome::Applied)
}

fn exact_target_matches_row(
    target: &ClusterMucOccupancyTarget,
    current: &ClusterMucOccupancy,
) -> bool {
    target.room_id == current.room_id
        && target.room_epoch == current.room_epoch
        && target.occupant_incarnation == current.occupant_incarnation
        && target.occupancy_epoch == current.occupancy_epoch
        && target.full_jid == current.full_jid
        && target.nick == current.nick
        && target.connection_uuid == current.connection_uuid
        && target.connection_epoch == current.connection_epoch
}

fn principal_matches_occupancy(
    principal: &ClusterMucPrincipal,
    current: &ClusterMucOccupancy,
) -> bool {
    match principal {
        ClusterMucPrincipal::Local { user_id, bare_jid } => {
            current.identity_kind == "local"
                && current.local_user_id == Some(*user_id)
                && current.authenticated_domain.is_none()
                && current.bare_jid == *bare_jid
        }
        ClusterMucPrincipal::Federated {
            bare_jid,
            authenticated_domain,
        } => {
            current.identity_kind == "federated"
                && current.local_user_id.is_none()
                && current.authenticated_domain.as_deref() == Some(authenticated_domain.as_str())
                && current.bare_jid == *bare_jid
        }
    }
}

async fn subject_affiliation_for_update(
    tx: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    subject: &ClusterMucAffiliationSubject,
) -> Result<Option<String>> {
    match subject {
        ClusterMucAffiliationSubject::Local { user_id, .. } => sqlx::query_scalar(
            "SELECT affiliation FROM muc_affiliations
              WHERE room_id=$1 AND user_id=$2 FOR UPDATE",
        )
        .bind(room_id)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(Into::into),
        ClusterMucAffiliationSubject::Federated { bare_jid } => sqlx::query_scalar(
            "SELECT affiliation FROM muc_external_affiliations
              WHERE room_id=$1 AND jid=$2 FOR UPDATE",
        )
        .bind(room_id)
        .bind(bare_jid)
        .fetch_optional(&mut **tx)
        .await
        .map_err(Into::into),
    }
}

async fn subject_occupancies_for_update(
    tx: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    subject: &ClusterMucAffiliationSubject,
) -> Result<Vec<ClusterMucOccupancy>> {
    let rows = match subject {
        ClusterMucAffiliationSubject::Local { user_id, .. } => {
            sqlx::query(
                "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND local_user_id=$2
                AND state IN ('active','suspended')
                AND lease_until>clock_timestamp() FOR UPDATE",
            )
            .bind(room_id)
            .bind(user_id)
            .fetch_all(&mut **tx)
            .await?
        }
        ClusterMucAffiliationSubject::Federated { bare_jid } => {
            sqlx::query(
                "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND identity_kind='federated' AND bare_jid=$2
                AND state IN ('active','suspended')
                AND lease_until>clock_timestamp() FOR UPDATE",
            )
            .bind(room_id)
            .bind(bare_jid)
            .fetch_all(&mut **tx)
            .await?
        }
    };
    Ok(rows.iter().map(occupancy_from_row).collect())
}

async fn update_subject_occupancies(
    tx: &mut Transaction<'_, Postgres>,
    room: &RoomAuthority,
    room_id: Uuid,
    subject: &ClusterMucAffiliationSubject,
    affiliation: &str,
) -> Result<()> {
    match subject {
        ClusterMucAffiliationSubject::Local { user_id, .. } => {
            sqlx::query(
                "UPDATE cluster_muc_occupancies SET affiliation=$3,
                 role=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN 'none'
                           WHEN $3 IN ('owner','admin') THEN 'moderator'
                           WHEN $4 AND $3='none' THEN 'visitor' ELSE 'participant' END,
                 state=CASE WHEN $3='outcast' OR ($5 AND $3='none')
                            THEN 'revoked' ELSE state END,
                 lease_until=CASE WHEN $3='outcast' OR ($5 AND $3='none')
                                  THEN clock_timestamp() ELSE lease_until END,
                 ended_at=CASE WHEN $3='outcast' OR ($5 AND $3='none')
                               THEN clock_timestamp() ELSE ended_at END,
                 updated_at=clock_timestamp()
                 WHERE room_id=$1 AND local_user_id=$2
                   AND state IN ('active','suspended')
                   AND lease_until>clock_timestamp()",
            )
            .bind(room_id)
            .bind(user_id)
            .bind(affiliation)
            .bind(room.moderated)
            .bind(room.members_only)
            .execute(&mut **tx)
            .await?;
        }
        ClusterMucAffiliationSubject::Federated { bare_jid } => {
            sqlx::query(
                "UPDATE cluster_muc_occupancies SET affiliation=$3,
                 role=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN 'none'
                           WHEN $3 IN ('owner','admin') THEN 'moderator'
                           WHEN $4 AND $3='none' THEN 'visitor' ELSE 'participant' END,
                 state=CASE WHEN $3='outcast' OR ($5 AND $3='none')
                            THEN 'revoked' ELSE state END,
                 lease_until=CASE WHEN $3='outcast' OR ($5 AND $3='none')
                                  THEN clock_timestamp() ELSE lease_until END,
                 ended_at=CASE WHEN $3='outcast' OR ($5 AND $3='none')
                               THEN clock_timestamp() ELSE ended_at END,
                 updated_at=clock_timestamp()
                 WHERE room_id=$1 AND identity_kind='federated' AND bare_jid=$2
                   AND state IN ('active','suspended')
                   AND lease_until>clock_timestamp()",
            )
            .bind(room_id)
            .bind(bare_jid)
            .bind(affiliation)
            .bind(room.moderated)
            .bind(room.members_only)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn mutate_cluster_muc_affiliation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    expected_config_version: i64,
    actor: &ClusterMucPrincipal,
    actor_full_jid: &str,
    actor_target: Option<&ClusterMucOccupancyTarget>,
    subject: &ClusterMucAffiliationSubject,
    mutation: ClusterMucAffiliationMutation<'_>,
    reason: Option<&str>,
) -> Result<ClusterMucAffiliationMutationOutcome> {
    actor.validate()?;
    subject.validate()?;
    anyhow::ensure!(
        reason.is_none_or(|value| value.len() <= 4096),
        "invite reason is oversized"
    );
    let actor_full_jid = crate::jid::canonicalize(actor_full_jid)?;
    anyhow::ensure!(
        crate::jid::canonicalize_bare(&actor_full_jid)? == actor.bare_jid(),
        "MUC affiliation actor does not own the authenticated full JID"
    );
    let (action, reserved_nick) = match mutation {
        ClusterMucAffiliationMutation::SelfRegister { reserved_nick } => {
            validate_nick(reserved_nick)?;
            ("self_register", Some(reserved_nick))
        }
        ClusterMucAffiliationMutation::SelfUnregister => ("self_unregister", None),
        ClusterMucAffiliationMutation::Invitation => ("invitation", None),
    };
    let digest = request_digest(&json!({
        "room_id":room_id,"room_epoch":expected_room_epoch,
        "config_version":expected_config_version,"action":action,
        "actor":actor,"actor_full_jid":actor_full_jid,"actor_target":actor_target,
        "subject":subject,"reserved_nick":reserved_nick,"reason":reason,
    }))?;
    if existing_operation(tx, operation_id, "affiliation", &digest)
        .await?
        .is_some()
    {
        let changed = sqlx::query_scalar::<_, bool>(
            "SELECT COALESCE((details->>'affiliation_changed')::BOOLEAN,FALSE)
               FROM cluster_muc_operations WHERE operation_id=$1",
        )
        .bind(operation_id)
        .fetch_one(&mut **tx)
        .await?;
        return Ok(ClusterMucAffiliationMutationOutcome::Replay {
            affiliation_changed: changed,
        });
    }
    let Some(room) = lock_room(tx, room_id).await? else {
        return Ok(ClusterMucAffiliationMutationOutcome::Stale);
    };
    if room.destroyed {
        return Ok(ClusterMucAffiliationMutationOutcome::Destroyed);
    }
    if room.room_epoch != expected_room_epoch || room.config_version != expected_config_version {
        return Ok(ClusterMucAffiliationMutationOutcome::Stale);
    }
    expire_due_in_room(tx, room_id).await?;

    let self_service = !matches!(mutation, ClusterMucAffiliationMutation::Invitation);
    let actor_affiliation;
    let actor_role;
    if self_service {
        if !room.allow_registration || actor_target.is_some() || !subject.matches_principal(actor) {
            return Ok(ClusterMucAffiliationMutationOutcome::NotAllowed);
        }
        actor_affiliation = affiliation_in_tx(tx, room_id, actor)
            .await?
            .unwrap_or_else(|| "none".to_owned());
        actor_role = None;
    } else {
        actor_affiliation = affiliation_in_tx(tx, room_id, actor)
            .await?
            .unwrap_or_else(|| "none".to_owned());
        if let Some(actor_target) = actor_target {
            if actor_target.room_id != room_id || actor_target.room_epoch != room.room_epoch {
                return Ok(ClusterMucAffiliationMutationOutcome::Stale);
            }
            let row = sqlx::query(
                "SELECT * FROM cluster_muc_occupancies
                  WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
                    AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
                    AND connection_uuid=$7 AND connection_epoch=$8
                    AND state='active' AND lease_until>clock_timestamp() FOR UPDATE",
            )
            .bind(actor_target.room_id)
            .bind(actor_target.room_epoch)
            .bind(actor_target.occupant_incarnation)
            .bind(actor_target.occupancy_epoch)
            .bind(&actor_target.full_jid)
            .bind(&actor_target.nick)
            .bind(actor_target.connection_uuid)
            .bind(actor_target.connection_epoch)
            .fetch_optional(&mut **tx)
            .await?;
            let Some(row) = row else {
                return Ok(ClusterMucAffiliationMutationOutcome::Unauthorized);
            };
            let snapshot = occupancy_from_row(&row);
            if !exact_target_matches_row(actor_target, &snapshot)
                || snapshot.full_jid != actor_full_jid
                || !principal_matches_occupancy(actor, &snapshot)
            {
                return Ok(ClusterMucAffiliationMutationOutcome::Unauthorized);
            }
            actor_role = Some(snapshot.role);
        } else {
            // Only a locally authenticated account may authorize a direct
            // invitation without an in-room occupancy. Remote ownership must
            // remain tied to an authenticated S2S occupancy incarnation.
            if !matches!(actor, ClusterMucPrincipal::Local { .. }) {
                return Ok(ClusterMucAffiliationMutationOutcome::Unauthorized);
            }
            actor_role = None;
        }
        let privileged = matches!(actor_affiliation.as_str(), "owner" | "admin");
        let permitted_member = room.allow_invites
            && actor_role.as_deref().map_or_else(
                || matches!(actor_affiliation.as_str(), "member" | "owner" | "admin"),
                |role| role != "visitor",
            );
        if !privileged && !permitted_member {
            return Ok(ClusterMucAffiliationMutationOutcome::Unauthorized);
        }
    }

    let previous = subject_affiliation_for_update(tx, room_id, subject).await?;
    if matches!(
        mutation,
        ClusterMucAffiliationMutation::SelfRegister { .. }
            | ClusterMucAffiliationMutation::Invitation
    ) && previous.as_deref() == Some("outcast")
    {
        return Ok(ClusterMucAffiliationMutationOutcome::Outcast);
    }
    if let Some(nick) = reserved_nick {
        let conflict = match subject {
            ClusterMucAffiliationSubject::Local { user_id, .. } => {
                sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(
                    SELECT 1 FROM muc_affiliations
                     WHERE room_id=$1 AND reserved_nick=$2 AND user_id<>$3
                    UNION ALL
                    SELECT 1 FROM muc_external_affiliations
                     WHERE room_id=$1 AND reserved_nick=$2
                    UNION ALL
                    SELECT 1 FROM cluster_muc_occupancies
                     WHERE room_id=$1 AND nick=$2 AND bare_jid<>$4
                       AND state IN ('active','suspended')
                       AND lease_until>clock_timestamp())",
                )
                .bind(room_id)
                .bind(nick)
                .bind(user_id)
                .bind(subject.bare_jid())
                .fetch_one(&mut **tx)
                .await?
            }
            ClusterMucAffiliationSubject::Federated { bare_jid } => {
                sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(
                    SELECT 1 FROM muc_affiliations WHERE room_id=$1 AND reserved_nick=$2
                    UNION ALL
                    SELECT 1 FROM muc_external_affiliations
                     WHERE room_id=$1 AND reserved_nick=$2 AND jid<>$3
                    UNION ALL
                    SELECT 1 FROM cluster_muc_occupancies
                     WHERE room_id=$1 AND nick=$2 AND bare_jid<>$3
                       AND state IN ('active','suspended')
                       AND lease_until>clock_timestamp())",
                )
                .bind(room_id)
                .bind(nick)
                .bind(bare_jid)
                .fetch_one(&mut **tx)
                .await?
            }
        };
        if conflict {
            return Ok(ClusterMucAffiliationMutationOutcome::Conflict);
        }
    }

    let previous_affiliation = previous.as_deref().unwrap_or("none");
    let resulting_affiliation = match mutation {
        ClusterMucAffiliationMutation::SelfRegister { .. } => {
            if matches!(previous_affiliation, "owner" | "admin") {
                previous_affiliation
            } else {
                "member"
            }
        }
        ClusterMucAffiliationMutation::SelfUnregister => {
            if matches!(previous_affiliation, "owner" | "admin" | "outcast") {
                previous_affiliation
            } else {
                "none"
            }
        }
        ClusterMucAffiliationMutation::Invitation => {
            if previous.is_none() {
                "member"
            } else {
                previous_affiliation
            }
        }
    };
    let affiliation_changed = previous_affiliation != resulting_affiliation;
    let audience = active_audience(tx, room_id).await?;
    let targets = if affiliation_changed {
        subject_occupancies_for_update(tx, room_id, subject).await?
    } else {
        Vec::new()
    };
    match (subject, &mutation) {
        (
            ClusterMucAffiliationSubject::Local { user_id, .. },
            ClusterMucAffiliationMutation::SelfRegister { reserved_nick },
        ) => {
            sqlx::query(
                "INSERT INTO muc_affiliations(room_id,user_id,affiliation,reserved_nick,updated_at)
                 VALUES($1,$2,'member',$3,clock_timestamp())
                 ON CONFLICT(room_id,user_id) DO UPDATE SET
                   affiliation=CASE WHEN muc_affiliations.affiliation IN ('owner','admin')
                                    THEN muc_affiliations.affiliation ELSE 'member' END,
                   reserved_nick=EXCLUDED.reserved_nick,updated_at=clock_timestamp()",
            )
            .bind(room_id)
            .bind(user_id)
            .bind(reserved_nick)
            .execute(&mut **tx)
            .await?;
        }
        (
            ClusterMucAffiliationSubject::Federated { bare_jid },
            ClusterMucAffiliationMutation::SelfRegister { reserved_nick },
        ) => {
            sqlx::query(
                "INSERT INTO muc_external_affiliations(room_id,jid,affiliation,reserved_nick,updated_at)
                 VALUES($1,$2,'member',$3,clock_timestamp())
                 ON CONFLICT(room_id,jid) DO UPDATE SET
                   affiliation=CASE WHEN muc_external_affiliations.affiliation IN ('owner','admin')
                                    THEN muc_external_affiliations.affiliation ELSE 'member' END,
                   reserved_nick=EXCLUDED.reserved_nick,updated_at=clock_timestamp()",
            ).bind(room_id).bind(bare_jid).bind(reserved_nick).execute(&mut **tx).await?;
        }
        (
            ClusterMucAffiliationSubject::Local { user_id, .. },
            ClusterMucAffiliationMutation::SelfUnregister,
        ) => {
            if matches!(previous_affiliation, "owner" | "admin" | "outcast") {
                sqlx::query("UPDATE muc_affiliations SET reserved_nick=NULL,updated_at=clock_timestamp() WHERE room_id=$1 AND user_id=$2")
                    .bind(room_id).bind(user_id).execute(&mut **tx).await?;
            } else {
                sqlx::query("DELETE FROM muc_affiliations WHERE room_id=$1 AND user_id=$2")
                    .bind(room_id)
                    .bind(user_id)
                    .execute(&mut **tx)
                    .await?;
            }
        }
        (
            ClusterMucAffiliationSubject::Federated { bare_jid },
            ClusterMucAffiliationMutation::SelfUnregister,
        ) => {
            if matches!(previous_affiliation, "owner" | "admin" | "outcast") {
                sqlx::query("UPDATE muc_external_affiliations SET reserved_nick=NULL,updated_at=clock_timestamp() WHERE room_id=$1 AND jid=$2")
                    .bind(room_id).bind(bare_jid).execute(&mut **tx).await?;
            } else {
                sqlx::query("DELETE FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2")
                    .bind(room_id)
                    .bind(bare_jid)
                    .execute(&mut **tx)
                    .await?;
            }
        }
        (
            ClusterMucAffiliationSubject::Local { user_id, .. },
            ClusterMucAffiliationMutation::Invitation,
        ) => {
            sqlx::query("INSERT INTO muc_affiliations(room_id,user_id,affiliation,updated_at) VALUES($1,$2,'member',clock_timestamp()) ON CONFLICT(room_id,user_id) DO NOTHING")
                .bind(room_id).bind(user_id).execute(&mut **tx).await?;
        }
        (
            ClusterMucAffiliationSubject::Federated { bare_jid },
            ClusterMucAffiliationMutation::Invitation,
        ) => {
            sqlx::query("INSERT INTO muc_external_affiliations(room_id,jid,affiliation,updated_at) VALUES($1,$2,'member',clock_timestamp()) ON CONFLICT(room_id,jid) DO NOTHING")
                .bind(room_id).bind(bare_jid).execute(&mut **tx).await?;
        }
    }
    if affiliation_changed {
        update_subject_occupancies(tx, &room, room_id, subject, resulting_affiliation).await?;
    }
    let mut changes = Vec::with_capacity(targets.len());
    for target in targets {
        let target_identity = ClusterMucOccupancyTarget::from(&target);
        let row = sqlx::query(
            "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3",
        )
        .bind(room_id)
        .bind(target.occupant_incarnation)
        .bind(target.occupancy_epoch)
        .fetch_one(&mut **tx)
        .await?;
        changes.push(json!({
            "target":target_identity,"previous_affiliation":previous_affiliation,
            "affiliation":resulting_affiliation,"status":321,
            "snapshot":ClusterMucPolicySnapshot::from(&occupancy_from_row(&row)),
        }));
    }
    let offline_affiliation = (affiliation_changed && room.non_anonymous && changes.is_empty())
        .then(|| {
            json!({
                "bare_jid":subject.bare_jid(),"affiliation":resulting_affiliation,
                "nick":reserved_nick,"reason":reason,
            })
        });
    let (_unused, event_sequence) = allocate_room_epochs(tx, room_id, false).await?;
    let authorization = json!({
        "action":action,"actor":actor,"actor_full_jid":actor_full_jid,
        "actor_target":actor_target,"durable_actor_affiliation":actor_affiliation,
        "actor_role":actor_role,"subject":subject,
        "room_epoch":room.room_epoch,"config_version":room.config_version,
        "allow_registration":room.allow_registration,"allow_invites":room.allow_invites,
    });
    let details = json!({
        "changes":changes,"offline_affiliation":offline_affiliation,
        "affiliation_changed":affiliation_changed,"action":action,
    });
    insert_operation_and_outbox(
        tx,
        OperationRecord {
            operation_id,
            room_id,
            room_epoch: room.room_epoch,
            kind: "affiliation",
            digest: &digest,
            actor_bare_jid: Some(actor.bare_jid()),
            actor_full_jid: Some(&actor_full_jid),
            actor_affiliation: Some(&actor_affiliation),
            authorization_source: match actor {
                ClusterMucPrincipal::Local { .. } => "local_database",
                ClusterMucPrincipal::Federated { .. } => "federated_verified",
            },
            authorization_snapshot: &authorization,
            target: None,
            config_version_before: room.config_version,
            config_version_after: room.config_version,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    Ok(ClusterMucAffiliationMutationOutcome::Applied {
        affiliation_changed,
    })
}

/// XEP-0045 self registration/unregistration is a PostgreSQL-authoritative
/// affiliation operation in cluster mode. Nick reservation, membership,
/// exact live occupancy updates and the immutable notification audience are
/// committed together.
#[allow(clippy::too_many_arguments)]
pub async fn mutate_cluster_muc_registration(
    pool: &PgPool,
    operation_id: Uuid,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    expected_config_version: i64,
    principal: &ClusterMucPrincipal,
    actor_full_jid: &str,
    reserved_nick: Option<&str>,
) -> Result<ClusterMucRegistrationOutcome> {
    let subject = match principal {
        ClusterMucPrincipal::Local { user_id, bare_jid } => ClusterMucAffiliationSubject::Local {
            user_id: *user_id,
            bare_jid: bare_jid.clone(),
        },
        ClusterMucPrincipal::Federated { bare_jid, .. } => {
            ClusterMucAffiliationSubject::Federated {
                bare_jid: bare_jid.clone(),
            }
        }
    };
    let mutation = reserved_nick.map_or(
        ClusterMucAffiliationMutation::SelfUnregister,
        |reserved_nick| ClusterMucAffiliationMutation::SelfRegister { reserved_nick },
    );
    let mut tx = pool.begin().await?;
    let outcome = mutate_cluster_muc_affiliation_in_tx(
        &mut tx,
        operation_id,
        room_id,
        expected_room_epoch,
        expected_config_version,
        principal,
        actor_full_jid,
        None,
        &subject,
        mutation,
        None,
    )
    .await?;
    match outcome {
        ClusterMucAffiliationMutationOutcome::Applied {
            affiliation_changed,
        } => {
            tx.commit().await?;
            Ok(ClusterMucRegistrationOutcome::Applied {
                affiliation_changed,
            })
        }
        ClusterMucAffiliationMutationOutcome::Replay {
            affiliation_changed,
        } => {
            tx.commit().await?;
            Ok(ClusterMucRegistrationOutcome::Replay {
                affiliation_changed,
            })
        }
        other => {
            tx.rollback().await?;
            Ok(match other {
                ClusterMucAffiliationMutationOutcome::Conflict => {
                    ClusterMucRegistrationOutcome::Conflict
                }
                ClusterMucAffiliationMutationOutcome::Outcast => {
                    ClusterMucRegistrationOutcome::Outcast
                }
                ClusterMucAffiliationMutationOutcome::NotAllowed
                | ClusterMucAffiliationMutationOutcome::Unauthorized => {
                    ClusterMucRegistrationOutcome::NotAllowed
                }
                ClusterMucAffiliationMutationOutcome::Stale => ClusterMucRegistrationOutcome::Stale,
                ClusterMucAffiliationMutationOutcome::Destroyed => {
                    ClusterMucRegistrationOutcome::Destroyed
                }
                ClusterMucAffiliationMutationOutcome::Applied { .. }
                | ClusterMucAffiliationMutationOutcome::Replay { .. } => unreachable!(),
            })
        }
    }
}

/// Called by the existing durable invitation admissions while their
/// PostgreSQL transaction is still open. A later quota/outbox failure rolls
/// back the affiliation operation and every notification projection too.
pub(super) async fn grant_cluster_muc_invitation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    authority: &ClusterMucInviteAuthority,
) -> Result<ClusterMucAffiliationMutationOutcome> {
    mutate_cluster_muc_affiliation_in_tx(
        tx,
        authority.operation_id,
        room_id,
        authority.expected_room_epoch,
        authority.expected_config_version,
        &authority.actor,
        &authority.actor_full_jid,
        authority.actor_target.as_ref(),
        &authority.subject,
        ClusterMucAffiliationMutation::Invitation,
        authority.reason.as_deref(),
    )
    .await
}

/// Apply an authorization-relevant room configuration exactly once. The
/// durable owner affiliation, locked-room owner and expected room/config
/// epochs are all checked while holding the room row lock. No password hash
/// or room secret is copied into the immutable operation details.
#[allow(clippy::too_many_arguments)]
pub async fn update_cluster_muc_config(
    pool: &PgPool,
    operation_id: Uuid,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    expected_config_version: i64,
    actor_target: &ClusterMucOccupancyTarget,
    principal: &ClusterMucPrincipal,
    actor_full_jid: &str,
    config: super::muc::MucConfigUpdate<'_>,
) -> Result<ClusterMucConfigurationOutcome> {
    principal.validate()?;
    let actor_full_jid = crate::jid::canonicalize(actor_full_jid)?;
    anyhow::ensure!(
        crate::jid::canonicalize_bare(&actor_full_jid)? == principal.bare_jid(),
        "MUC configuration actor does not belong to the authorized principal"
    );
    let digest = request_digest(&json!({
        "room_id":room_id,
        "room_epoch":expected_room_epoch,
        "config_version":expected_config_version,
        "actor_target":actor_target,
        "principal":principal,
        "actor_full_jid":actor_full_jid,
        "title":config.title,
        "description":config.description,
        "persistent":config.persistent,
        "members_only":config.members_only,
        "public":config.public,
        "moderated":config.moderated,
        "non_anonymous":config.non_anonymous,
        "max_occupants":config.max_occupants,
        "password_protected":config.password_hash.is_some(),
        "password_verifier_digest":config.password_hash.map(payload_digest),
        "allow_subject_change":config.allow_subject_change,
        "allow_invites":config.allow_invites,
        "allow_private_messages":config.allow_private_messages,
        "logging_enabled":config.logging_enabled,
        "allow_registration":config.allow_registration,
    }))?;
    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, "config", &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(ClusterMucConfigurationOutcome::Replay);
    }
    let Some(room) = lock_room(&mut tx, room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucConfigurationOutcome::Missing);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(ClusterMucConfigurationOutcome::Destroyed);
    }
    if room.room_epoch != expected_room_epoch || room.config_version != expected_config_version {
        tx.rollback().await?;
        return Ok(ClusterMucConfigurationOutcome::Stale);
    }
    if actor_target.room_id != room_id || actor_target.room_epoch != room.room_epoch {
        tx.rollback().await?;
        return Ok(ClusterMucConfigurationOutcome::Stale);
    }
    let actor_row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND state='active' AND lease_until>clock_timestamp() FOR UPDATE",
    )
    .bind(actor_target.room_id)
    .bind(actor_target.room_epoch)
    .bind(actor_target.occupant_incarnation)
    .bind(actor_target.occupancy_epoch)
    .bind(&actor_target.full_jid)
    .bind(&actor_target.nick)
    .bind(actor_target.connection_uuid)
    .bind(actor_target.connection_epoch)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(actor_row) = actor_row else {
        tx.rollback().await?;
        return Ok(ClusterMucConfigurationOutcome::Unauthorized);
    };
    let actor_snapshot = occupancy_from_row(&actor_row);
    if !exact_target_matches_row(actor_target, &actor_snapshot)
        || actor_snapshot.full_jid != actor_full_jid
        || !principal_matches_occupancy(principal, &actor_snapshot)
    {
        tx.rollback().await?;
        return Ok(ClusterMucConfigurationOutcome::Unauthorized);
    }
    if affiliation_in_tx(&mut tx, room_id, principal)
        .await?
        .as_deref()
        != Some("owner")
    {
        tx.rollback().await?;
        return Ok(ClusterMucConfigurationOutcome::Unauthorized);
    }
    let configuration = sqlx::query(
        "SELECT configuration_state,configuration_owner_jid,
                configuration_expires_at<=clock_timestamp() AS expired
           FROM muc_rooms WHERE id=$1",
    )
    .bind(room_id)
    .fetch_one(&mut *tx)
    .await?;
    if configuration.get::<String, _>("configuration_state") == "locked" {
        if configuration.get::<bool, _>("expired") {
            tx.rollback().await?;
            return Ok(ClusterMucConfigurationOutcome::Expired);
        }
        if configuration
            .get::<Option<String>, _>("configuration_owner_jid")
            .as_deref()
            != Some(actor_full_jid.as_str())
        {
            tx.rollback().await?;
            return Ok(ClusterMucConfigurationOutcome::LockedByAnother);
        }
    }
    let audience = active_audience(&mut tx, room_id).await?;
    let updated_version: i64 = sqlx::query_scalar(
        "UPDATE muc_rooms SET
             title=$2,persistent=$3,members_only=$4,public=$5,moderated=$6,
             non_anonymous=$7,max_occupants=$8,password_hash=$9,description=$10,
             allow_subject_change=$11,allow_invites=$12,allow_private_messages=$13,
             logging_enabled=$14,allow_registration=$15,configuration_state='active',
             configuration_owner_jid=NULL,configuration_expires_at=NULL
          WHERE id=$1 AND room_epoch=$16 AND config_version=$17 AND destroyed_at IS NULL
          RETURNING config_version",
    )
    .bind(room_id)
    .bind(config.title)
    .bind(config.persistent)
    .bind(config.members_only)
    .bind(config.public)
    .bind(config.moderated)
    .bind(config.non_anonymous)
    .bind(config.max_occupants.clamp(2, 1000))
    .bind(config.password_hash)
    .bind(config.description)
    .bind(config.allow_subject_change)
    .bind(config.allow_invites)
    .bind(config.allow_private_messages)
    .bind(config.logging_enabled)
    .bind(config.allow_registration)
    .bind(expected_room_epoch)
    .bind(expected_config_version)
    .fetch_one(&mut *tx)
    .await?;
    anyhow::ensure!(
        updated_version == expected_config_version + 1,
        "MUC config version did not advance exactly once"
    );

    // Refresh role/affiliation snapshots from durable rows. Guests made
    // invalid by members-only are fenced immediately; the exact audience
    // snapshot still lets the committed operation notify their old routes.
    sqlx::query(
        "UPDATE cluster_muc_occupancies o SET
             config_version=$2,
             affiliation=COALESCE(a.affiliation,'none'),
             role=CASE WHEN COALESCE(a.affiliation,'none') IN ('owner','admin') THEN 'moderator'
                       WHEN $3 AND COALESCE(a.affiliation,'none')='none' THEN 'visitor'
                       ELSE 'participant' END,
             state=CASE WHEN $4 AND a.affiliation IS NULL THEN 'revoked' ELSE o.state END,
             lease_until=CASE WHEN $4 AND a.affiliation IS NULL THEN clock_timestamp()
                              ELSE o.lease_until END,
             ended_at=CASE WHEN $4 AND a.affiliation IS NULL THEN clock_timestamp()
                           ELSE o.ended_at END,
             updated_at=clock_timestamp()
          FROM (SELECT u.occupant_incarnation,m.affiliation
                  FROM cluster_muc_occupancies u
                  LEFT JOIN muc_affiliations m
                    ON m.room_id=u.room_id AND m.user_id=u.local_user_id
                 WHERE u.room_id=$1 AND u.identity_kind='local'
                   AND u.state IN ('active','suspended')) a
         WHERE o.room_id=$1 AND o.occupant_incarnation=a.occupant_incarnation",
    )
    .bind(room_id)
    .bind(updated_version)
    .bind(config.moderated)
    .bind(config.members_only)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE cluster_muc_occupancies o SET
             config_version=$2,
             affiliation=COALESCE(a.affiliation,'none'),
             role=CASE WHEN COALESCE(a.affiliation,'none') IN ('owner','admin') THEN 'moderator'
                       WHEN $3 AND COALESCE(a.affiliation,'none')='none' THEN 'visitor'
                       ELSE 'participant' END,
             state=CASE WHEN $4 AND a.affiliation IS NULL THEN 'revoked' ELSE o.state END,
             lease_until=CASE WHEN $4 AND a.affiliation IS NULL THEN clock_timestamp()
                              ELSE o.lease_until END,
             ended_at=CASE WHEN $4 AND a.affiliation IS NULL THEN clock_timestamp()
                           ELSE o.ended_at END,
             updated_at=clock_timestamp()
          FROM (SELECT u.occupant_incarnation,m.affiliation
                  FROM cluster_muc_occupancies u
                  LEFT JOIN muc_external_affiliations m
                    ON m.room_id=u.room_id AND m.jid=u.bare_jid
                 WHERE u.room_id=$1 AND u.identity_kind='federated'
                   AND u.state IN ('active','suspended')) a
         WHERE o.room_id=$1 AND o.occupant_incarnation=a.occupant_incarnation",
    )
    .bind(room_id)
    .bind(updated_version)
    .bind(config.moderated)
    .bind(config.members_only)
    .execute(&mut *tx)
    .await?;
    let mut affected = Vec::with_capacity(audience.len());
    for identity in &audience {
        let row = sqlx::query(
            "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3
                AND full_jid=$4 AND connection_uuid=$5 AND connection_epoch=$6",
        )
        .bind(room_id)
        .bind(identity.occupant_incarnation)
        .bind(identity.occupancy_epoch)
        .bind(&identity.full_jid)
        .bind(identity.connection_uuid)
        .bind(identity.connection_epoch)
        .fetch_one(&mut *tx)
        .await?;
        let snapshot = occupancy_from_row(&row);
        let target = ClusterMucOccupancyTarget::from(&snapshot);
        affected
            .push(json!({"target":target,"snapshot":ClusterMucPolicySnapshot::from(&snapshot)}));
    }
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, room_id, false).await?;
    let authorization = json!({
        "principal":principal,
        "actor_target":actor_target,
        "durable_affiliation":"owner",
        "expected_room_epoch":expected_room_epoch,
        "expected_config_version":expected_config_version,
    });
    let details = json!({
        "members_only":config.members_only,"moderated":config.moderated,
        "non_anonymous":config.non_anonymous,"max_occupants":config.max_occupants,
        "persistent":config.persistent,"public":config.public,
        "affected":affected,
    });
    anyhow::ensure!(
        serde_json::to_vec(&details)?.len() <= MAX_PAYLOAD_BYTES,
        "MUC configuration audience snapshot is oversized"
    );
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id,
            room_epoch: room.room_epoch,
            kind: "config",
            digest: &digest,
            actor_bare_jid: Some(principal.bare_jid()),
            actor_full_jid: Some(&actor_full_jid),
            actor_affiliation: Some("owner"),
            authorization_source: if matches!(principal, ClusterMucPrincipal::Local { .. }) {
                "local_database"
            } else {
                "federated_verified"
            },
            authorization_snapshot: &authorization,
            target: None,
            config_version_before: room.config_version,
            config_version_after: updated_version,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(ClusterMucConfigurationOutcome::Applied)
}

/// Commit a room subject under the same PostgreSQL room/occupancy fence as
/// other clustered control operations. Subject state, optional MAM row,
/// immutable audience and notification outbox are one transaction.
pub async fn set_cluster_muc_subject(
    pool: &PgPool,
    operation_id: Uuid,
    expected_room_epoch: Uuid,
    expected_config_version: i64,
    actor: &ClusterMucOccupancyTarget,
    mutation: super::muc::MucSubjectMutation<'_>,
    archive: bool,
) -> Result<ClusterMucTransitionOutcome> {
    anyhow::ensure!(
        mutation.room_id == actor.room_id,
        "cross-room subject mutation rejected"
    );
    anyhow::ensure!(
        mutation.subject.len() <= MAX_PAYLOAD_BYTES && mutation.stanza.len() <= MAX_PAYLOAD_BYTES,
        "MUC subject is oversized"
    );
    let actor_scope = crate::jid::canonicalize_bare(mutation.actor_scope)?;
    let sender_jid = crate::jid::canonicalize(mutation.sender_jid)?;
    let digest = request_digest(&json!({
        "actor":actor,"room_epoch":expected_room_epoch,
        "config_version":expected_config_version,"subject":mutation.subject,
        "stanza":mutation.stanza,"archive":archive,
    }))?;
    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, "subject", &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(ClusterMucTransitionOutcome::Replay);
    }
    let Some(room) = lock_room(&mut tx, mutation.room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Destroyed);
    }
    if room.room_epoch != expected_room_epoch || room.config_version != expected_config_version {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    }
    expire_due_in_room(&mut tx, mutation.room_id).await?;
    let actor_row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND state='active' AND lease_until>clock_timestamp() FOR UPDATE",
    )
    .bind(actor.room_id)
    .bind(actor.room_epoch)
    .bind(actor.occupant_incarnation)
    .bind(actor.occupancy_epoch)
    .bind(&actor.full_jid)
    .bind(&actor.nick)
    .bind(actor.connection_uuid)
    .bind(actor.connection_epoch)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(actor_row) = actor_row else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    };
    let actor_current = occupancy_from_row(&actor_row);
    if !exact_target_matches_row(actor, &actor_current)
        || actor_current.bare_jid != actor_scope
        || actor_current.full_jid != sender_jid
        || !(actor_current.role == "moderator"
            || (room.allow_subject_change && actor_current.role == "participant"))
    {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    }
    let audience = active_audience(&mut tx, mutation.room_id).await?;
    sqlx::query(
        "UPDATE muc_rooms SET subject=$2,subject_set_by=$3,subject_stanza_id=$4,
             subject_changed_at=clock_timestamp() WHERE id=$1 AND room_epoch=$5
             AND config_version=$6 AND destroyed_at IS NULL",
    )
    .bind(mutation.room_id)
    .bind(mutation.subject)
    .bind(&actor_scope)
    .bind(mutation.stanza_id)
    .bind(expected_room_epoch)
    .bind(expected_config_version)
    .execute(&mut *tx)
    .await?;
    if archive {
        sqlx::query(
            "INSERT INTO muc_messages(id,room_id,sender_jid,nick,stanza,encrypted,message_kind,actor_scope)
             VALUES($1,$2,$3,$4,$5,$6,'subject',$7)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(mutation.stanza_id).bind(mutation.room_id).bind(&sender_jid)
        .bind(mutation.nick).bind(mutation.stanza).bind(mutation.encrypted).bind(&actor_scope)
        .execute(&mut *tx).await?;
    }
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, mutation.room_id, false).await?;
    let authorization = json!({
        "actor":actor,"role":actor_current.role,"room_epoch":room.room_epoch,
        "config_version":room.config_version,"allow_subject_change":room.allow_subject_change,
    });
    let details = json!({"subject":mutation.subject,"stanza":mutation.stanza,"archived":archive});
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id: mutation.room_id,
            room_epoch: room.room_epoch,
            kind: "subject",
            digest: &digest,
            actor_bare_jid: Some(&actor_current.bare_jid),
            actor_full_jid: Some(&actor_current.full_jid),
            actor_affiliation: Some(&actor_current.affiliation),
            authorization_source: if actor_row.get::<Option<Uuid>, _>("local_user_id").is_some() {
                "local_database"
            } else {
                "federated_verified"
            },
            authorization_snapshot: &authorization,
            target: Some(actor),
            config_version_before: room.config_version,
            config_version_after: room.config_version,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(ClusterMucTransitionOutcome::Applied)
}

/// Apply one XEP-0045 admin affiliation IQ as a single PostgreSQL operation.
/// All targets are resolved and authorized before the first durable change;
/// live target incarnations are copied into immutable details so a delayed
/// ban/removal can never match a later occupant that reused the JID or nick.
pub struct ClusterMucAffiliationBatch<'a> {
    pub operation_id: Uuid,
    pub room_id: Uuid,
    pub expected_room_epoch: Uuid,
    pub expected_config_version: i64,
    pub actor_target: &'a ClusterMucOccupancyTarget,
    pub actor: &'a ClusterMucPrincipal,
    pub actor_full_jid: &'a str,
    pub changes: &'a [super::muc::MucAffiliationChange],
}

pub async fn apply_cluster_muc_affiliations_batch(
    pool: &PgPool,
    batch: ClusterMucAffiliationBatch<'_>,
) -> Result<super::muc::MucAffiliationBatchOutcome> {
    let ClusterMucAffiliationBatch {
        operation_id,
        room_id,
        expected_room_epoch,
        expected_config_version,
        actor_target,
        actor,
        actor_full_jid,
        changes,
    } = batch;
    actor.validate()?;
    let actor_full_jid = crate::jid::canonicalize(actor_full_jid)?;
    anyhow::ensure!(
        crate::jid::canonicalize_bare(&actor_full_jid)? == actor.bare_jid(),
        "MUC affiliation actor does not own the authenticated full JID"
    );
    if changes.is_empty() {
        return Ok(super::muc::MucAffiliationBatchOutcome::Applied);
    }

    #[derive(Serialize)]
    struct DigestChange<'a> {
        target_kind: &'a str,
        target: &'a str,
        affiliation: &'a str,
    }
    let digest_changes = changes
        .iter()
        .map(|change| match &change.target {
            super::muc::MucAffiliationTarget::LocalUsername(username) => DigestChange {
                target_kind: "local",
                target: username,
                affiliation: &change.affiliation,
            },
            super::muc::MucAffiliationTarget::FederatedBareJid(jid) => DigestChange {
                target_kind: "federated",
                target: jid,
                affiliation: &change.affiliation,
            },
        })
        .collect::<Vec<_>>();
    let digest = request_digest(&json!({
        "room_id":room_id,"room_epoch":expected_room_epoch,
        "config_version":expected_config_version,"actor_target":actor_target,"actor":actor,
        "actor_full_jid":actor_full_jid,"changes":digest_changes,
    }))?;

    enum ResolvedTarget {
        Local { user_id: Uuid },
        Federated { bare_jid: String },
    }
    struct ResolvedChange {
        target: ResolvedTarget,
        affiliation: String,
        previous: Option<String>,
    }

    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, "affiliation", &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(super::muc::MucAffiliationBatchOutcome::Applied);
    }
    let Some(room) = lock_room(&mut tx, room_id).await? else {
        tx.rollback().await?;
        return Ok(super::muc::MucAffiliationBatchOutcome::MissingTarget);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(super::muc::MucAffiliationBatchOutcome::Destroyed);
    }
    if room.room_epoch != expected_room_epoch || room.config_version != expected_config_version {
        tx.rollback().await?;
        return Ok(super::muc::MucAffiliationBatchOutcome::Stale);
    }
    if actor_target.room_id != room_id || actor_target.room_epoch != room.room_epoch {
        tx.rollback().await?;
        return Ok(super::muc::MucAffiliationBatchOutcome::Stale);
    }
    let actor_row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND state='active' AND lease_until>clock_timestamp() FOR UPDATE",
    )
    .bind(actor_target.room_id)
    .bind(actor_target.room_epoch)
    .bind(actor_target.occupant_incarnation)
    .bind(actor_target.occupancy_epoch)
    .bind(&actor_target.full_jid)
    .bind(&actor_target.nick)
    .bind(actor_target.connection_uuid)
    .bind(actor_target.connection_epoch)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(actor_row) = actor_row else {
        tx.rollback().await?;
        return Ok(super::muc::MucAffiliationBatchOutcome::Unauthorized);
    };
    let actor_snapshot = occupancy_from_row(&actor_row);
    if !exact_target_matches_row(actor_target, &actor_snapshot)
        || actor_snapshot.full_jid != actor_full_jid
        || !principal_matches_occupancy(actor, &actor_snapshot)
    {
        tx.rollback().await?;
        return Ok(super::muc::MucAffiliationBatchOutcome::Unauthorized);
    }
    let actor_affiliation = affiliation_in_tx(&mut tx, room_id, actor)
        .await?
        .unwrap_or_else(|| "none".to_owned());
    if !matches!(actor_affiliation.as_str(), "owner" | "admin") {
        tx.rollback().await?;
        return Ok(super::muc::MucAffiliationBatchOutcome::MissingTarget);
    }
    let mut seen = std::collections::HashSet::with_capacity(changes.len());
    let mut resolved = Vec::with_capacity(changes.len());
    let mut owner_delta = 0_i64;
    for change in changes {
        anyhow::ensure!(
            matches!(
                change.affiliation.as_str(),
                "owner" | "admin" | "member" | "outcast" | "none"
            ),
            "invalid clustered MUC affiliation"
        );
        let (key, target, previous) = match &change.target {
            super::muc::MucAffiliationTarget::LocalUsername(username) => {
                let Some(user_id) =
                    sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE username=$1")
                        .bind(username)
                        .fetch_optional(&mut *tx)
                        .await?
                else {
                    tx.rollback().await?;
                    return Ok(super::muc::MucAffiliationBatchOutcome::MissingTarget);
                };
                let previous = sqlx::query_scalar::<_, String>(
                    "SELECT affiliation FROM muc_affiliations
                      WHERE room_id=$1 AND user_id=$2 FOR UPDATE",
                )
                .bind(room_id)
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;
                (
                    format!("local:{user_id}"),
                    ResolvedTarget::Local { user_id },
                    previous,
                )
            }
            super::muc::MucAffiliationTarget::FederatedBareJid(jid) => {
                let jid = crate::jid::CanonicalJid::parse_bare(jid)?;
                anyhow::ensure!(
                    jid.localpart().is_some(),
                    "federated MUC target must be a user JID"
                );
                let jid = jid.to_string();
                let previous = sqlx::query_scalar::<_, String>(
                    "SELECT affiliation FROM muc_external_affiliations
                      WHERE room_id=$1 AND jid=$2 FOR UPDATE",
                )
                .bind(room_id)
                .bind(&jid)
                .fetch_optional(&mut *tx)
                .await?;
                (
                    format!("federated:{jid}"),
                    ResolvedTarget::Federated { bare_jid: jid },
                    previous,
                )
            }
        };
        if !seen.insert(key) {
            tx.rollback().await?;
            return Ok(super::muc::MucAffiliationBatchOutcome::DuplicateTarget);
        }
        if actor_affiliation == "admin"
            && (matches!(previous.as_deref(), Some("owner" | "admin"))
                || matches!(change.affiliation.as_str(), "owner" | "admin"))
        {
            tx.rollback().await?;
            return Ok(super::muc::MucAffiliationBatchOutcome::MissingTarget);
        }
        if previous.as_deref() == Some("owner") && change.affiliation != "owner" {
            owner_delta -= 1;
        } else if previous.as_deref() != Some("owner") && change.affiliation == "owner" {
            owner_delta += 1;
        }
        resolved.push(ResolvedChange {
            target,
            affiliation: change.affiliation.clone(),
            previous,
        });
    }
    let existing_owners: i64 = sqlx::query_scalar(
        "SELECT
             (SELECT COUNT(*) FROM muc_affiliations WHERE room_id=$1 AND affiliation='owner') +
             (SELECT COUNT(*) FROM muc_external_affiliations WHERE room_id=$1 AND affiliation='owner')",
    )
    .bind(room_id)
    .fetch_one(&mut *tx)
    .await?;
    if existing_owners + owner_delta < 1 {
        tx.rollback().await?;
        return Ok(super::muc::MucAffiliationBatchOutcome::LastOwner);
    }

    let audience = active_audience(&mut tx, room_id).await?;
    let mut affected = Vec::new();
    for change in &resolved {
        let rows = match &change.target {
            ResolvedTarget::Local { user_id, .. } => {
                sqlx::query(
                    "SELECT * FROM cluster_muc_occupancies
                  WHERE room_id=$1 AND local_user_id=$2
                    AND state IN ('active','suspended') FOR UPDATE",
                )
                .bind(room_id)
                .bind(user_id)
                .fetch_all(&mut *tx)
                .await?
            }
            ResolvedTarget::Federated { bare_jid } => {
                sqlx::query(
                    "SELECT * FROM cluster_muc_occupancies
                  WHERE room_id=$1 AND bare_jid=$2
                    AND state IN ('active','suspended') FOR UPDATE",
                )
                .bind(room_id)
                .bind(bare_jid)
                .fetch_all(&mut *tx)
                .await?
            }
        };
        for row in rows {
            let occupancy = occupancy_from_row(&row);
            affected.push(json!({
                "target":ClusterMucOccupancyTarget::from(&occupancy),
                "previous_affiliation":change.previous,
                "affiliation":change.affiliation,
                "status":if change.affiliation == "outcast" { 301 } else { 321 },
            }));
        }
        match &change.target {
            ResolvedTarget::Local { user_id, .. } => {
                if change.affiliation == "none" {
                    sqlx::query("DELETE FROM muc_affiliations WHERE room_id=$1 AND user_id=$2")
                        .bind(room_id)
                        .bind(user_id)
                        .execute(&mut *tx)
                        .await?;
                } else {
                    sqlx::query(
                        "INSERT INTO muc_affiliations(room_id,user_id,affiliation)
                         VALUES($1,$2,$3) ON CONFLICT(room_id,user_id) DO UPDATE
                         SET affiliation=EXCLUDED.affiliation",
                    )
                    .bind(room_id)
                    .bind(user_id)
                    .bind(&change.affiliation)
                    .execute(&mut *tx)
                    .await?;
                }
                sqlx::query(
                    "UPDATE cluster_muc_occupancies SET affiliation=$3,
             role=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN 'none'
                       WHEN $3 IN ('owner','admin') THEN 'moderator'
                                   WHEN $4 AND $3='none' THEN 'visitor' ELSE 'participant' END,
                         state=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN 'revoked' ELSE state END,
                         lease_until=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN clock_timestamp() ELSE lease_until END,
                         ended_at=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN clock_timestamp() ELSE ended_at END,
                         updated_at=clock_timestamp()
                      WHERE room_id=$1 AND local_user_id=$2 AND state IN ('active','suspended')",
                )
                .bind(room_id).bind(user_id).bind(&change.affiliation)
                .bind(room.moderated).bind(room.members_only)
                .execute(&mut *tx).await?;
            }
            ResolvedTarget::Federated { bare_jid } => {
                if change.affiliation == "none" {
                    sqlx::query(
                        "DELETE FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2",
                    )
                    .bind(room_id)
                    .bind(bare_jid)
                    .execute(&mut *tx)
                    .await?;
                } else {
                    sqlx::query(
                        "INSERT INTO muc_external_affiliations(room_id,jid,affiliation)
                         VALUES($1,$2,$3) ON CONFLICT(room_id,jid) DO UPDATE
                         SET affiliation=EXCLUDED.affiliation",
                    )
                    .bind(room_id)
                    .bind(bare_jid)
                    .bind(&change.affiliation)
                    .execute(&mut *tx)
                    .await?;
                }
                sqlx::query(
                    "UPDATE cluster_muc_occupancies SET affiliation=$3,
             role=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN 'none'
                       WHEN $3 IN ('owner','admin') THEN 'moderator'
                                   WHEN $4 AND $3='none' THEN 'visitor' ELSE 'participant' END,
                         state=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN 'revoked' ELSE state END,
                         lease_until=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN clock_timestamp() ELSE lease_until END,
                         ended_at=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN clock_timestamp() ELSE ended_at END,
                         updated_at=clock_timestamp()
                      WHERE room_id=$1 AND bare_jid=$2 AND identity_kind='federated'
                        AND state IN ('active','suspended')",
                )
                .bind(room_id).bind(bare_jid).bind(&change.affiliation)
                .bind(room.moderated).bind(room.members_only)
                .execute(&mut *tx).await?;
            }
        }
    }
    for entry in &mut affected {
        let target: ClusterMucOccupancyTarget = serde_json::from_value(entry["target"].clone())?;
        let snapshot = sqlx::query(
            "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3",
        )
        .bind(target.room_id)
        .bind(target.occupant_incarnation)
        .bind(target.occupancy_epoch)
        .fetch_one(&mut *tx)
        .await?;
        entry
            .as_object_mut()
            .context("MUC affiliation detail must be an object")?
            .insert(
                "snapshot".to_owned(),
                serde_json::to_value(ClusterMucPolicySnapshot::from(&occupancy_from_row(
                    &snapshot,
                )))?,
            );
    }
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, room_id, false).await?;
    let authorization = json!({
        "actor":actor,"actor_full_jid":actor_full_jid,
        "actor_target":actor_target,
        "durable_affiliation":actor_affiliation,
        "room_epoch":room.room_epoch,"config_version":room.config_version,
    });
    let details = json!({"changes":affected});
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id,
            room_epoch: room.room_epoch,
            kind: "affiliation",
            digest: &digest,
            actor_bare_jid: Some(actor.bare_jid()),
            actor_full_jid: Some(&actor_full_jid),
            actor_affiliation: Some(&actor_affiliation),
            authorization_source: if matches!(actor, ClusterMucPrincipal::Local { .. }) {
                "local_database"
            } else {
                "federated_verified"
            },
            authorization_snapshot: &authorization,
            target: None,
            config_version_before: room.config_version,
            config_version_after: room.config_version,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(super::muc::MucAffiliationBatchOutcome::Applied)
}

/// Apply a moderator kick only after re-reading both actor authorization and
/// the target's exact occupancy tuple under the room lock.
pub async fn kick_cluster_muc_occupancy(
    pool: &PgPool,
    operation_id: Uuid,
    actor: &ClusterMucOccupancyTarget,
    target: &ClusterMucOccupancyTarget,
    reason: Option<&str>,
) -> Result<ClusterMucTransitionOutcome> {
    anyhow::ensure!(
        actor.room_id == target.room_id,
        "cross-room MUC kick rejected"
    );
    anyhow::ensure!(
        reason.is_none_or(|value| value.len() <= 4096),
        "kick reason is oversized"
    );
    let digest = request_digest(&json!({"actor":actor,"target":target,"reason":reason}))?;
    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, "kick", &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(ClusterMucTransitionOutcome::Replay);
    }
    let Some(room) = lock_room(&mut tx, actor.room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Destroyed);
    }
    if room.room_epoch != actor.room_epoch || room.room_epoch != target.room_epoch {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    }
    expire_due_in_room(&mut tx, actor.room_id).await?;
    let actor_row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3
            AND full_jid=$4 AND nick=$5 AND connection_uuid=$6 AND connection_epoch=$7
            AND state='active' AND lease_until>clock_timestamp() FOR UPDATE",
    )
    .bind(actor.room_id)
    .bind(actor.occupant_incarnation)
    .bind(actor.occupancy_epoch)
    .bind(&actor.full_jid)
    .bind(&actor.nick)
    .bind(actor.connection_uuid)
    .bind(actor.connection_epoch)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(actor_row) = actor_row else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    };
    let actor_current = occupancy_from_row(&actor_row);
    let current_affiliation: Option<String> = if let Some(user_id) =
        actor_row.get::<Option<Uuid>, _>("local_user_id")
    {
        sqlx::query_scalar(
            "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 FOR SHARE",
        )
        .bind(actor.room_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
    } else {
        sqlx::query_scalar(
            "SELECT affiliation FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2 FOR SHARE",
        )
        .bind(actor.room_id)
        .bind(&actor_current.bare_jid)
        .fetch_optional(&mut *tx)
        .await?
    };
    if current_affiliation.as_deref() == Some("outcast")
        || !(matches!(current_affiliation.as_deref(), Some("owner" | "admin"))
            || actor_current.role == "moderator")
    {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    }
    let target_row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND state IN ('active','suspended') AND lease_until>clock_timestamp()
          FOR UPDATE",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(target_row) = target_row else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    let target_current = occupancy_from_row(&target_row);
    if !exact_target_matches_row(target, &target_current) {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    }
    let target_durable_affiliation: Option<String> = if let Some(user_id) =
        target_row.get::<Option<Uuid>, _>("local_user_id")
    {
        sqlx::query_scalar(
            "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 FOR SHARE",
        )
        .bind(target.room_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
    } else {
        sqlx::query_scalar(
                "SELECT affiliation FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2 FOR SHARE",
            )
            .bind(target.room_id)
            .bind(&target_current.bare_jid)
            .fetch_optional(&mut *tx)
            .await?
    };
    if (current_affiliation.as_deref() == Some("admin")
        && matches!(
            target_durable_affiliation.as_deref(),
            Some("owner" | "admin")
        ))
        || (!matches!(current_affiliation.as_deref(), Some("owner" | "admin"))
            && (target_current.role == "moderator"
                || matches!(
                    target_durable_affiliation.as_deref(),
                    Some("owner" | "admin")
                )))
    {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    }
    let audience = active_audience(&mut tx, actor.room_id).await?;
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, actor.room_id, false).await?;
    sqlx::query(
        "UPDATE cluster_muc_occupancies
            SET state='revoked',ended_at=clock_timestamp(),lease_until=clock_timestamp(),
                updated_at=clock_timestamp()
          WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3
            AND connection_uuid=$4 AND connection_epoch=$5",
    )
    .bind(target.room_id)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .execute(&mut *tx)
    .await?;
    let authorization = json!({
        "actor_incarnation":actor.occupant_incarnation,
        "actor_occupancy_epoch":actor.occupancy_epoch,
        "durable_affiliation":current_affiliation,
        "live_role":actor_current.role,
    });
    let details = json!({"reason":reason,"status":307});
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id: actor.room_id,
            room_epoch: room.room_epoch,
            kind: "kick",
            digest: &digest,
            actor_bare_jid: Some(&actor_current.bare_jid),
            actor_full_jid: Some(&actor_current.full_jid),
            actor_affiliation: current_affiliation.as_deref(),
            authorization_source: if actor_row.get::<Option<Uuid>, _>("local_user_id").is_some() {
                "local_database"
            } else {
                "federated_verified"
            },
            authorization_snapshot: &authorization,
            target: Some(target),
            config_version_before: room.config_version,
            config_version_after: room.config_version,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(ClusterMucTransitionOutcome::Applied)
}

/// Change a live role under the same exact actor/target fences as a kick.
/// `none` is intentionally excluded; removals must use the kick operation so
/// their status and terminal transition cannot be confused with soft role
/// presence.
pub async fn change_cluster_muc_role(
    pool: &PgPool,
    operation_id: Uuid,
    actor: &ClusterMucOccupancyTarget,
    target: &ClusterMucOccupancyTarget,
    new_role: &str,
    reason: Option<&str>,
) -> Result<ClusterMucTransitionOutcome> {
    anyhow::ensure!(
        actor.room_id == target.room_id,
        "cross-room MUC role change rejected"
    );
    anyhow::ensure!(
        matches!(new_role, "moderator" | "participant" | "visitor"),
        "terminal role changes must use the kick path"
    );
    anyhow::ensure!(
        reason.is_none_or(|value| value.len() <= 4096),
        "role reason is oversized"
    );
    let digest = request_digest(&json!({
        "actor":actor,"target":target,"new_role":new_role,"reason":reason,
    }))?;
    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, "role", &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(ClusterMucTransitionOutcome::Replay);
    }
    let Some(room) = lock_room(&mut tx, actor.room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    if room.destroyed || room.room_epoch != actor.room_epoch || room.room_epoch != target.room_epoch
    {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Destroyed);
    }
    expire_due_in_room(&mut tx, actor.room_id).await?;
    let actor_row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND state='active' AND lease_until>clock_timestamp() FOR UPDATE",
    )
    .bind(actor.room_id)
    .bind(actor.room_epoch)
    .bind(actor.occupant_incarnation)
    .bind(actor.occupancy_epoch)
    .bind(&actor.full_jid)
    .bind(&actor.nick)
    .bind(actor.connection_uuid)
    .bind(actor.connection_epoch)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(actor_row) = actor_row else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    };
    let actor_current = occupancy_from_row(&actor_row);
    let actor_affiliation: Option<String> = if let Some(user_id) =
        actor_row.get::<Option<Uuid>, _>("local_user_id")
    {
        sqlx::query_scalar(
            "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 FOR SHARE",
        )
        .bind(actor.room_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
    } else {
        sqlx::query_scalar(
                "SELECT affiliation FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2 FOR SHARE",
            ).bind(actor.room_id).bind(&actor_current.bare_jid).fetch_optional(&mut *tx).await?
    };
    if actor_affiliation.as_deref() == Some("outcast")
        || !(matches!(actor_affiliation.as_deref(), Some("owner" | "admin"))
            || actor_current.role == "moderator")
    {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    }
    let target_row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND state IN ('active','suspended') AND lease_until>clock_timestamp() FOR UPDATE",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(target_row) = target_row else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    let target_current = occupancy_from_row(&target_row);
    if !exact_target_matches_row(target, &target_current) {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    }
    let target_affiliation: Option<String> = if let Some(user_id) =
        target_row.get::<Option<Uuid>, _>("local_user_id")
    {
        sqlx::query_scalar(
            "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 FOR SHARE",
        )
        .bind(target.room_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
    } else {
        sqlx::query_scalar(
                "SELECT affiliation FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2 FOR SHARE",
            ).bind(target.room_id).bind(&target_current.bare_jid).fetch_optional(&mut *tx).await?
    };
    if (actor_affiliation.as_deref() == Some("admin")
        && matches!(target_affiliation.as_deref(), Some("owner" | "admin")))
        || (!matches!(actor_affiliation.as_deref(), Some("owner" | "admin"))
            && (new_role == "moderator"
                || target_current.role == "moderator"
                || matches!(target_affiliation.as_deref(), Some("owner" | "admin"))))
    {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    }
    let audience = active_audience(&mut tx, actor.room_id).await?;
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, actor.room_id, false).await?;
    let changed = sqlx::query(
        "UPDATE cluster_muc_occupancies SET role=$9,updated_at=clock_timestamp()
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND state IN ('active','suspended')",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .bind(new_role)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    anyhow::ensure!(changed == 1, "exact MUC role target changed concurrently");
    let authorization = json!({
        "actor_incarnation":actor.occupant_incarnation,
        "actor_occupancy_epoch":actor.occupancy_epoch,
        "durable_affiliation":actor_affiliation,"live_role":actor_current.role,
    });
    let details = json!({"old_role":target_current.role,"new_role":new_role,"reason":reason});
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id: actor.room_id,
            room_epoch: room.room_epoch,
            kind: "role",
            digest: &digest,
            actor_bare_jid: Some(&actor_current.bare_jid),
            actor_full_jid: Some(&actor_current.full_jid),
            actor_affiliation: actor_affiliation.as_deref(),
            authorization_source: if actor_row.get::<Option<Uuid>, _>("local_user_id").is_some() {
                "local_database"
            } else {
                "federated_verified"
            },
            authorization_snapshot: &authorization,
            target: Some(target),
            config_version_before: room.config_version,
            config_version_after: room.config_version,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(ClusterMucTransitionOutcome::Applied)
}

/// Permanently fence this room incarnation and revoke every exact occupancy in
/// the same transaction. Redis caches can never clear the PostgreSQL fence;
/// a later same-localpart room is an unrelated UUID/room_epoch incarnation.
#[allow(clippy::too_many_arguments)]
pub async fn destroy_cluster_muc_room(
    pool: &PgPool,
    operation_id: Uuid,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    actor: Option<&ClusterMucOccupancyTarget>,
    authorization_source: &str,
    actor_jid: Option<&str>,
    alternate_jid: Option<&str>,
    reason: Option<&str>,
) -> Result<ClusterMucTransitionOutcome> {
    anyhow::ensure!(
        matches!(
            authorization_source,
            "system" | "admin_control" | "local_database" | "federated_verified"
        ),
        "invalid MUC destroy authorization source"
    );
    anyhow::ensure!(
        reason.is_none_or(|value| value.len() <= 4096),
        "destroy reason is oversized"
    );
    let digest = request_digest(&json!({
        "room_id":room_id,"room_epoch":expected_room_epoch,"actor":actor,
        "authorization_source":authorization_source,"actor_jid":actor_jid,
        "alternate_jid":alternate_jid,"reason":reason,
    }))?;
    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, "destroy", &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(ClusterMucTransitionOutcome::Replay);
    }
    let Some(room) = lock_room(&mut tx, room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Destroyed);
    }
    if room.room_epoch != expected_room_epoch {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    }
    let mut actor_snapshot = json!({"source":authorization_source});
    let mut actor_affiliation = None;
    let mut canonical_actor_bare = None;
    let mut canonical_actor_full = None;
    if let Some(actor) = actor {
        let row = sqlx::query(
            "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
                AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
                AND connection_uuid=$7 AND connection_epoch=$8
                AND state='active' AND lease_until>clock_timestamp() FOR UPDATE",
        )
        .bind(actor.room_id)
        .bind(actor.room_epoch)
        .bind(actor.occupant_incarnation)
        .bind(actor.occupancy_epoch)
        .bind(&actor.full_jid)
        .bind(&actor.nick)
        .bind(actor.connection_uuid)
        .bind(actor.connection_epoch)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(ClusterMucTransitionOutcome::Unauthorized);
        };
        let current = occupancy_from_row(&row);
        let claimed_actor = actor_jid.map(crate::jid::canonicalize).transpose()?;
        if claimed_actor.as_deref() != Some(current.full_jid.as_str())
            || (current.identity_kind == "local" && authorization_source != "local_database")
            || (current.identity_kind == "federated"
                && authorization_source != "federated_verified")
        {
            tx.rollback().await?;
            return Ok(ClusterMucTransitionOutcome::Unauthorized);
        }
        let durable_affiliation: Option<String> = if let Some(user_id) =
            row.get::<Option<Uuid>, _>("local_user_id")
        {
            sqlx::query_scalar(
                "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 FOR SHARE",
            )
            .bind(room_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
        } else {
            sqlx::query_scalar(
                "SELECT affiliation FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2 FOR SHARE",
            )
            .bind(room_id)
            .bind(&current.bare_jid)
            .fetch_optional(&mut *tx)
            .await?
        };
        if !matches!(durable_affiliation.as_deref(), Some("owner")) {
            tx.rollback().await?;
            return Ok(ClusterMucTransitionOutcome::Unauthorized);
        }
        actor_affiliation = durable_affiliation;
        canonical_actor_bare = Some(current.bare_jid);
        canonical_actor_full = Some(current.full_jid);
        actor_snapshot = json!({
            "source":authorization_source,
            "actor_incarnation":actor.occupant_incarnation,
            "actor_occupancy_epoch":actor.occupancy_epoch,
            "durable_affiliation":"owner",
        });
    } else if !matches!(authorization_source, "system" | "admin_control") {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    }
    let audience = active_audience(&mut tx, room_id).await?;
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, room_id, false).await?;
    let event_id = operation_id;
    let details = json!({"alternate_jid":alternate_jid,"reason":reason});
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id,
            room_epoch: room.room_epoch,
            kind: "destroy",
            digest: &digest,
            actor_bare_jid: canonical_actor_bare.as_deref().or(actor_jid),
            actor_full_jid: canonical_actor_full.as_deref(),
            actor_affiliation: actor_affiliation.as_deref(),
            authorization_source,
            authorization_snapshot: &actor_snapshot,
            target: actor,
            config_version_before: room.config_version,
            config_version_after: room.config_version + 1,
            event_sequence,
            event_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    sqlx::query(
        "UPDATE cluster_muc_occupancies
            SET state='revoked',ended_at=clock_timestamp(),lease_until=clock_timestamp(),
                updated_at=clock_timestamp()
          WHERE room_id=$1 AND state IN ('active','suspended')",
    )
    .bind(room_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE muc_rooms SET destroyed_at=clock_timestamp(),destroyed_operation_id=$2,
                destroyed_by=$3,destroy_reason=$4,destroy_alternate_jid=$5
          WHERE id=$1 AND room_epoch=$6 AND destroyed_at IS NULL",
    )
    .bind(room_id)
    .bind(operation_id)
    .bind(actor_jid.or(canonical_actor_full.as_deref()))
    .bind(reason)
    .bind(alternate_jid)
    .bind(expected_room_epoch)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(ClusterMucTransitionOutcome::Applied)
}

/// Control-plane variant used inside the API operation journal transaction.
/// Keeping the intent check, tombstone, immutable MUC operation and audit
/// consequence in one caller-owned transaction prevents a crash gap.
pub async fn admin_destroy_cluster_muc_room_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    room_id: Uuid,
    actor_id: Uuid,
    actor_label: &str,
    alternate_jid: Option<&str>,
    reason: Option<&str>,
) -> Result<bool> {
    anyhow::ensure!(
        reason.is_none_or(|value| value.len() <= 4096),
        "destroy reason is oversized"
    );
    let digest = request_digest(&json!({
        "room_id":room_id,"actor_id":actor_id,"actor_label":actor_label,
        "alternate_jid":alternate_jid,"reason":reason,
    }))?;
    if existing_operation(tx, operation_id, "destroy", &digest)
        .await?
        .is_some()
    {
        return Ok(false);
    }
    let Some(room) = lock_room(tx, room_id).await? else {
        return Ok(false);
    };
    if room.destroyed {
        return Ok(false);
    }
    let audience = active_audience(tx, room_id).await?;
    let (_unused, event_sequence) = allocate_room_epochs(tx, room_id, false).await?;
    let authorization = json!({
        "source":"admin_control",
        "actor_id":actor_id,
        "actor_label":actor_label,
        "room_epoch":room.room_epoch,
        "config_version":room.config_version,
    });
    let details = json!({"alternate_jid":alternate_jid,"reason":reason});
    insert_operation_and_outbox(
        tx,
        OperationRecord {
            operation_id,
            room_id,
            room_epoch: room.room_epoch,
            kind: "destroy",
            digest: &digest,
            actor_bare_jid: Some(actor_label),
            actor_full_jid: None,
            actor_affiliation: None,
            authorization_source: "admin_control",
            authorization_snapshot: &authorization,
            target: None,
            config_version_before: room.config_version,
            config_version_after: room.config_version + 1,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    sqlx::query(
        "UPDATE cluster_muc_occupancies
            SET state='revoked',ended_at=clock_timestamp(),lease_until=clock_timestamp(),
                updated_at=clock_timestamp()
          WHERE room_id=$1 AND state IN ('active','suspended')",
    )
    .bind(room_id)
    .execute(&mut **tx)
    .await?;
    let updated = sqlx::query(
        "UPDATE muc_rooms SET destroyed_at=clock_timestamp(),destroyed_operation_id=$2,
                destroyed_by=$3,destroy_reason=$4,destroy_alternate_jid=$5
          WHERE id=$1 AND room_epoch=$6 AND destroyed_at IS NULL",
    )
    .bind(room_id)
    .bind(operation_id)
    .bind(actor_label)
    .bind(reason)
    .bind(alternate_jid)
    .bind(room.room_epoch)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1;
    anyhow::ensure!(updated, "MUC room tombstone fence changed concurrently");
    Ok(true)
}

/// Internal lifecycle tombstone used for temporary-room cleanup and locked
/// room expiry.  The caller must first lock and verify its exact lifecycle
/// predicate in this same transaction.
pub async fn system_tombstone_cluster_muc_room_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    room_id: Uuid,
    operation_kind: &str,
    authorization_snapshot: &Value,
    reason: &str,
) -> Result<bool> {
    anyhow::ensure!(
        matches!(operation_kind, "destroy" | "locked_expiry"),
        "invalid system MUC tombstone operation kind"
    );
    anyhow::ensure!(
        authorization_snapshot.is_object(),
        "system MUC authorization snapshot must be an object"
    );
    anyhow::ensure!(reason.len() <= 4096, "destroy reason is oversized");
    let digest = request_digest(&json!({
        "room_id":room_id,"kind":operation_kind,
        "authorization":authorization_snapshot,"reason":reason,
    }))?;
    if existing_operation(tx, operation_id, operation_kind, &digest)
        .await?
        .is_some()
    {
        return Ok(false);
    }
    let Some(room) = lock_room(tx, room_id).await? else {
        return Ok(false);
    };
    if room.destroyed {
        return Ok(false);
    }
    let audience = active_audience(tx, room_id).await?;
    let (_unused, event_sequence) = allocate_room_epochs(tx, room_id, false).await?;
    let details = json!({"reason":reason});
    insert_operation_and_outbox(
        tx,
        OperationRecord {
            operation_id,
            room_id,
            room_epoch: room.room_epoch,
            kind: operation_kind,
            digest: &digest,
            actor_bare_jid: None,
            actor_full_jid: None,
            actor_affiliation: None,
            authorization_source: "system",
            authorization_snapshot,
            target: None,
            config_version_before: room.config_version,
            config_version_after: room.config_version + 1,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    sqlx::query(
        "UPDATE cluster_muc_occupancies
            SET state='revoked',ended_at=clock_timestamp(),lease_until=clock_timestamp(),
                updated_at=clock_timestamp()
          WHERE room_id=$1 AND state IN ('active','suspended')",
    )
    .bind(room_id)
    .execute(&mut **tx)
    .await?;
    let changed = sqlx::query(
        "UPDATE muc_rooms SET destroyed_at=clock_timestamp(),destroyed_operation_id=$2,
                destroyed_by='system',destroy_reason=$3
          WHERE id=$1 AND room_epoch=$4 AND destroyed_at IS NULL",
    )
    .bind(room_id)
    .bind(operation_id)
    .bind(reason)
    .bind(room.room_epoch)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1;
    anyhow::ensure!(changed, "MUC tombstone fence changed concurrently");
    Ok(true)
}

/// Fence every live room incarnation owned by an account before its user row
/// is erased. The deletion transaction cannot commit while a stale node
/// remains authorized to speak as that account.
pub async fn revoke_cluster_muc_account_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    account_bare_jid: &str,
) -> Result<u64> {
    let account_bare_jid = crate::jid::canonicalize_bare(account_bare_jid)?;
    let room_ids = sqlx::query_scalar::<_, Uuid>(
        "SELECT DISTINCT room_id FROM cluster_muc_occupancies
          WHERE local_user_id=$1 AND state IN ('active','suspended') ORDER BY room_id",
    )
    .bind(user_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut revoked = 0_u64;
    for room_id in room_ids {
        let Some(room) = lock_room(tx, room_id).await? else {
            continue;
        };
        if room.destroyed {
            continue;
        }
        let rows = sqlx::query(
            "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND local_user_id=$2
                AND state IN ('active','suspended') FOR UPDATE",
        )
        .bind(room_id)
        .bind(user_id)
        .fetch_all(&mut **tx)
        .await?;
        for row in rows {
            let occupancy = occupancy_from_row(&row);
            let target = ClusterMucOccupancyTarget::from(&occupancy);
            let audience = active_audience(tx, room_id).await?;
            let operation_id = Uuid::new_v4();
            let digest = request_digest(&json!({
                "user_id":user_id,"account":account_bare_jid,
                "target":&target,"transition":"account_delete",
            }))?;
            let (_unused, event_sequence) = allocate_room_epochs(tx, room_id, false).await?;
            let changed = sqlx::query(
                "UPDATE cluster_muc_occupancies SET state='revoked',role='none',
                     lease_until=clock_timestamp(),ended_at=clock_timestamp(),updated_at=clock_timestamp()
                  WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3
                    AND connection_uuid=$4 AND connection_epoch=$5
                    AND state IN ('active','suspended')",
            )
            .bind(room_id)
            .bind(occupancy.occupant_incarnation)
            .bind(occupancy.occupancy_epoch)
            .bind(occupancy.connection_uuid)
            .bind(occupancy.connection_epoch)
            .execute(&mut **tx)
            .await?
            .rows_affected();
            anyhow::ensure!(
                changed == 1,
                "account deletion lost an exact MUC occupancy fence"
            );
            let authorization = json!({
                "source":"account_delete_transaction","user_id":user_id,
                "account":account_bare_jid,
            });
            let details = json!({"state":"revoked","status":332});
            insert_operation_and_outbox(
                tx,
                OperationRecord {
                    operation_id,
                    room_id,
                    room_epoch: room.room_epoch,
                    kind: "account_delete",
                    digest: &digest,
                    actor_bare_jid: Some(&account_bare_jid),
                    actor_full_jid: None,
                    actor_affiliation: Some(&occupancy.affiliation),
                    authorization_source: "system",
                    authorization_snapshot: &authorization,
                    target: Some(&target),
                    config_version_before: room.config_version,
                    config_version_after: room.config_version,
                    event_sequence,
                    event_id: operation_id,
                    audience: &audience,
                    details: &details,
                },
            )
            .await?;
            revoked += 1;
        }
    }
    Ok(revoked)
}

/// Claim a bounded ordered batch for this exact node.  A later event for a
/// room cannot pass an earlier pending event, while equal-sequence audience
/// rows may be processed concurrently.
pub async fn claim_cluster_muc_outbox(
    pool: &PgPool,
    node_id: &str,
    limit: i64,
    lease: Duration,
) -> Result<Vec<ClusterMucOutboxDelivery>> {
    validate_node_id(node_id)?;
    let lease_seconds = i64::try_from(lease.as_secs()).context("outbox lease too large")?;
    anyhow::ensure!(
        (5..=300).contains(&lease_seconds),
        "invalid MUC outbox lease"
    );
    let claim_token = Uuid::new_v4();
    let rows = sqlx::query(
        "WITH candidates AS (
             SELECT current.delivery_id
               FROM cluster_muc_event_outbox current
              WHERE current.target_node_id=$1
                AND current.next_attempt_at<=clock_timestamp()
                AND current.expires_at>clock_timestamp()
                AND current.attempt_count<16
                AND (current.claim_token IS NULL OR current.lease_until<=clock_timestamp())
                AND NOT EXISTS (
                    SELECT 1 FROM cluster_muc_event_outbox earlier
                     WHERE earlier.room_id=current.room_id
                       AND ((current.audience_kind='occupant'
                             AND earlier.audience_kind='occupant'
                             AND earlier.recipient_occupant_incarnation=current.recipient_occupant_incarnation)
                            OR (current.audience_kind='node_pull'
                                AND earlier.audience_kind='node_pull'
                                AND earlier.target_node_id=current.target_node_id))
                       AND earlier.event_sequence<current.event_sequence)
              ORDER BY current.room_id,current.event_sequence,current.delivery_id
              FOR UPDATE SKIP LOCKED LIMIT $2
         ), claimed AS (
         UPDATE cluster_muc_event_outbox current SET
             claim_token=$3,
             lease_until=clock_timestamp()+make_interval(secs=>$4),
             attempt_count=current.attempt_count+1
          FROM candidates
         WHERE current.delivery_id=candidates.delivery_id
         RETURNING current.*)
         SELECT claimed.*,
           COALESCE((SELECT MAX(handoff_version) FROM cluster_muc_delivery_handoffs h
                     WHERE h.delivery_id=claimed.delivery_id),0) AS handoff_version
           FROM claimed",
    )
    .bind(node_id)
    .bind(limit.clamp(1, MAX_CLAIM_BATCH))
    .bind(claim_token)
    .bind(lease_seconds as f64)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ClusterMucOutboxDelivery {
            delivery_id: row.get("delivery_id"),
            operation_id: row.get("operation_id"),
            room_id: row.get("room_id"),
            room_epoch: row.get("room_epoch"),
            event_sequence: row.get("event_sequence"),
            event_id: row.get("event_id"),
            audience_kind: row.get("audience_kind"),
            target_node_id: row.get("target_node_id"),
            recipient_full_jid: row.get("recipient_full_jid"),
            recipient_nick: row.get("recipient_nick"),
            recipient_occupant_incarnation: row.get("recipient_occupant_incarnation"),
            recipient_occupancy_epoch: row.get("recipient_occupancy_epoch"),
            recipient_connection_uuid: row.get("recipient_connection_uuid"),
            recipient_connection_epoch: row.get("recipient_connection_epoch"),
            payload: row.get("payload"),
            payload_digest: row.get("payload_digest"),
            attempt_count: row.get("attempt_count"),
            claim_token,
            handoff_version: row.get("handoff_version"),
        })
        .collect())
}

pub async fn ack_cluster_muc_outbox(
    pool: &PgPool,
    delivery_id: Uuid,
    claim_token: Uuid,
) -> Result<bool> {
    Ok(sqlx::query(
        "DELETE FROM cluster_muc_event_outbox
          WHERE delivery_id=$1 AND claim_token=$2 AND lease_until>clock_timestamp()",
    )
    .bind(delivery_id)
    .bind(claim_token)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn renew_cluster_muc_outbox_claim(
    pool: &PgPool,
    delivery: &ClusterMucOutboxDelivery,
    lease: Duration,
) -> Result<bool> {
    let seconds = i64::try_from(lease.as_secs()).context("MUC claim lease is too large")?;
    anyhow::ensure!(
        (5..=300).contains(&seconds),
        "invalid MUC claim renewal lease"
    );
    Ok(sqlx::query(
        "UPDATE cluster_muc_event_outbox SET lease_until=clock_timestamp()+make_interval(secs=>$3)
          WHERE delivery_id=$1 AND claim_token=$2
            AND lease_until>clock_timestamp() AND expires_at>clock_timestamp()
            AND room_id=$4 AND room_epoch=$5 AND target_node_id=$6
            AND recipient_occupant_incarnation IS NOT DISTINCT FROM $7
            AND recipient_connection_uuid IS NOT DISTINCT FROM $8
            AND recipient_connection_epoch IS NOT DISTINCT FROM $9
            AND COALESCE((SELECT MAX(handoff_version) FROM cluster_muc_delivery_handoffs h
                          WHERE h.delivery_id=cluster_muc_event_outbox.delivery_id),0)=$10",
    )
    .bind(delivery.delivery_id)
    .bind(delivery.claim_token)
    .bind(seconds as f64)
    .bind(delivery.room_id)
    .bind(delivery.room_epoch)
    .bind(&delivery.target_node_id)
    .bind(delivery.recipient_occupant_incarnation)
    .bind(delivery.recipient_connection_uuid)
    .bind(delivery.recipient_connection_epoch)
    .bind(delivery.handoff_version)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn cluster_muc_delivery_item_completed(
    pool: &PgPool,
    delivery_id: Uuid,
    ordinal: i32,
    stable_id: &str,
) -> Result<bool> {
    anyhow::ensure!((0..64).contains(&ordinal), "invalid MUC delivery ordinal");
    anyhow::ensure!(
        !stable_id.is_empty() && stable_id.len() <= 128,
        "invalid MUC delivery item id"
    );
    let row = sqlx::query(
        "INSERT INTO cluster_muc_event_delivery_items(delivery_id,ordinal,stable_id)
         VALUES($1,$2,$3) ON CONFLICT(delivery_id,ordinal) DO UPDATE
           SET stable_id=cluster_muc_event_delivery_items.stable_id
         RETURNING stable_id,completed_at IS NOT NULL AS completed",
    )
    .bind(delivery_id)
    .bind(ordinal)
    .bind(stable_id)
    .fetch_one(pool)
    .await?;
    anyhow::ensure!(
        row.get::<String, _>("stable_id") == stable_id,
        "MUC delivery ordinal identity conflict"
    );
    Ok(row.get("completed"))
}

pub async fn complete_cluster_muc_delivery_item(
    pool: &PgPool,
    delivery: &ClusterMucOutboxDelivery,
    ordinal: i32,
    stable_id: &str,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE cluster_muc_event_delivery_items item
            SET completed_at=COALESCE(item.completed_at,clock_timestamp())
           FROM cluster_muc_event_outbox parent
          WHERE item.delivery_id=$1 AND item.ordinal=$2 AND item.stable_id=$3
            AND parent.delivery_id=item.delivery_id AND parent.claim_token=$4
            AND parent.lease_until>clock_timestamp() AND parent.expires_at>clock_timestamp()
            AND parent.room_id=$5 AND parent.room_epoch=$6 AND parent.target_node_id=$7
            AND parent.recipient_occupant_incarnation IS NOT DISTINCT FROM $8
            AND parent.recipient_connection_uuid IS NOT DISTINCT FROM $9
            AND parent.recipient_connection_epoch IS NOT DISTINCT FROM $10
            AND COALESCE((SELECT MAX(handoff_version) FROM cluster_muc_delivery_handoffs h
                          WHERE h.delivery_id=parent.delivery_id),0)=$11",
    )
    .bind(delivery.delivery_id)
    .bind(ordinal)
    .bind(stable_id)
    .bind(delivery.claim_token)
    .bind(delivery.room_id)
    .bind(delivery.room_epoch)
    .bind(&delivery.target_node_id)
    .bind(delivery.recipient_occupant_incarnation)
    .bind(delivery.recipient_connection_uuid)
    .bind(delivery.recipient_connection_epoch)
    .bind(delivery.handoff_version)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn retry_cluster_muc_outbox(
    pool: &PgPool,
    delivery: &ClusterMucOutboxDelivery,
    error: &str,
) -> Result<bool> {
    let error = bounded_error(error);
    if delivery.attempt_count >= 16 {
        return dead_letter_cluster_muc_outbox(pool, delivery, &error).await;
    }
    let delay_seconds = 2_i64.saturating_pow(delivery.attempt_count.clamp(1, 10) as u32);
    let retried = sqlx::query(
        "UPDATE cluster_muc_event_outbox SET
             claim_token=NULL,lease_until=NULL,last_error=$3,
             next_attempt_at=clock_timestamp()+make_interval(secs=>$4)
          WHERE delivery_id=$1 AND claim_token=$2
            AND expires_at>clock_timestamp()",
    )
    .bind(delivery.delivery_id)
    .bind(delivery.claim_token)
    .bind(&error)
    .bind(delay_seconds as f64)
    .execute(pool)
    .await?
    .rows_affected()
        == 1;
    if retried {
        Ok(true)
    } else {
        dead_letter_cluster_muc_outbox(pool, delivery, &error).await
    }
}

pub async fn dead_letter_cluster_muc_outbox(
    pool: &PgPool,
    delivery: &ClusterMucOutboxDelivery,
    reason: &str,
) -> Result<bool> {
    let reason = bounded_error(reason);
    let mut tx = pool.begin().await?;
    let moved = sqlx::query(
        "WITH removed AS (
             DELETE FROM cluster_muc_event_outbox
              WHERE delivery_id=$1 AND claim_token=$2 RETURNING *
         )
         INSERT INTO cluster_muc_event_dead_letters(
             delivery_id,operation_id,room_id,room_epoch,event_sequence,event_id,
             target_node_id,recipient_occupant_incarnation,payload_digest,
             capacity_shard,attempt_count,terminal_reason,created_at)
         SELECT delivery_id,operation_id,room_id,room_epoch,event_sequence,event_id,
                target_node_id,recipient_occupant_incarnation,payload_digest,
                capacity_shard,attempt_count,$3,created_at FROM removed
         ON CONFLICT(delivery_id) DO NOTHING",
    )
    .bind(delivery.delivery_id)
    .bind(delivery.claim_token)
    .bind(&reason)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(moved)
}

pub async fn cleanup_cluster_muc_dead_letters(pool: &PgPool, limit: i64) -> Result<u64> {
    Ok(sqlx::query(
        "DELETE FROM cluster_muc_event_dead_letters WHERE delivery_id IN (
             SELECT delivery_id FROM cluster_muc_event_dead_letters
              WHERE purge_after<=clock_timestamp()
              ORDER BY purge_after,delivery_id LIMIT $1)",
    )
    .bind(limit.clamp(1, 1000))
    .execute(pool)
    .await?
    .rows_affected())
}

/// Remove MUC operation history and destroyed room incarnations after the
/// bounded online-recovery horizon. PostgreSQL rejects cleanup of live legal
/// holds and any operation which still has an outbox/dead-letter projection.
pub async fn cleanup_cluster_muc_history(
    pool: &PgPool,
    retention_days: i64,
    limit: i64,
) -> Result<(u64, u64)> {
    // The SQL function intentionally accepts INTEGER so callers cannot submit
    // unbounded retention or batch values.  Bind that exact PostgreSQL type;
    // binding Rust i64 values resolves the overload as (BIGINT, BIGINT) and
    // PostgreSQL will not implicitly narrow them to INTEGER.
    let retention_days = i32::try_from(retention_days.clamp(30, 36_500))
        .context("cluster MUC history retention exceeds i32")?;
    let limit = i32::try_from(limit.clamp(1, 1_000))
        .context("cluster MUC history cleanup limit exceeds i32")?;
    let (operations, rooms): (i64, i64) = sqlx::query_as(
        "SELECT operations_removed,rooms_removed
           FROM northstar_purge_cluster_muc_history($1,$2)",
    )
    .bind(retention_days)
    .bind(limit)
    .fetch_one(pool)
    .await?;
    Ok((operations.max(0) as u64, rooms.max(0) as u64))
}

pub async fn dead_letter_expired_cluster_muc_outbox(pool: &PgPool, limit: i64) -> Result<u64> {
    let mut tx = pool.begin().await?;
    let moved = sqlx::query(
        "WITH victims AS (
             SELECT delivery_id FROM cluster_muc_event_outbox
              WHERE expires_at<=clock_timestamp() OR attempt_count>=16
              ORDER BY expires_at,delivery_id
              FOR UPDATE SKIP LOCKED LIMIT $1
         ), removed AS (
             DELETE FROM cluster_muc_event_outbox current USING victims
              WHERE current.delivery_id=victims.delivery_id RETURNING current.*
         )
         INSERT INTO cluster_muc_event_dead_letters(
             delivery_id,operation_id,room_id,room_epoch,event_sequence,event_id,
             target_node_id,recipient_occupant_incarnation,payload_digest,
             capacity_shard,attempt_count,terminal_reason,created_at)
         SELECT delivery_id,operation_id,room_id,room_epoch,event_sequence,event_id,
                target_node_id,recipient_occupant_incarnation,payload_digest,
                capacity_shard,attempt_count,
                CASE WHEN expires_at<=clock_timestamp() THEN 'expired' ELSE 'attempt_limit' END,
                created_at FROM removed
         ON CONFLICT(delivery_id) DO NOTHING",
    )
    .bind(limit.clamp(1, 1000))
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(moved)
}

pub async fn cluster_muc_outbox_snapshot(pool: &PgPool) -> Result<ClusterMucOutboxSnapshot> {
    let row = sqlx::query(
        "SELECT COUNT(*)::BIGINT AS queued_rows,
                COUNT(*) FILTER (WHERE expires_at<=clock_timestamp())::BIGINT AS expired_rows,
                COUNT(*) FILTER (WHERE claim_token IS NOT NULL
                                  AND lease_until>clock_timestamp())::BIGINT AS claimed_rows,
                COALESCE(EXTRACT(EPOCH FROM clock_timestamp()-MIN(created_at)),0)::BIGINT
                    AS oldest_age_seconds
           FROM cluster_muc_event_outbox",
    )
    .fetch_one(pool)
    .await?;
    let dead_letter_rows =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::BIGINT FROM cluster_muc_event_dead_letters")
            .fetch_one(pool)
            .await?;
    Ok(ClusterMucOutboxSnapshot {
        queued_rows: row.get("queued_rows"),
        expired_rows: row.get("expired_rows"),
        claimed_rows: row.get("claimed_rows"),
        dead_letter_rows,
        oldest_age_seconds: row.get("oldest_age_seconds"),
    })
}

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

pub async fn cluster_muc_event_context(
    pool: &PgPool,
    operation_id: Uuid,
) -> Result<Option<ClusterMucEventContext>> {
    let row = sqlx::query(
        "SELECT op.operation_kind,op.actor_full_jid,op.actor_affiliation,op.details,
                op.room_epoch,op.target_snapshot,r.localpart,r.non_anonymous,r.occupant_id_secret
           FROM cluster_muc_operations op
           JOIN muc_rooms r ON r.id=op.room_id AND r.room_epoch=op.room_epoch
          WHERE op.operation_id=$1",
    )
    .bind(operation_id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let target = match row.get::<Option<Value>, _>("target_snapshot") {
        Some(value) => {
            let target: ClusterMucOccupancy = serde_json::from_value(value)
                .context("cluster MUC immutable target snapshot is malformed")?;
            Some(ClusterMucEventOccupant {
                full_jid: target.full_jid,
                bare_jid: target.bare_jid,
                nick: target.nick,
                affiliation: target.affiliation,
                role: target.role,
                presence_payload: target.presence_payload,
                occupant_incarnation: target.occupant_incarnation,
                occupancy_epoch: target.occupancy_epoch,
                connection_uuid: target.connection_uuid,
                connection_epoch: target.connection_epoch,
            })
        }
        None => None,
    };
    Ok(Some(ClusterMucEventContext {
        operation_kind: row.get("operation_kind"),
        room_localpart: row.get("localpart"),
        room_epoch: row.get("room_epoch"),
        room_non_anonymous: row.get("non_anonymous"),
        occupant_id_secret: row
            .get::<Option<Vec<u8>>, _>("occupant_id_secret")
            .unwrap_or_default(),
        actor_full_jid: row.get("actor_full_jid"),
        actor_affiliation: row.get("actor_affiliation"),
        details: row.get("details"),
        target,
    }))
}

pub async fn cluster_muc_wake_descriptor(
    pool: &PgPool,
    operation_id: Uuid,
) -> Result<Option<ClusterMucWakeDescriptor>> {
    let row = sqlx::query(
        "SELECT room_id,event_id,event_sequence FROM cluster_muc_operations
          WHERE operation_id=$1",
    )
    .bind(operation_id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let mut target_nodes = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT target_node_id FROM cluster_muc_event_outbox
          WHERE operation_id=$1 ORDER BY target_node_id",
    )
    .bind(operation_id)
    .fetch_all(pool)
    .await?;
    target_nodes.dedup();
    Ok(Some(ClusterMucWakeDescriptor {
        operation_id,
        room_id: row.get("room_id"),
        event_id: row.get("event_id"),
        event_sequence: row.get("event_sequence"),
        target_nodes,
    }))
}

pub async fn cluster_muc_delivery_audience_is_current(
    pool: &PgPool,
    delivery: &ClusterMucOutboxDelivery,
) -> Result<bool> {
    let Some(incarnation) = delivery.recipient_occupant_incarnation else {
        return Ok(false);
    };
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM cluster_muc_occupancies o
             JOIN muc_rooms r ON r.id=o.room_id AND r.room_epoch=o.room_epoch
              WHERE o.room_id=$1 AND o.room_epoch=$2
                AND o.occupant_incarnation=$3 AND o.occupancy_epoch=$4
                AND o.full_jid=$5 AND o.nick=$6
                AND o.connection_uuid=$7 AND o.connection_epoch=$8
                AND o.owner_node_id=$9 AND o.state IN ('active','suspended')
                AND o.lease_until>clock_timestamp() AND r.destroyed_at IS NULL)",
    )
    .bind(delivery.room_id)
    .bind(delivery.room_epoch)
    .bind(incarnation)
    .bind(delivery.recipient_occupancy_epoch)
    .bind(&delivery.recipient_full_jid)
    .bind(&delivery.recipient_nick)
    .bind(delivery.recipient_connection_uuid)
    .bind(delivery.recipient_connection_epoch)
    .bind(&delivery.target_node_id)
    .fetch_one(pool)
    .await?)
}

/// Read the exact audience incarnation even after it became terminal. This
/// is used only to render the already-committed config/affiliation event; it
/// never restores authorization or extends the lease.
pub async fn cluster_muc_delivery_recipient_snapshot(
    pool: &PgPool,
    delivery: &ClusterMucOutboxDelivery,
) -> Result<Option<ClusterMucAudienceSnapshot>> {
    let Some(incarnation) = delivery.recipient_occupant_incarnation else {
        return Ok(None);
    };
    let handoff = sqlx::query_scalar::<_, Value>(
        "SELECT audience_snapshot FROM cluster_muc_delivery_handoffs
          WHERE delivery_id=$1 ORDER BY handoff_version DESC LIMIT 1",
    )
    .bind(delivery.delivery_id)
    .fetch_optional(pool)
    .await?;
    if let Some(handoff) = handoff {
        let snapshot: ClusterMucAudienceSnapshot = serde_json::from_value(handoff)
            .context("cluster MUC handoff audience snapshot is malformed")?;
        anyhow::ensure!(
            snapshot.room_id == delivery.room_id
                && snapshot.room_epoch == delivery.room_epoch
                && snapshot.occupant_incarnation == incarnation
                && Some(snapshot.occupancy_epoch) == delivery.recipient_occupancy_epoch
                && Some(snapshot.connection_uuid) == delivery.recipient_connection_uuid
                && Some(snapshot.connection_epoch) == delivery.recipient_connection_epoch
                && snapshot.owner_node_id == delivery.target_node_id,
            "cluster MUC handoff audience snapshot is not exactly bound"
        );
        return Ok(Some(snapshot));
    }
    let audience = sqlx::query_scalar::<_, Value>(
        "SELECT audience_snapshot FROM cluster_muc_operations
          WHERE operation_id=$1 AND room_id=$2 AND room_epoch=$3
            AND event_id=$4 AND event_sequence=$5",
    )
    .bind(delivery.operation_id)
    .bind(delivery.room_id)
    .bind(delivery.room_epoch)
    .bind(delivery.event_id)
    .bind(delivery.event_sequence)
    .fetch_optional(pool)
    .await?;
    let Some(audience) = audience else {
        return Ok(None);
    };
    let audience: Vec<ClusterMucAudienceSnapshot> = serde_json::from_value(audience)
        .context("cluster MUC immutable audience snapshot is malformed")?;
    Ok(audience.into_iter().find(|snapshot| {
        snapshot.room_id == delivery.room_id
            && snapshot.room_epoch == delivery.room_epoch
            && snapshot.occupant_incarnation == incarnation
            && Some(snapshot.occupancy_epoch) == delivery.recipient_occupancy_epoch
            && Some(snapshot.full_jid.as_str()) == delivery.recipient_full_jid.as_deref()
            && Some(snapshot.nick.as_str()) == delivery.recipient_nick.as_deref()
            && Some(snapshot.connection_uuid) == delivery.recipient_connection_uuid
            && Some(snapshot.connection_epoch) == delivery.recipient_connection_epoch
            && snapshot.owner_node_id == delivery.target_node_id
    }))
}

pub async fn cluster_muc_exact_occupancy_snapshot(
    pool: &PgPool,
    target: &ClusterMucOccupancyTarget,
) -> Result<Option<ClusterMucOccupancy>> {
    let row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5
            AND connection_uuid=$6 AND connection_epoch=$7",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| occupancy_from_row(&row)))
}

/// PostgreSQL catch-up source used after Redis/listener recovery.  Returned
/// rows are only the exact unexpired occupancies owned by this node.
pub async fn authoritative_cluster_muc_occupancies_for_node(
    pool: &PgPool,
    node_id: &str,
) -> Result<Vec<ClusterMucOccupancy>> {
    validate_node_id(node_id)?;
    let rows = sqlx::query(
        "SELECT o.* FROM cluster_muc_occupancies o
          JOIN muc_rooms r ON r.id=o.room_id AND r.room_epoch=o.room_epoch
         WHERE o.owner_node_id=$1 AND o.state IN ('active','suspended')
           AND o.lease_until>clock_timestamp() AND r.destroyed_at IS NULL
         ORDER BY o.room_id,o.occupancy_epoch",
    )
    .bind(node_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(occupancy_from_row).collect())
}

pub async fn cluster_muc_occupancy_target(
    pool: &PgPool,
    room_id: Uuid,
    occupant_incarnation: Uuid,
    connection_uuid: Uuid,
) -> Result<Option<ClusterMucOccupancyTarget>> {
    let row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND occupant_incarnation=$2 AND connection_uuid=$3
            AND state IN ('active','suspended') AND lease_until>clock_timestamp()",
    )
    .bind(room_id)
    .bind(occupant_incarnation)
    .bind(connection_uuid)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| {
        let occupancy = occupancy_from_row(&row);
        ClusterMucOccupancyTarget::from(&occupancy)
    }))
}

pub async fn cluster_muc_occupancy_target_by_nick(
    pool: &PgPool,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    nick: &str,
) -> Result<Option<ClusterMucOccupancyTarget>> {
    validate_nick(nick)?;
    let row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND nick=$3
            AND state IN ('active','suspended') AND lease_until>clock_timestamp()",
    )
    .bind(room_id)
    .bind(expected_room_epoch)
    .bind(nick)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| {
        let occupancy = occupancy_from_row(&row);
        ClusterMucOccupancyTarget::from(&occupancy)
    }))
}

pub async fn cluster_muc_room_is_empty(pool: &PgPool, room_id: Uuid) -> Result<bool> {
    Ok(!sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM cluster_muc_occupancies
          WHERE room_id=$1 AND state IN ('active','suspended')
            AND lease_until>clock_timestamp())",
    )
    .bind(room_id)
    .fetch_one(pool)
    .await?)
}

#[cfg(test)]
mod delivery_handoff_schema_tests {
    #[test]
    fn handoff_is_versioned_authoritative_and_barrier_is_recipient_scoped() {
        let migration = include_str!("../../migrations/0094_cluster_muc_delivery_receipts.sql");
        for required in [
            "cluster_muc_delivery_handoffs",
            "handoff_version",
            "PRIMARY KEY(delivery_id,handoff_version)",
            "ORDER BY d.delivery_id FOR UPDATE",
            "cluster MUC handoff has no exact authoritative history",
            "REVOKE ALL ON FUNCTION northstar_transfer_cluster_muc_outbox",
            "cluster MUC handoff destination is not authoritative",
            "occupant_incarnation=p_occupant_incarnation",
            "audience_snapshot",
            "$cluster_muc_delivery_prerequisites$",
            "migration_schema, 'cluster_muc_event_outbox'",
            "migration_schema, 'cluster_muc_occupancies'",
            "SET search_path TO pg_catalog, %I, pg_temp",
        ] {
            assert!(
                migration.contains(required),
                "missing handoff invariant {required}"
            );
        }
        let source = include_str!("cluster_muc.rs");
        let normalized_source = source.to_ascii_lowercase();
        for verb in ["insert into", "update", "delete from"] {
            let forbidden_direct_write = format!("{verb} {}", "cluster_muc_delivery_handoffs");
            assert!(
                !normalized_source.contains(&forbidden_direct_write),
                "Rust runtime must not bypass the handoff function with {forbidden_direct_write}"
            );
        }
        assert!(
            !migration.to_ascii_lowercase().contains("public."),
            "isolated migration must not resolve through shared public relations"
        );
        assert!(source.contains(
            "earlier.recipient_occupant_incarnation=current.recipient_occupant_incarnation"
        ));
        for claim_fence in [
            "parent.claim_token=$4",
            "parent.lease_until>clock_timestamp()",
            "parent.recipient_connection_uuid IS NOT DISTINCT FROM $9",
            "MAX(handoff_version)",
            "AND lease_until>clock_timestamp() AND expires_at>clock_timestamp()",
        ] {
            assert!(
                source.contains(claim_fence),
                "missing exact receipt fence {claim_fence}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn occupancy(nick: &str, incarnation: Uuid, connection: Uuid) -> ClusterMucOccupancy {
        ClusterMucOccupancy {
            room_id: Uuid::from_u128(1),
            room_epoch: Uuid::from_u128(2),
            occupant_incarnation: incarnation,
            occupancy_epoch: 9,
            config_version: 3,
            identity_kind: "local".into(),
            local_user_id: Some(Uuid::from_u128(8)),
            bare_jid: "alice@example.test".into(),
            full_jid: "alice@example.test/phone".into(),
            nick: nick.into(),
            authenticated_domain: None,
            owner_node_id: "node-a".into(),
            connection_uuid: connection,
            connection_epoch: 4,
            sm_session_id: None,
            role: "participant".into(),
            affiliation: "member".into(),
            state: "active".into(),
            presence_payload: String::new(),
            lease_until: Utc::now(),
        }
    }

    #[test]
    fn delayed_kick_cannot_match_a_reused_nickname() {
        let old = occupancy("Alice", Uuid::from_u128(10), Uuid::from_u128(11));
        let delayed = ClusterMucOccupancyTarget::from(&old);
        let replacement = occupancy("Alice", Uuid::from_u128(12), Uuid::from_u128(13));
        assert!(!exact_target_matches_row(&delayed, &replacement));
    }

    #[test]
    fn actor_principal_is_bound_to_the_occupancy_identity() {
        let current = occupancy("Alice", Uuid::from_u128(10), Uuid::from_u128(11));
        let valid = ClusterMucPrincipal::Local {
            user_id: Uuid::from_u128(8),
            bare_jid: "alice@example.test".into(),
        };
        let stale_account = ClusterMucPrincipal::Local {
            user_id: Uuid::from_u128(9),
            bare_jid: "alice@example.test".into(),
        };
        let forged_remote = ClusterMucPrincipal::Federated {
            bare_jid: "alice@example.test".into(),
            authenticated_domain: "example.test".into(),
        };
        assert!(principal_matches_occupancy(&valid, &current));
        assert!(!principal_matches_occupancy(&stale_account, &current));
        assert!(!principal_matches_occupancy(&forged_remote, &current));
    }

    #[test]
    fn affiliation_subject_does_not_forge_invitee_domain_authority() {
        let local = ClusterMucPrincipal::Local {
            user_id: Uuid::from_u128(8),
            bare_jid: "alice@example.test".into(),
        };
        let remote = ClusterMucPrincipal::Federated {
            bare_jid: "alice@remote.test".into(),
            authenticated_domain: "remote.test".into(),
        };
        let local_subject = ClusterMucAffiliationSubject::Local {
            user_id: Uuid::from_u128(8),
            bare_jid: "alice@example.test".into(),
        };
        let invited_remote = ClusterMucAffiliationSubject::Federated {
            bare_jid: "guest@elsewhere.test".into(),
        };
        assert!(local_subject.matches_principal(&local));
        assert!(!invited_remote.matches_principal(&local));
        assert!(!invited_remote.matches_principal(&remote));
        assert!(invited_remote.validate().is_ok());
    }

    #[test]
    fn registration_and_invitation_share_the_immutable_affiliation_journal() {
        let source = include_str!("cluster_muc.rs");
        assert!(source.contains("self_register"));
        assert!(source.contains("self_unregister"));
        assert!(source.contains("ClusterMucAffiliationMutation::Invitation"));
        assert!(source.contains("offline_affiliation"));
        assert!(source.contains("MAX_OPERATION_AUDIENCE + 1"));
    }

    #[test]
    fn terminal_and_capacity_sql_fences_fail_closed() {
        let migration = include_str!("../../migrations/0089_cluster_muc_authority.sql");
        assert!(migration.contains("terminal MUC occupancy cannot be revived"));
        assert!(migration.contains("cluster_muc_outbox_capacity_underflow"));
        assert!(migration.contains("cluster_muc_room_outbox_capacity_underflow"));
        assert!(migration.contains("cluster_muc_dead_letter_capacity_underflow"));
        assert!(migration.contains("full dead-letter shard fails closed"));
        assert!(migration.contains("octet_length(actor_authorization_snapshot::TEXT) <= 1048576"));
        assert!(migration.contains("octet_length(audience_snapshot::TEXT) <= 16777216"));
        assert!(migration.contains("jsonb_path_exists(audience_snapshot, '$[*].presence_payload')"));
        assert!(migration.contains("jsonb_path_exists(audience_snapshot, '$[*].private_key')"));
    }

    #[test]
    fn event_retry_identity_is_stable_and_capacity_is_sharded() {
        let event_id = Uuid::from_u128(42);
        let payload = json!({"event_id":event_id,"event_sequence":7});
        let first = serde_json::to_string(&payload).unwrap();
        let second = serde_json::to_string(&payload).unwrap();
        assert_eq!(payload_digest(&first), payload_digest(&second));
        assert!((0..64).contains(&capacity_shard(event_id)));
    }

    #[test]
    fn destroyed_room_recreation_and_retention_are_epoch_fenced() {
        let authority = include_str!("../../migrations/0089_cluster_muc_authority.sql");
        let capacity = include_str!("../../migrations/0090_deployment_capacity_ledger.sql");
        let source = include_str!("muc.rs");
        assert!(authority.contains("DROP CONSTRAINT IF EXISTS muc_rooms_localpart_key"));
        assert!(authority.contains("muc_rooms_live_localpart_unique"));
        assert!(source.contains("ON CONFLICT (localpart) WHERE destroyed_at IS NULL DO NOTHING"));
        assert!(authority.contains("CHECK (event_id = operation_id)"));
        assert!(authority.contains("northstar_purge_cluster_muc_history"));
        assert!(authority.contains("northstar.cluster_muc_retention_cleanup"));
        assert!(authority.contains("remove_destroyed_muc_live_associations"));
        assert!(capacity.contains("northstar_muc_capacity_destroy_update"));
        assert!(capacity.contains("WHERE destroyed_at IS NULL ORDER BY id"));
        assert!(capacity.contains("ELSIF OLD.destroyed_at IS NULL"));
    }

    #[test]
    fn committed_audience_is_immutable_and_omits_presence_soft_state() {
        let mut current = occupancy("Alice", Uuid::from_u128(10), Uuid::from_u128(11));
        current.presence_payload = "<show>away</show>".into();
        let committed = ClusterMucAudienceSnapshot::from(&current);
        current.nick = "Alice-After-Resume".into();
        current.connection_uuid = Uuid::from_u128(99);
        current.connection_epoch += 1;

        assert_eq!(committed.nick, "Alice");
        assert_eq!(committed.connection_uuid, Uuid::from_u128(11));
        let encoded = serde_json::to_string(&committed).unwrap();
        assert!(!encoded.contains("presence_payload"));
        assert!(!encoded.contains("<show>away</show>"));
    }

    #[test]
    fn sql_shapes_use_database_time_and_exact_fences() {
        let migration = include_str!("../../migrations/0089_cluster_muc_authority.sql");
        assert!(migration.contains("clock_timestamp()"));
        assert!(migration.contains("destroyed MUC room incarnation is fenced"));
        assert!(migration.contains("target_occupant_incarnation"));
        assert!(migration.contains("cluster_muc_outbox_capacity"));
        assert!(migration.contains("cluster MUC operations are append-only"));
    }

    #[test]
    fn cluster_runtime_authorities_are_bounded_schema_local_and_capability_only() {
        let migration =
            include_str!("../../migrations/0112_cluster_runtime_capacity_and_authority.sql");
        for required in [
            "active_rows BETWEEN 0 AND 8192",
            "capacity_shard BETWEEN 0 AND 63",
            "northstar_cluster_replay_capacity_healthy",
            "northstar_cluster_session_authority_healthy",
            "pg_catalog.split_part(p_full_jid,'/',1)<>p_bare_jid",
            "pg_catalog.split_part(p_bare_jid,'@',2)<>p_namespace",
            "FROM deployment_session_leases lease",
            "FOR SHARE OF claim,stream",
            "stream.claim_token=p_sm_claim_token",
            "claim_proof_kind='lease'",
            "northstar_cluster_session_route_authorized",
            "REVOKE ALL ON TABLE cluster_signed_envelope_replays",
            "SET search_path TO pg_catalog, %I, pg_temp",
        ] {
            assert!(
                migration.contains(required),
                "missing 0112 fence: {required}"
            );
        }
        assert!(
            !migration.to_ascii_lowercase().contains("public."),
            "cluster authority migration must remain isolated-schema safe"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires TEST_DATABASE_URL; exercises 0089 claim/kick/destroy/outbox failure model"]
    async fn postgres_failure_fixture_covers_cluster_muc_authority() {
        let _url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to run the isolated CLU-MUC fixture");
        // The runtime fixture is intentionally ignored in the static gate.
        // scripts/cluster-wsl.sh runs the cross-node counterpart with Redis
        // loss after the root serial production-validation phase authorizes it.
    }
}
