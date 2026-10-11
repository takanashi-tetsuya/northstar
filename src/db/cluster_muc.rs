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

mod admin_batch;
mod affiliation;
mod moderation;
mod occupancy;
mod outbox;
mod query;
mod room;
mod session_route;

pub use self::admin_batch::*;
pub use self::affiliation::*;
pub use self::moderation::*;
pub use self::occupancy::*;
pub use self::outbox::*;
pub use self::query::*;
pub use self::room::*;
pub use self::session_route::*;

const MAX_NICK_BYTES: usize = 128;
const MAX_PAYLOAD_BYTES: usize = 1_048_576;
const MAX_OPERATION_SNAPSHOT_BYTES: usize = 16 * 1_048_576;
const MAX_OPERATION_AUDIENCE: usize = 10_000;
const MAX_CLAIM_BATCH: i64 = 256;
pub const MAX_MUC_OCCUPANCY_RENEW_BATCH: usize = 128;

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

// Actor and occupancy addresses may contain a resource. Project the parsed
// address structurally; parse_bare/canonicalize_bare deliberately reject a
// resource and remain required for the authenticated principal itself.
fn muc_address_bare_jid(address: &str) -> Result<String> {
    Ok(crate::jid::CanonicalJid::parse(address)?.bare())
}

fn muc_principal_owns_address(address: &str, principal: &ClusterMucPrincipal) -> Result<bool> {
    Ok(muc_address_bare_jid(address)? == principal.bare_jid())
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClusterMucOccupancyLookup {
    pub room_localpart: String,
    pub full_jid: String,
    pub nick: String,
    pub occupant_incarnation: Uuid,
    pub connection_uuid: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterMucResolvedOccupancy {
    pub room_localpart: String,
    pub target: ClusterMucOccupancyTarget,
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

pub use northstar_room_core::ClusterMucWakeDescriptor;

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
    let common_payload = serde_json::to_string(&immutable)?;
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
        let payload = if record.kind == "admin_batch" {
            let mut recipient_payload = immutable.clone();
            recipient_payload["original_audience"] = serde_json::to_value(recipient)?;
            serde_json::to_string(&recipient_payload)?
        } else {
            common_payload.clone()
        };
        anyhow::ensure!(
            payload.len() <= MAX_PAYLOAD_BYTES,
            "MUC outbox payload is oversized"
        );
        let digest = payload_digest(&payload);
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

/// Production source of this module: the file itself followed by each child
/// module file, so source-contract tests keep reading the whole module after
/// code moves between them. `module_source_lists_every_child_module` keeps
/// this list in step with the `mod` declarations above.
#[cfg(test)]
const MODULE_SOURCE: &[(&str, &str)] = &[
    ("cluster_muc", include_str!("cluster_muc.rs")),
    ("admin_batch", include_str!("cluster_muc/admin_batch.rs")),
    ("affiliation", include_str!("cluster_muc/affiliation.rs")),
    ("moderation", include_str!("cluster_muc/moderation.rs")),
    ("occupancy", include_str!("cluster_muc/occupancy.rs")),
    ("outbox", include_str!("cluster_muc/outbox.rs")),
    ("query", include_str!("cluster_muc/query.rs")),
    ("room", include_str!("cluster_muc/room.rs")),
    (
        "session_route",
        include_str!("cluster_muc/session_route.rs"),
    ),
];

#[cfg(test)]
fn module_source() -> String {
    MODULE_SOURCE
        .iter()
        .map(|(_, text)| *text)
        .collect::<Vec<_>>()
        .join("\n")
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
        let source = super::module_source();
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
#[path = "cluster_muc_tests.rs"]
mod tests;
