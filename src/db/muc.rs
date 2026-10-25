use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

mod admin;
mod history;
mod membership;

pub use self::admin::*;
pub use self::history::*;
pub use self::membership::*;

const MAX_HISTORY_STANZA_BYTES: usize = 1_048_576;
const MAX_MUC_NICK_BYTES: usize = 128;
const MAX_ORIGIN_ID_BYTES: usize = 128;
const MAX_RETRACTION_REASON_BYTES: usize = 4096;
const MUC_CONFIGURATION_WINDOW_SECONDS: i64 = 300;

#[derive(Clone, Debug)]
pub struct MucRoom {
    pub id: Uuid,
    /// Immutable PostgreSQL room-incarnation fence used by clustered MUC.
    pub room_epoch: Uuid,
    /// Monotonic generation for authorization-relevant room configuration.
    pub config_version: i64,
    pub localpart: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub persistent: bool,
    pub members_only: bool,
    pub public: bool,
    pub moderated: bool,
    pub non_anonymous: bool,
    pub max_occupants: i32,
    pub subject: Option<String>,
    pub subject_changed_at: Option<DateTime<Utc>>,
    pub allow_subject_change: bool,
    pub allow_invites: bool,
    pub allow_private_messages: bool,
    pub logging_enabled: bool,
    pub allow_registration: bool,
    /// Argon2 PHC string. The cleartext room secret is never persisted.
    pub password_hash: Option<String>,
    /// Per-room XEP-0421 secret. It never leaves the server.
    pub occupant_id_secret: Vec<u8>,
    /// Newly-created rooms remain locked until this exact full JID accepts
    /// the defaults or completes the owner form (XEP-0045 section 10.1).
    pub configuration_owner_jid: Option<String>,
    pub configuration_expires_at: Option<DateTime<Utc>>,
}

impl MucRoom {
    pub fn is_locked(&self) -> bool {
        self.configuration_owner_jid.is_some()
    }

    #[cfg(test)]
    pub fn configuration_is_expired(&self, now: DateTime<Utc>) -> bool {
        self.configuration_expires_at
            .is_some_and(|expires_at| expires_at <= now)
    }

    #[cfg(test)]
    pub fn can_configure_locked_room(&self, actor_full_jid: &str, now: DateTime<Utc>) -> bool {
        self.configuration_owner_jid.as_deref() == Some(actor_full_jid)
            && !self.configuration_is_expired(now)
    }
}

#[derive(Debug)]
pub struct MucMessage {
    pub sender_jid: String,
    pub stanza: String,
    pub created_at: DateTime<Utc>,
}

/// Principal proven by the transport before a room operation reaches the
/// repository. PostgreSQL independently re-checks the corresponding
/// affiliation row; the transport assertion is never sufficient by itself.
#[derive(Clone, Debug)]
pub enum MucActorPrincipal<'a> {
    Local {
        user_id: Uuid,
        /// Canonical configured XMPP domain.  A matching localpart is not
        /// sufficient: a forged `user@foreign.example` must never inherit the
        /// local account's room authority.
        local_domain: &'a str,
    },
    Federated {
        bare_jid: &'a str,
        authenticated_domain: &'a str,
    },
}

/// Exact room-occupant authority presented to an atomic MUC operation.
///
/// `cluster_target` is mandatory in clustered mode and is checked against the
/// live PostgreSQL occupancy incarnation. In single-node mode it is `None`:
/// the caller must hold the process-wide per-room mutation gate from the final
/// in-memory incarnation check until every live fan-out has been admitted.
/// PostgreSQL still locks the room and current affiliation in that mode, so a
/// ban/membership change cannot race the archive projection.
#[derive(Clone, Debug)]
pub struct MucActorAuthority<'a> {
    pub clustered: bool,
    pub expected_room_epoch: Uuid,
    pub principal: MucActorPrincipal<'a>,
    pub actor_scope: &'a str,
    pub full_jid: &'a str,
    pub nick: &'a str,
    pub occupant_incarnation: Uuid,
    pub connection_uuid: Uuid,
    pub expected_role: &'a str,
    pub expected_affiliation: &'a str,
    pub cluster_target: Option<super::cluster_muc::ClusterMucOccupancyTarget>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucDiscussionAdmission {
    Stored(Uuid),
    Replay(Uuid),
    Unauthorized,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucSubjectOutcome {
    Applied,
    Unauthorized,
    Stale,
}

pub struct MucDiscussion<'a> {
    pub id: Uuid,
    pub room_id: Uuid,
    /// Canonical bare user JID.  This is the namespace for an XEP-0359
    /// origin-id and is deliberately distinct from the room nickname.
    pub actor_scope: &'a str,
    pub origin_id: Option<&'a str>,
    pub sender_jid: &'a str,
    pub nick: &'a str,
    pub stanza: &'a str,
    pub encrypted: bool,
    /// `false` records only the origin admission identity, honoring XEP-0334
    /// without reopening a replay/fan-out path.
    pub archive: bool,
    /// The same bounded age policy used by the room MAM archive.  Zero keeps
    /// the project's existing "automatic deletion disabled" semantics.
    pub retention_days: i64,
    pub authority: MucActorAuthority<'a>,
}

pub struct MucSubjectMutation<'a> {
    pub stanza_id: Uuid,
    pub room_id: Uuid,
    pub actor_scope: &'a str,
    pub sender_jid: &'a str,
    pub nick: &'a str,
    pub subject: &'a str,
    pub stanza: &'a str,
    pub encrypted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucRetractionKind {
    Author,
    Moderator,
}

pub struct MucRetractionMutation<'a> {
    pub action_id: Uuid,
    pub room_id: Uuid,
    pub target_id: Uuid,
    pub expected_stanza: &'a str,
    pub actor_scope: &'a str,
    pub sender_jid: &'a str,
    pub nick: &'a str,
    pub tombstone: &'a str,
    pub action_stanza: &'a str,
    pub reason: Option<&'a str>,
    pub kind: MucRetractionKind,
    pub authority: MucActorAuthority<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucRetractionOutcome {
    Applied,
    Conflict,
    Unauthorized,
    Stale,
}

#[cfg(test)]
#[derive(Clone)]
struct MucAuthorizationTestPause {
    operation: &'static str,
    entered: std::sync::Arc<tokio::sync::Notify>,
    resume: std::sync::Arc<tokio::sync::Notify>,
}

#[cfg(test)]
static MUC_AUTHORIZATION_TEST_PAUSE: std::sync::OnceLock<
    std::sync::Mutex<Option<MucAuthorizationTestPause>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn install_muc_authorization_test_pause(
    operation: &'static str,
) -> (
    std::sync::Arc<tokio::sync::Notify>,
    std::sync::Arc<tokio::sync::Notify>,
) {
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let resume = std::sync::Arc::new(tokio::sync::Notify::new());
    *MUC_AUTHORIZATION_TEST_PAUSE
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("MUC authorization test pause lock poisoned") = Some(MucAuthorizationTestPause {
        operation,
        entered: entered.clone(),
        resume: resume.clone(),
    });
    (entered, resume)
}

#[cfg(test)]
async fn maybe_pause_muc_authorization_for_test(operation: &'static str) {
    let hook = {
        let mut hook = MUC_AUTHORIZATION_TEST_PAUSE
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .expect("MUC authorization test pause lock poisoned");
        if hook
            .as_ref()
            .is_some_and(|candidate| candidate.operation == operation)
        {
            hook.take()
        } else {
            None
        }
    };
    if let Some(hook) = hook {
        hook.entered.notify_one();
        hook.resume.notified().await;
    }
}

pub async fn get_or_create_muc_room(
    pool: &PgPool,
    localpart: &str,
    creator_id: Uuid,
    creator_full_jid: &str,
) -> Result<(MucRoom, bool)> {
    let creator_full_jid = northstar_xmpp_types::jid::canonicalize(creator_full_jid)?;
    let mut transaction = pool.begin().await?;
    let room_id = Uuid::new_v4();
    let mut room_secret = vec![0_u8; 32];
    rand::thread_rng().fill_bytes(&mut room_secret);
    let inserted = sqlx::query(
        "INSERT INTO muc_rooms (
             id, localpart, owner_id, occupant_id_secret,
             configuration_state, configuration_owner_jid, configuration_expires_at
         ) VALUES ($1, $2, $3, $4, 'locked', $5, NOW() + make_interval(secs => $6))
         ON CONFLICT (localpart) WHERE destroyed_at IS NULL DO NOTHING",
    )
    .bind(room_id)
    .bind(localpart)
    .bind(creator_id)
    .bind(&room_secret)
    .bind(&creator_full_jid)
    .bind(MUC_CONFIGURATION_WINDOW_SECONDS as f64)
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        == 1;
    if inserted {
        sqlx::query(
            "INSERT INTO muc_affiliations (room_id, user_id, affiliation) VALUES ($1, $2, 'owner')",
        )
        .bind(room_id)
        .bind(creator_id)
        .execute(&mut *transaction)
        .await?;
    }
    let mut row =
        sqlx::query("SELECT * FROM muc_rooms WHERE localpart = $1 AND destroyed_at IS NULL")
            .bind(localpart)
            .fetch_one(&mut *transaction)
            .await?;
    if row
        .get::<Option<Vec<u8>>, _>("occupant_id_secret")
        .is_none()
    {
        sqlx::query("UPDATE muc_rooms SET occupant_id_secret = $2 WHERE id = $1 AND occupant_id_secret IS NULL")
            .bind(row.get::<Uuid, _>("id"))
            .bind(&room_secret)
            .execute(&mut *transaction)
            .await?;
        row = sqlx::query("SELECT * FROM muc_rooms WHERE localpart = $1 AND destroyed_at IS NULL")
            .bind(localpart)
            .fetch_one(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok((muc_room_from_row(&row), inserted))
}

pub async fn get_or_create_federated_muc_room(
    pool: &PgPool,
    localpart: &str,
    creator_full_jid: &str,
) -> Result<(MucRoom, bool)> {
    let creator = northstar_xmpp_types::jid::CanonicalJid::parse(creator_full_jid)?;
    anyhow::ensure!(
        creator.localpart().is_some(),
        "a federated MUC affiliation requires a user bare JID"
    );
    anyhow::ensure!(
        creator.resourcepart().is_some(),
        "a federated room creator requires a full JID"
    );
    let creator_full_jid = creator.to_string();
    let creator_bare_jid = creator.bare();
    let mut transaction = pool.begin().await?;
    let room_id = Uuid::new_v4();
    let mut room_secret = vec![0_u8; 32];
    rand::thread_rng().fill_bytes(&mut room_secret);
    let inserted = sqlx::query(
        "INSERT INTO muc_rooms (
             id, localpart, owner_id, occupant_id_secret,
             configuration_state, configuration_owner_jid, configuration_expires_at
         ) VALUES ($1, $2, NULL, $3, 'locked', $4, NOW() + make_interval(secs => $5))
         ON CONFLICT (localpart) WHERE destroyed_at IS NULL DO NOTHING",
    )
    .bind(room_id)
    .bind(localpart)
    .bind(&room_secret)
    .bind(&creator_full_jid)
    .bind(MUC_CONFIGURATION_WINDOW_SECONDS as f64)
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        == 1;
    if inserted {
        sqlx::query(
            "INSERT INTO muc_external_affiliations (room_id, jid, affiliation) VALUES ($1, $2, 'owner')",
        )
        .bind(room_id)
        .bind(&creator_bare_jid)
        .execute(&mut *transaction)
        .await?;
    }
    let mut row =
        sqlx::query("SELECT * FROM muc_rooms WHERE localpart = $1 AND destroyed_at IS NULL")
            .bind(localpart)
            .fetch_one(&mut *transaction)
            .await?;
    if row
        .get::<Option<Vec<u8>>, _>("occupant_id_secret")
        .is_none()
    {
        sqlx::query("UPDATE muc_rooms SET occupant_id_secret = $2 WHERE id = $1 AND occupant_id_secret IS NULL")
            .bind(row.get::<Uuid, _>("id"))
            .bind(&room_secret)
            .execute(&mut *transaction)
            .await?;
        row = sqlx::query("SELECT * FROM muc_rooms WHERE localpart = $1 AND destroyed_at IS NULL")
            .bind(localpart)
            .fetch_one(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok((muc_room_from_row(&row), inserted))
}

pub async fn muc_room(pool: &PgPool, localpart: &str) -> Result<Option<MucRoom>> {
    let mut row =
        sqlx::query("SELECT * FROM muc_rooms WHERE localpart = $1 AND destroyed_at IS NULL")
            .bind(localpart)
            .fetch_optional(pool)
            .await?;
    if let Some(existing) = row.as_ref() {
        if existing
            .get::<Option<Vec<u8>>, _>("occupant_id_secret")
            .is_none()
        {
            let mut room_secret = vec![0_u8; 32];
            rand::thread_rng().fill_bytes(&mut room_secret);
            sqlx::query("UPDATE muc_rooms SET occupant_id_secret = $2 WHERE id = $1 AND occupant_id_secret IS NULL")
                .bind(existing.get::<Uuid, _>("id"))
                .bind(room_secret)
                .execute(pool)
                .await?;
            row = sqlx::query(
                "SELECT * FROM muc_rooms WHERE localpart = $1 AND destroyed_at IS NULL",
            )
            .bind(localpart)
            .fetch_optional(pool)
            .await?;
        }
    }
    Ok(row.as_ref().map(muc_room_from_row))
}

#[derive(Clone, Debug)]
pub struct MucDiscoPage {
    pub rooms: Vec<MucRoom>,
    pub total: i64,
    pub first_index: i64,
}

/// Page public rooms in one stable snapshot. `before == Some(None)` is the
/// XEP-0059 empty-before request for the final page.
pub async fn public_muc_room_page(
    pool: &PgPool,
    after: Option<&str>,
    before: Option<Option<&str>>,
    max: i64,
) -> Result<Option<MucDiscoPage>> {
    anyhow::ensure!(
        after.is_none() || before.is_none(),
        "ambiguous MUC RSM page"
    );
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    if let Some(cursor) = after.or(before.flatten()) {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM muc_rooms
              WHERE destroyed_at IS NULL AND public
                AND configuration_state = 'active' AND localpart = $1)",
        )
        .bind(cursor)
        .fetch_one(&mut *transaction)
        .await?;
        if !exists {
            transaction.rollback().await?;
            return Ok(None);
        }
    }
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM muc_rooms
          WHERE destroyed_at IS NULL AND public AND configuration_state = 'active'",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let max = max.clamp(0, 100);
    let rows = if let Some(after) = after {
        sqlx::query(
            "SELECT * FROM muc_rooms
             WHERE destroyed_at IS NULL AND public
               AND configuration_state = 'active' AND localpart > $1
             ORDER BY localpart ASC LIMIT $2",
        )
        .bind(after)
        .bind(max + 1)
        .fetch_all(&mut *transaction)
        .await?
    } else if let Some(before) = before {
        sqlx::query(
            "SELECT * FROM muc_rooms WHERE destroyed_at IS NULL
               AND public AND configuration_state = 'active'
               AND ($1::text IS NULL OR localpart < $1)
             ORDER BY localpart DESC LIMIT $2",
        )
        .bind(before)
        .bind(max + 1)
        .fetch_all(&mut *transaction)
        .await?
    } else {
        sqlx::query(
            "SELECT * FROM muc_rooms
             WHERE destroyed_at IS NULL AND public AND configuration_state = 'active'
             ORDER BY localpart ASC LIMIT $1",
        )
        .bind(max + 1)
        .fetch_all(&mut *transaction)
        .await?
    };
    let mut rooms = rows.iter().map(muc_room_from_row).collect::<Vec<_>>();
    if rooms.len() > max as usize {
        rooms.truncate(max as usize);
    }
    if before.is_some() {
        rooms.reverse();
    }
    let first_index = if let Some(first) = rooms.first() {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM muc_rooms
             WHERE destroyed_at IS NULL AND public
               AND configuration_state = 'active' AND localpart < $1",
        )
        .bind(&first.localpart)
        .fetch_one(&mut *transaction)
        .await?
    } else {
        0
    };
    transaction.commit().await?;
    Ok(Some(MucDiscoPage {
        rooms,
        total,
        first_index,
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucRegistrationOutcome {
    Registered { affiliation_changed: bool },
    Conflict,
    Outcast,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableMucInviteOutcome {
    Stored {
        id: Uuid,
        affiliation_changed: bool,
        live_claim_id: Option<Uuid>,
    },
    Replay {
        id: Uuid,
    },
    QuotaExceeded,
    RecipientUnavailable,
    Outcast,
    AuthorityRejected,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FederatedMucInviteAffiliationOutcome {
    Stored,
    Replay,
    Rejected,
    Stale,
}

/// Admit one room discussion stanza.  With an XEP-0359 origin-id, the room,
/// canonical actor scope and exact origin-id form an idempotency key.  The
/// SHA-256 value is only an index accelerator: a conflicting row is always
/// compared byte-for-byte before it is accepted as a replay.
pub async fn admit_muc_discussion(
    pool: &PgPool,
    message: MucDiscussion<'_>,
) -> Result<MucDiscussionAdmission> {
    admit_muc_discussion_inner(pool, message, None).await
}

/// Project only this bound request into the unchanged SQL transaction. No
/// independent borrowed command can be paired with its COMMIT observation.
pub(crate) async fn admit_muc_discussion_observed(
    pool: &PgPool,
    request: &northstar_room_application::discussion::Request,
) -> Result<MucDiscussionAdmission> {
    admit_muc_discussion_inner(
        pool,
        super::room::discussion_to_db(request.command()),
        Some(request),
    )
    .await
}

pub struct MucConfigUpdate<'a> {
    pub title: Option<&'a str>,
    pub description: Option<&'a str>,
    pub persistent: bool,
    pub members_only: bool,
    pub public: bool,
    pub moderated: bool,
    pub non_anonymous: bool,
    pub max_occupants: i32,
    pub password_hash: Option<&'a str>,
    pub allow_subject_change: bool,
    pub allow_invites: bool,
    pub allow_private_messages: bool,
    pub logging_enabled: bool,
    pub allow_registration: bool,
}

pub async fn update_muc_config(
    pool: &PgPool,
    room_id: Uuid,
    actor_full_jid: &str,
    config: MucConfigUpdate<'_>,
) -> Result<MucConfigurationOutcome> {
    let actor_full_jid = northstar_xmpp_types::jid::canonicalize(actor_full_jid)?;
    let updated = sqlx::query(
        "UPDATE muc_rooms SET
             title = $2, persistent = $3, members_only = $4, public = $5,
             moderated = $6, non_anonymous = $7, max_occupants = $8,
             password_hash = $9, description = $10, allow_subject_change = $11,
             allow_invites = $12, allow_private_messages = $13,
             logging_enabled = $14, allow_registration = $15,
             configuration_state = 'active', configuration_owner_jid = NULL,
             configuration_expires_at = NULL
         WHERE id = $1 AND destroyed_at IS NULL
           AND (
             configuration_state = 'active'
             OR (
               configuration_state = 'locked'
               AND configuration_owner_jid = $16
               AND configuration_expires_at > NOW()
             )
           )",
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
    .bind(&actor_full_jid)
    .execute(pool)
    .await?
    .rows_affected();
    if updated == 1 {
        return Ok(MucConfigurationOutcome::Applied);
    }
    let state = sqlx::query(
        "SELECT configuration_state, configuration_owner_jid,
                configuration_expires_at <= NOW() AS expired
           FROM muc_rooms WHERE id = $1",
    )
    .bind(room_id)
    .fetch_optional(pool)
    .await?;
    Ok(match state {
        None => MucConfigurationOutcome::Missing,
        Some(row) if row.get::<String, _>("configuration_state") == "locked" => {
            if row.get::<bool, _>("expired") {
                MucConfigurationOutcome::Expired
            } else {
                MucConfigurationOutcome::LockedByAnother
            }
        }
        Some(_) => MucConfigurationOutcome::Missing,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucConfigurationOutcome {
    Applied,
    LockedByAnother,
    Expired,
    Missing,
}

/// Cancel the initial configuration session.  The predicate makes retries
/// harmless and prevents a stale session from deleting an active room.
pub async fn cancel_locked_muc_room(
    pool: &PgPool,
    room_id: Uuid,
    actor_full_jid: &str,
) -> Result<bool> {
    let actor_full_jid = northstar_xmpp_types::jid::canonicalize(actor_full_jid)?;
    let mut tx = pool.begin().await?;
    let matched = sqlx::query(
        "SELECT id FROM muc_rooms
          WHERE id=$1 AND destroyed_at IS NULL
            AND configuration_state='locked' AND configuration_owner_jid=$2
          FOR UPDATE",
    )
    .bind(room_id)
    .bind(&actor_full_jid)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    if !matched {
        tx.rollback().await?;
        return Ok(false);
    }
    let changed = super::cluster_muc::system_tombstone_cluster_muc_room_in_tx(
        &mut tx,
        Uuid::new_v4(),
        room_id,
        "destroy",
        &serde_json::json!({
            "lifecycle":"owner_cancelled_locked_room",
            "configuration_owner_jid":actor_full_jid,
        }),
        "initial room configuration was cancelled",
    )
    .await?;
    tx.commit().await?;
    Ok(changed)
}

/// Delete an abandoned initial configuration lease.  This is deliberately
/// conditional so concurrent acceptance wins cleanly over timeout cleanup.
pub async fn delete_expired_locked_muc_room(pool: &PgPool, room_id: Uuid) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let matched = sqlx::query(
        "SELECT id FROM muc_rooms
          WHERE id=$1 AND destroyed_at IS NULL
            AND configuration_state='locked'
            AND configuration_expires_at<=clock_timestamp()
          FOR UPDATE",
    )
    .bind(room_id)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    if !matched {
        tx.rollback().await?;
        return Ok(false);
    }
    let changed = super::cluster_muc::system_tombstone_cluster_muc_room_in_tx(
        &mut tx,
        Uuid::new_v4(),
        room_id,
        "locked_expiry",
        &serde_json::json!({"lifecycle":"locked_room_lease_expired","clock":"postgresql"}),
        "initial room configuration lease expired",
    )
    .await?;
    tx.commit().await?;
    Ok(changed)
}

/// Claim and remove a bounded batch of abandoned initial room leases.  Row
/// locking lets every application node run this worker without duplicate
/// destruction notifications or unbounded scans.
pub async fn delete_expired_locked_muc_rooms(pool: &PgPool, limit: i64) -> Result<Vec<String>> {
    let mut tx = pool.begin().await?;
    let rows = sqlx::query(
        "SELECT id,localpart FROM muc_rooms
          WHERE destroyed_at IS NULL AND configuration_state='locked'
            AND configuration_expires_at<=clock_timestamp()
          ORDER BY configuration_expires_at,id
          FOR UPDATE SKIP LOCKED LIMIT $1",
    )
    .bind(limit.clamp(1, 100))
    .fetch_all(&mut *tx)
    .await?;
    let mut destroyed = Vec::with_capacity(rows.len());
    for row in rows {
        let room_id: Uuid = row.get("id");
        let localpart: String = row.get("localpart");
        if super::cluster_muc::system_tombstone_cluster_muc_room_in_tx(
            &mut tx,
            Uuid::new_v4(),
            room_id,
            "locked_expiry",
            &serde_json::json!({"lifecycle":"locked_room_lease_expired","clock":"postgresql"}),
            "initial room configuration lease expired",
        )
        .await?
        {
            destroyed.push(localpart);
        }
    }
    tx.commit().await?;
    Ok(destroyed)
}

pub async fn delete_muc_room(pool: &PgPool, room_id: Uuid) -> Result<()> {
    let mut tx = pool.begin().await?;
    if sqlx::query("SELECT id FROM muc_rooms WHERE id=$1 AND destroyed_at IS NULL FOR UPDATE")
        .bind(room_id)
        .fetch_optional(&mut *tx)
        .await?
        .is_some()
    {
        super::cluster_muc::system_tombstone_cluster_muc_room_in_tx(
            &mut tx,
            Uuid::new_v4(),
            room_id,
            "destroy",
            &serde_json::json!({"lifecycle":"protocol_destroy"}),
            "room destroyed by an authorized protocol operation",
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn delete_temporary_muc_room(
    pool: &PgPool,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    expected_config_version: i64,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let locked = sqlx::query(
        "SELECT id FROM muc_rooms
          WHERE id=$1 AND room_epoch=$2 AND config_version=$3
            AND NOT persistent AND destroyed_at IS NULL FOR UPDATE",
    )
    .bind(room_id)
    .bind(expected_room_epoch)
    .bind(expected_config_version)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    if !locked {
        tx.rollback().await?;
        return Ok(false);
    }
    super::cluster_muc::expire_due_in_room(&mut tx, room_id).await?;
    let occupied: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND state IN ('active','suspended')
            AND lease_until>clock_timestamp())",
    )
    .bind(room_id)
    .bind(expected_room_epoch)
    .fetch_one(&mut *tx)
    .await?;
    if occupied {
        tx.rollback().await?;
        return Ok(false);
    }
    {
        super::cluster_muc::system_tombstone_cluster_muc_room_in_tx(
            &mut tx,
            Uuid::new_v4(),
            room_id,
            "destroy",
            &serde_json::json!({"lifecycle":"temporary_room_empty"}),
            "temporary room became empty",
        )
        .await?;
    }
    tx.commit().await?;
    Ok(true)
}

fn muc_room_from_row(row: &sqlx::postgres::PgRow) -> MucRoom {
    MucRoom {
        id: row.get("id"),
        room_epoch: row.get("room_epoch"),
        config_version: row.get("config_version"),
        localpart: row.get("localpart"),
        title: row.get("title"),
        description: row.get("description"),
        persistent: row.get("persistent"),
        members_only: row.get("members_only"),
        public: row.get("public"),
        moderated: row.get("moderated"),
        non_anonymous: row.get("non_anonymous"),
        max_occupants: row.get("max_occupants"),
        subject: row.get("subject"),
        subject_changed_at: row.get("subject_changed_at"),
        allow_subject_change: row.get("allow_subject_change"),
        allow_invites: row.get("allow_invites"),
        allow_private_messages: row.get("allow_private_messages"),
        logging_enabled: row.get("logging_enabled"),
        allow_registration: row.get("allow_registration"),
        password_hash: row.get("password_hash"),
        occupant_id_secret: row
            .get::<Option<Vec<u8>>, _>("occupant_id_secret")
            .unwrap_or_default(),
        configuration_owner_jid: row.get("configuration_owner_jid"),
        configuration_expires_at: row.get("configuration_expires_at"),
    }
}

#[cfg(test)]
pub(crate) use crate::services::muc::{
    hash_room_password as hash_muc_password, verify_room_password as verify_muc_password,
};

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucAffiliationOutcome {
    Applied,
    LastOwner,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub enum MucAffiliationTarget {
    LocalUsername(String),
    FederatedBareJid(String),
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct MucAffiliationChange {
    pub target: MucAffiliationTarget,
    pub affiliation: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucAffiliationBatchOutcome {
    Applied,
    DuplicateTarget,
    LastOwner,
    MissingTarget,
    /// Cluster-only fail-closed result: the exact live actor lost authority.
    Unauthorized,
    /// Cluster-only fail-closed result: a room or actor fence was superseded.
    Stale,
    /// Cluster-only fail-closed result: a tombstoned room cannot be mutated.
    Destroyed,
}

#[cfg(test)]
pub async fn set_muc_affiliation(
    pool: &PgPool,
    room_id: Uuid,
    username: &str,
    affiliation: &str,
) -> Result<MucAffiliationOutcome> {
    anyhow::ensure!(
        matches!(
            affiliation,
            "owner" | "admin" | "member" | "outcast" | "none"
        ),
        "invalid local MUC affiliation"
    );
    let mut transaction = pool.begin().await?;
    lock_muc_affiliation_namespace(&mut transaction, room_id).await?;
    let user_id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE username=$1")
        .bind(username)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(user_id) = user_id else {
        transaction.rollback().await?;
        return Ok(MucAffiliationOutcome::Applied);
    };
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 17))")
        .bind(format!("{room_id}:{user_id}"))
        .execute(&mut *transaction)
        .await?;
    let current: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 FOR UPDATE",
    )
    .bind(room_id)
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if current.as_deref() == Some("owner") && affiliation != "owner" {
        let owners: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM muc_affiliations
                      WHERE room_id=$1 AND affiliation='owner')
                  + (SELECT COUNT(*) FROM muc_external_affiliations
                      WHERE room_id=$1 AND affiliation='owner')",
        )
        .bind(room_id)
        .fetch_one(&mut *transaction)
        .await?;
        if owners <= 1 {
            transaction.rollback().await?;
            return Ok(MucAffiliationOutcome::LastOwner);
        }
    }
    if affiliation == "none" {
        sqlx::query("DELETE FROM muc_affiliations WHERE room_id=$1 AND user_id=$2")
            .bind(room_id)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
    } else {
        sqlx::query(
            "INSERT INTO muc_affiliations (room_id, user_id, affiliation, updated_at)
             VALUES ($1, $2, $3, NOW())
             ON CONFLICT (room_id, user_id) DO UPDATE SET
               affiliation = EXCLUDED.affiliation,
               reserved_nick = CASE WHEN EXCLUDED.affiliation='outcast'
                                    THEN NULL ELSE muc_affiliations.reserved_nick END,
               updated_at = NOW()",
        )
        .bind(room_id)
        .bind(user_id)
        .bind(affiliation)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(MucAffiliationOutcome::Applied)
}

#[cfg(test)]
pub async fn set_federated_muc_affiliation(
    pool: &PgPool,
    room_id: Uuid,
    bare_jid: &str,
    affiliation: &str,
) -> Result<MucAffiliationOutcome> {
    anyhow::ensure!(
        matches!(
            affiliation,
            "owner" | "admin" | "member" | "outcast" | "none"
        ),
        "invalid federated MUC affiliation"
    );
    let jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(bare_jid)?;
    anyhow::ensure!(
        jid.localpart().is_some(),
        "a federated MUC affiliation requires a user bare JID"
    );
    let jid = jid.to_string();
    let mut transaction = pool.begin().await?;
    lock_muc_affiliation_namespace(&mut transaction, room_id).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 17))")
        .bind(format!("{room_id}:{jid}"))
        .execute(&mut *transaction)
        .await?;
    let current: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM muc_external_affiliations
          WHERE room_id=$1 AND jid=$2 FOR UPDATE",
    )
    .bind(room_id)
    .bind(&jid)
    .fetch_optional(&mut *transaction)
    .await?;
    if current.as_deref() == Some("owner") && affiliation != "owner" {
        let owners: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM muc_affiliations
                      WHERE room_id=$1 AND affiliation='owner')
                  + (SELECT COUNT(*) FROM muc_external_affiliations
                      WHERE room_id=$1 AND affiliation='owner')",
        )
        .bind(room_id)
        .fetch_one(&mut *transaction)
        .await?;
        if owners <= 1 {
            transaction.rollback().await?;
            return Ok(MucAffiliationOutcome::LastOwner);
        }
    }
    if affiliation == "none" {
        sqlx::query("DELETE FROM muc_external_affiliations WHERE room_id = $1 AND jid = $2")
            .bind(room_id)
            .bind(&jid)
            .execute(&mut *transaction)
            .await?;
    } else {
        sqlx::query(
            "INSERT INTO muc_external_affiliations (room_id, jid, affiliation, updated_at)
             VALUES ($1, $2,$3,NOW())
             ON CONFLICT (room_id, jid) DO UPDATE SET
               affiliation = EXCLUDED.affiliation,
               reserved_nick = CASE WHEN EXCLUDED.affiliation='outcast'
                                    THEN NULL ELSE muc_external_affiliations.reserved_nick END,
               updated_at = NOW()",
        )
        .bind(room_id)
        .bind(&jid)
        .bind(affiliation)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(MucAffiliationOutcome::Applied)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucAdminRoleEntry {
    pub nick: String,
    pub role: String,
    pub bare_jid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucAdminRoleList {
    pub requester_role: String,
    pub non_anonymous: bool,
    /// Populated only in clustered mode, where PostgreSQL is live-occupancy
    /// authority. In single-node mode the caller reads the in-memory registry
    /// while retaining the same process-wide room mutation guard.
    pub entries: Vec<MucAdminRoleEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucAdminAffiliationEntry {
    pub bare_jid: String,
    pub affiliation: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MucAdminSnapshot<T> {
    Authorized(T),
    Unauthorized,
    Stale,
}

/// Production source of this module: the file itself followed by each
/// production child module file, so source-contract tests keep reading the
/// whole module after code moves between them. The children are listed in
/// the order their code had in the former single file, because some
/// contracts split the source on a marker that occurs in more than one child.
/// `module_source_lists_every_child_module` keeps this list in step with the
/// non-test `mod` declarations above.
#[cfg(test)]
pub(super) const MODULE_SOURCE: &[(&str, &str)] = &[
    ("muc", include_str!("muc.rs")),
    ("history", include_str!("muc/history.rs")),
    ("membership", include_str!("muc/membership.rs")),
    ("admin", include_str!("muc/admin.rs")),
];

#[cfg(test)]
pub(super) fn module_source() -> String {
    MODULE_SOURCE
        .iter()
        .map(|(_, text)| *text)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
#[path = "muc_tests.rs"]
mod tests;

#[cfg(test)]
mod module_source_tests;
