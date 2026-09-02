use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

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

fn canonical_history_actor(actor_scope: &str) -> Result<String> {
    anyhow::ensure!(
        !actor_scope.is_empty() && actor_scope.len() <= 3071,
        "MUC history actor scope must contain 1 to 3071 bytes"
    );
    let actor = crate::jid::CanonicalJid::parse_bare(actor_scope)?;
    anyhow::ensure!(
        actor.localpart().is_some(),
        "MUC history actor scope must be a user bare JID"
    );
    let canonical = actor.to_string();
    anyhow::ensure!(
        canonical == actor_scope,
        "MUC history actor scope must already be canonical"
    );
    Ok(canonical)
}

fn canonical_history_sender(sender_jid: &str) -> Result<String> {
    anyhow::ensure!(
        !sender_jid.is_empty() && sender_jid.len() <= 3071,
        "MUC history sender JID must contain 1 to 3071 bytes"
    );
    let canonical = crate::jid::canonicalize(sender_jid)?;
    anyhow::ensure!(
        canonical == sender_jid,
        "MUC history sender JID must already be canonical"
    );
    Ok(canonical)
}

fn validate_history_payload(nick: &str, stanza: &str) -> Result<()> {
    anyhow::ensure!(
        !nick.is_empty() && nick.len() <= MAX_MUC_NICK_BYTES,
        "MUC history nickname must contain 1 to 128 bytes"
    );
    anyhow::ensure!(
        !stanza.is_empty() && stanza.len() <= MAX_HISTORY_STANZA_BYTES,
        "MUC history stanza must contain 1 to 1048576 bytes"
    );
    Ok(())
}

fn validate_origin_id(origin_id: &str) -> Result<()> {
    anyhow::ensure!(
        !origin_id.is_empty() && origin_id.len() <= MAX_ORIGIN_ID_BYTES,
        "MUC origin-id must contain 1 to 128 bytes"
    );
    anyhow::ensure!(
        !origin_id.chars().any(char::is_control),
        "MUC origin-id must not contain control characters"
    );
    Ok(())
}

fn muc_origin_digest(actor_scope: &str, origin_id: &str) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"northstar:muc-origin-id:v1\0");
    digest.update((actor_scope.len() as u32).to_be_bytes());
    digest.update(actor_scope.as_bytes());
    digest.update((origin_id.len() as u32).to_be_bytes());
    digest.update(origin_id.as_bytes());
    digest.finalize().to_vec()
}

#[derive(Clone, Debug)]
struct LockedMucActor {
    role: String,
    affiliation: String,
}

#[derive(Clone, Debug)]
enum MucAuthorityCheck {
    Authorized(LockedMucActor),
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

/// Acquire the room-scoped affiliation namespace.
///
/// This is the first database lock in every MUC transaction that participates
/// in namespace 29. Callers lock `muc_rooms` next and, whenever both exact
/// occupancy and affiliation rows are needed, lock occupancy before
/// affiliation. They must never acquire this lock after a room, occupancy or
/// affiliation row. Cluster writers intentionally do not use namespace 29 and
/// follow room -> occupancy -> affiliation, so they cannot form a reverse edge.
async fn lock_muc_affiliation_namespace(
    transaction: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 29))")
        .bind(room_id.to_string())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

/// Establish the linearization point for a MUC operation.
///
/// Advisory namespace 29 is always acquired before the room row.  Legacy
/// affiliation writers already use that order (and may then lock affiliation
/// rows), while clustered writers begin with the room row and then take exact
/// occupancy before affiliation. Keeping one order prevents a room-row ->
/// advisory / advisory -> room-row deadlock cycle and also makes a missing
/// affiliation row safe: a concurrent insert/delete cannot slip between the
/// authorization check and the durable projection.
async fn lock_muc_actor_authority(
    transaction: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    authority: &MucActorAuthority<'_>,
) -> Result<MucAuthorityCheck> {
    if authority.clustered != authority.cluster_target.is_some() {
        return Ok(MucAuthorityCheck::Stale);
    }
    if authority.cluster_target.as_ref().is_some_and(|target| {
        target.room_id != room_id
            || target.room_epoch != authority.expected_room_epoch
            || target.occupant_incarnation != authority.occupant_incarnation
            || target.connection_uuid != authority.connection_uuid
            || target.full_jid != authority.full_jid
            || target.nick != authority.nick
    }) {
        return Ok(MucAuthorityCheck::Stale);
    }
    if authority.actor_scope != canonical_history_actor(authority.actor_scope)?
        || authority.full_jid != canonical_history_sender(authority.full_jid)?
        || crate::jid::canonical_bare_key(authority.full_jid)? != authority.actor_scope
        || authority.nick.is_empty()
        || authority.nick.len() > MAX_MUC_NICK_BYTES
        || !matches!(
            authority.expected_role,
            "moderator" | "participant" | "visitor"
        )
        || !matches!(
            authority.expected_affiliation,
            "owner" | "admin" | "member" | "outcast" | "none"
        )
    {
        return Ok(MucAuthorityCheck::Unauthorized);
    }

    lock_muc_affiliation_namespace(transaction, room_id).await?;
    #[cfg(test)]
    maybe_pause_muc_authorization_for_test("discussion_after_advisory").await;
    let room = sqlx::query(
        "SELECT room_epoch,members_only,destroyed_at,configuration_state
           FROM muc_rooms WHERE id=$1 FOR UPDATE",
    )
    .bind(room_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(room) = room else {
        return Ok(MucAuthorityCheck::Stale);
    };
    if room
        .get::<Option<DateTime<Utc>>, _>("destroyed_at")
        .is_some()
        || room.get::<String, _>("configuration_state") != "active"
        || room.get::<Uuid, _>("room_epoch") != authority.expected_room_epoch
    {
        return Ok(MucAuthorityCheck::Stale);
    }

    // Cluster writers lock room -> actor occupancy -> affiliation.  Follow
    // that order here as well; otherwise a demotion could hold the occupancy
    // row while waiting for the affiliation row that admission already held.
    let cluster_occupancy = if let Some(target) = authority.cluster_target.as_ref() {
        let row = sqlx::query(
            "SELECT identity_kind,local_user_id,bare_jid,full_jid,nick,
                    authenticated_domain,role,affiliation
               FROM cluster_muc_occupancies
              WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
                AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
                AND connection_uuid=$7 AND connection_epoch=$8
                AND state='active' AND lease_until>clock_timestamp()
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
        .fetch_optional(&mut **transaction)
        .await?;
        let Some(row) = row else {
            return Ok(MucAuthorityCheck::Unauthorized);
        };
        Some(row)
    } else {
        None
    };

    let (current_affiliation, principal_matches) = match &authority.principal {
        MucActorPrincipal::Local {
            user_id,
            local_domain,
        } => {
            let local_domain = crate::jid::prepare_domainpart(local_domain)?;
            let username: Option<String> = sqlx::query_scalar(
                "SELECT username FROM users WHERE id=$1 AND NOT is_disabled FOR SHARE",
            )
            .bind(user_id)
            .fetch_optional(&mut **transaction)
            .await?;
            let principal_matches = username.is_some_and(|username| {
                crate::jid::CanonicalJid::parse_bare(authority.actor_scope).is_ok_and(|actor| {
                    actor.localpart() == Some(username.as_str())
                        && actor.domainpart() == local_domain
                        && actor.resourcepart().is_none()
                })
            });
            let affiliation: Option<String> = sqlx::query_scalar(
                "SELECT affiliation FROM muc_affiliations
                  WHERE room_id=$1 AND user_id=$2 FOR UPDATE",
            )
            .bind(room_id)
            .bind(user_id)
            .fetch_optional(&mut **transaction)
            .await?;
            (
                affiliation.unwrap_or_else(|| "none".to_owned()),
                principal_matches,
            )
        }
        MucActorPrincipal::Federated {
            bare_jid,
            authenticated_domain,
        } => {
            let actor = crate::jid::CanonicalJid::parse_bare(bare_jid)?;
            let authenticated_domain = crate::jid::prepare_domainpart(authenticated_domain)?;
            let principal_matches = actor.localpart().is_some()
                && actor.resourcepart().is_none()
                && actor.to_string() == *bare_jid
                && actor.to_string() == authority.actor_scope
                && actor.domainpart() == authenticated_domain;
            let affiliation: Option<String> = sqlx::query_scalar(
                "SELECT affiliation FROM muc_external_affiliations
                  WHERE room_id=$1 AND jid=$2 FOR UPDATE",
            )
            .bind(room_id)
            .bind(actor.to_string())
            .fetch_optional(&mut **transaction)
            .await?;
            (
                affiliation.unwrap_or_else(|| "none".to_owned()),
                principal_matches,
            )
        }
    };
    if !principal_matches
        || current_affiliation != authority.expected_affiliation
        || current_affiliation == "outcast"
        || (room.get::<bool, _>("members_only") && current_affiliation == "none")
    {
        return Ok(MucAuthorityCheck::Unauthorized);
    }

    if let Some(row) = cluster_occupancy {
        let occupancy_principal_matches = match &authority.principal {
            MucActorPrincipal::Local {
                user_id,
                local_domain,
            } => {
                let local_domain = crate::jid::prepare_domainpart(local_domain)?;
                row.get::<String, _>("identity_kind") == "local"
                    && row.get::<Option<Uuid>, _>("local_user_id") == Some(*user_id)
                    && row.get::<String, _>("bare_jid") == authority.actor_scope
                    && crate::jid::CanonicalJid::parse_bare(authority.actor_scope)
                        .is_ok_and(|actor| actor.domainpart() == local_domain)
                    && row
                        .get::<Option<String>, _>("authenticated_domain")
                        .is_none()
            }
            MucActorPrincipal::Federated {
                bare_jid,
                authenticated_domain,
            } => {
                row.get::<String, _>("identity_kind") == "federated"
                    && row.get::<Option<Uuid>, _>("local_user_id").is_none()
                    && row.get::<String, _>("bare_jid") == *bare_jid
                    && row
                        .get::<Option<String>, _>("authenticated_domain")
                        .as_deref()
                        == Some(*authenticated_domain)
            }
        };
        if !occupancy_principal_matches
            || row.get::<String, _>("bare_jid") != authority.actor_scope
            || row.get::<String, _>("full_jid") != authority.full_jid
            || row.get::<String, _>("nick") != authority.nick
            || row.get::<String, _>("role") != authority.expected_role
            || row.get::<String, _>("affiliation") != current_affiliation
        {
            return Ok(MucAuthorityCheck::Unauthorized);
        }
    }

    Ok(MucAuthorityCheck::Authorized(LockedMucActor {
        role: authority.expected_role.to_owned(),
        affiliation: current_affiliation,
    }))
}

pub async fn get_or_create_muc_room(
    pool: &PgPool,
    localpart: &str,
    creator_id: Uuid,
    creator_full_jid: &str,
) -> Result<(MucRoom, bool)> {
    let creator_full_jid = crate::jid::canonicalize(creator_full_jid)?;
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
    let creator = crate::jid::CanonicalJid::parse(creator_full_jid)?;
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

pub async fn muc_affiliation(
    pool: &PgPool,
    room_id: Uuid,
    user_id: Uuid,
) -> Result<Option<String>> {
    sqlx::query_scalar(
        "SELECT affiliation FROM muc_affiliations WHERE room_id = $1 AND user_id = $2",
    )
    .bind(room_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(Into::into)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucRegistrationOutcome {
    Registered { affiliation_changed: bool },
    Conflict,
    Outcast,
}

/// Return the nickname reserved by a local user's room registration.
pub async fn muc_reserved_nick(
    pool: &PgPool,
    room_id: Uuid,
    user_id: Uuid,
) -> Result<Option<String>> {
    sqlx::query_scalar(
        "SELECT reserved_nick FROM muc_affiliations
          WHERE room_id=$1 AND user_id=$2 AND reserved_nick IS NOT NULL",
    )
    .bind(room_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(Into::into)
}

pub async fn federated_muc_reserved_nick(
    pool: &PgPool,
    room_id: Uuid,
    actor_bare_jid: &str,
) -> Result<Option<String>> {
    let actor = crate::jid::CanonicalJid::parse_bare(actor_bare_jid)?;
    sqlx::query_scalar(
        "SELECT reserved_nick FROM muc_external_affiliations
          WHERE room_id=$1 AND jid=$2 AND reserved_nick IS NOT NULL",
    )
    .bind(room_id)
    .bind(actor.to_string())
    .fetch_optional(pool)
    .await
    .map_err(Into::into)
}

/// Atomically register a local account as a room member and reserve its
/// nickname.  The room-wide advisory lock serializes the cross-table
/// uniqueness check for local and federated registrations.
pub async fn register_local_muc_member(
    pool: &PgPool,
    room_id: Uuid,
    user_id: Uuid,
    nick: &str,
) -> Result<MucRegistrationOutcome> {
    anyhow::ensure!(
        !nick.is_empty() && nick.len() <= MAX_MUC_NICK_BYTES,
        "reserved MUC nickname must contain 1 to 128 bytes"
    );
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 23))")
        .bind(room_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 FOR UPDATE",
    )
    .bind(room_id)
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if existing.as_deref() == Some("outcast") {
        transaction.rollback().await?;
        return Ok(MucRegistrationOutcome::Outcast);
    }
    let affiliation_changed = existing.is_none();
    let conflict: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM muc_affiliations
              WHERE room_id=$1 AND reserved_nick=$2 AND user_id<>$3
             UNION ALL
             SELECT 1 FROM muc_external_affiliations
              WHERE room_id=$1 AND reserved_nick=$2
         )",
    )
    .bind(room_id)
    .bind(nick)
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await?;
    if conflict {
        transaction.rollback().await?;
        return Ok(MucRegistrationOutcome::Conflict);
    }
    sqlx::query(
        "INSERT INTO muc_affiliations(room_id,user_id,affiliation,reserved_nick,updated_at)
         VALUES($1,$2,'member',$3,NOW())
         ON CONFLICT(room_id,user_id) DO UPDATE SET
           affiliation=CASE
             WHEN muc_affiliations.affiliation IN ('owner','admin')
               THEN muc_affiliations.affiliation
             ELSE 'member'
           END,
           reserved_nick=EXCLUDED.reserved_nick,
           updated_at=NOW()",
    )
    .bind(room_id)
    .bind(user_id)
    .bind(nick)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(MucRegistrationOutcome::Registered {
        affiliation_changed,
    })
}

/// Remove a local room registration without stripping owner/admin powers.
pub async fn unregister_local_muc_member(
    pool: &PgPool,
    room_id: Uuid,
    user_id: Uuid,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 23))")
        .bind(room_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let affiliation: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 FOR UPDATE",
    )
    .bind(room_id)
    .bind(user_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if matches!(affiliation.as_deref(), Some("owner" | "admin" | "outcast")) {
        sqlx::query(
            "UPDATE muc_affiliations SET reserved_nick=NULL,updated_at=NOW()
              WHERE room_id=$1 AND user_id=$2",
        )
        .bind(room_id)
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    } else if affiliation.is_some() {
        sqlx::query("DELETE FROM muc_affiliations WHERE room_id=$1 AND user_id=$2")
            .bind(room_id)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
    }
    let affiliation_changed = affiliation.as_deref() == Some("member");
    transaction.commit().await?;
    Ok(affiliation_changed)
}

pub async fn register_federated_muc_member(
    pool: &PgPool,
    room_id: Uuid,
    actor_bare_jid: &str,
    nick: &str,
) -> Result<MucRegistrationOutcome> {
    let actor = crate::jid::CanonicalJid::parse_bare(actor_bare_jid)?;
    anyhow::ensure!(
        actor.localpart().is_some(),
        "MUC registration requires a user JID"
    );
    anyhow::ensure!(
        !nick.is_empty() && nick.len() <= MAX_MUC_NICK_BYTES,
        "reserved MUC nickname must contain 1 to 128 bytes"
    );
    let actor = actor.to_string();
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 23))")
        .bind(room_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM muc_external_affiliations
          WHERE room_id=$1 AND jid=$2 FOR UPDATE",
    )
    .bind(room_id)
    .bind(&actor)
    .fetch_optional(&mut *transaction)
    .await?;
    if existing.as_deref() == Some("outcast") {
        transaction.rollback().await?;
        return Ok(MucRegistrationOutcome::Outcast);
    }
    let affiliation_changed = existing.is_none();
    let conflict: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM muc_affiliations WHERE room_id=$1 AND reserved_nick=$2
             UNION ALL
             SELECT 1 FROM muc_external_affiliations
              WHERE room_id=$1 AND reserved_nick=$2 AND jid<>$3
         )",
    )
    .bind(room_id)
    .bind(nick)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if conflict {
        transaction.rollback().await?;
        return Ok(MucRegistrationOutcome::Conflict);
    }
    sqlx::query(
        "INSERT INTO muc_external_affiliations(room_id,jid,affiliation,reserved_nick,updated_at)
         VALUES($1,$2,'member',$3,NOW())
         ON CONFLICT(room_id,jid) DO UPDATE SET
           affiliation=CASE
             WHEN muc_external_affiliations.affiliation IN ('owner','admin')
               THEN muc_external_affiliations.affiliation
             ELSE 'member'
           END,
           reserved_nick=EXCLUDED.reserved_nick,
           updated_at=NOW()",
    )
    .bind(room_id)
    .bind(actor)
    .bind(nick)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(MucRegistrationOutcome::Registered {
        affiliation_changed,
    })
}

pub async fn unregister_federated_muc_member(
    pool: &PgPool,
    room_id: Uuid,
    actor_bare_jid: &str,
) -> Result<bool> {
    let actor = crate::jid::CanonicalJid::parse_bare(actor_bare_jid)?.to_string();
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 23))")
        .bind(room_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let affiliation: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM muc_external_affiliations
          WHERE room_id=$1 AND jid=$2 FOR UPDATE",
    )
    .bind(room_id)
    .bind(&actor)
    .fetch_optional(&mut *transaction)
    .await?;
    if matches!(affiliation.as_deref(), Some("owner" | "admin" | "outcast")) {
        sqlx::query(
            "UPDATE muc_external_affiliations SET reserved_nick=NULL,updated_at=NOW()
              WHERE room_id=$1 AND jid=$2",
        )
        .bind(room_id)
        .bind(actor)
        .execute(&mut *transaction)
        .await?;
    } else if affiliation.is_some() {
        sqlx::query("DELETE FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2")
            .bind(room_id)
            .bind(actor)
            .execute(&mut *transaction)
            .await?;
    }
    let affiliation_changed = affiliation.as_deref() == Some("member");
    transaction.commit().await?;
    Ok(affiliation_changed)
}

/// True when `nick` is reserved for another local or federated account.
pub async fn muc_nick_reserved_for_other(
    pool: &PgPool,
    room_id: Uuid,
    user_id: Uuid,
    nick: &str,
) -> Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM muc_affiliations
              WHERE room_id=$1 AND reserved_nick=$2 AND user_id<>$3
             UNION ALL
             SELECT 1 FROM muc_external_affiliations
              WHERE room_id=$1 AND reserved_nick=$2
         )",
    )
    .bind(room_id)
    .bind(nick)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

/// Federated equivalent of `muc_nick_reserved_for_other`.  A remote account
/// may use its own reserved nickname, but never one reserved by a local or a
/// different remote account.
pub async fn federated_muc_nick_reserved_for_other(
    pool: &PgPool,
    room_id: Uuid,
    actor_bare_jid: &str,
    nick: &str,
) -> Result<bool> {
    let actor = crate::jid::CanonicalJid::parse_bare(actor_bare_jid)?;
    anyhow::ensure!(
        actor.localpart().is_some(),
        "a federated MUC registration requires a user bare JID"
    );
    sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM muc_affiliations
              WHERE room_id=$1 AND reserved_nick=$2
             UNION ALL
             SELECT 1 FROM muc_external_affiliations
              WHERE room_id=$1 AND reserved_nick=$2 AND jid<>$3
         )",
    )
    .bind(room_id)
    .bind(nick)
    .bind(actor.to_string())
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableMucInviteOutcome {
    Stored { id: Uuid, affiliation_changed: bool },
    Replay { id: Uuid },
    QuotaExceeded,
    RecipientUnavailable,
    Outcast,
    AuthorityRejected,
    Stale,
}

/// Grant the members-only affiliation inside a caller-owned transaction.
///
/// Capacity locks must already have been acquired by callers that also write
/// a durable C2S projection. This helper takes only the final room/user lock,
/// preserving the global -> account -> room lock order used by every invite
/// admission path. It never commits or rolls back.
pub(crate) async fn grant_local_muc_invite_affiliation_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    id: Uuid,
    room_id: Uuid,
    recipient_id: Uuid,
    cluster_authority: Option<&super::cluster_muc::ClusterMucInviteAuthority>,
) -> Result<DurableMucInviteOutcome> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 17))")
        .bind(format!("{room_id}:{recipient_id}"))
        .execute(&mut **transaction)
        .await?;
    let affiliation_changed = if let Some(authority) = cluster_authority {
        anyhow::ensure!(
            matches!(
                &authority.subject,
                super::cluster_muc::ClusterMucAffiliationSubject::Local {
                    user_id,
                    ..
                } if *user_id == recipient_id
            ),
            "clustered local MUC invite subject does not match recipient"
        );
        match super::cluster_muc::grant_cluster_muc_invitation_in_tx(
            transaction,
            room_id,
            authority,
        )
        .await?
        {
            super::cluster_muc::ClusterMucAffiliationMutationOutcome::Applied {
                affiliation_changed,
            } => affiliation_changed,
            super::cluster_muc::ClusterMucAffiliationMutationOutcome::Replay { .. } => {
                return Ok(DurableMucInviteOutcome::Replay { id });
            }
            super::cluster_muc::ClusterMucAffiliationMutationOutcome::Outcast => {
                return Ok(DurableMucInviteOutcome::Outcast);
            }
            super::cluster_muc::ClusterMucAffiliationMutationOutcome::Stale
            | super::cluster_muc::ClusterMucAffiliationMutationOutcome::Destroyed => {
                return Ok(DurableMucInviteOutcome::Stale);
            }
            super::cluster_muc::ClusterMucAffiliationMutationOutcome::Conflict
            | super::cluster_muc::ClusterMucAffiliationMutationOutcome::NotAllowed
            | super::cluster_muc::ClusterMucAffiliationMutationOutcome::Unauthorized => {
                return Ok(DurableMucInviteOutcome::AuthorityRejected);
            }
        }
    } else {
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 FOR UPDATE",
        )
        .bind(room_id)
        .bind(recipient_id)
        .fetch_optional(&mut **transaction)
        .await?;
        if existing.as_deref() == Some("outcast") {
            return Ok(DurableMucInviteOutcome::Outcast);
        }
        let affiliation_changed = existing.is_none();
        sqlx::query(
            "INSERT INTO muc_affiliations(room_id,user_id,affiliation,updated_at) VALUES($1,$2,'member',NOW()) ON CONFLICT(room_id,user_id) DO NOTHING",
        )
        .bind(room_id)
        .bind(recipient_id)
        .execute(&mut **transaction)
        .await?;
        affiliation_changed
    };
    Ok(DurableMucInviteOutcome::Stored {
        id,
        affiliation_changed,
    })
}

/// Atomically grant a local members-only affiliation and persist the invite
/// in the existing offline queue. The caller may deliver the durable row
/// online and let the owning transport delete it after its write boundary; a
/// crash at any point therefore yields either no affiliation/invite or an
/// affiliation plus a recoverable at-least-once invite.
#[allow(clippy::too_many_arguments)]
pub async fn admit_local_muc_invite(
    pool: &PgPool,
    id: Uuid,
    room_id: Uuid,
    recipient_id: Uuid,
    recipient_bare_jid: &str,
    sender_jid: &str,
    stanza: &str,
    encrypted: bool,
    policy: super::OfflineStorePolicy,
    cluster_authority: Option<&super::cluster_muc::ClusterMucInviteAuthority>,
) -> Result<DurableMucInviteOutcome> {
    let mut transaction = pool.begin().await?;
    if !super::lock_enabled_users_in_transaction(&mut transaction, &[recipient_id]).await? {
        transaction.rollback().await?;
        return Ok(DurableMucInviteOutcome::RecipientUnavailable);
    }
    let recipient_bare_jid = crate::jid::canonicalize_bare(recipient_bare_jid)?;
    let recipient_username = sqlx::query_scalar::<_, String>(
        "SELECT username FROM users WHERE id=$1 AND NOT is_disabled FOR SHARE",
    )
    .bind(recipient_id)
    .fetch_optional(&mut *transaction)
    .await?
    .context("local MUC invite recipient account is unavailable")?;
    let recipient_authority = crate::jid::CanonicalJid::parse_bare(&recipient_bare_jid)?;
    anyhow::ensure!(
        recipient_authority.localpart() == Some(recipient_username.as_str()),
        "local MUC invite recipient authority does not own recipient account"
    );
    let document = roxmltree::Document::parse(stanza)?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "message",
        "MUC invite is not a message"
    );
    let target = crate::jid::CanonicalJid::parse(
        root.attribute("to")
            .context("local MUC invite is missing to")?,
    )?;
    anyhow::ensure!(
        target.bare() == recipient_bare_jid,
        "local MUC invite target does not match recipient authority"
    );
    let target_resource = if root.attribute("type").unwrap_or("normal") == "normal" {
        target.resourcepart().map(str::to_owned)
    } else {
        None
    };
    sqlx::query("SELECT pg_advisory_xact_lock_shared(5645368709120102)")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 3))")
        .bind(recipient_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let affiliation = grant_local_muc_invite_affiliation_in_transaction(
        &mut transaction,
        id,
        room_id,
        recipient_id,
        cluster_authority,
    )
    .await?;
    let affiliation_changed = match affiliation {
        DurableMucInviteOutcome::Stored {
            affiliation_changed,
            ..
        } => affiliation_changed,
        DurableMucInviteOutcome::Replay { .. } => {
            transaction.commit().await?;
            return Ok(affiliation);
        }
        DurableMucInviteOutcome::QuotaExceeded | DurableMucInviteOutcome::RecipientUnavailable => {
            unreachable!("affiliation does not check account availability or quota")
        }
        DurableMucInviteOutcome::Outcast
        | DurableMucInviteOutcome::AuthorityRejected
        | DurableMucInviteOutcome::Stale => {
            transaction.rollback().await?;
            return Ok(affiliation);
        }
    };
    {
        sqlx::query(
            "WITH expired AS MATERIALIZED (
                 SELECT message.id FROM offline_messages message
                  WHERE message.recipient_id=$1
                    AND COALESCE(
                        (SELECT retention.offline_message_days
                           FROM user_retention_policies retention
                          WHERE retention.user_id=$1),NULLIF($2::BIGINT,0)
                    ) IS NOT NULL
                    AND message.created_at < clock_timestamp()-(
                        COALESCE(
                            (SELECT retention.offline_message_days
                               FROM user_retention_policies retention
                              WHERE retention.user_id=$1),NULLIF($2::BIGINT,0)
                        )::BIGINT*INTERVAL '1 day')
                    AND (message.delivery_claim_id IS NULL
                         OR message.delivery_claim_expires_at<=clock_timestamp())
                    AND NOT EXISTS (
                        SELECT 1 FROM sm_resume_stanzas sm
                         WHERE sm.delivery_message_id=message.id
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM bosh_delivery_fences bosh
                         WHERE bosh.message_id=message.id
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM legal_holds hold
                         WHERE hold.released_at IS NULL AND (
                             EXISTS (SELECT 1 FROM legal_hold_offline_messages link
                                      WHERE link.hold_id=hold.id AND link.message_id=message.id)
                             OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                                        WHERE scope_link.hold_id=hold.id
                                          AND scope_link.scope_type='offline_message_recipient'
                                          AND scope_link.subject_id=message.recipient_id)
                         )
                    )
                  FOR UPDATE OF message SKIP LOCKED
             )
             DELETE FROM offline_messages message USING expired
              WHERE message.id=expired.id",
        )
        .bind(recipient_id)
        .bind(policy.ttl_days)
        .execute(&mut *transaction)
        .await?;
    }
    let (current_messages, current_bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*)::BIGINT, COALESCE(SUM(octet_length(stanza)),0)::BIGINT FROM offline_messages WHERE recipient_id=$1",
    )
    .bind(recipient_id)
    .fetch_one(&mut *transaction)
    .await?;
    let stanza_bytes = i64::try_from(stanza.len()).unwrap_or(i64::MAX);
    if current_messages >= policy.max_messages
        || current_bytes
            .checked_add(stanza_bytes)
            .is_none_or(|projected| projected > policy.max_bytes)
    {
        transaction.rollback().await?;
        return Ok(DurableMucInviteOutcome::QuotaExceeded);
    }
    sqlx::query(
        "INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,target_resource,encrypted) VALUES($1,$2,$3,$4,$5,$6)",
    )
    .bind(id)
    .bind(recipient_id)
    .bind(sender_jid)
    .bind(stanza)
    .bind(target_resource)
    .bind(encrypted)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(DurableMucInviteOutcome::Stored {
        id,
        affiliation_changed,
    })
}

/// Federated members-only invitation admission uses the same transaction for
/// the affiliation and the durable S2S outbox row.
#[allow(clippy::too_many_arguments)]
pub async fn admit_federated_muc_invite(
    pool: &PgPool,
    room_id: Uuid,
    invitee_bare_jid: &str,
    target_domain: &str,
    stanza: &str,
    bounce_to: Option<&str>,
    policy: super::S2sOutboxPolicy,
    cluster_authority: Option<&super::cluster_muc::ClusterMucInviteAuthority>,
) -> Result<bool> {
    let invitee = crate::jid::CanonicalJid::parse_bare(invitee_bare_jid)?;
    anyhow::ensure!(
        invitee.localpart().is_some(),
        "MUC invitee requires a user JID"
    );
    let invitee = invitee.to_string();
    let mut transaction = pool.begin().await?;
    // The S2S outbox has one global capacity lock. Acquire it before the
    // room/user lock so personal-history + outbox admissions can append the
    // same room mutation without creating an outbox <-> room inversion.
    if let Err(error) = super::enqueue_s2s_outbox_in_transaction(
        &mut transaction,
        target_domain,
        stanza,
        bounce_to,
        policy,
    )
    .await
    {
        transaction.rollback().await?;
        return Err(error);
    }
    let affiliation = match grant_federated_muc_invite_affiliation_in_transaction(
        &mut transaction,
        room_id,
        &invitee,
        cluster_authority,
    )
    .await
    {
        Ok(affiliation) => affiliation,
        Err(error) => {
            transaction.rollback().await?;
            return Err(error);
        }
    };
    match affiliation {
        FederatedMucInviteAffiliationOutcome::Stored => {
            transaction.commit().await?;
            Ok(true)
        }
        FederatedMucInviteAffiliationOutcome::Replay => {
            // The authority operation is already durable. Roll back the
            // speculative outbox row allocated before replay detection.
            transaction.rollback().await?;
            Ok(true)
        }
        FederatedMucInviteAffiliationOutcome::Rejected => {
            transaction.rollback().await?;
            Ok(false)
        }
        FederatedMucInviteAffiliationOutcome::Stale => {
            transaction.rollback().await?;
            anyhow::bail!("clustered federated MUC invitation authority is stale")
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FederatedMucInviteAffiliationOutcome {
    Stored,
    Replay,
    Rejected,
    Stale,
}

/// Apply only the federated member authorization mutation in a caller-owned
/// transaction. Callers that also enqueue S2S must acquire the outbox lock
/// first; this helper then appends the final room/invitee lock.
pub(crate) async fn grant_federated_muc_invite_affiliation_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    invitee_bare_jid: &str,
    cluster_authority: Option<&super::cluster_muc::ClusterMucInviteAuthority>,
) -> Result<FederatedMucInviteAffiliationOutcome> {
    let invitee = crate::jid::CanonicalJid::parse_bare(invitee_bare_jid)?;
    anyhow::ensure!(
        invitee.localpart().is_some(),
        "MUC invitee requires a user JID"
    );
    let invitee = invitee.to_string();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 17))")
        .bind(format!("{room_id}:{invitee}"))
        .execute(&mut **transaction)
        .await?;
    if let Some(authority) = cluster_authority {
        anyhow::ensure!(
            matches!(
                &authority.subject,
                super::cluster_muc::ClusterMucAffiliationSubject::Federated { bare_jid }
                    if bare_jid == &invitee
            ),
            "clustered federated MUC invite subject does not match recipient"
        );
        match super::cluster_muc::grant_cluster_muc_invitation_in_tx(
            transaction,
            room_id,
            authority,
        )
        .await?
        {
            super::cluster_muc::ClusterMucAffiliationMutationOutcome::Applied { .. } => {}
            super::cluster_muc::ClusterMucAffiliationMutationOutcome::Replay { .. } => {
                return Ok(FederatedMucInviteAffiliationOutcome::Replay);
            }
            super::cluster_muc::ClusterMucAffiliationMutationOutcome::Outcast
            | super::cluster_muc::ClusterMucAffiliationMutationOutcome::Conflict
            | super::cluster_muc::ClusterMucAffiliationMutationOutcome::NotAllowed
            | super::cluster_muc::ClusterMucAffiliationMutationOutcome::Unauthorized => {
                return Ok(FederatedMucInviteAffiliationOutcome::Rejected);
            }
            super::cluster_muc::ClusterMucAffiliationMutationOutcome::Stale
            | super::cluster_muc::ClusterMucAffiliationMutationOutcome::Destroyed => {
                return Ok(FederatedMucInviteAffiliationOutcome::Stale);
            }
        }
    } else {
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT affiliation FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2 FOR UPDATE",
        )
        .bind(room_id)
        .bind(&invitee)
        .fetch_optional(&mut **transaction)
        .await?;
        if existing.as_deref() == Some("outcast") {
            return Ok(FederatedMucInviteAffiliationOutcome::Rejected);
        }
        sqlx::query(
            "INSERT INTO muc_external_affiliations(room_id,jid,affiliation,updated_at) VALUES($1,$2,'member',NOW()) ON CONFLICT(room_id,jid) DO NOTHING",
        )
        .bind(room_id)
        .bind(&invitee)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(FederatedMucInviteAffiliationOutcome::Stored)
}

pub async fn federated_muc_affiliation(
    pool: &PgPool,
    room_id: Uuid,
    bare_jid: &str,
) -> Result<Option<String>> {
    let jid = crate::jid::CanonicalJid::parse_bare(bare_jid)?;
    anyhow::ensure!(
        jid.localpart().is_some(),
        "a federated MUC affiliation requires a user bare JID"
    );
    sqlx::query_scalar(
        "SELECT affiliation FROM muc_external_affiliations WHERE room_id = $1 AND jid = $2",
    )
    .bind(room_id)
    .bind(jid.to_string())
    .fetch_optional(pool)
    .await
    .map_err(Into::into)
}

/// Admit one room discussion stanza.  With an XEP-0359 origin-id, the room,
/// canonical actor scope and exact origin-id form an idempotency key.  The
/// SHA-256 value is only an index accelerator: a conflicting row is always
/// compared byte-for-byte before it is accepted as a replay.
pub async fn admit_muc_discussion(
    pool: &PgPool,
    message: MucDiscussion<'_>,
) -> Result<MucDiscussionAdmission> {
    let actor_scope = canonical_history_actor(message.actor_scope)?;
    let sender_jid = canonical_history_sender(message.sender_jid)?;
    validate_history_payload(message.nick, message.stanza)?;
    let mut transaction = pool.begin().await?;
    #[cfg(test)]
    maybe_pause_muc_authorization_for_test("discussion").await;
    if message.authority.actor_scope != actor_scope
        || message.authority.full_jid != sender_jid
        || message.authority.nick != message.nick
    {
        transaction.rollback().await?;
        return Ok(MucDiscussionAdmission::Unauthorized);
    }
    match lock_muc_actor_authority(&mut transaction, message.room_id, &message.authority).await? {
        MucAuthorityCheck::Authorized(actor) if actor.role != "visitor" => {}
        MucAuthorityCheck::Authorized(_) | MucAuthorityCheck::Unauthorized => {
            transaction.rollback().await?;
            return Ok(MucDiscussionAdmission::Unauthorized);
        }
        MucAuthorityCheck::Stale => {
            transaction.rollback().await?;
            return Ok(MucDiscussionAdmission::Stale);
        }
    }

    let Some(origin_id) = message.origin_id else {
        if message.archive {
            sqlx::query(
                "INSERT INTO muc_messages
                 (id, room_id, sender_jid, nick, stanza, encrypted, message_kind, actor_scope)
                 VALUES ($1, $2, $3, $4, $5, $6, 'discussion', $7)",
            )
            .bind(message.id)
            .bind(message.room_id)
            .bind(&sender_jid)
            .bind(message.nick)
            .bind(message.stanza)
            .bind(message.encrypted)
            .bind(&actor_scope)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        return Ok(MucDiscussionAdmission::Stored(message.id));
    };
    validate_origin_id(origin_id)?;
    let digest = muc_origin_digest(&actor_scope, origin_id);
    let inserted = sqlx::query(
        "INSERT INTO muc_origin_admissions
         (room_id, origin_digest, actor_scope, origin_id, stanza_id)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (room_id, origin_digest) DO NOTHING",
    )
    .bind(message.room_id)
    .bind(&digest)
    .bind(&actor_scope)
    .bind(origin_id)
    .bind(message.id)
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        == 1;
    if inserted {
        if message.archive {
            sqlx::query(
                "INSERT INTO muc_messages
                 (id, room_id, sender_jid, nick, stanza, encrypted, message_kind,
                  actor_scope, origin_id, origin_digest)
                 VALUES ($1, $2, $3, $4, $5, $6, 'discussion', $7, $8, $9)",
            )
            .bind(message.id)
            .bind(message.room_id)
            .bind(&sender_jid)
            .bind(message.nick)
            .bind(message.stanza)
            .bind(message.encrypted)
            .bind(&actor_scope)
            .bind(origin_id)
            .bind(&digest)
            .execute(&mut *transaction)
            .await?;
        }
        if message.retention_days > 0 {
            sqlx::query(
                "WITH expired AS MATERIALIZED (
                     SELECT origin_digest FROM muc_origin_admissions
                     WHERE room_id=$1
                       AND created_at < NOW() - ($2 * INTERVAL '1 day')
                     ORDER BY created_at, origin_digest
                     LIMIT 1000 FOR UPDATE SKIP LOCKED
                 )
                 DELETE FROM muc_origin_admissions admission
                 USING expired
                 WHERE admission.room_id=$1
                   AND admission.origin_digest=expired.origin_digest",
            )
            .bind(message.room_id)
            .bind(message.retention_days)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        return Ok(MucDiscussionAdmission::Stored(message.id));
    }

    let existing = sqlx::query(
        "SELECT stanza_id, actor_scope, origin_id FROM muc_origin_admissions
         WHERE room_id=$1 AND origin_digest=$2
         FOR SHARE",
    )
    .bind(message.room_id)
    .bind(&digest)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(existing) = existing else {
        anyhow::bail!("MUC origin-id conflict row disappeared during admission");
    };
    let existing_actor: Option<String> = existing.get("actor_scope");
    let existing_origin: Option<String> = existing.get("origin_id");
    anyhow::ensure!(
        existing_actor.as_deref() == Some(actor_scope.as_str())
            && existing_origin.as_deref() == Some(origin_id),
        "MUC origin-id digest collision"
    );
    let existing_id: Uuid = existing.get("stanza_id");
    transaction.commit().await?;
    Ok(MucDiscussionAdmission::Replay(existing_id))
}

/// Change a single-node room subject under the same database authority fence
/// as discussion and retraction admission. The optional MAM projection is in
/// the same transaction, so a failed archive insert cannot leave a subject
/// that history cannot explain. Plaintext subjects may still update room state
/// when encrypted-only archive policy deliberately disables that projection.
pub async fn set_local_muc_subject(
    pool: &PgPool,
    mutation: MucSubjectMutation<'_>,
    archive: bool,
    authority: MucActorAuthority<'_>,
) -> Result<MucSubjectOutcome> {
    let actor_scope = canonical_history_actor(mutation.actor_scope)?;
    let sender_jid = canonical_history_sender(mutation.sender_jid)?;
    validate_history_payload(mutation.nick, mutation.stanza)?;
    anyhow::ensure!(
        mutation.subject.len() <= MAX_HISTORY_STANZA_BYTES,
        "MUC subject exceeds 1048576 bytes"
    );
    if authority.clustered || authority.cluster_target.is_some() {
        return Ok(MucSubjectOutcome::Stale);
    }
    if authority.actor_scope != actor_scope
        || authority.full_jid != sender_jid
        || authority.nick != mutation.nick
    {
        return Ok(MucSubjectOutcome::Unauthorized);
    }

    let mut transaction = pool.begin().await?;
    let locked =
        match lock_muc_actor_authority(&mut transaction, mutation.room_id, &authority).await? {
            MucAuthorityCheck::Authorized(actor) => actor,
            MucAuthorityCheck::Unauthorized => {
                transaction.rollback().await?;
                return Ok(MucSubjectOutcome::Unauthorized);
            }
            MucAuthorityCheck::Stale => {
                transaction.rollback().await?;
                return Ok(MucSubjectOutcome::Stale);
            }
        };
    let allow_subject_change: bool =
        sqlx::query_scalar("SELECT allow_subject_change FROM muc_rooms WHERE id=$1")
            .bind(mutation.room_id)
            .fetch_one(&mut *transaction)
            .await?;
    if locked.role != "moderator" && !(locked.role == "participant" && allow_subject_change) {
        transaction.rollback().await?;
        return Ok(MucSubjectOutcome::Unauthorized);
    }
    let changed = sqlx::query(
        "UPDATE muc_rooms
         SET subject=$2, subject_set_by=$3, subject_stanza_id=$4,
             subject_changed_at=clock_timestamp()
         WHERE id=$1 AND room_epoch=$5 AND destroyed_at IS NULL",
    )
    .bind(mutation.room_id)
    .bind(mutation.subject)
    .bind(&actor_scope)
    .bind(mutation.stanza_id)
    .bind(authority.expected_room_epoch)
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        == 1;
    if !changed {
        transaction.rollback().await?;
        return Ok(MucSubjectOutcome::Stale);
    }
    if archive {
        sqlx::query(
            "INSERT INTO muc_messages
             (id, room_id, sender_jid, nick, stanza, encrypted, message_kind, actor_scope)
             VALUES ($1, $2, $3, $4, $5, $6, 'subject', $7)",
        )
        .bind(mutation.stanza_id)
        .bind(mutation.room_id)
        .bind(sender_jid)
        .bind(mutation.nick)
        .bind(mutation.stanza)
        .bind(mutation.encrypted)
        .bind(actor_scope)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(MucSubjectOutcome::Applied)
}

/// Replace a discussion payload with a tombstone and archive the author
/// retraction or moderator action in the same transaction.  `expected_stanza`
/// makes concurrent actions deterministic: exactly one action can commit.
pub async fn retract_muc_message_and_archive_action(
    pool: &PgPool,
    mutation: MucRetractionMutation<'_>,
) -> Result<MucRetractionOutcome> {
    let actor_scope = canonical_history_actor(mutation.actor_scope)?;
    let sender_jid = canonical_history_sender(mutation.sender_jid)?;
    validate_history_payload(mutation.nick, mutation.tombstone)?;
    validate_history_payload(mutation.nick, mutation.action_stanza)?;
    if let Some(reason) = mutation.reason {
        anyhow::ensure!(
            reason.len() <= MAX_RETRACTION_REASON_BYTES,
            "MUC retraction reason exceeds 4096 bytes"
        );
    }
    let action_kind = match mutation.kind {
        MucRetractionKind::Author => "retraction",
        MucRetractionKind::Moderator => "moderation",
    };

    let mut transaction = pool.begin().await?;
    if mutation.authority.actor_scope != actor_scope
        || mutation.authority.full_jid != sender_jid
        || mutation.authority.nick != mutation.nick
    {
        transaction.rollback().await?;
        return Ok(MucRetractionOutcome::Unauthorized);
    }
    let actor =
        match lock_muc_actor_authority(&mut transaction, mutation.room_id, &mutation.authority)
            .await?
        {
            MucAuthorityCheck::Authorized(actor) => actor,
            MucAuthorityCheck::Unauthorized => {
                transaction.rollback().await?;
                return Ok(MucRetractionOutcome::Unauthorized);
            }
            MucAuthorityCheck::Stale => {
                transaction.rollback().await?;
                return Ok(MucRetractionOutcome::Stale);
            }
        };
    if mutation.kind == MucRetractionKind::Moderator
        && actor.role != "moderator"
        && !matches!(actor.affiliation.as_str(), "owner" | "admin")
    {
        transaction.rollback().await?;
        return Ok(MucRetractionOutcome::Unauthorized);
    }

    let target = sqlx::query(
        "SELECT stanza,actor_scope FROM muc_messages
          WHERE room_id=$1 AND id=$2 AND message_kind='discussion'
            AND retracted_at IS NULL FOR UPDATE",
    )
    .bind(mutation.room_id)
    .bind(mutation.target_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(target) = target else {
        transaction.rollback().await?;
        return Ok(MucRetractionOutcome::Conflict);
    };
    if target.get::<String, _>("stanza") != mutation.expected_stanza
        || (mutation.kind == MucRetractionKind::Author
            && target.get::<Option<String>, _>("actor_scope").as_deref()
                != Some(actor_scope.as_str()))
    {
        transaction.rollback().await?;
        return Ok(if mutation.kind == MucRetractionKind::Author {
            MucRetractionOutcome::Unauthorized
        } else {
            MucRetractionOutcome::Conflict
        });
    }

    let changed = sqlx::query(
        "UPDATE muc_messages
         SET stanza=$4, encrypted=FALSE, retracted_at=NOW(), retracted_by=$5,
             retraction_reason=$6, retraction_action_id=$7
         WHERE room_id=$1 AND id=$2 AND stanza=$3
           AND message_kind='discussion' AND retracted_at IS NULL",
    )
    .bind(mutation.room_id)
    .bind(mutation.target_id)
    .bind(mutation.expected_stanza)
    .bind(mutation.tombstone)
    .bind(&actor_scope)
    .bind(mutation.reason)
    .bind(mutation.action_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        == 1;
    if !changed {
        transaction.rollback().await?;
        return Ok(MucRetractionOutcome::Conflict);
    }
    sqlx::query(
        "INSERT INTO muc_messages
         (id, room_id, sender_jid, nick, stanza, encrypted, message_kind, actor_scope)
         VALUES ($1, $2, $3, $4, $5, FALSE, $6, $7)",
    )
    .bind(mutation.action_id)
    .bind(mutation.room_id)
    .bind(sender_jid)
    .bind(mutation.nick)
    .bind(mutation.action_stanza)
    .bind(action_kind)
    .bind(actor_scope)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(MucRetractionOutcome::Applied)
}

pub async fn muc_message_by_id(
    pool: &PgPool,
    room_id: Uuid,
    message_id: Uuid,
) -> Result<Option<MucMessage>> {
    let row = sqlx::query(
        "SELECT sender_jid, stanza, created_at FROM muc_messages WHERE room_id = $1 AND id = $2 AND retracted_at IS NULL",
    )
    .bind(room_id)
    .bind(message_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| MucMessage {
        sender_jid: row.get("sender_jid"),
        stanza: row.get("stanza"),
        created_at: row.get("created_at"),
    }))
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
    let actor_full_jid = crate::jid::canonicalize(actor_full_jid)?;
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
    let actor_full_jid = crate::jid::canonicalize(actor_full_jid)?;
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

/// Fetch a bounded, chronological suffix of room history, optionally limited
/// by an inclusive UTC lower bound.  A zero limit is meaningful in XEP-0045
/// (`maxstanzas='0'`) and must never be clamped up to one message.
pub async fn muc_history_since(
    pool: &PgPool,
    room_id: Uuid,
    limit: i64,
    since: Option<DateTime<Utc>>,
) -> Result<Vec<MucMessage>> {
    let limit = limit.clamp(0, 100);
    if limit == 0 {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        "SELECT sender_jid, stanza, created_at
          FROM muc_messages
          WHERE room_id = $1
            AND ($3::timestamptz IS NULL OR created_at >= $3)
            AND message_kind <> 'subject'
          ORDER BY created_at DESC, id DESC
          LIMIT $2",
    )
    .bind(room_id)
    .bind(limit)
    .bind(since)
    .fetch_all(pool)
    .await?;
    let mut messages: Vec<MucMessage> = rows
        .iter()
        .map(|row| MucMessage {
            sender_jid: row.get("sender_jid"),
            stanza: row.get("stanza"),
            created_at: row.get("created_at"),
        })
        .collect();
    messages.reverse();
    Ok(messages)
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

/// Hash a room password for storage. XEP-0045 transmits this value inside the
/// TLS-protected XMPP stream, but the server never stores the cleartext value.
pub fn hash_muc_password(password: &str) -> Result<String> {
    if password.is_empty() || password.len() > 1024 {
        anyhow::bail!("room password must contain 1 to 1024 bytes");
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow::anyhow!("room password hashing failed: {error}"))
}

pub fn verify_muc_password(password_hash: &str, candidate: &str) -> bool {
    if candidate.len() > 1024 {
        return false;
    }
    PasswordHash::new(password_hash).ok().is_some_and(|parsed| {
        Argon2::default()
            .verify_password(candidate.as_bytes(), &parsed)
            .is_ok()
    })
}

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

/// Apply every affiliation item from one MUC admin IQ in one transaction.
///
/// XEP-0045 permits multiple `<item/>` children in an admin request.  Applying
/// them through the single-item helpers can otherwise expose a committed
/// prefix when a later item is invalid or would remove the final owner.  The
/// room advisory lock is shared with the single-item paths, so concurrent
/// local and federated administrators observe one serial order.
pub async fn set_muc_affiliations_batch(
    pool: &PgPool,
    room_id: Uuid,
    changes: &[MucAffiliationChange],
) -> Result<MucAffiliationBatchOutcome> {
    if changes.is_empty() {
        return Ok(MucAffiliationBatchOutcome::Applied);
    }

    enum ResolvedTarget {
        Local(Uuid),
        Federated(String),
    }
    struct ResolvedChange {
        target: ResolvedTarget,
        affiliation: String,
    }

    let mut transaction = pool.begin().await?;
    lock_muc_affiliation_namespace(&mut transaction, room_id).await?;

    let mut seen = std::collections::HashSet::with_capacity(changes.len());
    let mut resolved = Vec::with_capacity(changes.len());
    let mut owner_delta = 0_i64;
    for change in changes {
        anyhow::ensure!(
            matches!(
                change.affiliation.as_str(),
                "owner" | "admin" | "member" | "outcast" | "none"
            ),
            "invalid MUC affiliation in atomic batch"
        );
        let (key, target, current) = match &change.target {
            MucAffiliationTarget::LocalUsername(username) => {
                let user_id: Option<Uuid> = sqlx::query_scalar(
                    "SELECT id FROM users
                          WHERE username=$1 AND NOT is_disabled FOR SHARE",
                )
                .bind(username)
                .fetch_optional(&mut *transaction)
                .await?;
                let Some(user_id) = user_id else {
                    transaction.rollback().await?;
                    return Ok(MucAffiliationBatchOutcome::MissingTarget);
                };
                let current: Option<String> = sqlx::query_scalar(
                    "SELECT affiliation FROM muc_affiliations
                      WHERE room_id=$1 AND user_id=$2 FOR UPDATE",
                )
                .bind(room_id)
                .bind(user_id)
                .fetch_optional(&mut *transaction)
                .await?;
                (
                    format!("local:{user_id}"),
                    ResolvedTarget::Local(user_id),
                    current,
                )
            }
            MucAffiliationTarget::FederatedBareJid(jid) => {
                let jid = crate::jid::CanonicalJid::parse_bare(jid)?;
                anyhow::ensure!(
                    jid.localpart().is_some(),
                    "a federated MUC affiliation requires a user bare JID"
                );
                let jid = jid.to_string();
                let current: Option<String> = sqlx::query_scalar(
                    "SELECT affiliation FROM muc_external_affiliations
                      WHERE room_id=$1 AND jid=$2 FOR UPDATE",
                )
                .bind(room_id)
                .bind(&jid)
                .fetch_optional(&mut *transaction)
                .await?;
                (
                    format!("federated:{jid}"),
                    ResolvedTarget::Federated(jid),
                    current,
                )
            }
        };
        if !seen.insert(key) {
            transaction.rollback().await?;
            return Ok(MucAffiliationBatchOutcome::DuplicateTarget);
        }
        if current.as_deref() == Some("owner") && change.affiliation != "owner" {
            owner_delta -= 1;
        } else if current.as_deref() != Some("owner") && change.affiliation == "owner" {
            owner_delta += 1;
        }
        resolved.push(ResolvedChange {
            target,
            affiliation: change.affiliation.clone(),
        });
    }

    let owners: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM muc_affiliations
                  WHERE room_id=$1 AND affiliation='owner')
              + (SELECT COUNT(*) FROM muc_external_affiliations
                  WHERE room_id=$1 AND affiliation='owner')",
    )
    .bind(room_id)
    .fetch_one(&mut *transaction)
    .await?;
    if owners + owner_delta < 1 {
        transaction.rollback().await?;
        return Ok(MucAffiliationBatchOutcome::LastOwner);
    }

    for change in resolved {
        match change.target {
            ResolvedTarget::Local(user_id) => {
                if change.affiliation == "none" {
                    sqlx::query("DELETE FROM muc_affiliations WHERE room_id=$1 AND user_id=$2")
                        .bind(room_id)
                        .bind(user_id)
                        .execute(&mut *transaction)
                        .await?;
                } else {
                    sqlx::query(
                        "INSERT INTO muc_affiliations
                           (room_id, user_id, affiliation, updated_at)
                         VALUES ($1, $2, $3, NOW())
                         ON CONFLICT (room_id, user_id) DO UPDATE SET
                           affiliation = EXCLUDED.affiliation,
                           reserved_nick = CASE WHEN EXCLUDED.affiliation='outcast'
                                                THEN NULL ELSE muc_affiliations.reserved_nick END,
                           updated_at = NOW()",
                    )
                    .bind(room_id)
                    .bind(user_id)
                    .bind(&change.affiliation)
                    .execute(&mut *transaction)
                    .await?;
                }
            }
            ResolvedTarget::Federated(jid) => {
                if change.affiliation == "none" {
                    sqlx::query(
                        "DELETE FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2",
                    )
                    .bind(room_id)
                    .bind(&jid)
                    .execute(&mut *transaction)
                    .await?;
                } else {
                    sqlx::query(
                        "INSERT INTO muc_external_affiliations
                           (room_id, jid, affiliation, updated_at)
                         VALUES ($1, $2, $3, NOW())
                         ON CONFLICT (room_id, jid) DO UPDATE SET
                           affiliation = EXCLUDED.affiliation,
                           reserved_nick = CASE WHEN EXCLUDED.affiliation='outcast'
                                                THEN NULL ELSE muc_external_affiliations.reserved_nick END,
                           updated_at = NOW()",
                    )
                    .bind(room_id)
                    .bind(&jid)
                    .bind(&change.affiliation)
                    .execute(&mut *transaction)
                    .await?;
                }
            }
        }
    }
    transaction.commit().await?;
    Ok(MucAffiliationBatchOutcome::Applied)
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
    let jid = crate::jid::CanonicalJid::parse_bare(bare_jid)?;
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

enum LocalAdminPrincipalCheck {
    Authorized {
        members_only: bool,
        non_anonymous: bool,
    },
    Unauthorized,
    Stale,
}

async fn lock_local_admin_principal(
    transaction: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    user_id: Uuid,
    actor_scope: &str,
    local_domain: &str,
) -> Result<LocalAdminPrincipalCheck> {
    let local_domain = crate::jid::prepare_domainpart(local_domain)?;
    // Namespace 29 precedes every room/affiliation row lock.  See
    // `lock_muc_actor_authority` for the global writer lock order.
    lock_muc_affiliation_namespace(transaction, room_id).await?;
    let room = sqlx::query(
        "SELECT room_epoch,members_only,non_anonymous,destroyed_at,configuration_state
           FROM muc_rooms WHERE id=$1 FOR UPDATE",
    )
    .bind(room_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(room) = room else {
        return Ok(LocalAdminPrincipalCheck::Stale);
    };
    if room
        .get::<Option<DateTime<Utc>>, _>("destroyed_at")
        .is_some()
        || room.get::<String, _>("configuration_state") != "active"
        || room.get::<Uuid, _>("room_epoch") != expected_room_epoch
    {
        return Ok(LocalAdminPrincipalCheck::Stale);
    }
    let username: Option<String> =
        sqlx::query_scalar("SELECT username FROM users WHERE id=$1 AND NOT is_disabled FOR SHARE")
            .bind(user_id)
            .fetch_optional(&mut **transaction)
            .await?;
    let actor = crate::jid::CanonicalJid::parse_bare(actor_scope)?;
    if username.as_deref() != actor.localpart()
        || actor.domainpart() != local_domain
        || actor.resourcepart().is_some()
        || actor.to_string() != actor_scope
    {
        return Ok(LocalAdminPrincipalCheck::Unauthorized);
    }
    Ok(LocalAdminPrincipalCheck::Authorized {
        members_only: room.get("members_only"),
        non_anonymous: room.get("non_anonymous"),
    })
}

async fn lock_local_admin_affiliation(
    transaction: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    user_id: Uuid,
) -> Result<String> {
    let affiliation: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM muc_affiliations
          WHERE room_id=$1 AND user_id=$2 FOR UPDATE",
    )
    .bind(room_id)
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(affiliation.unwrap_or_else(|| "none".to_owned()))
}

#[allow(clippy::too_many_arguments)]
pub async fn authorized_muc_admin_role_list(
    pool: &PgPool,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    user_id: Uuid,
    actor_scope: &str,
    local_domain: &str,
    asserted_local_role: &str,
    actor_target: Option<&super::cluster_muc::ClusterMucOccupancyTarget>,
    clustered: bool,
    requested_role: &str,
) -> Result<MucAdminSnapshot<MucAdminRoleList>> {
    anyhow::ensure!(
        matches!(requested_role, "moderator" | "participant" | "visitor"),
        "invalid MUC admin role list"
    );
    anyhow::ensure!(
        matches!(
            asserted_local_role,
            "moderator" | "participant" | "visitor" | "none"
        ),
        "invalid asserted MUC requester role"
    );
    let actor_scope = canonical_history_actor(actor_scope)?;
    let mut transaction = pool.begin().await?;
    #[cfg(test)]
    maybe_pause_muc_authorization_for_test("admin_role").await;
    let non_anonymous = match lock_local_admin_principal(
        &mut transaction,
        room_id,
        expected_room_epoch,
        user_id,
        &actor_scope,
        local_domain,
    )
    .await?
    {
        LocalAdminPrincipalCheck::Authorized { non_anonymous, .. } => non_anonymous,
        LocalAdminPrincipalCheck::Unauthorized => {
            transaction.rollback().await?;
            return Ok(MucAdminSnapshot::Unauthorized);
        }
        LocalAdminPrincipalCheck::Stale => {
            transaction.rollback().await?;
            return Ok(MucAdminSnapshot::Stale);
        }
    };

    let clustered_actor = if clustered {
        if let Some(target) = actor_target {
            if target.room_id != room_id || target.room_epoch != expected_room_epoch {
                transaction.rollback().await?;
                return Ok(MucAdminSnapshot::Unauthorized);
            }
            let row = sqlx::query(
                "SELECT role,affiliation FROM cluster_muc_occupancies
                  WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
                    AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
                    AND connection_uuid=$7 AND connection_epoch=$8
                    AND identity_kind='local' AND local_user_id=$9
                    AND bare_jid=$10 AND state='active'
                    AND lease_until>clock_timestamp() FOR UPDATE",
            )
            .bind(target.room_id)
            .bind(target.room_epoch)
            .bind(target.occupant_incarnation)
            .bind(target.occupancy_epoch)
            .bind(&target.full_jid)
            .bind(&target.nick)
            .bind(target.connection_uuid)
            .bind(target.connection_epoch)
            .bind(user_id)
            .bind(&actor_scope)
            .fetch_optional(&mut *transaction)
            .await?;
            row.map(|row| {
                (
                    row.get::<String, _>("role"),
                    row.get::<String, _>("affiliation"),
                )
            })
        } else {
            None
        }
    } else {
        None
    };
    let affiliation = lock_local_admin_affiliation(&mut transaction, room_id, user_id).await?;
    let requester_role = if clustered {
        match clustered_actor {
            Some((role, occupancy_affiliation)) => {
                if occupancy_affiliation != affiliation {
                    transaction.rollback().await?;
                    return Ok(MucAdminSnapshot::Unauthorized);
                }
                role
            }
            // Owners/admins may issue admin IQs without joining the room.  A
            // missing asserted target is therefore represented by role=none;
            // a supplied-but-stale target remains fail closed.
            None if actor_target.is_none() => "none".to_owned(),
            None => {
                transaction.rollback().await?;
                return Ok(MucAdminSnapshot::Unauthorized);
            }
        }
    } else {
        asserted_local_role.to_owned()
    };
    if affiliation == "outcast" {
        transaction.rollback().await?;
        return Ok(MucAdminSnapshot::Unauthorized);
    }
    if requester_role != "moderator" && !matches!(affiliation.as_str(), "owner" | "admin") {
        transaction.rollback().await?;
        return Ok(MucAdminSnapshot::Unauthorized);
    }

    let entries = if clustered {
        sqlx::query(
            "SELECT nick,role,bare_jid FROM cluster_muc_occupancies
              WHERE room_id=$1 AND room_epoch=$2 AND role=$3
                AND state IN ('active','suspended')
                AND lease_until>clock_timestamp()
              ORDER BY nick,occupancy_epoch FOR SHARE",
        )
        .bind(room_id)
        .bind(expected_room_epoch)
        .bind(requested_role)
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .map(|row| MucAdminRoleEntry {
            nick: row.get("nick"),
            role: row.get("role"),
            bare_jid: row.get("bare_jid"),
        })
        .collect()
    } else {
        Vec::new()
    };
    transaction.commit().await?;
    Ok(MucAdminSnapshot::Authorized(MucAdminRoleList {
        requester_role,
        non_anonymous,
        entries,
    }))
}

pub async fn authorized_muc_admin_affiliation_list(
    pool: &PgPool,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    user_id: Uuid,
    actor_scope: &str,
    requested_affiliation: &str,
    local_domain: &str,
) -> Result<MucAdminSnapshot<Vec<MucAdminAffiliationEntry>>> {
    anyhow::ensure!(
        matches!(
            requested_affiliation,
            "owner" | "admin" | "member" | "outcast"
        ),
        "invalid MUC admin affiliation list"
    );
    let local_domain = crate::jid::prepare_domainpart(local_domain)?;
    let actor_scope = canonical_history_actor(actor_scope)?;
    let mut transaction = pool.begin().await?;
    #[cfg(test)]
    maybe_pause_muc_authorization_for_test("admin_affiliation").await;
    let (members_only, non_anonymous) = match lock_local_admin_principal(
        &mut transaction,
        room_id,
        expected_room_epoch,
        user_id,
        &actor_scope,
        &local_domain,
    )
    .await?
    {
        LocalAdminPrincipalCheck::Authorized {
            members_only,
            non_anonymous,
        } => (members_only, non_anonymous),
        LocalAdminPrincipalCheck::Unauthorized => {
            transaction.rollback().await?;
            return Ok(MucAdminSnapshot::Unauthorized);
        }
        LocalAdminPrincipalCheck::Stale => {
            transaction.rollback().await?;
            return Ok(MucAdminSnapshot::Stale);
        }
    };
    let requester_affiliation =
        lock_local_admin_affiliation(&mut transaction, room_id, user_id).await?;
    let authorized = matches!(requester_affiliation.as_str(), "owner" | "admin")
        || (requester_affiliation == "member"
            && members_only
            && non_anonymous
            && matches!(requested_affiliation, "owner" | "admin" | "member"));
    if !authorized {
        transaction.rollback().await?;
        return Ok(MucAdminSnapshot::Unauthorized);
    }
    let mut entries = sqlx::query(
        "SELECT users.username FROM muc_affiliations affiliation
          JOIN users ON users.id=affiliation.user_id
         WHERE affiliation.room_id=$1 AND affiliation.affiliation=$2
         ORDER BY users.username FOR SHARE OF affiliation,users",
    )
    .bind(room_id)
    .bind(requested_affiliation)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .map(|row| MucAdminAffiliationEntry {
        bare_jid: format!("{}@{}", row.get::<String, _>("username"), local_domain),
        affiliation: requested_affiliation.to_owned(),
    })
    .collect::<Vec<_>>();
    entries.extend(
        sqlx::query(
            "SELECT jid FROM muc_external_affiliations
              WHERE room_id=$1 AND affiliation=$2 ORDER BY jid FOR SHARE",
        )
        .bind(room_id)
        .bind(requested_affiliation)
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .map(|row| MucAdminAffiliationEntry {
            bare_jid: row.get("jid"),
            affiliation: requested_affiliation.to_owned(),
        }),
    );
    transaction.commit().await?;
    Ok(MucAdminSnapshot::Authorized(entries))
}

pub async fn get_federated_muc_affiliations(
    pool: &PgPool,
    room_id: Uuid,
    affiliation: &str,
) -> Result<Vec<String>> {
    sqlx::query_scalar(
        "SELECT jid FROM muc_external_affiliations WHERE room_id = $1 AND affiliation = $2 ORDER BY jid",
    )
    .bind(room_id)
    .bind(affiliation)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

pub async fn get_muc_affiliations(
    pool: &PgPool,
    room_id: Uuid,
    affiliation: &str,
) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT u.username FROM muc_affiliations a JOIN users u ON a.user_id = u.id WHERE a.room_id = $1 AND a.affiliation = $2",
    )
    .bind(room_id)
    .bind(affiliation)
    .fetch_all(pool)
    .await?;
    let mut usernames = Vec::with_capacity(rows.len());
    for row in rows {
        usernames.push(row.get::<String, _>("username"));
    }
    Ok(usernames)
}

#[cfg(test)]
mod tests {
    use super::{
        admit_federated_muc_invite, admit_local_muc_invite, admit_muc_discussion,
        authorized_muc_admin_affiliation_list, authorized_muc_admin_role_list,
        cancel_locked_muc_room, delete_expired_locked_muc_room, get_or_create_muc_room,
        hash_muc_password, install_muc_authorization_test_pause, muc_history_since,
        muc_origin_digest, muc_reserved_nick, muc_room, public_muc_room_page,
        register_local_muc_member, retract_muc_message_and_archive_action,
        set_federated_muc_affiliation, set_local_muc_subject, set_muc_affiliation,
        set_muc_affiliations_batch, unregister_local_muc_member, update_muc_config,
        verify_muc_password, DurableMucInviteOutcome, MucActorAuthority, MucActorPrincipal,
        MucAdminSnapshot, MucAffiliationBatchOutcome, MucAffiliationChange, MucAffiliationOutcome,
        MucAffiliationTarget, MucConfigUpdate, MucConfigurationOutcome, MucDiscussion,
        MucDiscussionAdmission, MucRegistrationOutcome, MucRetractionKind, MucRetractionMutation,
        MucRetractionOutcome, MucSubjectMutation, MucSubjectOutcome,
    };
    use crate::db::{OfflineStorePolicy, S2sOutboxPolicy};
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Barrier;
    use uuid::Uuid;

    fn register_isolated_schema_for_harness(schema: &str, owner_token: &str) {
        let log_path = std::env::var_os("XMPP_TEST_CREATED_SCHEMA_LOG").expect(
            "run this ignored database test through scripts/muc-db-wsl.sh so its schema can be recovered after interruption",
        );
        let mut log = OpenOptions::new()
            .append(true)
            .open(log_path)
            .expect("open the harness-owned schema recovery log");
        let record = format!("{schema} {owner_token}\n");
        log.write_all(record.as_bytes())
            .expect("record the isolated MUC test schema");
        log.sync_all()
            .expect("durably flush the isolated MUC test schema record");
    }

    async fn create_harness_owned_schema(admin: &sqlx::PgPool, schema: &str) {
        let owner_token = Uuid::new_v4().simple().to_string();
        register_isolated_schema_for_harness(schema, &owner_token);
        let mut transaction = admin.begin().await.unwrap();
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query(&format!(
            "CREATE TABLE {schema}.northstar_test_schema_guard \
             (singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton), token TEXT NOT NULL)"
        ))
        .execute(&mut *transaction)
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO {schema}.northstar_test_schema_guard(token) VALUES($1)"
        ))
        .bind(owner_token)
        .execute(&mut *transaction)
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }

    fn local_process_authority<'a>(
        room_epoch: Uuid,
        user_id: Uuid,
        actor_scope: &'a str,
        full_jid: &'a str,
        nick: &'a str,
        role: &'a str,
        affiliation: &'a str,
    ) -> MucActorAuthority<'a> {
        MucActorAuthority {
            clustered: false,
            expected_room_epoch: room_epoch,
            principal: MucActorPrincipal::Local {
                user_id,
                local_domain: "local.test",
            },
            actor_scope,
            full_jid,
            nick,
            occupant_incarnation: Uuid::nil(),
            connection_uuid: Uuid::nil(),
            expected_role: role,
            expected_affiliation: affiliation,
            cluster_target: None,
        }
    }

    fn federated_process_authority<'a>(
        room_epoch: Uuid,
        actor_scope: &'a str,
        full_jid: &'a str,
        nick: &'a str,
        authenticated_domain: &'a str,
    ) -> MucActorAuthority<'a> {
        MucActorAuthority {
            clustered: false,
            expected_room_epoch: room_epoch,
            principal: MucActorPrincipal::Federated {
                bare_jid: actor_scope,
                authenticated_domain,
            },
            actor_scope,
            full_jid,
            nick,
            occupant_incarnation: Uuid::nil(),
            connection_uuid: Uuid::nil(),
            expected_role: "participant",
            expected_affiliation: "none",
            cluster_target: None,
        }
    }

    #[test]
    fn room_passwords_are_argon2_hashed_and_verified() {
        let hash = hash_muc_password("cauldron burn").unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(!hash.contains("cauldron burn"));
        assert!(verify_muc_password(&hash, "cauldron burn"));
        assert!(!verify_muc_password(&hash, "wrong"));
    }

    #[test]
    fn room_password_validation_rejects_empty_and_oversized_values() {
        assert!(hash_muc_password("").is_err());
        assert!(hash_muc_password(&"x".repeat(1025)).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn locked_room_configuration_is_atomic_restart_safe_and_bounded() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("muc_lifecycle_test_{}", Uuid::new_v4().simple());
        create_harness_owned_schema(&admin, &schema).await;
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(6)
            .acquire_timeout(Duration::from_secs(60))
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

        let alice_id = Uuid::new_v4();
        let bob_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,username,password_hash) VALUES
             ($1,'lock-alice','test'),($2,'lock-bob','test')",
        )
        .bind(alice_id)
        .bind(bob_id)
        .execute(&pool)
        .await
        .unwrap();
        let alice = "lock-alice@local.test/Phone";
        let bob = "lock-bob@local.test/Tablet";
        let (room, created) = get_or_create_muc_room(&pool, "locked", alice_id, alice)
            .await
            .unwrap();
        assert!(created);
        assert!(room.is_locked());
        assert!(room.can_configure_locked_room(alice, chrono::Utc::now()));
        assert!(!room.can_configure_locked_room(bob, chrono::Utc::now()));
        assert!(public_muc_room_page(&pool, None, None, 100)
            .await
            .unwrap()
            .unwrap()
            .rooms
            .is_empty());

        // A racing second creator observes the locked row and cannot acquire
        // either creation ownership or a visibility window.
        let (same_room, second_created) = get_or_create_muc_room(&pool, "locked", bob_id, bob)
            .await
            .unwrap();
        assert!(!second_created);
        assert_eq!(same_room.id, room.id);
        assert_eq!(same_room.configuration_owner_jid.as_deref(), Some(alice));

        // Recreate the application pool to model a process restart.  The
        // durable lease and exact full-JID authorization survive it.
        pool.close().await;
        let restart_schema = schema.clone();
        let restarted = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {restart_schema}");
                Box::pin(async move {
                    sqlx::query(&statement).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        let after_restart = muc_room(&restarted, "locked").await.unwrap().unwrap();
        assert_eq!(
            after_restart.configuration_owner_jid.as_deref(),
            Some(alice)
        );
        let defaults = |persistent| MucConfigUpdate {
            title: Some("Locked room"),
            description: None,
            persistent,
            members_only: false,
            public: true,
            moderated: false,
            non_anonymous: true,
            max_occupants: 100,
            password_hash: None,
            allow_subject_change: false,
            allow_invites: true,
            allow_private_messages: true,
            logging_enabled: true,
            allow_registration: true,
        };
        assert_eq!(
            update_muc_config(&restarted, room.id, bob, defaults(false))
                .await
                .unwrap(),
            MucConfigurationOutcome::LockedByAnother
        );
        assert_eq!(
            update_muc_config(&restarted, room.id, alice, defaults(true))
                .await
                .unwrap(),
            MucConfigurationOutcome::Applied
        );
        let active = muc_room(&restarted, "locked").await.unwrap().unwrap();
        assert!(!active.is_locked());
        assert!(active.persistent);
        assert_eq!(
            public_muc_room_page(&restarted, None, None, 100)
                .await
                .unwrap()
                .unwrap()
                .rooms
                .len(),
            1
        );

        assert_eq!(
            set_muc_affiliations_batch(
                &restarted,
                room.id,
                &[
                    MucAffiliationChange {
                        target: MucAffiliationTarget::LocalUsername("lock-alice".to_owned()),
                        affiliation: "member".to_owned(),
                    },
                    MucAffiliationChange {
                        target: MucAffiliationTarget::LocalUsername("lock-bob".to_owned()),
                        affiliation: "owner".to_owned(),
                    },
                    MucAffiliationChange {
                        target: MucAffiliationTarget::FederatedBareJid(
                            "admin@remote.test".to_owned(),
                        ),
                        affiliation: "admin".to_owned(),
                    },
                ],
            )
            .await
            .unwrap(),
            MucAffiliationBatchOutcome::Applied
        );
        assert_eq!(
            super::muc_affiliation(&restarted, room.id, bob_id)
                .await
                .unwrap()
                .as_deref(),
            Some("owner")
        );
        assert_eq!(
            super::federated_muc_affiliation(&restarted, room.id, "admin@remote.test")
                .await
                .unwrap()
                .as_deref(),
            Some("admin")
        );

        // A multi-item request that would remove the final owner rolls back
        // every local and federated item rather than exposing a prefix.
        assert_eq!(
            set_muc_affiliations_batch(
                &restarted,
                room.id,
                &[
                    MucAffiliationChange {
                        target: MucAffiliationTarget::LocalUsername("lock-bob".to_owned()),
                        affiliation: "member".to_owned(),
                    },
                    MucAffiliationChange {
                        target: MucAffiliationTarget::LocalUsername("lock-alice".to_owned()),
                        affiliation: "none".to_owned(),
                    },
                    MucAffiliationChange {
                        target: MucAffiliationTarget::FederatedBareJid(
                            "admin@remote.test".to_owned(),
                        ),
                        affiliation: "none".to_owned(),
                    },
                ],
            )
            .await
            .unwrap(),
            MucAffiliationBatchOutcome::LastOwner
        );
        assert_eq!(
            super::muc_affiliation(&restarted, room.id, bob_id)
                .await
                .unwrap()
                .as_deref(),
            Some("owner")
        );
        assert_eq!(
            super::muc_affiliation(&restarted, room.id, alice_id)
                .await
                .unwrap()
                .as_deref(),
            Some("member")
        );

        // A missing or repeated target is rejected before any mutation.
        for (changes, outcome) in [
            (
                vec![
                    MucAffiliationChange {
                        target: MucAffiliationTarget::LocalUsername("lock-alice".to_owned()),
                        affiliation: "admin".to_owned(),
                    },
                    MucAffiliationChange {
                        target: MucAffiliationTarget::LocalUsername("missing".to_owned()),
                        affiliation: "member".to_owned(),
                    },
                ],
                MucAffiliationBatchOutcome::MissingTarget,
            ),
            (
                vec![
                    MucAffiliationChange {
                        target: MucAffiliationTarget::LocalUsername("lock-alice".to_owned()),
                        affiliation: "admin".to_owned(),
                    },
                    MucAffiliationChange {
                        target: MucAffiliationTarget::LocalUsername("lock-alice".to_owned()),
                        affiliation: "member".to_owned(),
                    },
                ],
                MucAffiliationBatchOutcome::DuplicateTarget,
            ),
        ] {
            assert_eq!(
                set_muc_affiliations_batch(&restarted, room.id, &changes)
                    .await
                    .unwrap(),
                outcome
            );
            assert_eq!(
                super::muc_affiliation(&restarted, room.id, alice_id)
                    .await
                    .unwrap()
                    .as_deref(),
                Some("member")
            );
        }

        let (cancelled, _) = get_or_create_muc_room(&restarted, "cancelled", alice_id, alice)
            .await
            .unwrap();
        assert!(!cancel_locked_muc_room(&restarted, cancelled.id, bob)
            .await
            .unwrap());
        assert!(cancel_locked_muc_room(&restarted, cancelled.id, alice)
            .await
            .unwrap());
        assert!(muc_room(&restarted, "cancelled").await.unwrap().is_none());

        let (expired, _) = get_or_create_muc_room(&restarted, "expired", alice_id, alice)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE muc_rooms SET configuration_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1",
        )
        .bind(expired.id)
        .execute(&restarted)
        .await
        .unwrap();
        assert!(delete_expired_locked_muc_room(&restarted, expired.id)
            .await
            .unwrap());
        assert!(muc_room(&restarted, "expired").await.unwrap().is_none());

        restarted.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn durable_invitation_admission_is_atomic_under_injected_failures() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("muc_invite_test_{}", uuid::Uuid::new_v4().simple());
        create_harness_owned_schema(&admin, &schema).await;
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(60))
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

        for statement in [
            "CREATE TABLE users(id UUID PRIMARY KEY, username TEXT NOT NULL UNIQUE, is_disabled BOOLEAN NOT NULL DEFAULT FALSE)",
            // Keep the fixture aligned with the complete retention/legal-hold
            // authority read performed by `admit_local_muc_invite`. PostgreSQL
            // resolves every relation in that statement even when this test
            // has no active policy or hold rows, so omitting one turns a valid
            // admission into a schema error before the transaction invariant
            // under test is reached.
            "CREATE TABLE user_retention_policies(user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, offline_message_days INTEGER CHECK (offline_message_days BETWEEN 1 AND 36500))",
            "CREATE TABLE legal_holds(id UUID PRIMARY KEY, released_at TIMESTAMPTZ)",
            "CREATE TABLE legal_hold_offline_messages(hold_id UUID NOT NULL REFERENCES legal_holds(id) ON DELETE RESTRICT, message_id UUID NOT NULL, PRIMARY KEY(hold_id,message_id))",
            "CREATE TABLE legal_hold_scopes(hold_id UUID NOT NULL REFERENCES legal_holds(id) ON DELETE RESTRICT, scope_type VARCHAR(40) NOT NULL CHECK (scope_type IN ('personal_archive_owner','muc_archive_room','offline_message_recipient','report_evidence_report')), subject_id UUID NOT NULL, PRIMARY KEY(hold_id,scope_type,subject_id))",
            "CREATE TABLE muc_affiliations(room_id UUID NOT NULL, user_id UUID NOT NULL, affiliation TEXT NOT NULL, reserved_nick VARCHAR(128), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(room_id,user_id))",
            "CREATE TABLE muc_external_affiliations(room_id UUID NOT NULL, jid TEXT NOT NULL, affiliation TEXT NOT NULL, reserved_nick VARCHAR(128), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(room_id,jid))",
            "CREATE TABLE offline_messages(id UUID PRIMARY KEY, recipient_id UUID NOT NULL, sender_jid TEXT NOT NULL, stanza TEXT NOT NULL, target_resource VARCHAR(1023), encrypted BOOLEAN NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), delivery_claim_id UUID, delivery_claim_expires_at TIMESTAMPTZ)",
            "CREATE TABLE sm_resume_stanzas(delivery_message_id UUID)",
            "CREATE TABLE bosh_delivery_fences(message_id UUID)",
            "CREATE TABLE s2s_outbox(id UUID PRIMARY KEY, target_domain TEXT NOT NULL, bounce_to TEXT, stanza TEXT NOT NULL, dedupe_hash BYTEA NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), expires_at TIMESTAMPTZ NOT NULL, next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), attempt_count INTEGER NOT NULL DEFAULT 0, locked_until TIMESTAMPTZ, lock_token UUID, last_error TEXT, enqueue_sequence BIGINT GENERATED BY DEFAULT AS IDENTITY, UNIQUE(target_domain,dedupe_hash))",
        ] {
            sqlx::query(statement).execute(&pool).await.unwrap();
        }
        let room_id = uuid::Uuid::new_v4();
        let recipient_id = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username) VALUES($1,'invitee')")
            .bind(recipient_id)
            .execute(&pool)
            .await
            .unwrap();
        let local_policy = OfflineStorePolicy {
            max_messages: 100,
            max_bytes: 1_000_000,
            ttl_days: 30,
            mam_backed: false,
        };
        let s2s_policy = S2sOutboxPolicy {
            ttl_seconds: 300,
            max_rows: 100,
            max_bytes: 1_000_000,
            max_per_domain: 100,
        };

        sqlx::query(
            "CREATE FUNCTION fail_invite_offline() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced offline admission failure'; END $$",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("CREATE TRIGGER fail_invite_offline BEFORE INSERT ON offline_messages FOR EACH ROW EXECUTE FUNCTION fail_invite_offline()")
            .execute(&pool)
            .await
            .unwrap();
        assert!(admit_local_muc_invite(
            &pool,
            Uuid::new_v4(),
            room_id,
            recipient_id,
            "invitee@local.test",
            "room@conference.local.test",
            "<message id='local-failure' to='invitee@local.test'/>",
            false,
            local_policy,
            None,
        )
        .await
        .is_err());
        let local_halves: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM muc_affiliations), (SELECT COUNT(*) FROM offline_messages)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(local_halves, (0, 0));
        sqlx::query("DROP TRIGGER fail_invite_offline ON offline_messages")
            .execute(&pool)
            .await
            .unwrap();

        let offline_id = Uuid::new_v4();
        let local_invitation = format!(
            "<message from='room@conference.local.test' to='invitee@local.test' type='normal'><stanza-id xmlns='urn:xmpp:sid:0' by='invitee@local.test' id='{offline_id}'/></message>"
        );
        let admitted_offline_id = match admit_local_muc_invite(
            &pool,
            offline_id,
            room_id,
            recipient_id,
            "invitee@local.test",
            "room@conference.local.test",
            &local_invitation,
            false,
            local_policy,
            None,
        )
        .await
        .unwrap()
        {
            DurableMucInviteOutcome::Stored {
                id,
                affiliation_changed,
            } => {
                assert!(
                    affiliation_changed,
                    "first invite must create the member affiliation"
                );
                id
            }
            outcome => panic!("unexpected local admission outcome: {outcome:?}"),
        };
        let local_halves: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM muc_affiliations WHERE affiliation='member'), (SELECT COUNT(*) FROM offline_messages)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(local_halves, (1, 1));
        assert_eq!(admitted_offline_id, offline_id);
        // Accepting a mediated invitation into a connection queue is not a
        // delivery acknowledgement. Simulate a disconnect before socket
        // write: the exact durable item is dropped, but its spool row remains
        // available for a later transport to complete.
        let local_delivery = crate::outbound::DurableDelivery {
            recipient_id,
            message_id: offline_id,
            claim_id: None,
        };
        let (local_tx, mut local_rx) = tokio::sync::mpsc::channel(1);
        crate::outbound::OutboundSender::new(local_tx)
            .try_send_durable(local_invitation, local_delivery)
            .unwrap();
        let queued = local_rx.recv().await.unwrap();
        assert_eq!(queued.durable_delivery, Some(local_delivery));
        drop(queued);
        drop(local_rx);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
                .bind(offline_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        crate::db::replay::acknowledge_durable_delivery(&pool, local_delivery)
            .await
            .unwrap();
        let repeated_invite_id = Uuid::new_v4();
        let federated_invitation = format!(
            "<message from='room@conference.local.test' to='invitee@local.test' type='normal'><x xmlns='http://jabber.org/protocol/muc#user'><invite from='alice@remote.test/device'/></x><stanza-id xmlns='urn:xmpp:sid:0' by='invitee@local.test' id='{repeated_invite_id}'/></message>"
        );
        let admitted_repeated_invite_id = match admit_local_muc_invite(
            &pool,
            repeated_invite_id,
            room_id,
            recipient_id,
            "invitee@local.test",
            "room@conference.local.test",
            &federated_invitation,
            false,
            local_policy,
            None,
        )
        .await
        .unwrap()
        {
            DurableMucInviteOutcome::Stored {
                id,
                affiliation_changed,
            } => {
                assert!(
                    !affiliation_changed,
                    "repeated invite must not recreate membership"
                );
                id
            }
            outcome => panic!("unexpected repeated local admission outcome: {outcome:?}"),
        };
        assert_eq!(admitted_repeated_invite_id, repeated_invite_id);
        let federated_delivery = crate::outbound::DurableDelivery {
            recipient_id,
            message_id: repeated_invite_id,
            claim_id: None,
        };
        let (federated_tx, mut federated_rx) = tokio::sync::mpsc::channel(1);
        crate::outbound::OutboundSender::new(federated_tx)
            .try_send_durable(federated_invitation, federated_delivery)
            .unwrap();
        let queued = federated_rx.recv().await.unwrap();
        assert_eq!(queued.durable_delivery, Some(federated_delivery));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
                .bind(repeated_invite_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        crate::db::replay::acknowledge_durable_delivery(&pool, federated_delivery)
            .await
            .unwrap();
        set_muc_affiliation(&pool, room_id, "invitee", "outcast")
            .await
            .unwrap();
        assert_eq!(
            admit_local_muc_invite(
                &pool,
                Uuid::new_v4(),
                room_id,
                recipient_id,
                "invitee@local.test",
                "room@conference.local.test",
                "<message id='blocked' to='invitee@local.test'/>",
                false,
                local_policy,
                None,
            )
            .await
            .unwrap(),
            DurableMucInviteOutcome::Outcast
        );

        sqlx::query(
            "CREATE FUNCTION fail_invite_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced outbox admission failure'; END $$",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("CREATE TRIGGER fail_invite_outbox BEFORE INSERT ON s2s_outbox FOR EACH ROW EXECUTE FUNCTION fail_invite_outbox()")
            .execute(&pool)
            .await
            .unwrap();
        let injected_outbox_error = admit_federated_muc_invite(
            &pool,
            room_id,
            "guest@remote.test",
            "remote.test",
            "<message from='room@conference.local.test' to='guest@remote.test' type='normal' id='remote-failure'/>",
            Some("room@conference.local.test"),
            s2s_policy,
            None,
        )
        .await
        .expect_err("the injected outbox failure must abort the invitation");
        let injected_outbox_error = format!("{injected_outbox_error:#}");
        assert!(
            injected_outbox_error.contains("forced outbox admission failure"),
            "the fixture must reach the injected database failure instead of failing stanza validation: {injected_outbox_error}"
        );
        let remote_halves: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM muc_external_affiliations), (SELECT COUNT(*) FROM s2s_outbox)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(remote_halves, (0, 0));
        sqlx::query("DROP TRIGGER fail_invite_outbox ON s2s_outbox")
            .execute(&pool)
            .await
            .unwrap();
        assert!(admit_federated_muc_invite(
            &pool,
            room_id,
            "guest@remote.test",
            "remote.test",
            "<message from='room@conference.local.test' to='guest@remote.test' type='normal' id='remote-success'/>",
            Some("room@conference.local.test"),
            s2s_policy,
            None,
        )
        .await
        .unwrap());
        let remote_halves: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM muc_external_affiliations WHERE affiliation='member'), (SELECT COUNT(*) FROM s2s_outbox)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(remote_halves, (1, 1));
        set_federated_muc_affiliation(&pool, room_id, "banned@remote.test", "outcast")
            .await
            .unwrap();
        assert!(!admit_federated_muc_invite(
            &pool,
            room_id,
            "banned@remote.test",
            "remote.test",
            "<message from='room@conference.local.test' to='banned@remote.test' type='normal' id='remote-blocked'/>",
            Some("room@conference.local.test"),
            s2s_policy,
            None,
        )
        .await
        .unwrap());

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn history_identity_and_mutations_are_atomic_under_replay_and_failure() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("muc_history_test_{}", Uuid::new_v4().simple());
        create_harness_owned_schema(&admin, &schema).await;
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(60))
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

        let owner_id = Uuid::new_v4();
        let room_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'alice','test')")
            .bind(owner_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO muc_rooms(id,localpart,owner_id,occupant_id_secret,subject)
             VALUES($1,'history',$2,$3,'old')",
        )
        .bind(room_id)
        .bind(owner_id)
        .bind(vec![7_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
        let room_epoch: Uuid = sqlx::query_scalar("SELECT room_epoch FROM muc_rooms WHERE id=$1")
            .bind(room_id)
            .fetch_one(&pool)
            .await
            .unwrap();

        let first_id = Uuid::new_v4();
        assert_eq!(
            admit_muc_discussion(
                &pool,
                MucDiscussion {
                    id: first_id,
                    room_id,
                    actor_scope: "alice@local.test",
                    origin_id: Some("client-1"),
                    sender_jid: "alice@local.test/Phone",
                    nick: "Alice",
                    stanza: "<message id='first'/>",
                    encrypted: false,
                    archive: true,
                    retention_days: 30,
                    authority: local_process_authority(
                        room_epoch,
                        owner_id,
                        "alice@local.test",
                        "alice@local.test/Phone",
                        "Alice",
                        "participant",
                        "none",
                    ),
                },
            )
            .await
            .unwrap(),
            MucDiscussionAdmission::Stored(first_id)
        );
        assert_eq!(
            admit_muc_discussion(
                &pool,
                MucDiscussion {
                    id: Uuid::new_v4(),
                    room_id,
                    actor_scope: "alice@local.test",
                    origin_id: Some("client-1"),
                    sender_jid: "alice@local.test/Tablet",
                    nick: "Renamed",
                    stanza: "<message id='altered-retry'/>",
                    encrypted: true,
                    archive: true,
                    retention_days: 30,
                    authority: local_process_authority(
                        room_epoch,
                        owner_id,
                        "alice@local.test",
                        "alice@local.test/Tablet",
                        "Renamed",
                        "participant",
                        "none",
                    ),
                },
            )
            .await
            .unwrap(),
            MucDiscussionAdmission::Replay(first_id)
        );
        let other_actor_id = Uuid::new_v4();
        assert_eq!(
            admit_muc_discussion(
                &pool,
                MucDiscussion {
                    id: other_actor_id,
                    room_id,
                    actor_scope: "bob@remote.test",
                    origin_id: Some("client-1"),
                    sender_jid: "bob@remote.test/Laptop",
                    nick: "Bob",
                    stanza: "<message id='same-id-other-actor'/>",
                    encrypted: false,
                    archive: true,
                    retention_days: 30,
                    authority: federated_process_authority(
                        room_epoch,
                        "bob@remote.test",
                        "bob@remote.test/Laptop",
                        "Bob",
                        "remote.test",
                    ),
                },
            )
            .await
            .unwrap(),
            MucDiscussionAdmission::Stored(other_actor_id)
        );

        let no_store_id = Uuid::new_v4();
        assert_eq!(
            admit_muc_discussion(
                &pool,
                MucDiscussion {
                    id: no_store_id,
                    room_id,
                    actor_scope: "alice@local.test",
                    origin_id: Some("no-store-origin"),
                    sender_jid: "alice@local.test/Phone",
                    nick: "Alice",
                    stanza: "<message><body>not retained</body></message>",
                    encrypted: false,
                    archive: false,
                    retention_days: 30,
                    authority: local_process_authority(
                        room_epoch,
                        owner_id,
                        "alice@local.test",
                        "alice@local.test/Phone",
                        "Alice",
                        "participant",
                        "none",
                    ),
                },
            )
            .await
            .unwrap(),
            MucDiscussionAdmission::Stored(no_store_id)
        );
        assert_eq!(
            admit_muc_discussion(
                &pool,
                MucDiscussion {
                    id: Uuid::new_v4(),
                    room_id,
                    actor_scope: "alice@local.test",
                    origin_id: Some("no-store-origin"),
                    sender_jid: "alice@local.test/Phone",
                    nick: "Alice",
                    stanza: "<message><body>retry must not be retained</body></message>",
                    encrypted: false,
                    archive: true,
                    retention_days: 30,
                    authority: local_process_authority(
                        room_epoch,
                        owner_id,
                        "alice@local.test",
                        "alice@local.test/Phone",
                        "Alice",
                        "participant",
                        "none",
                    ),
                },
            )
            .await
            .unwrap(),
            MucDiscussionAdmission::Replay(no_store_id)
        );
        let no_store_payloads: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM muc_messages WHERE room_id=$1 AND id=$2")
                .bind(room_id)
                .bind(no_store_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(no_store_payloads, 0);

        let collision_origin = "collision-probe";
        let collision_digest = muc_origin_digest("alice@local.test", collision_origin);
        sqlx::query(
            "INSERT INTO muc_origin_admissions
             (room_id,origin_digest,actor_scope,origin_id,stanza_id)
             VALUES($1,$2,'mallory@local.test','different-raw-value',$3)",
        )
        .bind(room_id)
        .bind(collision_digest)
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await
        .unwrap();
        assert!(admit_muc_discussion(
            &pool,
            MucDiscussion {
                id: Uuid::new_v4(),
                room_id,
                actor_scope: "alice@local.test",
                origin_id: Some(collision_origin),
                sender_jid: "alice@local.test/Phone",
                nick: "Alice",
                stanza: "<message/>",
                encrypted: false,
                archive: true,
                retention_days: 30,
                authority: local_process_authority(
                    room_epoch,
                    owner_id,
                    "alice@local.test",
                    "alice@local.test/Phone",
                    "Alice",
                    "participant",
                    "none",
                ),
            },
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("digest collision"));

        let concurrent_origin = "concurrent-origin";
        let barrier = Arc::new(Barrier::new(3));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let pool = pool.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                let id = Uuid::new_v4();
                barrier.wait().await;
                admit_muc_discussion(
                    &pool,
                    MucDiscussion {
                        id,
                        room_id,
                        actor_scope: "alice@local.test",
                        origin_id: Some(concurrent_origin),
                        sender_jid: "alice@local.test/Phone",
                        nick: "Alice",
                        stanza: "<message id='concurrent'/>",
                        encrypted: false,
                        archive: true,
                        retention_days: 30,
                        authority: local_process_authority(
                            room_epoch,
                            owner_id,
                            "alice@local.test",
                            "alice@local.test/Phone",
                            "Alice",
                            "participant",
                            "none",
                        ),
                    },
                )
                .await
                .unwrap()
            }));
        }
        barrier.wait().await;
        let outcomes = futures::future::join_all(tasks)
            .await
            .into_iter()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, MucDiscussionAdmission::Stored(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, MucDiscussionAdmission::Replay(_)))
                .count(),
            1
        );

        sqlx::query(
            "CREATE FUNCTION reject_subject_history() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN IF NEW.message_kind='subject' THEN RAISE EXCEPTION 'forced subject failure'; END IF;
             RETURN NEW; END $$",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER reject_subject_history BEFORE INSERT ON muc_messages
             FOR EACH ROW EXECUTE FUNCTION reject_subject_history()",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(set_local_muc_subject(
            &pool,
            MucSubjectMutation {
                stanza_id: Uuid::new_v4(),
                room_id,
                actor_scope: "alice@local.test",
                sender_jid: "alice@local.test/Phone",
                nick: "Alice",
                subject: "must roll back",
                stanza: "<message><subject>must roll back</subject></message>",
                encrypted: false,
            },
            true,
            local_process_authority(
                room_epoch,
                owner_id,
                "alice@local.test",
                "alice@local.test/Phone",
                "Alice",
                "moderator",
                "none",
            ),
        )
        .await
        .is_err());
        let subject: Option<String> =
            sqlx::query_scalar("SELECT subject FROM muc_rooms WHERE id=$1")
                .bind(room_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(subject.as_deref(), Some("old"));
        sqlx::query("DROP TRIGGER reject_subject_history ON muc_messages")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP FUNCTION reject_subject_history()")
            .execute(&pool)
            .await
            .unwrap();

        let subject_id = Uuid::new_v4();
        assert_eq!(
            set_local_muc_subject(
                &pool,
                MucSubjectMutation {
                    stanza_id: subject_id,
                    room_id,
                    actor_scope: "alice@local.test",
                    sender_jid: "alice@local.test/Phone",
                    nick: "Alice",
                    subject: "committed",
                    stanza: "<message><subject>committed</subject></message>",
                    encrypted: false,
                },
                true,
                local_process_authority(
                    room_epoch,
                    owner_id,
                    "alice@local.test",
                    "alice@local.test/Phone",
                    "Alice",
                    "moderator",
                    "none",
                ),
            )
            .await
            .unwrap(),
            MucSubjectOutcome::Applied
        );
        let subject_state: (Option<String>, Option<Uuid>, i64) = sqlx::query_as(
            "SELECT r.subject,r.subject_stanza_id,
                    (SELECT COUNT(*) FROM muc_messages m
                     WHERE m.room_id=r.id AND m.id=$2 AND m.message_kind='subject')
             FROM muc_rooms r WHERE r.id=$1",
        )
        .bind(room_id)
        .bind(subject_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            subject_state,
            (Some("committed".to_owned()), Some(subject_id), 1)
        );
        let unarchived_subject_id = Uuid::new_v4();
        assert_eq!(
            set_local_muc_subject(
                &pool,
                MucSubjectMutation {
                    stanza_id: unarchived_subject_id,
                    room_id,
                    actor_scope: "alice@local.test",
                    sender_jid: "alice@local.test/Phone",
                    nick: "Alice",
                    subject: "state only",
                    stanza: "<message><subject>state only</subject></message>",
                    encrypted: false,
                },
                false,
                local_process_authority(
                    room_epoch,
                    owner_id,
                    "alice@local.test",
                    "alice@local.test/Phone",
                    "Alice",
                    "moderator",
                    "none",
                ),
            )
            .await
            .unwrap(),
            MucSubjectOutcome::Applied
        );
        let state_only: (Option<String>, i64) = sqlx::query_as(
            "SELECT subject,(SELECT COUNT(*) FROM muc_messages WHERE id=$2)
               FROM muc_rooms WHERE id=$1",
        )
        .bind(room_id)
        .bind(unarchived_subject_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state_only, (Some("state only".to_owned()), 0));
        assert!(muc_history_since(&pool, room_id, 0, None)
            .await
            .unwrap()
            .is_empty());
        assert!(muc_history_since(
            &pool,
            room_id,
            100,
            Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        )
        .await
        .unwrap()
        .is_empty());
        assert!(muc_history_since(&pool, room_id, 100, None)
            .await
            .unwrap()
            .iter()
            .all(|message| !message.stanza.contains("<subject>committed</subject>")));

        update_muc_config(
            &pool,
            room_id,
            "alice@local.test/Phone",
            MucConfigUpdate {
                title: Some("Configured"),
                description: Some("A production room"),
                persistent: true,
                members_only: true,
                public: false,
                moderated: true,
                non_anonymous: true,
                max_occupants: 42,
                password_hash: None,
                allow_subject_change: true,
                allow_invites: false,
                allow_private_messages: false,
                logging_enabled: false,
                allow_registration: false,
            },
        )
        .await
        .unwrap();
        let configured = muc_room(&pool, "history").await.unwrap().unwrap();
        assert_eq!(configured.description.as_deref(), Some("A production room"));
        assert!(configured.allow_subject_change);
        assert!(!configured.allow_invites);
        assert!(!configured.allow_private_messages);
        assert!(!configured.logging_enabled);
        assert!(!configured.allow_registration);

        let bob_id = Uuid::new_v4();
        let carol_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,username,password_hash) VALUES
             ($1,'bob','test'),($2,'carol','test')",
        )
        .bind(bob_id)
        .bind(carol_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO muc_affiliations(room_id,user_id,affiliation)
             VALUES($1,$2,'owner')",
        )
        .bind(room_id)
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            register_local_muc_member(&pool, room_id, owner_id, "OwnerNick")
                .await
                .unwrap(),
            MucRegistrationOutcome::Registered {
                affiliation_changed: false,
            }
        );
        let owner_registration: (String, Option<String>) = sqlx::query_as(
            "SELECT affiliation,reserved_nick FROM muc_affiliations
              WHERE room_id=$1 AND user_id=$2",
        )
        .bind(room_id)
        .bind(owner_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(owner_registration.0, "owner");
        assert_eq!(owner_registration.1.as_deref(), Some("OwnerNick"));
        assert_eq!(
            set_muc_affiliation(&pool, room_id, "alice", "member")
                .await
                .unwrap(),
            MucAffiliationOutcome::LastOwner
        );
        assert_eq!(
            super::muc_affiliation(&pool, room_id, owner_id)
                .await
                .unwrap()
                .as_deref(),
            Some("owner")
        );
        assert_eq!(
            set_muc_affiliation(&pool, room_id, "carol", "owner")
                .await
                .unwrap(),
            MucAffiliationOutcome::Applied
        );
        assert_eq!(
            set_muc_affiliation(&pool, room_id, "alice", "member")
                .await
                .unwrap(),
            MucAffiliationOutcome::Applied
        );
        assert_eq!(
            set_muc_affiliation(&pool, room_id, "alice", "owner")
                .await
                .unwrap(),
            MucAffiliationOutcome::Applied
        );
        assert_eq!(
            set_muc_affiliation(&pool, room_id, "carol", "none")
                .await
                .unwrap(),
            MucAffiliationOutcome::Applied
        );

        // Deterministic authorization races. The test hook pauses after the
        // request has begun but before the room/actor locks are acquired. A
        // revocation which commits during that pause must win the serial
        // order and leave no archive/admission projection behind.
        assert_eq!(
            set_muc_affiliation(&pool, room_id, "carol", "owner")
                .await
                .unwrap(),
            MucAffiliationOutcome::Applied
        );

        // A local username cannot be re-used under a foreign domain.  Both
        // the service boundary (unit-tested in services::muc) and this locked
        // repository fence reject the forged principal without a projection.
        let forged_domain_id = Uuid::new_v4();
        let forged_domain = admit_muc_discussion(
            &pool,
            MucDiscussion {
                id: forged_domain_id,
                room_id,
                actor_scope: "alice@evil.test",
                origin_id: None,
                sender_jid: "alice@evil.test/Phone",
                nick: "Alice",
                stanza: "<message id='forged-domain'/>",
                encrypted: false,
                archive: true,
                retention_days: 30,
                authority: local_process_authority(
                    room_epoch,
                    owner_id,
                    "alice@evil.test",
                    "alice@evil.test/Phone",
                    "Alice",
                    "moderator",
                    "owner",
                ),
            },
        )
        .await
        .unwrap();
        assert_eq!(forged_domain, MucDiscussionAdmission::Unauthorized);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM muc_messages WHERE id=$1")
                .bind(forged_domain_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );

        // Global lock-order regression: admission owns namespace 29 before it
        // asks for the room row.  Therefore a clustered room-row writer can
        // finish while admission is paused, and a legacy affiliation writer
        // merely queues behind the advisory lock; all three complete without
        // a room-row/advisory cycle once admission resumes.
        let lock_order_id = Uuid::new_v4();
        let (entered, resume) = install_muc_authorization_test_pause("discussion_after_advisory");
        let lock_order_admission = {
            let pool = pool.clone();
            tokio::spawn(async move {
                admit_muc_discussion(
                    &pool,
                    MucDiscussion {
                        id: lock_order_id,
                        room_id,
                        actor_scope: "alice@local.test",
                        origin_id: None,
                        sender_jid: "alice@local.test/Phone",
                        nick: "Alice",
                        stanza: "<message id='lock-order'/>",
                        encrypted: false,
                        archive: false,
                        retention_days: 30,
                        authority: local_process_authority(
                            room_epoch,
                            owner_id,
                            "alice@local.test",
                            "alice@local.test/Phone",
                            "Alice",
                            "moderator",
                            "owner",
                        ),
                    },
                )
                .await
                .unwrap()
            })
        };
        entered.notified().await;
        let cluster_room_writer = {
            let pool = pool.clone();
            tokio::spawn(async move {
                let mut tx = pool.begin().await.unwrap();
                sqlx::query("SELECT id FROM muc_rooms WHERE id=$1 FOR UPDATE")
                    .bind(room_id)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                tx.commit().await.unwrap();
            })
        };
        tokio::time::timeout(Duration::from_secs(5), cluster_room_writer)
            .await
            .expect("room-row writer must not wait behind the advisory-only admission phase")
            .unwrap();
        let legacy_affiliation_writer = {
            let pool = pool.clone();
            tokio::spawn(async move {
                set_muc_affiliation(&pool, room_id, "alice", "owner")
                    .await
                    .unwrap()
            })
        };
        resume.notify_one();
        let (admission, affiliation) = tokio::time::timeout(
            Duration::from_secs(5),
            futures::future::join(lock_order_admission, legacy_affiliation_writer),
        )
        .await
        .expect("MUC room/advisory writers must not deadlock");
        assert_eq!(
            admission.unwrap(),
            MucDiscussionAdmission::Stored(lock_order_id)
        );
        assert_eq!(affiliation.unwrap(), MucAffiliationOutcome::Applied);

        let local_race_id = Uuid::new_v4();
        let (entered, resume) = install_muc_authorization_test_pause("discussion");
        let local_race = {
            let pool = pool.clone();
            tokio::spawn(async move {
                admit_muc_discussion(
                    &pool,
                    MucDiscussion {
                        id: local_race_id,
                        room_id,
                        actor_scope: "alice@local.test",
                        origin_id: None,
                        sender_jid: "alice@local.test/Phone",
                        nick: "Alice",
                        stanza: "<message id='revoked-local'/>",
                        encrypted: false,
                        // Even volatile/no-store traffic must cross the same
                        // authorization transaction before live fan-out.
                        archive: false,
                        retention_days: 30,
                        authority: local_process_authority(
                            room_epoch,
                            owner_id,
                            "alice@local.test",
                            "alice@local.test/Phone",
                            "Alice",
                            "moderator",
                            "owner",
                        ),
                    },
                )
                .await
                .unwrap()
            })
        };
        entered.notified().await;
        set_muc_affiliation(&pool, room_id, "alice", "outcast")
            .await
            .unwrap();
        resume.notify_one();
        assert_eq!(
            local_race.await.unwrap(),
            MucDiscussionAdmission::Unauthorized
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM muc_messages WHERE id=$1")
                .bind(local_race_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        set_muc_affiliation(&pool, room_id, "alice", "owner")
            .await
            .unwrap();

        let federated_race_id = Uuid::new_v4();
        let (entered, resume) = install_muc_authorization_test_pause("discussion");
        let federated_race = {
            let pool = pool.clone();
            tokio::spawn(async move {
                admit_muc_discussion(
                    &pool,
                    MucDiscussion {
                        id: federated_race_id,
                        room_id,
                        actor_scope: "race@remote.test",
                        origin_id: None,
                        sender_jid: "race@remote.test/Phone",
                        nick: "Remote",
                        stanza: "<message id='revoked-federated'/>",
                        encrypted: false,
                        archive: true,
                        retention_days: 30,
                        authority: federated_process_authority(
                            room_epoch,
                            "race@remote.test",
                            "race@remote.test/Phone",
                            "Remote",
                            "remote.test",
                        ),
                    },
                )
                .await
                .unwrap()
            })
        };
        entered.notified().await;
        set_federated_muc_affiliation(&pool, room_id, "race@remote.test", "outcast")
            .await
            .unwrap();
        resume.notify_one();
        assert_eq!(
            federated_race.await.unwrap(),
            MucDiscussionAdmission::Unauthorized
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM muc_messages WHERE id=$1")
                .bind(federated_race_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        set_federated_muc_affiliation(&pool, room_id, "race@remote.test", "none")
            .await
            .unwrap();

        // Exercise the repository's real authorization expression before the
        // race.  This is the intentional OMEMO recipient-discovery exception:
        // a member of a members-only, non-anonymous room may read the three
        // positive affiliation lists, but not the outcast list.
        assert_eq!(
            set_muc_affiliation(&pool, room_id, "carol", "member")
                .await
                .unwrap(),
            MucAffiliationOutcome::Applied
        );
        for requested in ["owner", "admin", "member"] {
            assert!(matches!(
                authorized_muc_admin_affiliation_list(
                    &pool,
                    room_id,
                    room_epoch,
                    carol_id,
                    "carol@local.test",
                    requested,
                    "local.test",
                )
                .await
                .unwrap(),
                MucAdminSnapshot::Authorized(_)
            ));
        }
        assert_eq!(
            authorized_muc_admin_affiliation_list(
                &pool,
                room_id,
                room_epoch,
                carol_id,
                "carol@local.test",
                "outcast",
                "local.test",
            )
            .await
            .unwrap(),
            MucAdminSnapshot::Unauthorized
        );
        assert_eq!(
            set_muc_affiliation(&pool, room_id, "carol", "owner")
                .await
                .unwrap(),
            MucAffiliationOutcome::Applied
        );

        let (entered, resume) = install_muc_authorization_test_pause("admin_affiliation");
        let admin_snapshot = {
            let pool = pool.clone();
            tokio::spawn(async move {
                authorized_muc_admin_affiliation_list(
                    &pool,
                    room_id,
                    room_epoch,
                    carol_id,
                    "carol@local.test",
                    "owner",
                    "local.test",
                )
                .await
                .unwrap()
            })
        };
        entered.notified().await;
        // In a members-only, non-anonymous room a member intentionally keeps
        // read access to owner/admin/member lists so an OMEMO client can build
        // the complete recipient set.  Use `none` here: this race is meant to
        // prove that a real authorization revocation committed before the
        // repository locks are acquired wins the serial order.
        assert_eq!(
            set_muc_affiliation(&pool, room_id, "carol", "none")
                .await
                .unwrap(),
            MucAffiliationOutcome::Applied
        );
        resume.notify_one();
        assert_eq!(
            admin_snapshot.await.unwrap(),
            MucAdminSnapshot::Unauthorized
        );
        set_muc_affiliation(&pool, room_id, "carol", "owner")
            .await
            .unwrap();

        let (entered, resume) = install_muc_authorization_test_pause("admin_role");
        let role_snapshot = {
            let pool = pool.clone();
            tokio::spawn(async move {
                authorized_muc_admin_role_list(
                    &pool,
                    room_id,
                    room_epoch,
                    owner_id,
                    "alice@local.test",
                    "local.test",
                    "none",
                    None,
                    false,
                    "participant",
                )
                .await
                .unwrap()
            })
        };
        entered.notified().await;
        set_muc_affiliation(&pool, room_id, "alice", "member")
            .await
            .unwrap();
        resume.notify_one();
        assert_eq!(role_snapshot.await.unwrap(), MucAdminSnapshot::Unauthorized);
        set_muc_affiliation(&pool, room_id, "alice", "owner")
            .await
            .unwrap();

        let cluster_incarnation = Uuid::new_v4();
        let cluster_connection = Uuid::new_v4();
        let config_version: i64 =
            sqlx::query_scalar("SELECT config_version FROM muc_rooms WHERE id=$1")
                .bind(room_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        sqlx::query(
            "INSERT INTO cluster_muc_occupancies(
                 room_id,room_epoch,occupant_incarnation,occupancy_epoch,config_version,
                 identity_kind,local_user_id,bare_jid,full_jid,nick,authenticated_domain,
                 owner_node_id,connection_uuid,connection_epoch,sm_session_id,state,role,
                 affiliation,presence_payload,lease_until)
             VALUES($1,$2,$3,9001,$4,'local',$5,'alice@local.test',
                    'alice@local.test/Cluster','ClusterAlice',NULL,'test-node',$6,1,NULL,
                    'active','moderator','owner','',clock_timestamp()+INTERVAL '1 hour')",
        )
        .bind(room_id)
        .bind(room_epoch)
        .bind(cluster_incarnation)
        .bind(config_version)
        .bind(owner_id)
        .bind(cluster_connection)
        .execute(&pool)
        .await
        .unwrap();
        let cluster_target = crate::db::ClusterMucOccupancyTarget {
            room_id,
            room_epoch,
            occupant_incarnation: cluster_incarnation,
            occupancy_epoch: 9001,
            full_jid: "alice@local.test/Cluster".to_owned(),
            nick: "ClusterAlice".to_owned(),
            connection_uuid: cluster_connection,
            connection_epoch: 1,
        };
        let cluster_outbox_before: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM cluster_muc_event_outbox WHERE room_id=$1")
                .bind(room_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let cluster_race_id = Uuid::new_v4();
        let (entered, resume) = install_muc_authorization_test_pause("discussion");
        let cluster_race = {
            let pool = pool.clone();
            let cluster_target = cluster_target.clone();
            tokio::spawn(async move {
                admit_muc_discussion(
                    &pool,
                    MucDiscussion {
                        id: cluster_race_id,
                        room_id,
                        actor_scope: "alice@local.test",
                        origin_id: None,
                        sender_jid: "alice@local.test/Cluster",
                        nick: "ClusterAlice",
                        stanza: "<message id='revoked-cluster'/>",
                        encrypted: false,
                        archive: true,
                        retention_days: 30,
                        authority: MucActorAuthority {
                            clustered: true,
                            expected_room_epoch: room_epoch,
                            principal: MucActorPrincipal::Local {
                                user_id: owner_id,
                                local_domain: "local.test",
                            },
                            actor_scope: "alice@local.test",
                            full_jid: "alice@local.test/Cluster",
                            nick: "ClusterAlice",
                            occupant_incarnation: cluster_incarnation,
                            connection_uuid: cluster_connection,
                            expected_role: "moderator",
                            expected_affiliation: "owner",
                            cluster_target: Some(cluster_target),
                        },
                    },
                )
                .await
                .unwrap()
            })
        };
        entered.notified().await;
        sqlx::query(
            "UPDATE cluster_muc_occupancies
                SET state='revoked',role='none',ended_at=clock_timestamp(),updated_at=clock_timestamp()
              WHERE room_id=$1 AND occupant_incarnation=$2",
        )
        .bind(room_id)
        .bind(cluster_incarnation)
        .execute(&pool)
        .await
        .unwrap();
        resume.notify_one();
        assert_eq!(
            cluster_race.await.unwrap(),
            MucDiscussionAdmission::Unauthorized
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM muc_messages WHERE id=$1")
                .bind(cluster_race_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );

        let federated_cluster_incarnation = Uuid::new_v4();
        let federated_cluster_connection = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO cluster_muc_occupancies(
                 room_id,room_epoch,occupant_incarnation,occupancy_epoch,config_version,
                 identity_kind,local_user_id,bare_jid,full_jid,nick,authenticated_domain,
                 owner_node_id,connection_uuid,connection_epoch,sm_session_id,state,role,
                 affiliation,presence_payload,lease_until)
             VALUES($1,$2,$3,9002,$4,'federated',NULL,'cluster@remote.test',
                    'cluster@remote.test/Phone','ClusterRemote','remote.test','test-node',$5,1,NULL,
                    'active','participant','none','',clock_timestamp()+INTERVAL '1 hour')",
        )
        .bind(room_id)
        .bind(room_epoch)
        .bind(federated_cluster_incarnation)
        .bind(config_version)
        .bind(federated_cluster_connection)
        .execute(&pool)
        .await
        .unwrap();
        let federated_cluster_target = crate::db::ClusterMucOccupancyTarget {
            room_id,
            room_epoch,
            occupant_incarnation: federated_cluster_incarnation,
            occupancy_epoch: 9002,
            full_jid: "cluster@remote.test/Phone".to_owned(),
            nick: "ClusterRemote".to_owned(),
            connection_uuid: federated_cluster_connection,
            connection_epoch: 1,
        };
        let federated_cluster_race_id = Uuid::new_v4();
        let (entered, resume) = install_muc_authorization_test_pause("discussion");
        let federated_cluster_race = {
            let pool = pool.clone();
            tokio::spawn(async move {
                admit_muc_discussion(
                    &pool,
                    MucDiscussion {
                        id: federated_cluster_race_id,
                        room_id,
                        actor_scope: "cluster@remote.test",
                        origin_id: None,
                        sender_jid: "cluster@remote.test/Phone",
                        nick: "ClusterRemote",
                        stanza: "<message id='revoked-federated-cluster'/>",
                        encrypted: false,
                        archive: true,
                        retention_days: 30,
                        authority: MucActorAuthority {
                            clustered: true,
                            expected_room_epoch: room_epoch,
                            principal: MucActorPrincipal::Federated {
                                bare_jid: "cluster@remote.test",
                                authenticated_domain: "remote.test",
                            },
                            actor_scope: "cluster@remote.test",
                            full_jid: "cluster@remote.test/Phone",
                            nick: "ClusterRemote",
                            occupant_incarnation: federated_cluster_incarnation,
                            connection_uuid: federated_cluster_connection,
                            expected_role: "participant",
                            expected_affiliation: "none",
                            cluster_target: Some(federated_cluster_target),
                        },
                    },
                )
                .await
                .unwrap()
            })
        };
        entered.notified().await;
        sqlx::query(
            "UPDATE cluster_muc_occupancies
                SET state='revoked',role='none',ended_at=clock_timestamp(),updated_at=clock_timestamp()
              WHERE room_id=$1 AND occupant_incarnation=$2",
        )
        .bind(room_id)
        .bind(federated_cluster_incarnation)
        .execute(&pool)
        .await
        .unwrap();
        resume.notify_one();
        assert_eq!(
            federated_cluster_race.await.unwrap(),
            MucDiscussionAdmission::Unauthorized
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM muc_messages WHERE id=$1")
                .bind(federated_cluster_race_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM cluster_muc_event_outbox WHERE room_id=$1",
            )
            .bind(room_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            cluster_outbox_before
        );
        set_muc_affiliation(&pool, room_id, "carol", "none")
            .await
            .unwrap();

        let barrier = Arc::new(Barrier::new(3));
        let mut registrations = Vec::new();
        for user_id in [bob_id, carol_id] {
            let pool = pool.clone();
            let barrier = Arc::clone(&barrier);
            registrations.push(tokio::spawn(async move {
                barrier.wait().await;
                register_local_muc_member(&pool, room_id, user_id, "SharedNick")
                    .await
                    .unwrap()
            }));
        }
        barrier.wait().await;
        let outcomes = futures::future::join_all(registrations)
            .await
            .into_iter()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| {
                    matches!(
                        **outcome,
                        MucRegistrationOutcome::Registered {
                            affiliation_changed: true
                        }
                    )
                })
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == MucRegistrationOutcome::Conflict)
                .count(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM muc_affiliations
                  WHERE room_id=$1 AND reserved_nick='SharedNick'",
            )
            .bind(room_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        assert!(!unregister_local_muc_member(&pool, room_id, owner_id)
            .await
            .unwrap());
        assert!(muc_reserved_nick(&pool, room_id, owner_id)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            super::muc_affiliation(&pool, room_id, owner_id)
                .await
                .unwrap()
                .as_deref(),
            Some("owner")
        );
        set_muc_affiliation(&pool, room_id, "bob", "outcast")
            .await
            .unwrap();
        assert!(muc_reserved_nick(&pool, room_id, bob_id)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            register_local_muc_member(&pool, room_id, bob_id, "BannedNick")
                .await
                .unwrap(),
            MucRegistrationOutcome::Outcast
        );

        let target_id = Uuid::new_v4();
        admit_muc_discussion(
            &pool,
            MucDiscussion {
                id: target_id,
                room_id,
                actor_scope: "alice@local.test",
                origin_id: None,
                sender_jid: "alice@local.test/Phone",
                nick: "Alice",
                stanza: "<message id='target'><body>secret</body></message>",
                encrypted: false,
                archive: true,
                retention_days: 30,
                authority: local_process_authority(
                    room_epoch,
                    owner_id,
                    "alice@local.test",
                    "alice@local.test/Phone",
                    "Alice",
                    "moderator",
                    "owner",
                ),
            },
        )
        .await
        .unwrap();
        let revoked_moderation_id = Uuid::new_v4();
        let (entered, resume) = install_muc_authorization_test_pause("retraction");
        let revoked_moderation = {
            let pool = pool.clone();
            tokio::spawn(async move {
                retract_muc_message_and_archive_action(
                    &pool,
                    MucRetractionMutation {
                        action_id: revoked_moderation_id,
                        room_id,
                        target_id,
                        expected_stanza: "<message id='target'><body>secret</body></message>",
                        actor_scope: "alice@local.test",
                        sender_jid: "alice@local.test/Phone",
                        nick: "Alice",
                        tombstone: "<message id='target'><retracted/></message>",
                        action_stanza: "<message id='revoked-moderation'/>",
                        reason: Some("revoked"),
                        kind: MucRetractionKind::Moderator,
                        authority: local_process_authority(
                            room_epoch,
                            owner_id,
                            "alice@local.test",
                            "alice@local.test/Phone",
                            "Alice",
                            "moderator",
                            "owner",
                        ),
                    },
                )
                .await
                .unwrap()
            })
        };
        entered.notified().await;
        set_muc_affiliation(&pool, room_id, "carol", "owner")
            .await
            .unwrap();
        set_muc_affiliation(&pool, room_id, "alice", "member")
            .await
            .unwrap();
        resume.notify_one();
        assert_eq!(
            revoked_moderation.await.unwrap(),
            MucRetractionOutcome::Unauthorized
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM muc_messages WHERE id=$1")
                .bind(revoked_moderation_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        let unchanged: (String, Option<chrono::DateTime<chrono::Utc>>) =
            sqlx::query_as("SELECT stanza,retracted_at FROM muc_messages WHERE id=$1")
                .bind(target_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            unchanged,
            (
                "<message id='target'><body>secret</body></message>".to_owned(),
                None
            )
        );

        // The same moderation fence applies to an authenticated federated
        // moderator. A committed remote-affiliation demotion wins before any
        // tombstone or moderation action can be projected.
        set_federated_muc_affiliation(&pool, room_id, "moderator@remote.test", "admin")
            .await
            .unwrap();
        let federated_moderation_id = Uuid::new_v4();
        let (entered, resume) = install_muc_authorization_test_pause("retraction");
        let federated_moderation = {
            let pool = pool.clone();
            tokio::spawn(async move {
                retract_muc_message_and_archive_action(
                    &pool,
                    MucRetractionMutation {
                        action_id: federated_moderation_id,
                        room_id,
                        target_id,
                        expected_stanza: "<message id='target'><body>secret</body></message>",
                        actor_scope: "moderator@remote.test",
                        sender_jid: "moderator@remote.test/Phone",
                        nick: "RemoteModerator",
                        tombstone: "<message id='target'><retracted/></message>",
                        action_stanza: "<message id='revoked-federated-moderation'/>",
                        reason: Some("revoked"),
                        kind: MucRetractionKind::Moderator,
                        authority: MucActorAuthority {
                            clustered: false,
                            expected_room_epoch: room_epoch,
                            principal: MucActorPrincipal::Federated {
                                bare_jid: "moderator@remote.test",
                                authenticated_domain: "remote.test",
                            },
                            actor_scope: "moderator@remote.test",
                            full_jid: "moderator@remote.test/Phone",
                            nick: "RemoteModerator",
                            occupant_incarnation: Uuid::nil(),
                            connection_uuid: Uuid::nil(),
                            expected_role: "moderator",
                            expected_affiliation: "admin",
                            cluster_target: None,
                        },
                    },
                )
                .await
                .unwrap()
            })
        };
        entered.notified().await;
        set_federated_muc_affiliation(&pool, room_id, "moderator@remote.test", "member")
            .await
            .unwrap();
        resume.notify_one();
        assert_eq!(
            federated_moderation.await.unwrap(),
            MucRetractionOutcome::Unauthorized
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM muc_messages WHERE id=$1")
                .bind(federated_moderation_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        set_federated_muc_affiliation(&pool, room_id, "moderator@remote.test", "none")
            .await
            .unwrap();
        set_muc_affiliation(&pool, room_id, "alice", "owner")
            .await
            .unwrap();
        set_muc_affiliation(&pool, room_id, "carol", "none")
            .await
            .unwrap();
        sqlx::query(
            "CREATE FUNCTION reject_moderation_action() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN IF NEW.message_kind='moderation' THEN RAISE EXCEPTION 'forced action failure'; END IF;
             RETURN NEW; END $$",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER reject_moderation_action BEFORE INSERT ON muc_messages
             FOR EACH ROW EXECUTE FUNCTION reject_moderation_action()",
        )
        .execute(&pool)
        .await
        .unwrap();
        let failed_action = Uuid::new_v4();
        assert!(retract_muc_message_and_archive_action(
            &pool,
            MucRetractionMutation {
                action_id: failed_action,
                room_id,
                target_id,
                expected_stanza: "<message id='target'><body>secret</body></message>",
                actor_scope: "alice@local.test",
                sender_jid: "alice@local.test/Phone",
                nick: "Alice",
                tombstone: "<message id='target'><retracted/></message>",
                action_stanza: "<message id='moderate'><moderated/></message>",
                reason: Some("policy"),
                kind: MucRetractionKind::Moderator,
                authority: local_process_authority(
                    room_epoch,
                    owner_id,
                    "alice@local.test",
                    "alice@local.test/Phone",
                    "Alice",
                    "moderator",
                    "owner",
                ),
            },
        )
        .await
        .is_err());
        let target_after_failure: (String, Option<chrono::DateTime<chrono::Utc>>) =
            sqlx::query_as("SELECT stanza,retracted_at FROM muc_messages WHERE id=$1")
                .bind(target_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            target_after_failure,
            (
                "<message id='target'><body>secret</body></message>".to_owned(),
                None
            )
        );
        sqlx::query("DROP TRIGGER reject_moderation_action ON muc_messages")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP FUNCTION reject_moderation_action()")
            .execute(&pool)
            .await
            .unwrap();

        let action_id = Uuid::new_v4();
        assert_eq!(
            retract_muc_message_and_archive_action(
                &pool,
                MucRetractionMutation {
                    action_id,
                    room_id,
                    target_id,
                    expected_stanza: "<message id='target'><body>secret</body></message>",
                    actor_scope: "alice@local.test",
                    sender_jid: "alice@local.test/Phone",
                    nick: "Alice",
                    tombstone: "<message id='target'><retracted/></message>",
                    action_stanza: "<message id='moderate'><moderated/></message>",
                    reason: Some("policy"),
                    kind: MucRetractionKind::Author,
                    authority: local_process_authority(
                        room_epoch,
                        owner_id,
                        "alice@local.test",
                        "alice@local.test/Phone",
                        "Alice",
                        "moderator",
                        "owner",
                    ),
                },
            )
            .await
            .unwrap(),
            MucRetractionOutcome::Applied
        );
        let committed: (String, Option<Uuid>, i64) = sqlx::query_as(
            "SELECT stanza,retraction_action_id,
                    (SELECT COUNT(*) FROM muc_messages a
                     WHERE a.room_id=m.room_id AND a.id=$2 AND a.message_kind='retraction')
             FROM muc_messages m WHERE m.id=$1",
        )
        .bind(target_id)
        .bind(action_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            committed,
            (
                "<message id='target'><retracted/></message>".to_owned(),
                Some(action_id),
                1
            )
        );

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}
