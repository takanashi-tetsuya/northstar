use anyhow::{Context, Result};
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
    // The retraction race fixture must stop before the authority snapshot.
    // A concurrent affiliation change can then commit, after which this
    // transaction takes the normal namespace/row locks and observes the
    // changed authority instead of creating a time-of-check/time-of-use gap.
    #[cfg(test)]
    maybe_pause_muc_authorization_for_test("retraction").await;
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
#[path = "muc_tests.rs"]
mod tests;
