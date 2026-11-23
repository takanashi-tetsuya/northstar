//! Validate and authorize room history operations and persist discussion, subject, and retraction transactions.

use super::*;
use northstar_room_application::muc_service::{DiscussionCommit, LiveAudience};

mod live_audience;

pub fn canonical_history_actor(actor_scope: &str) -> Result<String> {
    anyhow::ensure!(
        !actor_scope.is_empty() && actor_scope.len() <= 3071,
        "MUC history actor scope must contain 1 to 3071 bytes"
    );
    let actor = northstar_xmpp_types::jid::CanonicalJid::parse_bare(actor_scope)?;
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

pub fn canonical_history_sender(sender_jid: &str) -> Result<String> {
    anyhow::ensure!(
        !sender_jid.is_empty() && sender_jid.len() <= 3071,
        "MUC history sender JID must contain 1 to 3071 bytes"
    );
    let canonical = northstar_xmpp_types::jid::canonicalize(sender_jid)?;
    anyhow::ensure!(
        canonical == sender_jid,
        "MUC history sender JID must already be canonical"
    );
    Ok(canonical)
}

pub fn validate_history_payload(nick: &str, stanza: &str) -> Result<()> {
    validate_history_payload_size(nick, stanza.len())
}

fn validate_history_payload_size(nick: &str, stanza_bytes: usize) -> Result<()> {
    anyhow::ensure!(
        !nick.is_empty() && nick.len() <= MAX_MUC_NICK_BYTES,
        "MUC history nickname must contain 1 to 128 bytes"
    );
    anyhow::ensure!(
        (1..=MAX_HISTORY_STANZA_BYTES).contains(&stanza_bytes),
        "MUC history stanza must contain 1 to 1048576 bytes"
    );
    Ok(())
}

pub fn validate_origin_id(origin_id: &str) -> Result<()> {
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

pub fn muc_origin_digest(actor_scope: &str, origin_id: &str) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"northstar:muc-origin-id:v1\0");
    digest.update((actor_scope.len() as u32).to_be_bytes());
    digest.update(actor_scope.as_bytes());
    digest.update((origin_id.len() as u32).to_be_bytes());
    digest.update(origin_id.as_bytes());
    digest.finalize().to_vec()
}

#[derive(Clone, Debug)]
pub struct LockedMucActor {
    pub role: String,
    pub affiliation: String,
    logging_enabled: bool,
    allow_subject_change: bool,
}

#[derive(Clone, Debug)]
pub enum MucAuthorityCheck {
    Authorized(LockedMucActor),
    Unauthorized,
    Stale,
}

/// Acquire the room-scoped affiliation namespace.
///
/// Archive writers take the archive relation fence first. Callers take this
/// namespace before locking `muc_rooms` and, whenever both exact
/// occupancy and affiliation rows are needed, lock occupancy before
/// affiliation. They must never acquire this lock after a room, occupancy or
/// affiliation row. Cluster writers intentionally do not use namespace 29 and
/// follow room -> occupancy -> affiliation, so they cannot form a reverse edge.
pub async fn lock_muc_affiliation_namespace(
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
/// The local account fence precedes advisory namespace 29 and the room row. Legacy
/// affiliation writers already use that order (and may then lock affiliation
/// rows), while clustered writers begin with the room row and then take exact
/// occupancy before affiliation. Keeping one order prevents a room-row ->
/// advisory / advisory -> room-row deadlock cycle and also makes a missing
/// affiliation row safe: a concurrent insert/delete cannot slip between the
/// authorization check and the durable projection.
pub async fn lock_muc_actor_authority(
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
        || northstar_xmpp_types::jid::canonical_bare_key(authority.full_jid)?
            != authority.actor_scope
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

    if let MucActorPrincipal::Local {
        user_id,
        local_domain,
    } = &authority.principal
    {
        let local_domain = northstar_xmpp_types::jid::prepare_domainpart(local_domain)?;
        let Ok(actor) = northstar_xmpp_types::jid::CanonicalJid::parse_bare(authority.actor_scope)
        else {
            return Ok(MucAuthorityCheck::Unauthorized);
        };
        if actor.domainpart() != local_domain
            || actor.resourcepart().is_some()
            || !crate::accounts::lock_enabled_user_name(
                transaction,
                *user_id,
                actor.localpart().unwrap_or_default(),
            )
            .await?
        {
            return Ok(MucAuthorityCheck::Unauthorized);
        }
    }
    lock_muc_affiliation_namespace(transaction, room_id).await?;
    #[cfg(any(test, feature = "test-support"))]
    maybe_pause_muc_authorization_for_test("discussion_after_advisory").await;
    let room = sqlx::query(
        "SELECT room_epoch,members_only,destroyed_at,configuration_state,
                logging_enabled,allow_subject_change
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
        MucActorPrincipal::Local { user_id, .. } => {
            let affiliation: Option<String> = sqlx::query_scalar(
                "SELECT affiliation FROM muc_affiliations
                  WHERE room_id=$1 AND user_id=$2 FOR UPDATE",
            )
            .bind(room_id)
            .bind(user_id)
            .fetch_optional(&mut **transaction)
            .await?;
            (affiliation.unwrap_or_else(|| "none".to_owned()), true)
        }
        MucActorPrincipal::Federated {
            bare_jid,
            authenticated_domain,
        } => {
            let actor = northstar_xmpp_types::jid::CanonicalJid::parse_bare(bare_jid)?;
            let authenticated_domain =
                northstar_xmpp_types::jid::prepare_domainpart(authenticated_domain)?;
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
                let local_domain = northstar_xmpp_types::jid::prepare_domainpart(local_domain)?;
                row.get::<String, _>("identity_kind") == "local"
                    && row.get::<Option<Uuid>, _>("local_user_id") == Some(*user_id)
                    && row.get::<String, _>("bare_jid") == authority.actor_scope
                    && northstar_xmpp_types::jid::CanonicalJid::parse_bare(authority.actor_scope)
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
        logging_enabled: room.get("logging_enabled"),
        allow_subject_change: room.get("allow_subject_change"),
    }))
}

async fn commit_muc_discussion(
    transaction: Transaction<'_, Postgres>,
    request: Option<&northstar_room_application::discussion::Request>,
    outcome: MucDiscussionAdmission,
    audience: Option<LiveAudience>,
) -> Result<DiscussionCommit> {
    if let Some(request) = request {
        use northstar_room_application::discussion::{commit_observed_with_audience, CommitError};
        commit_observed_with_audience(transaction.commit(), request, outcome, audience.clone())
            .await
            .map_err(|error| match error {
                CommitError::Observation(error) => anyhow::Error::from(error),
                CommitError::Commit(error) => anyhow::Error::from(error),
            })?;
    } else {
        transaction.commit().await?;
    }
    Ok(DiscussionCommit { outcome, audience })
}

pub async fn admit_muc_discussion_inner(
    pool: &PgPool,
    message: MucDiscussion<'_>,
    request: Option<&northstar_room_application::discussion::Request>,
) -> Result<MucDiscussionAdmission> {
    Ok(admit_muc_discussion_live(pool, message, request)
        .await?
        .outcome)
}

pub(crate) async fn admit_muc_discussion_live(
    pool: &PgPool,
    message: MucDiscussion<'_>,
    request: Option<&northstar_room_application::discussion::Request>,
) -> Result<DiscussionCommit> {
    let actor_scope = canonical_history_actor(message.actor_scope)?;
    let sender_jid = canonical_history_sender(message.sender_jid)?;
    if message.unarchived_stanza_bytes.is_none() {
        validate_history_payload(message.nick, message.stanza)?;
    }
    let mut transaction = pool.begin().await?;
    #[cfg(any(test, feature = "test-support"))]
    maybe_pause_muc_authorization_for_test("discussion").await;
    if message.authority.actor_scope != actor_scope
        || message.authority.full_jid != sender_jid
        || message.authority.nick != message.nick
    {
        transaction.rollback().await?;
        return Ok(DiscussionCommit {
            outcome: MucDiscussionAdmission::Unauthorized,
            audience: None,
        });
    }
    if message.archive_eligible {
        sqlx::query(LOCK_MUC_ARCHIVE_WRITER)
            .execute(&mut *transaction)
            .await?;
    }
    let authority =
        lock_muc_actor_authority(&mut transaction, message.room_id, &message.authority).await?;
    let archived = match authority {
        MucAuthorityCheck::Authorized(actor) if actor.role != "visitor" => {
            message.archive_eligible && actor.logging_enabled
        }
        MucAuthorityCheck::Authorized(_) | MucAuthorityCheck::Unauthorized => {
            transaction.rollback().await?;
            return Ok(DiscussionCommit {
                outcome: MucDiscussionAdmission::Unauthorized,
                audience: None,
            });
        }
        MucAuthorityCheck::Stale => {
            transaction.rollback().await?;
            return Ok(DiscussionCommit {
                outcome: MucDiscussionAdmission::Stale,
                audience: None,
            });
        }
    };
    if let Some(live_bytes) = message.unarchived_stanza_bytes {
        let bytes = if archived {
            message.stanza.len()
        } else {
            live_bytes
        };
        validate_history_payload_size(message.nick, bytes)?;
    }

    let fresh = MucDiscussionAdmission::Stored {
        id: message.id,
        archived,
    };

    let Some(origin_id) = message.origin_id else {
        if archived {
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
        let audience =
            live_audience::capture(&mut transaction, message.room_id, &message.authority).await?;
        return commit_muc_discussion(transaction, request, fresh, audience).await;
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
        if archived {
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
        let audience =
            live_audience::capture(&mut transaction, message.room_id, &message.authority).await?;
        return commit_muc_discussion(transaction, request, fresh, audience).await;
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
    commit_muc_discussion(
        transaction,
        request,
        MucDiscussionAdmission::Replay(existing_id),
        None,
    )
    .await
}

/// Change a single-node room subject under the same database authority fence
/// as discussion and retraction admission. The optional MAM projection is in
/// the same transaction, so a failed archive insert cannot leave a subject
/// that history cannot explain. Plaintext subjects may still update room state
/// when encrypted-only archive policy deliberately disables that projection.
pub async fn set_local_muc_subject(
    pool: &PgPool,
    mutation: MucSubjectMutation<'_>,
    archive_stanza: Option<&str>,
    authority: MucActorAuthority<'_>,
) -> Result<MucSubjectOutcome> {
    let actor_scope = canonical_history_actor(mutation.actor_scope)?;
    let sender_jid = canonical_history_sender(mutation.sender_jid)?;
    let live_bytes = mutation.stanza.len();
    let candidate_bytes = archive_stanza.map_or(live_bytes, str::len);
    if live_bytes == candidate_bytes {
        validate_history_payload_size(mutation.nick, live_bytes)?;
    }
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
    if archive_stanza.is_some() {
        sqlx::query(LOCK_MUC_ARCHIVE_WRITER)
            .execute(&mut *transaction)
            .await?;
    }
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
    let archive_stanza = archive_stanza.filter(|_| locked.logging_enabled);
    if live_bytes != candidate_bytes {
        let bytes = archive_stanza.map_or(live_bytes, str::len);
        validate_history_payload_size(mutation.nick, bytes)?;
    }
    if locked.role != "moderator" && !(locked.role == "participant" && locked.allow_subject_change)
    {
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
    if let Some(stanza) = archive_stanza {
        sqlx::query(
            "INSERT INTO muc_messages
             (id, room_id, sender_jid, nick, stanza, encrypted, message_kind, actor_scope)
             VALUES ($1, $2, $3, $4, $5, $6, 'subject', $7)",
        )
        .bind(mutation.stanza_id)
        .bind(mutation.room_id)
        .bind(sender_jid)
        .bind(mutation.nick)
        .bind(stanza)
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
    Ok(retract_muc_message_live(pool, mutation).await?.0)
}

pub(crate) async fn retract_muc_message_live(
    pool: &PgPool,
    mutation: MucRetractionMutation<'_>,
) -> Result<(MucRetractionOutcome, Option<LiveAudience>)> {
    match retract_muc_message_once(pool, &mutation).await {
        Err(error)
            if error
                .downcast_ref::<sqlx::Error>()
                .and_then(sqlx::Error::as_database_error)
                .and_then(|database| database.code())
                .is_some_and(|code| matches!(code.as_ref(), "40P01" | "40001")) =>
        {
            retract_muc_message_once(pool, &mutation).await
        }
        result => result,
    }
}

async fn retract_muc_message_once(
    pool: &PgPool,
    mutation: &MucRetractionMutation<'_>,
) -> Result<(MucRetractionOutcome, Option<LiveAudience>)> {
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
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await?;
    // The retraction race fixture must stop before the authority snapshot.
    // A concurrent affiliation change can then commit, after which this
    // transaction takes the normal namespace/row locks and observes the
    // changed authority instead of creating a time-of-check/time-of-use gap.
    #[cfg(any(test, feature = "test-support"))]
    maybe_pause_muc_authorization_for_test("retraction").await;
    if mutation.authority.actor_scope != actor_scope
        || mutation.authority.full_jid != sender_jid
        || mutation.authority.nick != mutation.nick
    {
        transaction.rollback().await?;
        return Ok((MucRetractionOutcome::Unauthorized, None));
    }
    // Scoped holds take SHARE before inspecting the room subject. Take our
    // compatible writer fence before the namespace and room locks.
    sqlx::query(LOCK_MUC_ARCHIVE_WRITER)
        .execute(&mut *transaction)
        .await?;
    let actor =
        match lock_muc_actor_authority(&mut transaction, mutation.room_id, &mutation.authority)
            .await?
        {
            MucAuthorityCheck::Authorized(actor) => actor,
            MucAuthorityCheck::Unauthorized => {
                transaction.rollback().await?;
                return Ok((MucRetractionOutcome::Unauthorized, None));
            }
            MucAuthorityCheck::Stale => {
                transaction.rollback().await?;
                return Ok((MucRetractionOutcome::Stale, None));
            }
        };
    if mutation.kind == MucRetractionKind::Moderator
        && actor.role != "moderator"
        && !matches!(actor.affiliation.as_str(), "owner" | "admin")
    {
        transaction.rollback().await?;
        return Ok((MucRetractionOutcome::Unauthorized, None));
    }

    let target = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM muc_messages
          WHERE room_id=$1 AND id=$2 AND message_kind='discussion'
            AND retracted_at IS NULL FOR UPDATE",
    )
    .bind(mutation.room_id)
    .bind(mutation.target_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if target.is_none() {
        transaction.rollback().await?;
        return Ok((MucRetractionOutcome::Conflict, None));
    }
    let target = sqlx::query(
        "SELECT a.stanza,a.actor_scope,
                (EXISTS (
                    SELECT 1 FROM legal_hold_muc_archives l
                    JOIN legal_holds h ON h.id=l.hold_id
                    WHERE l.message_id=a.id AND h.released_at IS NULL
                ) OR EXISTS (
                    SELECT 1 FROM legal_hold_scopes s
                    JOIN legal_holds h ON h.id=s.hold_id
                    WHERE s.scope_type='muc_archive_room'
                      AND s.subject_id=a.room_id AND h.released_at IS NULL
                )) AS held
         FROM muc_messages a
         WHERE a.room_id=$1 AND a.id=$2
           AND NOT EXISTS (SELECT 1 FROM muc_archive_display_changes d WHERE d.message_id=a.id)",
    )
    .bind(mutation.room_id)
    .bind(mutation.target_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(target) = target else {
        transaction.rollback().await?;
        return Ok((MucRetractionOutcome::Conflict, None));
    };
    if target.get::<String, _>("stanza") != mutation.expected_stanza
        || (mutation.kind == MucRetractionKind::Author
            && target.get::<Option<String>, _>("actor_scope").as_deref()
                != Some(actor_scope.as_str()))
    {
        transaction.rollback().await?;
        let outcome = if mutation.kind == MucRetractionKind::Author {
            MucRetractionOutcome::Unauthorized
        } else {
            MucRetractionOutcome::Conflict
        };
        return Ok((outcome, None));
    }

    if target.get::<bool, _>("held") {
        let change_kind = match mutation.kind {
            MucRetractionKind::Author => "muc_retraction",
            MucRetractionKind::Moderator => "muc_moderation",
        };
        sqlx::query(
            "INSERT INTO muc_archive_display_changes
                (message_id,display_stanza,change_kind,actor_bare_jid,action_id,reason)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(mutation.target_id)
        .bind(mutation.tombstone)
        .bind(change_kind)
        .bind(&actor_scope)
        .bind(mutation.action_id)
        .bind(mutation.reason)
        .execute(&mut *transaction)
        .await?;
    } else {
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
            return Ok((MucRetractionOutcome::Conflict, None));
        }
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
    let audience =
        live_audience::capture(&mut transaction, mutation.room_id, &mutation.authority).await?;
    transaction.commit().await?;
    Ok((MucRetractionOutcome::Applied, audience))
}

pub async fn muc_message_by_id(
    pool: &PgPool,
    room_id: Uuid,
    message_id: Uuid,
) -> Result<Option<MucMessage>> {
    let row = sqlx::query(
        "SELECT sender_jid, stanza, created_at FROM muc_messages
         WHERE room_id=$1 AND id=$2 AND retracted_at IS NULL
           AND NOT EXISTS (SELECT 1 FROM muc_archive_display_changes d
                           WHERE d.message_id=muc_messages.id)",
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
        "SELECT sender_jid, COALESCE(d.display_stanza,a.stanza) AS stanza, created_at
          FROM muc_messages a
          LEFT JOIN muc_archive_display_changes d ON d.message_id=a.id
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
