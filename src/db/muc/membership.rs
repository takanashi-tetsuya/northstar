//! Persist local and federated membership, nickname reservations, and durable invitation admission.

use super::*;

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
    let actor = northstar_xmpp_types::jid::CanonicalJid::parse_bare(actor_bare_jid)?;
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
    let actor = northstar_xmpp_types::jid::CanonicalJid::parse_bare(actor_bare_jid)?;
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
    let actor = northstar_xmpp_types::jid::CanonicalJid::parse_bare(actor_bare_jid)?.to_string();
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
    let actor = northstar_xmpp_types::jid::CanonicalJid::parse_bare(actor_bare_jid)?;
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
    cluster_authority: Option<&super::super::cluster_muc::ClusterMucInviteAuthority>,
) -> Result<DurableMucInviteOutcome> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 17))")
        .bind(format!("{room_id}:{recipient_id}"))
        .execute(&mut **transaction)
        .await?;
    let affiliation_changed = if let Some(authority) = cluster_authority {
        anyhow::ensure!(
            matches!(
                &authority.subject,
                super::super::cluster_muc::ClusterMucAffiliationSubject::Local {
                    user_id,
                    ..
                } if *user_id == recipient_id
            ),
            "clustered local MUC invite subject does not match recipient"
        );
        match super::super::cluster_muc::grant_cluster_muc_invitation_in_tx(
            transaction,
            room_id,
            authority,
        )
        .await?
        {
            super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::Applied {
                affiliation_changed,
            } => affiliation_changed,
            super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::Replay { .. } => {
                return Ok(DurableMucInviteOutcome::Replay { id });
            }
            super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::Outcast => {
                return Ok(DurableMucInviteOutcome::Outcast);
            }
            super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::Stale
            | super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::Destroyed => {
                return Ok(DurableMucInviteOutcome::Stale);
            }
            super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::Conflict
            | super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::NotAllowed
            | super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::Unauthorized => {
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
        live_claim_id: None,
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
    policy: super::super::OfflineStorePolicy,
    cluster_authority: Option<&super::super::cluster_muc::ClusterMucInviteAuthority>,
) -> Result<DurableMucInviteOutcome> {
    let mut transaction = pool.begin().await?;
    if cluster_authority.is_some() {
        // The node-instance claim takes this lock exclusively. Acquire its
        // shared side before user and room locks, as for personal direct
        // admission, so a new instance cannot miss this late wake fanout.
        super::super::cluster_keys::lock_direct_spool_instance_claims_in_transaction(
            &mut transaction,
        )
        .await?;
    }
    if !northstar_auth_postgres::users::lock_enabled_users_in_transaction(
        &mut transaction,
        &[recipient_id],
    )
    .await?
    {
        transaction.rollback().await?;
        return Ok(DurableMucInviteOutcome::RecipientUnavailable);
    }
    let recipient_bare_jid = northstar_xmpp_types::jid::canonicalize_bare(recipient_bare_jid)?;
    let recipient_authority =
        northstar_xmpp_types::jid::CanonicalJid::parse_bare(&recipient_bare_jid)?;
    if let Some(authority) = cluster_authority {
        anyhow::ensure!(
            matches!(
                &authority.subject,
                super::super::cluster_muc::ClusterMucAffiliationSubject::Local { user_id, bare_jid }
                    if *user_id == recipient_id && bare_jid == &recipient_bare_jid
            ),
            "cluster MUC invite recipient authority does not match the durable row"
        );
    }
    let recipient_matches: bool =
        sqlx::query_scalar("SELECT northstar_lock_enabled_user_name($1,$2)")
            .bind(recipient_id)
            .bind(recipient_authority.localpart().unwrap_or_default())
            .fetch_one(&mut *transaction)
            .await?;
    anyhow::ensure!(
        recipient_matches,
        "local MUC invite recipient account is unavailable or authority does not match"
    );
    let document = roxmltree::Document::parse(stanza)?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "message",
        "MUC invite is not a message"
    );
    let target = northstar_xmpp_types::jid::CanonicalJid::parse(
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
    let live_claim_id = if cluster_authority.is_some() {
        super::super::archive::reserve_cluster_live_delivery_in_transaction(
            &mut transaction,
            recipient_id,
            id,
        )
        .await?;
        super::super::direct_spool_wake_repository::record_direct_spool_wake_in_transaction(
            &mut transaction,
            recipient_authority.domainpart(),
            recipient_id,
        )
        .await?;
        Some(id)
    } else {
        None
    };
    transaction.commit().await?;
    Ok(DurableMucInviteOutcome::Stored {
        id,
        affiliation_changed,
        live_claim_id,
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
    policy: super::super::S2sOutboxPolicy,
    cluster_authority: Option<&super::super::cluster_muc::ClusterMucInviteAuthority>,
) -> Result<bool> {
    let invitee = northstar_xmpp_types::jid::CanonicalJid::parse_bare(invitee_bare_jid)?;
    anyhow::ensure!(
        invitee.localpart().is_some(),
        "MUC invitee requires a user JID"
    );
    let invitee = invitee.to_string();
    let mut transaction = pool.begin().await?;
    // The S2S outbox has one global capacity lock. Acquire it before the
    // room/user lock so personal-history + outbox admissions can append the
    // same room mutation without creating an outbox <-> room inversion.
    if let Err(error) = super::super::enqueue_s2s_outbox_in_transaction(
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

/// Apply only the federated member authorization mutation in a caller-owned
/// transaction. Callers that also enqueue S2S must acquire the outbox lock
/// first; this helper then appends the final room/invitee lock.
pub(crate) async fn grant_federated_muc_invite_affiliation_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    invitee_bare_jid: &str,
    cluster_authority: Option<&super::super::cluster_muc::ClusterMucInviteAuthority>,
) -> Result<FederatedMucInviteAffiliationOutcome> {
    let invitee = northstar_xmpp_types::jid::CanonicalJid::parse_bare(invitee_bare_jid)?;
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
                super::super::cluster_muc::ClusterMucAffiliationSubject::Federated { bare_jid }
                    if bare_jid == &invitee
            ),
            "clustered federated MUC invite subject does not match recipient"
        );
        match super::super::cluster_muc::grant_cluster_muc_invitation_in_tx(
            transaction,
            room_id,
            authority,
        )
        .await?
        {
            super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::Applied { .. } => {}
            super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::Replay { .. } => {
                return Ok(FederatedMucInviteAffiliationOutcome::Replay);
            }
            super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::Outcast
            | super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::Conflict
            | super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::NotAllowed
            | super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::Unauthorized => {
                return Ok(FederatedMucInviteAffiliationOutcome::Rejected);
            }
            super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::Stale
            | super::super::cluster_muc::ClusterMucAffiliationMutationOutcome::Destroyed => {
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
    let jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(bare_jid)?;
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
