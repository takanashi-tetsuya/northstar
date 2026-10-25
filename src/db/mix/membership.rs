//! MIX channel events, participant rosters and channel join.

use super::*;

pub(super) async fn prune_mix_events_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    max_events: i32,
) -> Result<()> {
    // `max_events` is the channel message/MAM retention limit.  Current-state
    // nodes are independent authorities: message traffic must never evict the
    // singleton info/config item, participants, avatar or live presence.
    sqlx::query(
        "DELETE FROM mix_events
          WHERE channel_id=$1 AND node=$3
            AND id NOT IN (
                SELECT id FROM mix_events
                 WHERE channel_id=$1 AND node=$3
                 ORDER BY created_at DESC,id DESC LIMIT $2
            )",
    )
    .bind(channel_id)
    .bind(max_events)
    .bind(NODE_MESSAGES)
    .execute(&mut **transaction)
    .await?;
    // Information and configuration are singleton current-state nodes. Their
    // committed notification history lives in the normalized delivery
    // outbox; retaining superseded authority rows here is both misleading
    // and unbounded.
    sqlx::query(
        "DELETE FROM mix_events
          WHERE channel_id=$1 AND node IN ($2,$3)
            AND id NOT IN (
                SELECT DISTINCT ON (node) id FROM mix_events
                 WHERE channel_id=$1 AND node IN ($2,$3)
                 ORDER BY node,created_at DESC,id DESC
            )",
    )
    .bind(channel_id)
    .bind(NODE_INFO)
    .bind(NODE_CONFIG)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub(super) async fn store_mix_event_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel: &MixChannel,
    node: &str,
    item_id: &str,
    publisher: Option<&MixParticipant>,
    payload: &str,
) -> Result<Option<Uuid>> {
    anyhow::ensure!(ALL_NODES.contains(&node), "unknown MIX node");
    anyhow::ensure!(
        !item_id.is_empty() && item_id.len() <= 3071,
        "invalid MIX item id"
    );
    anyhow::ensure!(payload.len() <= 1_048_576, "MIX event payload too large");
    let id = Uuid::new_v4();
    let replace_existing = node != NODE_MESSAGES;
    let affected = sqlx::query(
        "INSERT INTO mix_events (id, channel_id, node, item_id, publisher_id, publisher_jid, payload) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (channel_id, node, item_id) DO UPDATE SET publisher_id = EXCLUDED.publisher_id, publisher_jid = EXCLUDED.publisher_jid, payload = EXCLUDED.payload, created_at = NOW() WHERE $8",
    )
    .bind(id)
    .bind(channel.id)
    .bind(node)
    .bind(item_id)
    .bind(publisher.map(|participant| participant.participant_id))
    .bind(publisher.map(|participant| participant.jid.as_str()))
    .bind(payload)
    .bind(replace_existing)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if affected == 0 {
        return Ok(None);
    }
    prune_mix_events_tx(transaction, channel.id, channel.max_events).await?;
    Ok(Some(id))
}

pub(super) async fn upsert_mix_roster_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    channel_jid: &str,
    display_name: Option<&str>,
    share_presence: bool,
) -> Result<super::super::RosterChange> {
    let channel_jid = northstar_xmpp_types::jid::canonicalize_bare(channel_jid)?;
    sqlx::query(
        "INSERT INTO roster_items (owner_id, contact_jid, display_name, subscription, ask) VALUES ($1, $2, $3, $4, NULL) ON CONFLICT (owner_id, contact_jid) DO UPDATE SET display_name = EXCLUDED.display_name, subscription = EXCLUDED.subscription, ask = NULL, updated_at = NOW()",
    )
    .bind(user_id)
    .bind(&channel_jid)
    .bind(display_name)
    .bind(if share_presence { "to" } else { "none" })
    .execute(&mut **transaction)
    .await?;
    let version: i64 = sqlx::query_scalar("SELECT northstar_user_bump_roster_version($1)")
        .bind(user_id)
        .fetch_one(&mut **transaction)
        .await?;
    super::super::roster::record_roster_change(transaction, user_id, version, &channel_jid, false)
        .await
}

pub(super) async fn delete_mix_roster_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    channel_jid: &str,
) -> Result<Option<super::super::RosterChange>> {
    let channel_jid = northstar_xmpp_types::jid::canonicalize_bare(channel_jid)?;
    let deleted = sqlx::query("DELETE FROM roster_items WHERE owner_id = $1 AND contact_jid = $2")
        .bind(user_id)
        .bind(&channel_jid)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Ok(None);
    }
    let version: i64 = sqlx::query_scalar("SELECT northstar_user_bump_roster_version($1)")
        .bind(user_id)
        .fetch_one(&mut **transaction)
        .await?;
    Ok(Some(
        super::super::roster::record_roster_change(
            transaction,
            user_id,
            version,
            &channel_jid,
            true,
        )
        .await?,
    ))
}

pub async fn join_mix_channel(
    pool: &PgPool,
    channel_id: Uuid,
    request: JoinMixRequest<'_>,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<JoinChannelOutcome> {
    let actor_jid = canonical_user_bare(request.actor_jid)?;
    let nodes = valid_join_nodes(request.nodes)?;
    let nick = request.nick.map(prepare_mix_nick).transpose()?;
    let mut preference = request.preference.cloned().unwrap_or_default();
    validate_mix_participant_preference(&preference)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("mix-actor:{actor_jid}"))
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(channel_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR UPDATE")
        .bind(channel_id)
        .fetch_one(&mut *transaction)
        .await?;
    let channel = channel_from_row(&row);
    if let Some(user_id) = request.pam_user_id {
        anyhow::ensure!(
            pam_account_matches_actor_tx(&mut transaction, user_id, &actor_jid).await?,
            "MIX-PAM account UUID does not belong to authenticated actor"
        );
    }
    if (channel.jid_visibility == "visible" && preference.jid_visibility == "never")
        || (channel.jid_visibility == "hidden" && preference.jid_visibility == "always")
    {
        transaction.rollback().await?;
        return Ok(JoinChannelOutcome::NotAllowed);
    }
    let registered_nick: Option<String> = sqlx::query_scalar(
        "SELECT nick FROM mix_registered_nicks WHERE service_domain = $1 AND jid = $2",
    )
    .bind(&channel.service_domain)
    .bind(&actor_jid)
    .fetch_optional(&mut *transaction)
    .await?;
    if channel.enforce_registered_nick && registered_nick.as_deref() != nick.as_deref() {
        transaction.rollback().await?;
        return Ok(if nick.is_none() {
            JoinChannelOutcome::MissingNick
        } else {
            JoinChannelOutcome::NickConflict
        });
    }
    if channel.nick_required && nick.is_none() {
        transaction.rollback().await?;
        return Ok(JoinChannelOutcome::MissingNick);
    }
    if let Some(nick) = nick.as_deref() {
        let collision: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mix_participants WHERE channel_id = $1 AND nick = $2 AND jid <> $3)",
        )
        .bind(channel_id)
        .bind(nick)
        .bind(&actor_jid)
        .fetch_one(&mut *transaction)
        .await?;
        if collision {
            transaction.rollback().await?;
            return Ok(JoinChannelOutcome::NickConflict);
        }
    }
    let actor_domain = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&actor_jid)?
        .domainpart()
        .to_owned();
    let banned: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_banned WHERE channel_id = $1 AND jid_pattern IN ($2, $3))",
    )
    .bind(channel_id)
    .bind(&actor_jid)
    .bind(&actor_domain)
    .fetch_one(&mut *transaction)
    .await?;
    if banned {
        transaction.rollback().await?;
        return Ok(JoinChannelOutcome::Banned);
    }
    if channel.access_model == "allowlist" {
        let mut allowed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mix_allowed WHERE channel_id = $1 AND jid_pattern IN ($2, $3)) OR EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2)",
        )
        .bind(channel_id)
        .bind(&actor_jid)
        .bind(&actor_domain)
        .fetch_one(&mut *transaction)
        .await?;
        if !allowed {
            if let Some(invitation) = request.invitation {
                let channel_jid =
                    northstar_xmpp_types::jid::canonicalize_bare(&invitation.channel_jid)?;
                let inviter_jid = canonical_user_bare(&invitation.inviter_jid)?;
                let invitee_jid = canonical_user_bare(&invitation.invitee_jid)?;
                anyhow::ensure!(
                    channel_jid == channel.jid() && invitee_jid == actor_jid,
                    "MIX invitation identity mismatch"
                );
                let digest = Sha256::digest(invitation.token.as_bytes()).to_vec();
                let consumed = sqlx::query(
                    "UPDATE mix_invitations SET consumed_at = NOW() WHERE channel_id = $1 AND inviter_jid = $2 AND invitee_jid = $3 AND token_hash = $4 AND consumed_at IS NULL AND expires_at > NOW() RETURNING id",
                )
                .bind(channel_id)
                .bind(&inviter_jid)
                .bind(&invitee_jid)
                .bind(digest)
                .fetch_optional(&mut *transaction)
                .await?
                .is_some();
                if consumed {
                    sqlx::query(
                        "INSERT INTO mix_allowed (channel_id, jid_pattern, added_by) VALUES ($1, $2, $3) ON CONFLICT (channel_id, jid_pattern) DO NOTHING",
                    )
                    .bind(channel_id)
                    .bind(&actor_jid)
                    .bind(&inviter_jid)
                    .execute(&mut *transaction)
                    .await?;
                    allowed = true;
                }
            }
        }
        if !allowed {
            transaction.rollback().await?;
            return Ok(JoinChannelOutcome::NotAllowed);
        }
    }

    let existing = sqlx::query(
        "SELECT channel_id, participant_id, jid, nick, role, joined_at FROM mix_participants WHERE channel_id = $1 AND jid = $2",
    )
    .bind(channel_id)
    .bind(&actor_jid)
    .fetch_optional(&mut *transaction)
    .await?;
    let newly_joined = existing.is_none();
    let nick_changed = existing
        .as_ref()
        .is_some_and(|row| nick.is_some() && row.get::<Option<String>, _>("nick") != nick);
    let participant = if let Some(row) = existing {
        if nick.is_some() && row.get::<Option<String>, _>("nick") != nick {
            sqlx::query(
                "UPDATE mix_participants SET nick = $3, updated_at = NOW() WHERE channel_id = $1 AND jid = $2",
            )
            .bind(channel_id)
            .bind(&actor_jid)
            .bind(&nick)
            .execute(&mut *transaction)
            .await?;
        }
        let mut participant = participant_from_row(&row);
        if nick.is_some() {
            participant.nick = nick.clone();
        }
        participant
    } else {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM mix_participants WHERE channel_id = $1")
                .bind(channel_id)
                .fetch_one(&mut *transaction)
                .await?;
        if count >= i64::from(channel.max_participants) {
            transaction.rollback().await?;
            return Ok(JoinChannelOutcome::Full);
        }
        let candidate = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO mix_participant_identities (channel_id, jid, participant_id) VALUES ($1, $2, $3) ON CONFLICT (channel_id, jid) DO NOTHING",
        )
        .bind(channel_id)
        .bind(&actor_jid)
        .bind(candidate)
        .execute(&mut *transaction)
        .await?;
        let participant_id: Uuid = sqlx::query_scalar(
            "SELECT participant_id FROM mix_participant_identities WHERE channel_id = $1 AND jid = $2",
        )
        .bind(channel_id)
        .bind(&actor_jid)
        .fetch_one(&mut *transaction)
        .await?;
        let role = sqlx::query_scalar::<_, String>(
            "SELECT role FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2",
        )
        .bind(channel_id)
        .bind(&actor_jid)
        .fetch_optional(&mut *transaction)
        .await?
        .unwrap_or_else(|| "participant".to_owned());
        let role = if role == "administrator" {
            "administrator".to_owned()
        } else if role == "owner" {
            "owner".to_owned()
        } else {
            "participant".to_owned()
        };
        let row = sqlx::query(
            "INSERT INTO mix_participants (channel_id, participant_id, jid, nick, role) VALUES ($1, $2, $3, $4, $5) RETURNING channel_id, participant_id, jid, nick, role, joined_at",
        )
        .bind(channel_id)
        .bind(participant_id)
        .bind(&actor_jid)
        .bind(&nick)
        .bind(role)
        .fetch_one(&mut *transaction)
        .await?;
        let participant = participant_from_row(&row);
        sqlx::query(
            "INSERT INTO mix_participant_preferences (channel_id, participant_id, jid_visibility, private_messages, vcard, share_presence) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(channel_id)
        .bind(participant.participant_id)
        .bind(&preference.jid_visibility)
        .bind(&preference.private_messages)
        .bind(&preference.vcard)
        .bind(preference.share_presence)
        .execute(&mut *transaction)
        .await?;
        participant
    };
    if !newly_joined && request.preference.is_some() {
        sqlx::query(
            "INSERT INTO mix_participant_preferences (channel_id, participant_id, jid_visibility, private_messages, vcard, share_presence) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (channel_id, participant_id) DO UPDATE SET jid_visibility = EXCLUDED.jid_visibility, private_messages = EXCLUDED.private_messages, vcard = EXCLUDED.vcard, share_presence = EXCLUDED.share_presence, updated_at = NOW()",
        )
        .bind(channel_id)
        .bind(participant.participant_id)
        .bind(&preference.jid_visibility)
        .bind(&preference.private_messages)
        .bind(&preference.vcard)
        .bind(preference.share_presence)
        .execute(&mut *transaction)
        .await?;
    } else if !newly_joined {
        let row = sqlx::query(
            "SELECT jid_visibility, private_messages, vcard, share_presence FROM mix_participant_preferences WHERE channel_id = $1 AND participant_id = $2",
        )
        .bind(channel_id)
        .bind(participant.participant_id)
        .fetch_one(&mut *transaction)
        .await?;
        preference = MixParticipantPreference {
            jid_visibility: row.get("jid_visibility"),
            private_messages: row.get("private_messages"),
            vcard: row.get("vcard"),
            share_presence: row.get("share_presence"),
        };
    }
    for node in &nodes {
        sqlx::query(
            "INSERT INTO mix_subscriptions (channel_id, participant_id, node) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(channel_id)
        .bind(participant.participant_id)
        .bind(node)
        .execute(&mut *transaction)
        .await?;
    }
    if newly_joined || nick_changed {
        let payload = payloads.participant_payload(&channel, &participant, &preference);
        let event_id = store_mix_event_tx(
            &mut transaction,
            &channel,
            NODE_PARTICIPANTS,
            &participant.participant_id.to_string(),
            Some(&participant),
            &payload,
        )
        .await?
        .context("MIX participant event unexpectedly conflicted")?;
        enqueue_mix_node_event_tx(
            &mut transaction,
            &delivery_fence,
            MixNodeProjection {
                channel: &channel,
                node: NODE_PARTICIPANTS,
                item_id: &participant.participant_id.to_string(),
                payload: Some(&payload),
                retract: false,
                event_id,
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
    }
    let mut roster_change = None;
    if let Some(user_id) = request.pam_user_id {
        let membership_id = Uuid::new_v4();
        sqlx::query(
        "INSERT INTO mix_pam_memberships (id, user_id, channel_jid, participant_id, nick, state) VALUES ($1, $2, $3, $4, $5, 'joined') ON CONFLICT (user_id, channel_jid) DO UPDATE SET participant_id = EXCLUDED.participant_id, nick = EXCLUDED.nick, state = 'joined', request_id = NULL, client_request_id = NULL, requester_full_jid = NULL, updated_at = NOW()",
        )
        .bind(membership_id)
        .bind(user_id)
        .bind(channel.jid())
        .bind(participant.participant_id.to_string())
        .bind(&participant.nick)
        .execute(&mut *transaction)
        .await?;
        let membership_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM mix_pam_memberships WHERE user_id = $1 AND channel_jid = $2",
        )
        .bind(user_id)
        .bind(channel.jid())
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query("DELETE FROM mix_pam_subscriptions WHERE membership_id = $1")
            .bind(membership_id)
            .execute(&mut *transaction)
            .await?;
        for node in &nodes {
            sqlx::query("INSERT INTO mix_pam_subscriptions (membership_id, node) VALUES ($1, $2)")
                .bind(membership_id)
                .bind(node)
                .execute(&mut *transaction)
                .await?;
        }
        roster_change = Some(Box::new(
            upsert_mix_roster_tx(
                &mut transaction,
                user_id,
                &channel.jid(),
                channel.name.as_deref(),
                preference.share_presence,
            )
            .await?,
        ));
    }
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::Join {
            participant: participant.clone(),
            subscriptions: nodes.clone(),
            preference: request.preference.map(|_| preference.clone()),
            anonymous_profile: request.anonymous_profile,
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(JoinChannelOutcome::Joined {
        participant,
        preference,
        subscriptions: nodes,
        newly_joined,
        roster_change,
    })
}
