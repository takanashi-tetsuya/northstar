//! Occupant construction and the PostgreSQL-authoritative join.

use super::*;
use northstar_room_application::muc_service::{
    MucJoinCommitOutcome, MucJoinProjection, MucJoinProjectionRequest, SerializableMucOccupant,
};

pub(super) struct CommittedJoin<H: MucHost> {
    pub(super) occupant: Occupant<H>,
    pub(super) serializable: SerializableMucOccupant,
    pub(super) cluster_event_id: Option<String>,
    pub(super) projection: Option<Box<MucJoinProjection>>,
}

pub(super) async fn commit_join<S: MucSession>(
    session: &S,
    request: &JoinRequest<'_, '_>,
    raw: &str,
    room: &mut MucRoom,
    affiliation: String,
    role: String,
    history_request: MucHistoryRequest,
) -> Result<JoinStep<CommittedJoin<S::Host>>> {
    let JoinRequest {
        root,
        user,
        full_jid,
        room_jid,
        nick,
    } = *request;
    let payload = muc_presence_payload(root, raw);

    let mut occupant = MucOccupant {
        full_jid: full_jid.clone(),
        room_jid: room_jid.clone(),
        nick: nick.to_owned(),
        endpoint: northstar_room_core::occupancy::MucOccupantEndpoint::Local(
            session.outbound().clone(),
        ),
        affiliation,
        role,
        room_non_anonymous: room.non_anonymous,
        occupant_id: muc_occupant_id(&room.occupant_id_secret, bare_jid(full_jid)),
        cluster_epoch: uuid::Uuid::new_v4(),
        connection_id: session.connection_id(),
        sm_session_id: session.sm_db_id(),
        payload,
    };
    let mut projection = None;
    let mut cluster_event_id = None;
    if session.host().muc_pg_authority_enabled() {
        session.host().admit_muc_pg_mutation()?;
        // PostgreSQL authorizes the join in both runtime modes. Redis is
        // only a routing cache when multiple nodes are configured.
        let principal = ClusterMucPrincipal::Local {
            user_id: user.id,
            bare_jid: bare_jid(full_jid).to_owned(),
        };
        let cluster_operation_id = uuid::Uuid::new_v4();
        let committed = match session
            .host()
            .muc_service()
            .commit_muc_join(
                ClusterMucJoin {
                    operation_id: cluster_operation_id,
                    room_id: room.id,
                    expected_room_epoch: room.room_epoch,
                    expected_config_version: room.config_version,
                    principal,
                    full_jid,
                    nick,
                    owner_node_id: session.host().muc_cluster_node_id(),
                    connection_uuid: session.connection_id(),
                    connection_epoch: 1,
                    sm_session_id: session.sm_db_id(),
                    occupant_incarnation: occupant.cluster_epoch,
                    presence_payload: &occupant.payload,
                    lease: std::time::Duration::from_secs(90),
                },
                MucJoinProjectionRequest {
                    room_jid,
                    verified_password_hash: room.password_hash.as_deref(),
                    include_history: history_request.max_stanzas != 0,
                    history_since: history_request.since,
                },
            )
            .await?
        {
            MucJoinCommitOutcome::Committed(committed) => committed,
            MucJoinCommitOutcome::PasswordChanged => {
                return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                    root,
                    full_jid,
                    "auth",
                    "not-authorized",
                ))));
            }
            MucJoinCommitOutcome::Claim(outcome) => {
                let (kind, condition) = match *outcome {
                    ClusterMucJoinOutcome::Outcast => ("auth", "forbidden"),
                    ClusterMucJoinOutcome::MembershipRequired => ("auth", "registration-required"),
                    ClusterMucJoinOutcome::ReservedNickname
                    | ClusterMucJoinOutcome::NicknameConflict
                    | ClusterMucJoinOutcome::FullJidConflict => ("cancel", "conflict"),
                    ClusterMucJoinOutcome::Full => ("wait", "service-unavailable"),
                    ClusterMucJoinOutcome::RoomMissing
                    | ClusterMucJoinOutcome::RoomDestroyed
                    | ClusterMucJoinOutcome::RoomLocked
                    | ClusterMucJoinOutcome::StaleRoom => ("cancel", "item-not-found"),
                    ClusterMucJoinOutcome::Joined(_) | ClusterMucJoinOutcome::Replay(_) => {
                        anyhow::bail!(
                            "successful MUC join did not return its committed projection"
                        );
                    }
                };
                return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                    root, full_jid, kind, condition,
                ))));
            }
        };
        anyhow::ensure!(
            committed.actor.identity_kind == "local"
                && committed.actor.local_user_id == Some(user.id)
                && committed.actor.authenticated_domain.is_none()
                && committed.actor.owner_node_id == session.host().muc_cluster_node_id(),
            "committed MUC join changed the local principal or owner"
        );
        super::projection::apply_committed_join(&mut occupant, room, &committed)?;
        cluster_event_id = Some(cluster_operation_id.to_string());
        if let Err(error) = session
            .host()
            .wake_committed_muc_operation(cluster_operation_id)
            .await
        {
            tracing::warn!(?error, %room_jid, operation_id=%cluster_operation_id,
                    "MUC join committed; signed wake failed and PostgreSQL polling will catch up");
        }
        if session.host().muc_redis_transport_enabled() {
            let effective_capacity = committed.max_occupants as usize
                + usize::from(matches!(occupant.affiliation.as_str(), "owner" | "admin")) * 10;
            // The cache cannot authorize a join; PostgreSQL already did.
            let cache = session
                .host()
                .cache_committed_muc_join(
                    &SerializableMucOccupant::from(&occupant),
                    effective_capacity,
                )
                .await?;
            if let Err(error) = cache.refresh {
                tracing::warn!(?error, %room_jid,
                        "PostgreSQL committed MUC join; Redis occupancy cache refresh failed");
            }
            match cache.registration {
                Ok(northstar_room_core::occupancy::MucRegistration::Joined) => {}
                Ok(northstar_room_core::occupancy::MucRegistration::Conflict)
                | Ok(northstar_room_core::occupancy::MucRegistration::Full) => {
                    tracing::warn!(%room_jid, %nick,
                            "Redis MUC cache disagreed with committed PostgreSQL occupancy; cache will reconcile");
                }
                Err(error) => tracing::warn!(?error, %room_jid,
                        "PostgreSQL committed MUC join; Redis cache update failed"),
            }
        }
        projection = Some(committed);
    }
    Ok(JoinStep::Next(CommittedJoin {
        serializable: SerializableMucOccupant::from(&occupant),
        occupant,
        cluster_event_id,
        projection,
    }))
}
