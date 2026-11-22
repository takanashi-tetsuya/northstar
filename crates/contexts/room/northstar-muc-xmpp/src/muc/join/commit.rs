//! Occupant construction and the PostgreSQL-authoritative join.

use super::*;
use northstar_room_application::muc_service::SerializableMucOccupant;

pub(super) struct CommittedJoin<H: MucHost> {
    pub(super) occupant: Occupant<H>,
    pub(super) serializable: SerializableMucOccupant,
    pub(super) cluster_event_id: Option<String>,
}

pub(super) async fn commit_join<S: MucSession>(
    session: &S,
    request: &JoinRequest<'_, '_>,
    raw: &str,
    room: &MucRoom,
    affiliation: String,
    role: String,
    effective_capacity: usize,
) -> Result<JoinStep<CommittedJoin<S::Host>>> {
    let JoinRequest {
        root,
        user,
        full_jid,
        room_jid,
        nick,
    } = *request;
    let payload = muc_presence_payload(root, raw);

    let occupant = MucOccupant {
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
    let serializable =
        northstar_room_application::muc_service::SerializableMucOccupant::from(&occupant);
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
        match session
            .host()
            .muc_service()
            .claim_local_cluster_occupancy(ClusterMucJoin {
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
            })
            .await?
        {
            ClusterMucJoinOutcome::Joined(authority) | ClusterMucJoinOutcome::Replay(authority) => {
                debug_assert_eq!(authority.occupant_incarnation, occupant.cluster_epoch);
                debug_assert_eq!(authority.connection_uuid, session.connection_id());
            }
            ClusterMucJoinOutcome::Outcast => {
                return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                    root,
                    full_jid,
                    "auth",
                    "forbidden",
                ))));
            }
            ClusterMucJoinOutcome::MembershipRequired => {
                return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                    root,
                    full_jid,
                    "auth",
                    "registration-required",
                ))));
            }
            ClusterMucJoinOutcome::ReservedNickname
            | ClusterMucJoinOutcome::NicknameConflict
            | ClusterMucJoinOutcome::FullJidConflict => {
                return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                    root, full_jid, "cancel", "conflict",
                ))));
            }
            ClusterMucJoinOutcome::Full => {
                return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                    root,
                    full_jid,
                    "wait",
                    "service-unavailable",
                ))));
            }
            ClusterMucJoinOutcome::RoomMissing
            | ClusterMucJoinOutcome::RoomDestroyed
            | ClusterMucJoinOutcome::RoomLocked
            | ClusterMucJoinOutcome::StaleRoom => {
                return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                    root,
                    full_jid,
                    "cancel",
                    "item-not-found",
                ))));
            }
        }
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
            // The cache cannot authorize a join; PostgreSQL already did.
            let cache = session
                .host()
                .cache_committed_muc_join(&serializable, effective_capacity)
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
    }
    Ok(JoinStep::Next(CommittedJoin {
        occupant,
        serializable,
        cluster_event_id,
    }))
}
