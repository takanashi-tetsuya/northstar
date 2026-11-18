//! SM resume of local MUC occupants: associating joined occupants with a newly enabled SM session, restoring the
//! suspended ones on resume, checkpointing, committing or aborting that restore, and compensating a cluster resume
//! that did not commit. The node supplies its tables and cluster calls through [`MucResumeHost`].

use crate::ports::MucHost;
use anyhow::{Context, Result};
use dashmap::DashMap;
use northstar_room_application::muc_service::{MucWakePort, SerializableMucOccupant};
use northstar_room_core::{ClusterMucOccupancyTarget, ClusterMucTransitionOutcome};
use northstar_session_core::{JoinedMucMembership, SmMucMembership};
use northstar_stream::local_routes::muc::{
    CommittedLocalMucResume, MucOccupant, MucOccupantEndpoint, RestoreLocalMucOccupantsRequest,
    RestoredMucOccupancy, SmCapacityLease, SuspendedMucEndpoint, SuspendedMucPhase,
    SuspendedMucRoute,
};
use northstar_stream::local_routes::muc_table::LocalMucOccupantTable;
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::local_routes::session_table::LocalSessionTable;
use northstar_stream::local_routes::suspended_muc::*;
use northstar_stream::outbound::OutboundSender;
use northstar_stream::protocol::SessionHost;
use northstar_xmpp_types::jid_text::{bare_jid, jid_domain, localpart};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// What SM resume needs from the node besides its session and MUC host roles: the live MUC occupant, suspended
/// endpoint and session tables, whether PostgreSQL cluster authority is on and the wake port for its committed
/// operations, and the Redis soft-state records of resumed and suspended occupants.
pub trait MucResumeHost:
    SessionHost
    + MucHost<
        Outbound = OutboundSender,
        SuspendedEndpoint = SuspendedMucEndpoint,
        Session = OnlineSession,
    >
{
    type MucWake: MucWakePort;

    fn muc_occupant_table(&self) -> &LocalMucOccupantTable;
    fn suspended_muc_sessions(&self) -> &DashMap<Uuid, Arc<SuspendedMucEndpoint>>;
    fn local_session_table(&self) -> &LocalSessionTable;
    fn muc_cluster_enabled(&self) -> bool;
    fn muc_wake(&self) -> &Self::MucWake;
    fn resume_cluster_muc_occupant(
        &self,
        previous: &SerializableMucOccupant,
        resumed: &SerializableMucOccupant,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn unregister_cluster_muc_occupant_epoch(
        &self,
        room_jid: &str,
        nick: &str,
        cluster_epoch: Uuid,
        connection_id: Uuid,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn register_suspended_cluster_muc_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        sm_session_id: Uuid,
        json: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
}

/// Result of reattaching one resumed XEP-0198 stream's local MUC occupancies:
/// the memberships which could not be proven valid, plus the volatile
/// suspension FIFO in exact order. The caller must emit the suffix strictly
/// after `<resumed/>` and the durable unacked replay so suspended-room
/// traffic never overtakes older sequenced stanzas.
pub struct RestoredLocalMucOccupants {
    pub failures: Vec<SmMucMembership>,
    pub replay_suffix: Vec<String>,
    pub(crate) resume_gate: Option<Arc<SuspendedMucEndpoint>>,
    pub(crate) actors: Vec<RestoredMucActor>,
}

#[derive(Clone)]
pub(crate) struct RestoredMucActor {
    pub(crate) key: String,
    pub(crate) full_jid: String,
    pub(crate) connection_id: Uuid,
    pub(crate) cluster_epoch: Uuid,
    pub(crate) sm_session_id: Uuid,
    pub(crate) endpoint: Arc<SuspendedMucEndpoint>,
    pub(crate) membership: SmMucMembership,
    pub(crate) resumed_cluster_target: Option<ClusterMucOccupancyTarget>,
}

impl RestoredMucOccupancy for RestoredLocalMucOccupants {
    fn failures(&self) -> &[SmMucMembership] {
        &self.failures
    }

    fn replay_suffix(&self) -> &[String] {
        &self.replay_suffix
    }

    fn planned_memberships(&self) -> Vec<SmMucMembership> {
        self.actors
            .iter()
            .map(|actor| actor.membership.clone())
            .collect()
    }

    fn planned_joined_rooms(&self) -> Vec<(String, JoinedMucMembership)> {
        self.actors
            .iter()
            .map(|actor| {
                (
                    actor.membership.room_jid.clone(),
                    JoinedMucMembership {
                        nick: actor.membership.nick.clone(),
                        cluster_epoch: actor.cluster_epoch,
                    },
                )
            })
            .collect()
    }
}

/// Associate MUC occupants which were joined before SM enable with the
/// newly-created durable stream epoch and update their Redis control
/// records. This also makes active-session revocation exact and immune to
/// nick reuse races.
pub async fn associate_local_muc_sm_session<H: MucResumeHost>(
    host: &H,
    full_jid: &str,
    connection_id: Uuid,
    sm_session_id: Uuid,
    memberships: &DashMap<String, JoinedMucMembership>,
) {
    // Install the session-global gate even when the resource has not joined
    // a room yet. Future joins carry `sm_session_id` and therefore route
    // through this same Arc from their first stanza onward.
    let Some(live_sender) = host
        .local_session_table()
        .get(full_jid)
        .and_then(|session| {
            (session.connection_id == connection_id).then(|| session.sender.clone())
        })
    else {
        tracing::warn!(%full_jid, %connection_id, %sm_session_id,
            "could not install the live SM MUC route gate");
        return;
    };
    let proposed = Arc::new(SuspendedMucEndpoint::new_live(sm_session_id, live_sender));
    let _endpoint =
        canonical_suspended_muc_endpoint(host.suspended_muc_sessions(), sm_session_id, proposed);
    for (room_jid, membership) in local_muc_membership_snapshots(memberships) {
        let key = northstar_room_core::stanza::muc_occupant_key(&room_jid, &membership.nick);
        let serializable = {
            let Some(mut occupant) = host.muc_occupant_table().get_mut(&key) else {
                continue;
            };
            if !muc_actor_identity_matches(
                &occupant,
                full_jid,
                connection_id,
                &room_jid,
                &membership,
            ) {
                continue;
            }
            occupant.sm_session_id = Some(sm_session_id);
            SerializableMucOccupant::from(&*occupant)
        };
        let encoded = serde_json::to_string(&serializable).unwrap_or_default();
        if host.muc_cluster_enabled() {
            let association = async {
                let room = host
                    .muc_service()
                    .local_room_snapshot(localpart(&serializable.room_jid))
                    .await?
                    .context("SM association references a missing MUC room")?;
                let target = host
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        serializable.cluster_epoch,
                        serializable.connection_id,
                    )
                    .await?
                    .context("SM association lost its exact MUC occupancy")?;
                anyhow::ensure!(
                    host.muc_service()
                        .associate_local_cluster_sm_session(
                            &target,
                            host.muc_cluster_node_id(),
                            sm_session_id,
                        )
                        .await?,
                    "SM association lost its PG occupancy fence"
                );
                Ok::<_, anyhow::Error>(())
            }
            .await;
            if let Err(error) = association {
                tracing::warn!(?error, room=%serializable.room_jid, nick=%serializable.nick,
                    "failed to associate PG-authoritative MUC occupancy with SM epoch");
            }
        }
        if let Err(error) = host
            .register_suspended_cluster_muc_occupant(
                &serializable.room_jid,
                &serializable.nick,
                sm_session_id,
                &encoded,
            )
            .await
        {
            tracing::warn!(?error, room = %serializable.room_jid, nick = %serializable.nick, "failed to associate clustered MUC occupant with SM epoch");
        }
    }
}

/// Reattach only memberships that can still be proven valid. Existing
/// suspended actors are swapped in place; after a process restart a new
/// actor is recreated without join broadcast or history replay. The
/// volatile suspension FIFO moves into the returned replay suffix so the
/// resumed stream emits it strictly after `<resumed/>` and the durable
/// unacked replay.
pub async fn restore_local_muc_occupants<H: MucResumeHost>(
    host: &H,
    request: RestoreLocalMucOccupantsRequest<'_>,
) -> RestoredLocalMucOccupants {
    let RestoreLocalMucOccupantsRequest {
        user,
        full_jid,
        connection_id,
        sm_session_id,
        memberships,
        base_stanzas,
        base_bytes,
    } = request;
    let Ok(full_jid) = northstar_xmpp_types::jid::canonical_session_key(full_jid) else {
        return RestoredLocalMucOccupants {
            failures: memberships.to_vec(),
            replay_suffix: Vec::new(),
            resume_gate: None,
            actors: Vec::new(),
        };
    };
    if connection_id.is_nil() {
        return RestoredLocalMucOccupants {
            failures: memberships.to_vec(),
            replay_suffix: Vec::new(),
            resume_gate: None,
            actors: Vec::new(),
        };
    }
    let muc_domain = northstar_xmpp_types::jid::prepare_domainpart(&format!(
        "conference.{}",
        MucHost::local_domain(host)
    ))
    .expect("configured XMPP domain must form a valid MUC domain");
    let mut failures = Vec::new();
    let mut actors = Vec::new();
    let mut resume_gate = host
        .suspended_muc_sessions()
        .get(&sm_session_id)
        .map(|endpoint| Arc::clone(&endpoint));
    for membership in memberships {
        let (Ok(room_jid), Ok(nick)) = (
            northstar_xmpp_types::jid::canonicalize_bare(&membership.room_jid),
            northstar_room_core::stanza::prepare_muc_nick(&membership.nick),
        ) else {
            failures.push(membership.clone());
            continue;
        };
        if jid_domain(&room_jid) != Some(muc_domain.as_str()) {
            failures.push(membership.clone());
            continue;
        }
        let Ok(Some(initial_room)) = host
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await
        else {
            failures.push(membership.clone());
            continue;
        };
        let key = northstar_room_core::stanza::muc_occupant_key(&room_jid, &nick);
        // Single-node join, rename and SM restore publish into the same
        // room-local map. Existing suspended actors already own a slot
        // and bypass the new-admission capacity check; a post-restart
        // recreation must compete under the same gate as a fresh join so
        // delayed resumes cannot overfill the room.
        let _local_resume_guard = if host.muc_cluster_enabled() {
            None
        } else {
            Some(host.muc_service().lock_local_join(initial_room.id).await)
        };
        let Ok(Some(room)) = host
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await
        else {
            failures.push(membership.clone());
            continue;
        };
        if room.id != initial_room.id
            || room.room_epoch != initial_room.room_epoch
            || room.config_version != initial_room.config_version
        {
            failures.push(membership.clone());
            continue;
        }
        let affiliation = match host.muc_service().local_affiliation(room.id, user.id).await {
            Ok(value) => value.unwrap_or_else(|| "none".to_owned()),
            Err(error) => {
                tracing::warn!(?error, "failed to reauthorize resumed MUC membership");
                failures.push(membership.clone());
                continue;
            }
        };
        if affiliation == "outcast" || (room.members_only && affiliation == "none") {
            failures.push(membership.clone());
            continue;
        }
        match host
            .muc_service()
            .local_nick_reserved_for_other(room.id, user.id, &nick)
            .await
        {
            Ok(false) => {}
            Ok(true) => {
                failures.push(membership.clone());
                continue;
            }
            Err(error) => {
                tracing::warn!(?error, room=%room_jid, %nick,
                    "failed to revalidate a reserved nickname during SM resume");
                failures.push(membership.clone());
                continue;
            }
        }
        let role = if matches!(affiliation.as_str(), "owner" | "admin") {
            "moderator"
        } else if room.moderated && affiliation == "none" {
            "visitor"
        } else {
            "participant"
        }
        .to_owned();

        // From here through the final Entry publication the single-node
        // room gate remains held, so the exact room policy, nickname and
        // capacity decision cannot be invalidated by join/rename/config.
        if room.configuration_is_expired(northstar_time::Utc::now()) {
            failures.push(membership.clone());
            continue;
        };
        if let Some(occupant) = host.muc_occupant_table().get(&key) {
            let previous = SerializableMucOccupant::from(&*occupant);
            let endpoint = match &occupant.endpoint {
                MucOccupantEndpoint::Suspended(endpoint)
                    if endpoint.sm_session_id == sm_session_id =>
                {
                    Some(Arc::clone(endpoint))
                }
                _ => None,
            };
            let owned = occupant.full_jid == full_jid && endpoint.is_some();
            if !owned {
                failures.push(membership.clone());
                continue;
            }
            let endpoint = endpoint.expect("checked above");
            drop(occupant);
            let canonical_endpoint = canonical_suspended_muc_endpoint(
                host.suspended_muc_sessions(),
                sm_session_id,
                Arc::clone(&endpoint),
            );
            if !Arc::ptr_eq(&canonical_endpoint, &endpoint)
                || resume_gate
                    .as_ref()
                    .is_some_and(|current| !Arc::ptr_eq(current, &endpoint))
            {
                failures.push(membership.clone());
                continue;
            }
            resume_gate = Some(Arc::clone(&endpoint));

            let resumed_cluster_target = if host.muc_cluster_enabled() {
                let resume = async {
                    let target = host
                        .muc_service()
                        .local_cluster_occupancy_target(
                            room.id,
                            previous.cluster_epoch,
                            previous.connection_id,
                        )
                        .await?
                        .context("SM resume lost its exact suspended MUC occupancy")?;
                    let next_epoch = target
                        .connection_epoch
                        .checked_add(1)
                        .context("MUC connection epoch overflow")?;
                    let operation_id = Uuid::new_v4();
                    let outcome = host
                        .muc_service()
                        .transition_local_cluster_occupancy(
                            operation_id,
                            &target,
                            "resume",
                            host.muc_cluster_node_id(),
                            Some(connection_id),
                            Some(next_epoch),
                            Some(sm_session_id),
                            Duration::from_secs(90),
                        )
                        .await?;
                    anyhow::ensure!(
                        matches!(
                            outcome,
                            ClusterMucTransitionOutcome::Applied
                                | ClusterMucTransitionOutcome::Replay
                        ),
                        "PG MUC resume rejected stale occupancy: {outcome:?}"
                    );
                    if let Err(error) = host
                        .muc_service()
                        .wake_committed_operation(host.muc_wake(), operation_id)
                        .await
                    {
                        tracing::warn!(?error, %operation_id, room=%room_jid,
                            "MUC resume wake failed; PG outbox polling will catch up");
                    }
                    let mut resumed = target;
                    resumed.connection_uuid = connection_id;
                    resumed.connection_epoch = next_epoch;
                    Ok::<_, anyhow::Error>(resumed)
                }
                .await;
                match resume {
                    Ok(target) => Some(target),
                    Err(error) => {
                        tracing::warn!(?error, room=%room_jid, nick=%nick,
                            "could not commit PG-authoritative MUC resume");
                        failures.push(membership.clone());
                        continue;
                    }
                }
            } else {
                None
            };
            let Some(mut occupant) = host.muc_occupant_table().get_mut(&key) else {
                if let Some(target) = &resumed_cluster_target {
                    compensate_resumed_muc_target(host, target, sm_session_id).await;
                }
                failures.push(membership.clone());
                continue;
            };
            if !matches!(
                &occupant.endpoint,
                MucOccupantEndpoint::Suspended(current)
                    if Arc::ptr_eq(current, &endpoint)
                        && current.sm_session_id == sm_session_id
            ) || occupant.full_jid != full_jid
                || occupant.connection_id != previous.connection_id
                || occupant.cluster_epoch != previous.cluster_epoch
                || occupant.sm_session_id != Some(sm_session_id)
            {
                drop(occupant);
                if let Some(target) = &resumed_cluster_target {
                    compensate_resumed_muc_target(host, target, sm_session_id).await;
                }
                failures.push(membership.clone());
                continue;
            }
            occupant.connection_id = connection_id;
            occupant.sm_session_id = Some(sm_session_id);
            occupant.affiliation = affiliation;
            occupant.role = role;
            occupant.room_non_anonymous = room.non_anonymous;
            let serializable = SerializableMucOccupant::from(&*occupant);
            drop(occupant);
            match host
                .resume_cluster_muc_occupant(&previous, &serializable)
                .await
            {
                Ok(true) => {}
                Ok(false) | Err(_) if !host.muc_cluster_enabled() => {
                    host.muc_occupant_table().remove_if(&key, |_, current| {
                        current.full_jid == full_jid
                            && current.cluster_epoch == serializable.cluster_epoch
                            && current.connection_id == connection_id
                            && matches!(
                                &current.endpoint,
                                MucOccupantEndpoint::Suspended(current)
                                    if Arc::ptr_eq(current, &endpoint)
                            )
                    });
                    if let Some(target) = &resumed_cluster_target {
                        compensate_resumed_muc_target(host, target, sm_session_id).await;
                    }
                    failures.push(membership.clone());
                    continue;
                }
                Ok(false) | Err(_) => {
                    tracing::warn!(room=%room_jid, nick=%nick,
                        "PG MUC resume committed but Redis soft-state refresh failed");
                }
            }
            actors.push(RestoredMucActor {
                key,
                full_jid: full_jid.clone(),
                connection_id,
                cluster_epoch: serializable.cluster_epoch,
                sm_session_id,
                endpoint,
                membership: SmMucMembership { room_jid, nick },
                resumed_cluster_target,
            });
            continue;
        }

        if !host.muc_cluster_enabled() {
            let privileged = matches!(affiliation.as_str(), "owner" | "admin");
            let effective_capacity = room.max_occupants as usize + usize::from(privileged) * 10;
            if host.muc_occupants_for(&room_jid).len() >= effective_capacity {
                failures.push(membership.clone());
                continue;
            }
        }

        let cluster_authority = if host.muc_cluster_enabled() {
            let authority = match host
                .muc_service()
                .suspended_local_cluster_occupancy(
                    room.id,
                    room.room_epoch,
                    sm_session_id,
                    &full_jid,
                    &nick,
                )
                .await
            {
                Ok(Some(authority)) => authority,
                Ok(None) | Err(_) => {
                    failures.push(membership.clone());
                    continue;
                }
            };
            Some(authority)
        } else {
            None
        };

        let proposed_endpoint = resume_gate.clone().unwrap_or_else(|| {
            Arc::new(SuspendedMucEndpoint::new_reserved(
                sm_session_id,
                base_stanzas,
                base_bytes,
            ))
        });
        let created_endpoint = canonical_suspended_muc_endpoint(
            host.suspended_muc_sessions(),
            sm_session_id,
            proposed_endpoint,
        );
        if resume_gate
            .as_ref()
            .is_some_and(|current| !Arc::ptr_eq(current, &created_endpoint))
        {
            failures.push(membership.clone());
            continue;
        }
        resume_gate = Some(Arc::clone(&created_endpoint));

        let occupant = MucOccupant {
            full_jid: full_jid.clone(),
            room_jid: room_jid.clone(),
            nick: nick.clone(),
            endpoint: MucOccupantEndpoint::Suspended(Arc::clone(&created_endpoint)),
            affiliation,
            role,
            room_non_anonymous: room.non_anonymous,
            occupant_id: northstar_room_core::stanza::muc_occupant_id(
                &room.occupant_id_secret,
                bare_jid(&full_jid),
            ),
            cluster_epoch: cluster_authority
                .as_ref()
                .map(|authority| authority.occupant_incarnation)
                .unwrap_or_else(Uuid::new_v4),
            connection_id,
            sm_session_id: Some(sm_session_id),
            payload: cluster_authority
                .as_ref()
                .map(|authority| authority.presence_payload.clone())
                .unwrap_or_default(),
        };
        let serializable = SerializableMucOccupant::from(&occupant);
        // A concurrent join or a winning resume may have created the same
        // (room, nick) occupancy while the restore awaited PostgreSQL.
        if !insert_restored_muc_occupant(host.muc_occupant_table(), key.clone(), occupant) {
            failures.push(membership.clone());
            continue;
        }

        let resumed_cluster_target = if let Some(authority) = cluster_authority.as_ref() {
            let target = ClusterMucOccupancyTarget::from(authority);
            let Some(next_epoch) = target.connection_epoch.checked_add(1) else {
                host.muc_occupant_table().remove_if(&key, |_, occupant| {
                    suspended_occupant_is_created(occupant, &created_endpoint)
                        && occupant.full_jid == full_jid
                        && occupant.connection_id == connection_id
                });
                failures.push(membership.clone());
                continue;
            };
            let operation_id = Uuid::new_v4();
            match host
                .muc_service()
                .transition_local_cluster_occupancy(
                    operation_id,
                    &target,
                    "resume",
                    host.muc_cluster_node_id(),
                    Some(connection_id),
                    Some(next_epoch),
                    Some(sm_session_id),
                    Duration::from_secs(90),
                )
                .await
            {
                Ok(ClusterMucTransitionOutcome::Applied)
                | Ok(ClusterMucTransitionOutcome::Replay) => {
                    if let Err(error) = host
                        .muc_service()
                        .wake_committed_operation(host.muc_wake(), operation_id)
                        .await
                    {
                        tracing::warn!(?error, %operation_id, room=%room_jid,
                            "MUC resume wake failed; PG outbox polling will catch up");
                    }
                    let mut resumed = target;
                    resumed.connection_uuid = connection_id;
                    resumed.connection_epoch = next_epoch;
                    Some(resumed)
                }
                Ok(outcome) => {
                    tracing::warn!(?outcome, room=%room_jid, nick=%nick,
                        "PG MUC restart resume rejected the reserved local actor");
                    host.muc_occupant_table().remove_if(&key, |_, occupant| {
                        suspended_occupant_is_created(occupant, &created_endpoint)
                            && occupant.full_jid == full_jid
                            && occupant.connection_id == connection_id
                    });
                    failures.push(membership.clone());
                    continue;
                }
                Err(error) => {
                    tracing::warn!(?error, room=%room_jid, nick=%nick,
                        "PG MUC restart resume failed after local reservation");
                    host.muc_occupant_table().remove_if(&key, |_, occupant| {
                        suspended_occupant_is_created(occupant, &created_endpoint)
                            && occupant.full_jid == full_jid
                            && occupant.connection_id == connection_id
                    });
                    failures.push(membership.clone());
                    continue;
                }
            }
        } else {
            None
        };

        let refresh = if let Some(authority) = cluster_authority.as_ref() {
            let previous = SerializableMucOccupant {
                full_jid: authority.full_jid.clone(),
                room_jid: room_jid.clone(),
                nick: authority.nick.clone(),
                affiliation: authority.affiliation.clone(),
                role: authority.role.clone(),
                room_non_anonymous: room.non_anonymous,
                occupant_id: northstar_room_core::stanza::muc_occupant_id(
                    &room.occupant_id_secret,
                    bare_jid(&authority.full_jid),
                ),
                cluster_epoch: authority.occupant_incarnation,
                connection_id: authority.connection_uuid,
                federated_domain: None,
                sm_session_id: authority.sm_session_id,
                payload: authority.presence_payload.clone(),
            };
            host.resume_cluster_muc_occupant(&previous, &serializable)
                .await
        } else {
            Ok(true)
        };
        if !matches!(refresh, Ok(true)) {
            tracing::warn!(room=%room_jid, nick=%nick,
                "PG MUC restart resume committed but Redis soft-state refresh failed");
        }
        actors.push(RestoredMucActor {
            key,
            full_jid: full_jid.clone(),
            connection_id,
            cluster_epoch: serializable.cluster_epoch,
            sm_session_id,
            endpoint: created_endpoint,
            membership: SmMucMembership { room_jid, nick },
            resumed_cluster_target,
        });
    }

    let replay_suffix = if let Some(endpoint) = &resume_gate {
        match snapshot_suspended_muc_buffer_for_resume(endpoint).await {
            Some(stanzas) => stanzas,
            None => {
                for actor in &actors {
                    if let Some(target) = &actor.resumed_cluster_target {
                        compensate_resumed_muc_target(host, target, actor.sm_session_id).await;
                    }
                    host.muc_occupant_table()
                        .remove_if(&actor.key, |_, current| {
                            current.full_jid == actor.full_jid
                                && current.connection_id == actor.connection_id
                                && current.cluster_epoch == actor.cluster_epoch
                                && current.sm_session_id == Some(actor.sm_session_id)
                                && matches!(
                                    &current.endpoint,
                                    MucOccupantEndpoint::Suspended(current_endpoint)
                                        if Arc::ptr_eq(current_endpoint, &actor.endpoint)
                                )
                        });
                }
                failures.extend(actors.iter().map(|actor| actor.membership.clone()));
                actors.clear();
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    RestoredLocalMucOccupants {
        failures,
        replay_suffix,
        resume_gate,
        actors,
    }
}

pub(crate) async fn compensate_resumed_muc_target<H: MucResumeHost>(
    host: &H,
    target: &ClusterMucOccupancyTarget,
    sm_session_id: Uuid,
) {
    if !host.muc_cluster_enabled() {
        return;
    }
    let operation_id = Uuid::new_v4();
    match host
        .muc_service()
        .transition_local_cluster_occupancy(
            operation_id,
            target,
            "suspend",
            host.muc_cluster_node_id(),
            None,
            None,
            Some(sm_session_id),
            Duration::from_secs(90),
        )
        .await
    {
        Ok(ClusterMucTransitionOutcome::Applied) | Ok(ClusterMucTransitionOutcome::Replay) => {
            if let Err(error) = host
                .muc_service()
                .wake_committed_operation(host.muc_wake(), operation_id)
                .await
            {
                tracing::warn!(?error, %operation_id,
                    "MUC resume compensation wake failed; PG polling will converge");
            }
        }
        Ok(outcome) => tracing::warn!(?outcome, room_id=%target.room_id,
            "MUC resume compensation no longer owned the exact PG actor"),
        Err(error) => tracing::error!(?error, room_id=%target.room_id,
            "failed to re-suspend a PG MUC actor after local resume failure"),
    }
}

/// Transfer the volatile suffix to the exact live SM checkpoint. The
/// queue is cleared only after PostgreSQL accepted that checkpoint, while
/// the endpoint mutex still excludes both delivery and transport
/// publication. A later socket failure therefore re-suspends the snapshot
/// without appending a duplicate copy of the suffix.
pub async fn checkpoint_local_muc_resume(restored: &RestoredLocalMucOccupants) -> bool {
    let Some(endpoint) = restored.resume_gate.as_ref() else {
        return true;
    };
    let mut buffer = endpoint.buffer.lock().await;
    if !transfer_muc_suffix_to_checkpoint(&mut buffer) {
        buffer.phase = SuspendedMucPhase::Sealed;
        endpoint.changed.notify_waiters();
        return false;
    }
    endpoint.changed.notify_waiters();
    true
}

/// Publish a restore plan only after the `<resumed/>` control and complete
/// replay have reached the transport. The endpoint mutex is held while all
/// exact actors are swapped, so an arriving stanza observes either the
/// sealed gate or the final live route, never a partially transferred FIFO.
pub async fn commit_local_muc_resume<H: MucResumeHost>(
    host: &H,
    restored: RestoredLocalMucOccupants,
    sender: &OutboundSender,
    capacity: SmCapacityLease,
) -> CommittedLocalMucResume {
    let RestoredLocalMucOccupants {
        mut failures,
        replay_suffix: _,
        resume_gate,
        actors,
    } = restored;
    let Some(endpoint) = resume_gate else {
        return CommittedLocalMucResume {
            joined_rooms: Vec::new(),
            failures,
        };
    };
    let recovery_connection_id = actors
        .first()
        .map(|actor| actor.connection_id)
        .unwrap_or_else(Uuid::nil);

    let mut committed = Vec::new();
    let mut failed_actors = Vec::new();
    let mut stale_suspended = Vec::new();
    let mut published = false;
    {
        // Keep both publication fences in a lexical scope that ends
        // before any compensation I/O. In particular, a std mutex guard
        // must never become part of the Send future used by deferred SM
        // resume completion.
        let mut buffer = endpoint.buffer.lock().await;
        let mut route = endpoint
            .route
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(&buffer.phase, SuspendedMucPhase::CheckpointOwned)
            && matches!(&*route, SuspendedMucRoute::Suspended)
        {
            for actor in actors {
                let activated =
                    host.muc_occupant_table()
                        .get_mut(&actor.key)
                        .is_some_and(|mut current| {
                            if suspended_muc_resume_actor_matches(
                                &current,
                                &actor.endpoint,
                                &actor.full_jid,
                                actor.connection_id,
                                actor.cluster_epoch,
                                actor.sm_session_id,
                            ) {
                                current.endpoint = MucOccupantEndpoint::Local(sender.clone());
                                true
                            } else {
                                false
                            }
                        });
                if activated {
                    committed.push((
                        actor.membership.room_jid.clone(),
                        JoinedMucMembership {
                            nick: actor.membership.nick.clone(),
                            cluster_epoch: actor.cluster_epoch,
                        },
                    ));
                } else {
                    failures.push(actor.membership.clone());
                    failed_actors.push(actor);
                }
            }

            stale_suspended = host
                .muc_occupant_table()
                .iter()
                .filter_map(|current| match &current.endpoint {
                    MucOccupantEndpoint::Suspended(current_endpoint)
                        if Arc::ptr_eq(current_endpoint, &endpoint) =>
                    {
                        Some((
                            current.key().clone(),
                            SerializableMucOccupant::from(&*current),
                        ))
                    }
                    _ => None,
                })
                .collect();
            for (key, expected) in &stale_suspended {
                host.muc_occupant_table().remove_if(key, |_, current| {
                    muc_suspended_teardown_identity_matches(
                        current,
                        endpoint.sm_session_id,
                        expected,
                    ) && matches!(
                        &current.endpoint,
                        MucOccupantEndpoint::Suspended(current_endpoint)
                            if Arc::ptr_eq(current_endpoint, &endpoint)
                    )
                });
            }
            buffer.stanzas.clear();
            buffer.bytes = 0;
            buffer.base_stanzas = 0;
            buffer.base_bytes = 0;
            buffer.snapshot_owned = false;
            buffer.phase = SuspendedMucPhase::Dormant;
            *route = SuspendedMucRoute::Live(sender.clone());
            published = true;
            // Keep the route fence locked until the async buffer mutex is
            // released. A concurrent disconnect can then observe Live only
            // after `try_lock()` is guaranteed to succeed; no publication
            // window can panic or reset a partially committed FIFO.
            drop(buffer);
            drop(route);
            endpoint.changed.notify_waiters();
        } else {
            failures.extend(actors.iter().map(|actor| actor.membership.clone()));
            failed_actors = actors;
            if !matches!(&buffer.phase, SuspendedMucPhase::Dormant) {
                buffer.phase = SuspendedMucPhase::Sealed;
            }
            endpoint.changed.notify_waiters();
            drop(buffer);
            drop(route);
        }
    }
    for actor in failed_actors {
        if let Some(target) = actor.resumed_cluster_target {
            compensate_resumed_muc_target(host, &target, actor.sm_session_id).await;
        }
    }
    for (_, expected) in stale_suspended {
        if let Err(error) = host
            .unregister_cluster_muc_occupant_epoch(
                &expected.room_jid,
                &expected.nick,
                expected.cluster_epoch,
                expected.connection_id,
            )
            .await
        {
            tracing::warn!(?error, room=%expected.room_jid, nick=%expected.nick,
                "failed to remove stale suspended MUC soft state after resume");
        }
    }
    if !published
        && !host
            .mark_suspended_muc_durable(vec![Arc::clone(&endpoint)])
            .await
    {
        let queued = host.enqueue_sm_promote_recovery(
            recovery_connection_id,
            endpoint.sm_session_id,
            vec![Arc::clone(&endpoint)],
            capacity,
        );
        if !queued {
            host.sm_memory_governor().mark_invariant_failure();
            seal_suspended_muc_buffer(&endpoint).await;
            let _ = host
                .revoke_sm_session_with_teardown(endpoint.sm_session_id)
                .await;
        }
    }
    failures
        .sort_by(|left, right| (&left.room_jid, &left.nick).cmp(&(&right.room_jid, &right.nick)));
    failures.dedup();
    CommittedLocalMucResume {
        joined_rooms: committed,
        failures,
    }
}

/// Roll a failed restore back to a suspended actor without taking suffix
/// ownership away from its sole durable source. `snapshot_backed` is true
/// only after the protocol session itself contains the staged suffix; in
/// that case successful connection cleanup clears this backup instead of
/// appending it again.
pub async fn abort_local_muc_resume<H: MucResumeHost>(
    host: &H,
    restored: &RestoredLocalMucOccupants,
    snapshot_backed: bool,
) {
    let Some(endpoint) = restored.resume_gate.as_ref() else {
        return;
    };
    {
        let mut buffer = endpoint.buffer.lock().await;
        buffer.snapshot_owned |= snapshot_backed;
        buffer.phase = SuspendedMucPhase::Sealed;
    }
    endpoint.changed.notify_waiters();

    for actor in &restored.actors {
        if let Some(target) = &actor.resumed_cluster_target {
            compensate_resumed_muc_target(host, target, actor.sm_session_id).await;
        }
        let suspended = host
            .muc_occupant_table()
            .get(&actor.key)
            .and_then(|current| {
                suspended_muc_resume_actor_matches(
                    &current,
                    &actor.endpoint,
                    &actor.full_jid,
                    actor.connection_id,
                    actor.cluster_epoch,
                    actor.sm_session_id,
                )
                .then(|| SerializableMucOccupant::from(&*current))
            });
        if let Some(suspended) = suspended {
            let encoded = serde_json::to_string(&suspended).unwrap_or_default();
            if let Err(error) = host
                .register_suspended_cluster_muc_occupant(
                    &suspended.room_jid,
                    &suspended.nick,
                    actor.sm_session_id,
                    &encoded,
                )
                .await
            {
                tracing::warn!(?error, room=%suspended.room_jid, nick=%suspended.nick,
                    "failed to restore suspended MUC soft state after resume rollback");
            }
        }
    }
}
