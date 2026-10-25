//! Restoring, checkpointing, committing and aborting local MUC occupants on SM resume.

use super::*;

/// Result of reattaching one resumed XEP-0198 stream's local MUC occupancies:
/// the memberships which could not be proven valid, plus the volatile
/// suspension FIFO in exact order. The caller must emit the suffix strictly
/// after `<resumed/>` and the durable unacked replay so suspended-room
/// traffic never overtakes older sequenced stanzas.
pub struct RestoredLocalMucOccupants {
    pub failures: Vec<crate::services::sm::SmMucMembership>,
    pub replay_suffix: Vec<String>,
    pub(super) resume_gate: Option<Arc<SuspendedMucEndpoint>>,
    pub(super) actors: Vec<RestoredMucActor>,
}

#[derive(Clone)]
pub(super) struct RestoredMucActor {
    pub(super) key: String,
    pub(super) full_jid: String,
    pub(super) connection_id: uuid::Uuid,
    pub(super) cluster_epoch: uuid::Uuid,
    pub(super) sm_session_id: uuid::Uuid,
    pub(super) endpoint: Arc<SuspendedMucEndpoint>,
    pub(super) membership: crate::services::sm::SmMucMembership,
    pub(super) resumed_cluster_target: Option<db::ClusterMucOccupancyTarget>,
}

impl RestoredLocalMucOccupants {
    pub(crate) fn planned_memberships(&self) -> Vec<crate::services::sm::SmMucMembership> {
        self.actors
            .iter()
            .map(|actor| actor.membership.clone())
            .collect()
    }

    pub(crate) fn planned_joined_rooms(&self) -> Vec<(String, JoinedMucMembership)> {
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

pub(crate) struct CommittedLocalMucResume {
    pub(crate) joined_rooms: Vec<(String, JoinedMucMembership)>,
    pub(crate) failures: Vec<crate::services::sm::SmMucMembership>,
}

impl AppState {
    /// Reattach only memberships that can still be proven valid. Existing
    /// suspended actors are swapped in place; after a process restart a new
    /// actor is recreated without join broadcast or history replay. The
    /// volatile suspension FIFO moves into the returned replay suffix so the
    /// resumed stream emits it strictly after `<resumed/>` and the durable
    /// unacked replay.
    pub async fn restore_local_muc_occupants(
        &self,
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
            self.config.domain
        ))
        .expect("configured XMPP domain must form a valid MUC domain");
        let mut failures = Vec::new();
        let mut actors = Vec::new();
        let mut resume_gate = self
            .suspended_muc_sessions
            .get(&sm_session_id)
            .map(|endpoint| Arc::clone(&endpoint));
        for membership in memberships {
            let (Ok(room_jid), Ok(nick)) = (
                northstar_xmpp_types::jid::canonicalize_bare(&membership.room_jid),
                crate::services::xml_util::prepare_muc_nick(&membership.nick),
            ) else {
                failures.push(membership.clone());
                continue;
            };
            if jid_domain(&room_jid) != Some(muc_domain.as_str()) {
                failures.push(membership.clone());
                continue;
            }
            let Ok(Some(initial_room)) = self
                .muc_service()
                .local_room_snapshot(localpart(&room_jid))
                .await
            else {
                failures.push(membership.clone());
                continue;
            };
            let key = crate::services::xml_util::muc_occupant_key(&room_jid, &nick);
            // Single-node join, rename and SM restore publish into the same
            // room-local map. Existing suspended actors already own a slot
            // and bypass the new-admission capacity check; a post-restart
            // recreation must compete under the same gate as a fresh join so
            // delayed resumes cannot overfill the room.
            let _local_resume_guard = if self.cluster.is_enabled() {
                None
            } else {
                Some(self.muc_service().lock_local_join(initial_room.id).await)
            };
            let Ok(Some(room)) = self
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
            let affiliation = match self.muc_service().local_affiliation(room.id, user.id).await {
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
            match self
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
            if room.configuration_is_expired(chrono::Utc::now()) {
                failures.push(membership.clone());
                continue;
            };
            if let Some(occupant) = self.muc_occupants.get(&key) {
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
                    &self.suspended_muc_sessions,
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

                let resumed_cluster_target = if self.cluster.is_enabled() {
                    let resume = async {
                        let target = db::cluster_muc_occupancy_target(
                            &self.pool,
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
                        let operation_id = uuid::Uuid::new_v4();
                        let outcome = db::transition_cluster_muc_occupancy(
                            &self.pool,
                            operation_id,
                            &target,
                            "resume",
                            &self.cluster.node_id,
                            Some(connection_id),
                            Some(next_epoch),
                            Some(sm_session_id),
                            Duration::from_secs(90),
                        )
                        .await?;
                        anyhow::ensure!(
                            matches!(
                                outcome,
                                db::ClusterMucTransitionOutcome::Applied
                                    | db::ClusterMucTransitionOutcome::Replay
                            ),
                            "PG MUC resume rejected stale occupancy: {outcome:?}"
                        );
                        if let Err(error) = self
                            .muc_service()
                            .wake_committed_operation(&self.cluster, operation_id)
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
                let Some(mut occupant) = self.muc_occupants.get_mut(&key) else {
                    if let Some(target) = &resumed_cluster_target {
                        self.compensate_resumed_muc_target(target, sm_session_id)
                            .await;
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
                        self.compensate_resumed_muc_target(target, sm_session_id)
                            .await;
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
                match self
                    .cluster
                    .resume_muc_occupant(&previous, &serializable)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) | Err(_) if !self.cluster.is_enabled() => {
                        self.muc_occupants.remove_if(&key, |_, current| {
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
                            self.compensate_resumed_muc_target(target, sm_session_id)
                                .await;
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
                    membership: crate::services::sm::SmMucMembership { room_jid, nick },
                    resumed_cluster_target,
                });
                continue;
            }

            if !self.cluster.is_enabled() {
                let privileged = matches!(affiliation.as_str(), "owner" | "admin");
                let effective_capacity = room.max_occupants as usize + usize::from(privileged) * 10;
                if self.muc_occupants_for(&room_jid).len() >= effective_capacity {
                    failures.push(membership.clone());
                    continue;
                }
            }

            let cluster_authority = if self.cluster.is_enabled() {
                let authority = match db::suspended_cluster_muc_occupancy(
                    &self.pool,
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
                &self.suspended_muc_sessions,
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
                occupant_id: crate::services::xml_util::muc_occupant_id(
                    &room.occupant_id_secret,
                    bare_jid(&full_jid),
                ),
                cluster_epoch: cluster_authority
                    .as_ref()
                    .map(|authority| authority.occupant_incarnation)
                    .unwrap_or_else(uuid::Uuid::new_v4),
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
            if !insert_restored_muc_occupant(&self.muc_occupants, key.clone(), occupant) {
                failures.push(membership.clone());
                continue;
            }

            let resumed_cluster_target = if let Some(authority) = cluster_authority.as_ref() {
                let target = db::ClusterMucOccupancyTarget::from(authority);
                let Some(next_epoch) = target.connection_epoch.checked_add(1) else {
                    self.muc_occupants.remove_if(&key, |_, occupant| {
                        suspended_occupant_is_created(occupant, &created_endpoint)
                            && occupant.full_jid == full_jid
                            && occupant.connection_id == connection_id
                    });
                    failures.push(membership.clone());
                    continue;
                };
                let operation_id = uuid::Uuid::new_v4();
                match db::transition_cluster_muc_occupancy(
                    &self.pool,
                    operation_id,
                    &target,
                    "resume",
                    &self.cluster.node_id,
                    Some(connection_id),
                    Some(next_epoch),
                    Some(sm_session_id),
                    Duration::from_secs(90),
                )
                .await
                {
                    Ok(db::ClusterMucTransitionOutcome::Applied)
                    | Ok(db::ClusterMucTransitionOutcome::Replay) => {
                        if let Err(error) = self
                            .muc_service()
                            .wake_committed_operation(&self.cluster, operation_id)
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
                        self.muc_occupants.remove_if(&key, |_, occupant| {
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
                        self.muc_occupants.remove_if(&key, |_, occupant| {
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
                    occupant_id: crate::services::xml_util::muc_occupant_id(
                        &room.occupant_id_secret,
                        bare_jid(&authority.full_jid),
                    ),
                    cluster_epoch: authority.occupant_incarnation,
                    connection_id: authority.connection_uuid,
                    federated_domain: None,
                    sm_session_id: authority.sm_session_id,
                    payload: authority.presence_payload.clone(),
                };
                self.cluster
                    .resume_muc_occupant(&previous, &serializable)
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
                membership: crate::services::sm::SmMucMembership { room_jid, nick },
                resumed_cluster_target,
            });
        }

        let replay_suffix = if let Some(endpoint) = &resume_gate {
            match snapshot_suspended_muc_buffer_for_resume(endpoint).await {
                Some(stanzas) => stanzas,
                None => {
                    for actor in &actors {
                        if let Some(target) = &actor.resumed_cluster_target {
                            self.compensate_resumed_muc_target(target, actor.sm_session_id)
                                .await;
                        }
                        self.muc_occupants.remove_if(&actor.key, |_, current| {
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

    pub(super) async fn compensate_resumed_muc_target(
        &self,
        target: &db::ClusterMucOccupancyTarget,
        sm_session_id: uuid::Uuid,
    ) {
        if !self.cluster.is_enabled() {
            return;
        }
        let operation_id = uuid::Uuid::new_v4();
        match db::transition_cluster_muc_occupancy(
            &self.pool,
            operation_id,
            target,
            "suspend",
            &self.cluster.node_id,
            None,
            None,
            Some(sm_session_id),
            Duration::from_secs(90),
        )
        .await
        {
            Ok(db::ClusterMucTransitionOutcome::Applied)
            | Ok(db::ClusterMucTransitionOutcome::Replay) => {
                if let Err(error) = self
                    .muc_service()
                    .wake_committed_operation(&self.cluster, operation_id)
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
    pub async fn checkpoint_local_muc_resume(&self, restored: &RestoredLocalMucOccupants) -> bool {
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
    pub async fn commit_local_muc_resume(
        &self,
        restored: RestoredLocalMucOccupants,
        sender: &crate::xmpp::outbound::OutboundSender,
        capacity: crate::services::sm_capacity::SmCapacityLease,
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
            .unwrap_or_else(uuid::Uuid::nil);

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
                        self.muc_occupants
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

                stale_suspended = self
                    .muc_occupants
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
                    self.muc_occupants.remove_if(key, |_, current| {
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
                self.compensate_resumed_muc_target(&target, actor.sm_session_id)
                    .await;
            }
        }
        for (_, expected) in stale_suspended {
            if let Err(error) = self
                .cluster
                .unregister_muc_occupant_epoch(
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
            && !self
                .mark_suspended_muc_durable(vec![Arc::clone(&endpoint)])
                .await
        {
            let queued = self.sm_suspension_recovery_queue().enqueue_promote(
                recovery_connection_id,
                endpoint.sm_session_id,
                vec![Arc::clone(&endpoint)],
                capacity,
            );
            if !queued {
                self.sm_memory_governor().mark_invariant_failure();
                seal_suspended_muc_buffer(&endpoint).await;
                let _ = self
                    .revoke_sm_session_with_teardown(endpoint.sm_session_id)
                    .await;
            }
        }
        failures.sort_by(|left, right| {
            (&left.room_jid, &left.nick).cmp(&(&right.room_jid, &right.nick))
        });
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
    pub async fn abort_local_muc_resume(
        &self,
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
                self.compensate_resumed_muc_target(target, actor.sm_session_id)
                    .await;
            }
            let suspended = self.muc_occupants.get(&actor.key).and_then(|current| {
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
                if let Err(error) = self
                    .cluster
                    .register_suspended_muc_occupant(
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
}
