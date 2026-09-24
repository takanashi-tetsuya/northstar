use super::*;

#[derive(Default)]
pub(super) struct ListenerContinuations {
    pub(super) pending: VecDeque<BoxFuture<'static, Result<()>>>,
}

impl ListenerContinuations {
    pub(super) fn push(
        &mut self,
        work: impl std::future::Future<Output = Result<()>> + Send + 'static,
    ) -> Result<()> {
        anyhow::ensure!(
            self.pending.len() < MAX_LISTENER_CONTINUATIONS,
            "Redis listener response continuation capacity exceeded"
        );
        self.pending.push_back(work.boxed());
        Ok(())
    }

    pub(super) async fn next(&mut self) -> Option<Result<()>> {
        // Poll only the first response batch, preserving remote presence
        // transition order. Cancelling this wait leaves that batch in place.
        let result = self.pending.front_mut()?.await;
        self.pending.pop_front();
        Some(result)
    }
}

pub(super) struct ListenerResponse {
    pub(super) node_id: String,
    pub(super) recipient: String,
    pub(super) stanza: String,
    pub(super) presence_authority: Option<ClusterPresenceAuthority>,
}

#[derive(Default)]
pub(super) struct ListenerResponses {
    pub(super) items: Vec<ListenerResponse>,
    pub(super) bytes: usize,
}

impl ListenerResponses {
    pub(super) fn push(&mut self, response: ListenerResponse) -> Result<()> {
        let bytes = self
            .bytes
            .saturating_add(response.node_id.len())
            .saturating_add(response.recipient.len())
            .saturating_add(response.stanza.len());
        anyhow::ensure!(
            self.items.len() < MAX_PENDING_CLUSTER_ACKS && bytes <= MAX_CLUSTER_PAYLOAD_BYTES,
            "Redis listener response batch exceeded its count or byte budget"
        );
        self.items.push(response);
        self.bytes = bytes;
        Ok(())
    }
}

pub(super) struct ListenerCommandAuthority {
    pub(super) generation: u64,
    pub(super) rotation_epoch: u64,
    pub(super) envelope: crate::cluster_security::SignedClusterEnvelope,
}

impl ListenerCommandAuthority {
    pub(super) fn validate(
        &self,
        admission: &ClusterListenerAdmission,
        security: &ClusterListenerSecurity,
    ) -> Result<()> {
        admission.validate_generation(self.generation, self.rotation_epoch)?;
        // Recheck expiry and current source key/process authority after deferred
        // work. Replay admission already happened once in the reader.
        security.validate_verified_envelope(&self.envelope)?;
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn validate_listener_generation(
    cluster: &ClusterManager,
    generation: u64,
    rotation_epoch: u64,
) -> Result<()> {
    validate_listener_generation_health(&cluster.health, generation, rotation_epoch)
}

pub(super) fn validate_listener_generation_health(
    health: &ClusterHealth,
    generation: u64,
    rotation_epoch: u64,
) -> Result<()> {
    let _transition = health
        .failure_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    anyhow::ensure!(
        health.state.load(Ordering::Acquire) != CLUSTER_SHUTDOWN_REQUIRED
            && health.listener_rotation_epoch.load(Ordering::Acquire) == rotation_epoch
            && health.listener_generation.load(Ordering::Acquire) == generation
            && !health.listener_requires_rotation(generation),
        "Redis listener response belongs to a retired listener generation"
    );
    Ok(())
}

async fn publish_listener_ack(
    admission: &ClusterListenerAdmission,
    security: &ClusterListenerSecurity,
    source_node: &str,
    ack: NodeDeliveryAck,
    authority: &ListenerCommandAuthority,
) -> Result<()> {
    security
        .publish_ack(admission, source_node, ack, authority)
        .await
}

struct ListenerResponseContext {
    admission: Arc<ClusterListenerAdmission>,
    security: Arc<ClusterListenerSecurity>,
    message_policy: Arc<crate::state::cluster_listener_message::ClusterListenerMessagePolicy>,
    sender: Arc<ClusterNodeDelivery>,
}

async fn complete_listener_responses(
    context: ListenerResponseContext,
    authority: ListenerCommandAuthority,
    responses: ListenerResponses,
    source_node: String,
    mut ack: Option<NodeDeliveryAck>,
) -> Result<()> {
    for response in responses.items {
        authority.validate(&context.admission, &context.security)?;
        let result = if let Some(presence_authority) = response.presence_authority {
            context
                .sender
                .send_current_presence_replay(
                    &response.node_id,
                    &response.recipient,
                    &response.stanza,
                    presence_authority,
                )
                .await
        } else {
            context
                .sender
                .send_available_presence(&response.node_id, &response.recipient, &response.stanza)
                .await
        };
        match result {
            Ok(accepted) => {
                if let Some(ack) = &mut ack {
                    ack.delivered += usize::from(accepted);
                }
            }
            Err(error) => {
                if response.presence_authority.is_some() {
                    context.message_policy.presence_probe_failed();
                }
                return Err(error.context("cluster listener remote presence response failed"));
            }
        }
    }
    authority.validate(&context.admission, &context.security)?;
    if let Some(ack) = ack {
        publish_listener_ack(
            &context.admission,
            &context.security,
            &source_node,
            ack,
            &authority,
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn listen_once(
    transport: Arc<ClusterPubsubListenerTransport>,
    admission: Arc<ClusterListenerAdmission>,
    runtime: ClusterListenerRuntime,
    cancel: CancellationToken,
    heartbeat: crate::workers::WorkerHeartbeat,
) -> Result<()> {
    let ClusterListenerRuntime {
        message_policy,
        dispatch,
        muc_endpoints,
        muc_delivery,
        mix_caps,
        blocking,
        sm_muc_teardown,
        presence_sender,
        security,
    } = runtime;
    let client = transport
        .client
        .as_ref()
        .context("Redis listener started without a configured Redis client")?;
    // Register before any setup await: repeated failures can request rotation
    // without increasing the required generation again, so a fresh notified()
    // inside the loop could miss their notify_waiters() call.
    let rotation = transport.listener_rotation.notified();
    tokio::pin!(rotation);
    rotation.as_mut().enable();
    let (candidate_generation, rotation_epoch) = transport.health.begin_listener_attempt();
    let mut redis_setup_timer = Some(message_policy.start_redis_setup_timer());
    let mut pubsub_conn = open_pubsub(client).await?;
    let channel = transport.key(format!("node:{}", transport.node_id));
    let probe_channel = transport.key(format!(
        "listener_probe:{}:{}:{}",
        transport.node_id,
        transport.connection_uuid,
        transport.instance_epoch.load(Ordering::Acquire)
    ));
    subscribe_pubsub(&mut pubsub_conn, &channel).await?;
    subscribe_pubsub(&mut pubsub_conn, &probe_channel).await?;
    let (_pubsub_sink, mut stream) = pubsub_conn.split();
    let initial_probe = uuid::Uuid::new_v4().to_string();
    publish_listener_probe(&transport, &probe_channel, &initial_probe).await?;
    let mut pending_probe = Some((
        initial_probe,
        tokio::time::Instant::now() + REDIS_CONNECT_TIMEOUT,
        true,
    ));
    let mut liveness = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(15),
        Duration::from_secs(15),
    );
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // No spawned tasks: dropping this listener synchronously drops every
    // outstanding receipt registration before a replacement listener starts.
    let mut continuations = ListenerContinuations::default();
    enum ListenerInput {
        ProbeDue,
        ProbeTimedOut,
        Message(Option<redis::Msg>),
        ResponseComplete(Option<Result<()>>),
    }

    loop {
        // This connection must be allowed to receive its initial self-loop
        // before publishing its generation. Comparing the last completed
        // generation here would reject every startup and recovery attempt.
        if transport
            .health
            .listener_requires_rotation(candidate_generation)
        {
            anyhow::bail!("Redis PubSub listener rotation was requested");
        }
        let probe_deadline = pending_probe
            .as_ref()
            .map(|(_, deadline, _)| *deadline)
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400));
        let input = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            _ = &mut rotation => {
                anyhow::bail!("Redis PubSub listener rotation was requested");
            }
            result = continuations.next(), if !continuations.pending.is_empty() => ListenerInput::ResponseComplete(result),
            _ = liveness.tick() => ListenerInput::ProbeDue,
            _ = tokio::time::sleep_until(probe_deadline), if pending_probe.is_some() => {
                ListenerInput::ProbeTimedOut
            }
            message = stream.next() => ListenerInput::Message(message),
        };
        let message = match input {
            ListenerInput::ResponseComplete(result) => {
                result.context("Redis listener response set ended unexpectedly")??;
                continue;
            }
            ListenerInput::ProbeDue => {
                anyhow::ensure!(
                    pending_probe.is_none(),
                    "Redis PubSub self-loop probe remained outstanding"
                );
                let token = uuid::Uuid::new_v4().to_string();
                publish_listener_probe(&transport, &probe_channel, &token).await?;
                pending_probe = Some((
                    token,
                    tokio::time::Instant::now() + REDIS_CONNECT_TIMEOUT,
                    false,
                ));
                continue;
            }
            ListenerInput::ProbeTimedOut => {
                anyhow::bail!("Redis PubSub publish/subscription self-loop timed out")
            }
            ListenerInput::Message(message) => message,
        };
        let Some(message) = message else {
            return Ok(());
        };
        let received_channel = message.get_channel_name().to_owned();
        let Ok(payload) = message.get_payload::<String>() else {
            continue;
        };
        if received_channel == probe_channel {
            if pending_probe
                .as_ref()
                .is_some_and(|(token, _, _)| token == &payload)
            {
                let (_, _, establishing) = pending_probe.take().expect("probe was present");
                if establishing {
                    transport.confirm_generation(candidate_generation, rotation_epoch)?;
                    drop(redis_setup_timer.take());
                }
                heartbeat.ok();
            }
            continue;
        }
        anyhow::ensure!(
            received_channel == channel,
            "Redis PubSub listener received an unexpected channel"
        );
        if pending_probe
            .as_ref()
            .is_some_and(|(_, _, establishing)| *establishing)
        {
            // Do not consume signature replay records or execute node commands
            // until this subscription has proved its own publish/receive path.
            // Durable deliveries remain eligible for their normal retry.
            continue;
        }
        let envelope = match security
            .verify_signed_payload_persisted(&payload, &channel, None)
            .await
        {
            Ok(envelope) => envelope,
            Err(error) => {
                admission.note_authentication_failure(&error);
                continue;
            }
        };
        let protocol_version = envelope.version;
        let envelope_kind = envelope.kind;
        let source_node = envelope.source_node.clone();
        admission.validate_generation(candidate_generation, rotation_epoch)?;
        if envelope_kind == crate::cluster_security::ClusterCommandKind::Ack {
            if !admission.dispatch_pending_ack(&source_node, envelope.payload) {
                admission.note_authentication_failure(&anyhow::anyhow!(
                    "cluster acknowledgement had no exact pending request"
                ));
            }
            continue;
        }
        let json = &envelope.payload;
        let Some(target) = json["target"].as_str() else {
            continue;
        };
        let mut delivered = 0usize;
        let mut accepted_full_jid = None;
        let mut mix_supported = 0usize;
        let mut mix_unsupported = 0usize;
        let mut mix_unknown = 0usize;
        let mut mix_handoff = None;
        let mut control_processed = None;
        let mut control_outcome = None;
        let mut acknowledged_delivery = None;
        let mut responses = ListenerResponses::default();
        let is_muc = json["muc_broadcast"].as_bool().unwrap_or(false);
        let is_muc_presence = json["muc_presence"].as_bool().unwrap_or(false);
        let is_muc_nickname_change = json["muc_nickname_change"].as_bool().unwrap_or(false);
        let is_muc_role_change = json["muc_role_change"].as_bool().unwrap_or(false);
        let is_muc_evict = json["muc_evict"].as_bool().unwrap_or(false);
        let is_muc_destroy = json["muc_destroy"].as_bool().unwrap_or(false);
        let is_muc_operation_wake = json["muc_operation_wake"].as_bool().unwrap_or(false);
        let is_muc_private = json["muc_private"].as_bool().unwrap_or(false);
        let is_sm_muc_teardown = json["sm_muc_teardown"].as_bool().unwrap_or(false);
        let is_sm_session_teardown = json["sm_session_teardown"].as_bool().unwrap_or(false);
        let is_account_generation_teardown = json["account_generation_teardown"]
            .as_bool()
            .unwrap_or(false);
        let is_user_agent_replacement = json["user_agent_replacement"].as_bool().unwrap_or(false);
        let is_session_termination = json["session_termination"].as_bool().unwrap_or(false);
        let is_blocking_presence_change =
            json["blocking_presence_change"].as_bool().unwrap_or(false);
        let is_presence_probe = json["presence_probe"].as_bool().unwrap_or(false);

        if protocol_version >= crate::cluster_security::SIGNED_PROTOCOL_VERSION
            && (is_muc_nickname_change || is_muc_role_change || is_muc_evict || is_muc_destroy)
        {
            // Protocol-v9 MUC controls are wake-only. A signed Redis payload
            // is authenticated transport data, not authorization to execute
            // a mutation; peers must commit/pull the PG operation instead.
            admission.note_authentication_failure(&anyhow::anyhow!(
                "protocol-v9 executable MUC control rejected"
            ));
            continue;
        }

        if is_muc_operation_wake {
            let valid = uuid::Uuid::parse_str(target).is_ok()
                && json["operation_id"]
                    .as_str()
                    .and_then(|value| uuid::Uuid::parse_str(value).ok())
                    .is_some()
                && json["database_event_id"]
                    .as_str()
                    .and_then(|value| uuid::Uuid::parse_str(value).ok())
                    .is_some()
                && json["event_sequence"]
                    .as_i64()
                    .is_some_and(|value| value >= 1);
            if valid {
                // This is deliberately the only side effect of the Redis
                // command. The worker re-reads the operation, exact audience
                // and payload digest from PostgreSQL before delivery.
                dispatch.wake_muc_outbox();
                control_processed = Some(true);
            }
        } else if is_session_termination {
            let instance = json["connection_id"]
                .as_str()
                .and_then(|value| uuid::Uuid::parse_str(value).ok());
            if let (Ok(target), Some(instance)) =
                (crate::jid::canonical_session_key(target), instance)
            {
                match dispatch.terminate_exact_session(&target, instance).await? {
                    crate::state::cluster_listener_dispatch::SessionTerminationEffect::Absent => {
                        control_processed = Some(true);
                        control_outcome = Some(ClusterControlOutcome::AuthoritativelyAbsent);
                    }
                    crate::state::cluster_listener_dispatch::SessionTerminationEffect::WrongOwner => {
                        control_processed = Some(false);
                        control_outcome = Some(ClusterControlOutcome::WrongOwner);
                    }
                    crate::state::cluster_listener_dispatch::SessionTerminationEffect::Matched => {
                        delivered = 1;
                        control_processed = Some(true);
                        control_outcome = Some(ClusterControlOutcome::Matched);
                    }
                }
            }
        } else if is_user_agent_replacement {
            let parsed = crate::jid::canonicalize_bare(target)
                .ok()
                .zip(
                    json["user_id"]
                        .as_str()
                        .and_then(|value| uuid::Uuid::parse_str(value).ok()),
                )
                .zip(
                    json["device_id"]
                        .as_str()
                        .and_then(|value| uuid::Uuid::parse_str(value).ok()),
                );
            let epoch = json["minimum_epoch"].as_i64().filter(|value| *value > 0);
            if let (Some(((account, user_id), device_id)), Some(epoch)) = (parsed, epoch) {
                for (_, session) in dispatch.session_entries_for(&account) {
                    if user_agent_control_revokes(
                        session.user_id,
                        session.user_agent_id,
                        session.user_agent_epoch,
                        user_id,
                        device_id,
                        epoch,
                    ) {
                        session.disconnect.cancel();
                        delivered += 1;
                    }
                }
                control_processed = Some(true);
            }
        } else if is_account_generation_teardown {
            let parsed = crate::jid::canonicalize_bare(target).ok().zip(
                json["user_id"]
                    .as_str()
                    .and_then(|value| uuid::Uuid::parse_str(value).ok()),
            );
            let generation = json["minimum_generation"]
                .as_i64()
                .filter(|value| *value >= 0);
            if let (Some((account, user_id)), Some(generation)) = (parsed, generation) {
                delivered +=
                    dispatch.revoke_account_before_generation(user_id, &account, generation);
                control_processed = Some(true);
            }
        } else if is_sm_session_teardown {
            if let Some(sm_session_id) = json["sm_session_id"]
                .as_str()
                .and_then(|value| uuid::Uuid::parse_str(value).ok())
            {
                if let Ok(target) = crate::jid::canonical_session_key(target) {
                    if dispatch.fence_sm_session(&target, sm_session_id) {
                        delivered = 1;
                    }
                    control_processed = Some(true);
                }
            }
        } else if is_presence_probe {
            if json["protocol_version"].as_str() != Some(NODE_PROTOCOL_VERSION) {
                admission.note_incompatible_peer_version(
                    &source_node,
                    json["protocol_version"].as_str(),
                );
                continue;
            }
            let owner = crate::jid::canonicalize(target).ok();
            let recipient = json["recipient"]
                .as_str()
                .and_then(|recipient| crate::jid::canonicalize(recipient).ok());
            let availability_only = json["availability_only"].as_bool().unwrap_or(false);
            let authority = match presence_authority(json) {
                Ok(Some(authority)) => Some(authority),
                Ok(None) => {
                    admission.note_authentication_failure(&anyhow::anyhow!(
                        "cluster presence probe omitted versioned account authority"
                    ));
                    continue;
                }
                Err(error) => {
                    admission.note_authentication_failure(&error);
                    continue;
                }
            };
            if let (Some(owner), Some(recipient), Some(authority)) = (owner, recipient, authority) {
                if !message_policy
                    .presence_authority_is_current(
                        &owner,
                        authority.owner_id,
                        authority.owner_auth_generation,
                        &recipient,
                        authority.recipient_id,
                        authority.recipient_auth_generation,
                    )
                    .await
                {
                    admission.note_authentication_failure(&anyhow::anyhow!(
                        "cluster presence probe account authority is stale or mismatched"
                    ));
                    continue;
                }
                let authoritative_avatar_hash = message_policy
                    .owner_avatar_hash(authority.owner_id)
                    .await
                    .ok();
                let mut presences = Vec::new();
                for (owner_full, session) in dispatch.session_entries_for(&owner) {
                    if session.user_id != authority.owner_id
                        || session.auth_generation != authority.owner_auth_generation
                        || !session.available.load(Ordering::Acquire)
                        || !message_policy
                            .privacy_allows_session(
                                &session,
                                &recipient,
                                crate::db::PrivacyStanzaKind::PresenceOut,
                            )
                            .await
                            .unwrap_or(false)
                    {
                        continue;
                    }
                    let presence = if availability_only {
                        let original_id = session
                            .last_presence
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .clone()
                            .and_then(|presence| {
                                let document = roxmltree::Document::parse(&presence).ok()?;
                                document
                                    .root_element()
                                    .attribute("id")
                                    .filter(|id| {
                                        !id.is_empty()
                                            && id.len() <= 1_024
                                            && !id.chars().any(char::is_control)
                                    })
                                    .map(str::to_owned)
                            });
                        crate::xmpp::xml_builder::XmlElement::namespaced(
                            "presence",
                            "jabber:client",
                        )
                        .attr("from", &owner_full)
                        .attr("to", &recipient)
                        .optional_attr("id", original_id.as_deref())
                        .finish()
                    } else {
                        session
                            .last_presence
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .clone()
                            .map(|presence| {
                                let presence = authoritative_avatar_hash
                                    .as_ref()
                                    .and_then(|hash| {
                                        let document =
                                            roxmltree::Document::parse(&presence).ok()?;
                                        Some(crate::xmpp::xml_util::inject_vcard_avatar_hash(
                                            &presence,
                                            document.root_element(),
                                            hash.as_deref(),
                                        ))
                                    })
                                    .unwrap_or(presence);
                                crate::xmpp::xml_util::set_to(&presence, &recipient)
                            })
                            .unwrap_or_else(|| {
                                crate::xmpp::xml_builder::XmlElement::namespaced(
                                    "presence",
                                    "jabber:client",
                                )
                                .attr("from", &owner_full)
                                .attr("to", &recipient)
                                .finish()
                            })
                    };
                    presences.push(presence);
                }

                let mut processed = true;
                for presence in presences {
                    for (_, recipient_session) in dispatch
                        .session_entries_for(&recipient)
                        .into_iter()
                        .filter(|(_, session)| {
                            session.user_id == authority.recipient_id
                                && session.auth_generation == authority.recipient_auth_generation
                                && session.available.load(Ordering::Acquire)
                        })
                    {
                        if message_policy
                            .privacy_allows_session(
                                &recipient_session,
                                &owner,
                                crate::db::PrivacyStanzaKind::PresenceIn,
                            )
                            .await
                            .unwrap_or(false)
                        {
                            delivered += usize::from(
                                recipient_session.sender.try_send(presence.clone()).is_ok(),
                            );
                        }
                    }
                    match dispatch.remote_presence_nodes(&recipient).await {
                        Ok(nodes) => {
                            for node_id in nodes {
                                responses.push(ListenerResponse {
                                    node_id,
                                    recipient: recipient.clone(),
                                    stanza: presence.clone(),
                                    presence_authority: Some(authority),
                                })?;
                            }
                        }
                        Err(error) => {
                            processed = false;
                            message_policy.presence_probe_failed();
                            tracing::warn!(?error, %owner, %recipient, "could not resolve cross-node initial-presence recipients");
                        }
                    }
                }
                control_processed = Some(processed);
            }
        } else if is_blocking_presence_change {
            let owner = crate::jid::canonicalize_bare(target).ok();
            let targets = json["blocking_targets"]
                .as_array()
                .filter(|items| items.len() <= northstar_xep_0191::MAX_ITEMS)
                .and_then(|items| {
                    items
                        .iter()
                        .map(|item| {
                            item.as_str()
                                .and_then(|jid| crate::jid::canonicalize(jid).ok())
                        })
                        .collect::<Option<Vec<_>>>()
                });
            let patterns = json["blocking_patterns"]
                .as_array()
                .filter(|items| items.len() <= northstar_xep_0191::MAX_ITEMS)
                .and_then(|items| {
                    items
                        .iter()
                        .map(|item| {
                            item.as_str()
                                .and_then(|jid| crate::jid::canonicalize(jid).ok())
                        })
                        .collect::<Option<Vec<_>>>()
                });
            if let (Some(owner), Some(targets), Some(patterns)) = (owner, targets, patterns) {
                blocking
                    .deliver_presence_change(
                        &owner,
                        &targets,
                        &patterns,
                        json["available"].as_bool().unwrap_or(false),
                        |node_id, recipient, stanza| {
                            responses.push(ListenerResponse {
                                node_id,
                                recipient,
                                stanza,
                                presence_authority: None,
                            })
                        },
                    )
                    .await?;
            }
        } else if is_sm_muc_teardown {
            let parsed = json["sm_session_id"]
                .as_str()
                .and_then(|value| uuid::Uuid::parse_str(value).ok())
                .zip(
                    serde_json::from_value::<crate::state::SerializableMucOccupant>(
                        json["occupant"].clone(),
                    )
                    .ok(),
                );
            if let Some((sm_session_id, occupant)) = parsed {
                let target_matches = crate::jid::canonicalize_bare(target)
                    .ok()
                    .is_some_and(|room| room == occupant.room_jid);
                if target_matches {
                    match sm_muc_teardown
                        .teardown_exact(sm_session_id, &occupant)
                        .await
                    {
                        Ok(_) => {
                            delivered = 1;
                            control_processed = Some(true);
                        }
                        Err(error) => {
                            tracing::warn!(?error, %target, "clustered SM MUC teardown failed and will be retried by its DB lease owner")
                        }
                    }
                }
            }
        } else if is_muc_evict {
            if let Ok(occupant) = serde_json::from_value::<crate::state::SerializableMucOccupant>(
                json["occupant"].clone(),
            ) {
                let status = json["status"]
                    .as_u64()
                    .and_then(|value| u16::try_from(value).ok());
                let reason = json["reason"].as_str().filter(|value| value.len() <= 4096);
                let actor_nick = json["actor_nick"].as_str();
                if status.is_some()
                    && occupant.room_jid == target
                    && !occupant.cluster_epoch.is_nil()
                    && !occupant.connection_id.is_nil()
                {
                    if let Some(removed) =
                        muc_endpoints.revoke_exact_recipient_returning_local(&occupant)
                    {
                        let self_presence = crate::xmpp::xml_util::muc_presence_stanza_with_status(
                            &occupant,
                            &removed.full_jid,
                            true,
                            true,
                            false,
                            None,
                            true,
                            status,
                            actor_nick,
                            reason,
                        );
                        delivered += usize::from(
                            muc_delivery
                                .deliver_to_muc_occupant(&removed, self_presence)
                                .await,
                        );
                    }
                    if muc_endpoints.room_occupants(target).is_empty() {
                        let _ = dispatch.leave_empty_muc_room(target).await;
                    }
                    control_processed = Some(true);
                }
            }
        } else if is_muc_destroy {
            if let Ok(room) = crate::jid::canonicalize_bare(target) {
                let alternate = json["alternate"]
                    .as_str()
                    .and_then(|jid| crate::jid::canonicalize_bare(jid).ok());
                let reason = json["reason"]
                    .as_str()
                    .filter(|reason| reason.len() <= 4096);
                let identities = serde_json::from_value::<Vec<MucOccupancyIdentity>>(
                    json["occupancies"].clone(),
                )
                .ok()
                .filter(|items| items.len() <= 10_000);
                if let Some(identities) = identities {
                    for identity in identities {
                        if identity.cluster_epoch.is_nil() || identity.connection_id.is_nil() {
                            continue;
                        }
                        let removed = muc_endpoints.remove_local_exact(
                            crate::state::LocalMucOccupantIdentity {
                                room_jid: &room,
                                nick: &identity.nick,
                                full_jid: &identity.full_jid,
                                connection_id: identity.connection_id,
                                cluster_epoch: identity.cluster_epoch,
                            },
                        );
                        if let Some(occupant) = removed {
                            let serializable =
                                crate::state::SerializableMucOccupant::from(&occupant);
                            muc_endpoints.remove_live_membership_exact(&serializable);
                            let presence = crate::xmpp::xml_util::muc_destroy_presence(
                                &serializable,
                                alternate.as_deref(),
                                reason,
                            );
                            delivered += usize::from(
                                muc_delivery
                                    .deliver_to_muc_occupant(&occupant, presence)
                                    .await,
                            );
                        }
                    }
                    control_processed = Some(true);
                }
            }
        } else if is_muc_role_change {
            if let Ok(occupant) = serde_json::from_value::<crate::state::SerializableMucOccupant>(
                json["occupant"].clone(),
            ) {
                if occupant.room_jid == target
                    && !occupant.cluster_epoch.is_nil()
                    && matches!(
                        occupant.role.as_str(),
                        "moderator" | "participant" | "visitor"
                    )
                {
                    muc_endpoints.apply_policy_projection_exact(&occupant);
                    for session in muc_endpoints.room_occupants(target) {
                        let self_presence = session.full_jid == occupant.full_jid;
                        let presence = crate::xmpp::xml_util::muc_presence_stanza(
                            &occupant,
                            &session.full_jid,
                            false,
                            self_presence,
                            false,
                            None,
                            occupant.room_non_anonymous
                                || self_presence
                                || session.role == "moderator",
                        );
                        delivered += usize::from(
                            muc_delivery
                                .deliver_to_muc_occupant(&session, presence)
                                .await,
                        );
                    }
                    control_processed = Some(true);
                }
            }
        } else if is_muc_nickname_change {
            if let (Ok(old_occupant), Ok(new_occupant)) = (
                serde_json::from_value::<crate::state::SerializableMucOccupant>(
                    json["old_occupant"].clone(),
                ),
                serde_json::from_value::<crate::state::SerializableMucOccupant>(
                    json["new_occupant"].clone(),
                ),
            ) {
                if old_occupant.cluster_epoch == new_occupant.cluster_epoch
                    && old_occupant.full_jid == new_occupant.full_jid
                    && old_occupant.room_jid == target
                    && new_occupant.room_jid == target
                    && old_occupant.nick != new_occupant.nick
                {
                    let id = json["id"].as_str();
                    for session in muc_endpoints.room_occupants(target) {
                        let unavailable = crate::xmpp::xml_util::muc_nickname_change_presence(
                            &old_occupant,
                            &crate::state::SerializableMucOccupant::from(&session),
                            &new_occupant.nick,
                            id,
                        );
                        delivered += usize::from(
                            muc_delivery
                                .deliver_to_muc_occupant(&session, unavailable)
                                .await,
                        );
                        let available = crate::xmpp::xml_util::muc_presence_stanza(
                            &new_occupant,
                            &session.full_jid,
                            false,
                            session.full_jid == new_occupant.full_jid,
                            false,
                            id,
                            new_occupant.room_non_anonymous
                                || session.full_jid == new_occupant.full_jid
                                || session.role == "moderator",
                        );
                        delivered += usize::from(
                            muc_delivery
                                .deliver_to_muc_occupant(&session, available)
                                .await,
                        );
                    }
                }
            }
        } else if is_muc_presence {
            if let Ok(occupant) = serde_json::from_value::<crate::state::SerializableMucOccupant>(
                json["occupant"].clone(),
            ) {
                let unavailable = json["unavailable"].as_bool().unwrap_or(false);
                let created = json["created"].as_bool().unwrap_or(false);
                let id = json["id"].as_str();
                let removal_status = json["removal_status"]
                    .as_u64()
                    .and_then(|value| u16::try_from(value).ok());
                let actor_nick = json["actor_nick"].as_str();
                let reason = json["reason"].as_str();
                for session in muc_endpoints.room_occupants(target) {
                    let disclose = occupant.room_non_anonymous || session.role == "moderator";
                    let self_presence = session.full_jid == occupant.full_jid;
                    let presence = crate::xmpp::xml_util::muc_presence_stanza_with_status(
                        &occupant,
                        &session.full_jid,
                        unavailable,
                        self_presence,
                        created,
                        id,
                        disclose,
                        removal_status,
                        actor_nick,
                        reason,
                    );
                    delivered += usize::from(
                        muc_delivery
                            .deliver_to_muc_occupant(&session, presence)
                            .await,
                    );
                }
            }
        } else if let Some(stanza) = json["stanza"].as_str() {
            let parsed_stanza = roxmltree::Document::parse(stanza).ok();
            let current_presence_replay = json["current_presence_replay"].as_bool() == Some(true);
            let presence_subscription = json["presence_subscription"].as_bool() == Some(true);
            if current_presence_replay && presence_subscription {
                continue;
            }
            // A v9 sender did not carry account-incarnation authority. Detect
            // its subscription stanza from the XML itself instead of trusting
            // the absent boolean marker, otherwise a mixed-version sender
            // could reach the old generic presence fan-out path.
            if parsed_stanza
                .as_ref()
                .is_some_and(is_presence_subscription_stanza)
                && !presence_subscription
            {
                admission.note_incompatible_peer_version(
                    &source_node,
                    json["protocol_version"].as_str(),
                );
                continue;
            }
            if (current_presence_replay || presence_subscription)
                && json["protocol_version"].as_str() != Some(NODE_PROTOCOL_VERSION)
            {
                admission.note_incompatible_peer_version(
                    &source_node,
                    json["protocol_version"].as_str(),
                );
                continue;
            }
            let parsed_presence_authority = match presence_authority(json) {
                Ok(authority) => authority,
                Err(error) => {
                    admission.note_authentication_failure(&error);
                    continue;
                }
            };
            if current_presence_replay || presence_subscription {
                let Some(authority) = parsed_presence_authority else {
                    admission.note_authentication_failure(&anyhow::anyhow!(
                        "cluster presence delivery omitted versioned account authority"
                    ));
                    continue;
                };
                let Some(document) = parsed_stanza.as_ref() else {
                    continue;
                };
                let root = document.root_element();
                let expected_delivery = if current_presence_replay {
                    ClusterPresenceDelivery::CurrentReplay
                } else {
                    ClusterPresenceDelivery::Subscription
                };
                let endpoints = root
                    .attribute("from")
                    .and_then(|from| crate::jid::canonicalize(from).ok())
                    .zip(
                        root.attribute("to")
                            .and_then(|to| crate::jid::canonicalize(to).ok()),
                    );
                let Some((owner, recipient)) = endpoints else {
                    continue;
                };
                if !presence_delivery_stanza_matches(document, expected_delivery)
                    || crate::jid::canonical_bare_key(&recipient).ok()
                        != crate::jid::canonical_bare_key(target).ok()
                    || !message_policy
                        .presence_authority_is_current(
                            &owner,
                            authority.owner_id,
                            authority.owner_auth_generation,
                            &recipient,
                            authority.recipient_id,
                            authority.recipient_auth_generation,
                        )
                        .await
                {
                    admission.note_authentication_failure(&anyhow::anyhow!(
                        "cluster presence delivery account authority is stale or mismatched"
                    ));
                    continue;
                }
            } else if parsed_presence_authority.is_some() {
                admission.note_authentication_failure(&anyhow::anyhow!(
                    "ordinary cluster delivery carried executable presence authority"
                ));
                continue;
            }
            let is_message_stanza = parsed_stanza
                .as_ref()
                .is_some_and(|document| document.root_element().tag_name().name() == "message");
            let (resolved_message_delivery, direct_delivery_contract_valid) =
                if !is_muc && !is_muc_private {
                    match requested_node_message_delivery(json, is_message_stanza) {
                        Ok(Some(request)) => {
                            match resolve_node_message_delivery(
                                message_policy.verifier(),
                                request,
                                stanza,
                                target,
                            )
                            .await
                            {
                                Ok(resolved) => {
                                    acknowledged_delivery = Some(resolved.contract());
                                    (Some(resolved), true)
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        ?error,
                                        target,
                                        "rejected an unverified clustered message delivery contract"
                                    );
                                    (None, false)
                                }
                            }
                        }
                        Ok(None) => (None, true),
                        Err(error) => {
                            tracing::warn!(
                                ?error,
                                target,
                                "rejected an invalid clustered message delivery contract"
                            );
                            (None, false)
                        }
                    }
                } else {
                    (None, true)
                };
            let carbons_only = json["carbons_only"].as_bool().unwrap_or(false);
            let privacy_peer_kind = parsed_stanza
                .as_ref()
                .and_then(|document| delivery_privacy_peer(document, carbons_only));
            // Both Carbon directions deliberately use a self-addressed outer
            // wrapper. If the exact forwarded conversation peer cannot be
            // recovered, an unfiltered fallback would bypass the resource's
            // active XEP-0016 list.
            if carbons_only && privacy_peer_kind.is_none() {
                continue;
            }
            let mut muc_senders = roxmltree::Document::parse(stanza)
                .ok()
                .and_then(|document| document.root_element().attribute("from").map(str::to_owned))
                .into_iter()
                .collect::<Vec<_>>();
            if let Some(real_sender) = json["real_sender"]
                .as_str()
                .and_then(|sender| crate::jid::canonicalize(sender).ok())
            {
                muc_senders.push(real_sender);
            }
            if is_muc_private {
                if let Some(nick) = json["target_nick"].as_str() {
                    if let Some(session) = muc_endpoints.cached_recipient(target, nick) {
                        let delivery = crate::xmpp::xml_util::set_to(stanza, &session.full_jid);
                        let blocked = muc_delivery
                            .blocked_muc_recipient_accounts(
                                std::slice::from_ref(&session),
                                &muc_senders,
                            )
                            .await;
                        if !crate::jid::canonical_bare_key(&session.full_jid)
                            .is_ok_and(|owner| blocked.contains(&owner))
                        {
                            delivered += usize::from(
                                muc_delivery
                                    .deliver_to_muc_occupant_unchecked(&session, delivery)
                                    .await,
                            );
                        }
                    }
                }
            } else if is_muc {
                let sessions = muc_endpoints.room_occupants(target);
                let blocked = muc_delivery
                    .blocked_muc_recipient_accounts(&sessions, &muc_senders)
                    .await;
                for session in sessions {
                    if crate::jid::canonical_bare_key(&session.full_jid)
                        .is_ok_and(|owner| blocked.contains(&owner))
                    {
                        continue;
                    }
                    let delivery = crate::xmpp::xml_util::set_to(stanza, &session.full_jid);
                    delivered += usize::from(
                        muc_delivery
                            .deliver_to_muc_occupant_unchecked(&session, delivery)
                            .await,
                    );
                }
            } else {
                let blocklist_requested_only =
                    json["blocklist_requested_only"].as_bool().unwrap_or(false);
                let roster_requested_only =
                    json["roster_requested_only"].as_bool().unwrap_or(false);
                let expected_user_id = match json.get("expected_user_id") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(serde_json::Value::String(value)) => {
                        let Ok(value) = uuid::Uuid::parse_str(value) else {
                            continue;
                        };
                        Some(value)
                    }
                    Some(_) => continue,
                };
                let expected_auth_generation = match json.get("expected_auth_generation") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(value) => value.as_i64().filter(|value| *value >= 0),
                };
                if json
                    .get("expected_auth_generation")
                    .is_some_and(|value| !value.is_null() && expected_auth_generation.is_none())
                {
                    continue;
                }
                if let Some(authority) = parsed_presence_authority {
                    if expected_user_id != Some(authority.recipient_id)
                        || expected_auth_generation != Some(authority.recipient_auth_generation)
                    {
                        continue;
                    }
                }
                let roster_version = match json.get("roster_version") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(value) => value.as_i64(),
                };
                let roster_annotated_stanza = match json.get("roster_annotated_stanza") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(serde_json::Value::String(value))
                        if value.len() <= crate::xmpp::MAX_XMPP_FRAME_BYTES
                            && roxmltree::Document::parse(value).is_ok() =>
                    {
                        Some(value.as_str())
                    }
                    Some(_) => continue,
                };
                if roster_requested_only && (expected_user_id.is_none() || roster_version.is_none())
                {
                    continue;
                }
                if roster_requested_only {
                    let Some(roster_version) = roster_version else {
                        continue;
                    };
                    if cluster_roster_push_version(stanza) != Some(roster_version)
                        || roster_annotated_stanza.is_some_and(|value| {
                            cluster_roster_push_version(value) != Some(roster_version)
                        })
                    {
                        continue;
                    }
                }
                if !roster_requested_only
                    && (roster_version.is_some() || roster_annotated_stanza.is_some())
                {
                    continue;
                }
                let privacy_requested_only =
                    json["privacy_requested_only"].as_bool().unwrap_or(false);
                let mix_capable_only = match json.get("mix_capable_only") {
                    None => false,
                    Some(serde_json::Value::Bool(value)) => *value,
                    Some(_) => continue,
                };
                let transport_receipt_required = match json.get("transport_receipt_required") {
                    None => false,
                    Some(serde_json::Value::Bool(value)) => *value,
                    Some(_) => continue,
                };
                let mix_transport_receipt_required =
                    match json.get("mix_transport_receipt_required") {
                        None => false,
                        Some(serde_json::Value::Bool(value)) => *value,
                        Some(_) => continue,
                    };
                let exclude_jids = delivery_exclusions(json);
                let Ok(carbon_muc_scope) = delivery_carbon_muc_scope(json) else {
                    continue;
                };
                let primary_one_to_one = json["primary_one_to_one"].as_bool().unwrap_or(false);
                let available_only = json["available_only"].as_bool().unwrap_or(false);
                let available_nonnegative_only = json["available_nonnegative_only"]
                    .as_bool()
                    .unwrap_or(false);
                let transport_receipt_stanza_valid =
                    parsed_stanza.as_ref().is_some_and(|document| {
                        let root = document.root_element();
                        root.tag_name().name() == "iq"
                            && root.tag_name().namespace() == Some("jabber:client")
                            && matches!(root.attribute("type"), Some("result" | "error"))
                            && root.attribute("id").is_some_and(|id| !id.is_empty())
                            && root.attribute("to").is_some_and(|to| {
                                matches!(
                                    (
                                        crate::jid::canonical_session_key(to),
                                        crate::jid::canonical_session_key(target),
                                    ),
                                    (Ok(addressed), Ok(expected)) if addressed == expected
                                )
                            })
                    });
                if transport_receipt_required
                    && (is_message_stanza
                        || expected_user_id.is_none()
                        || !target.contains('/')
                        || carbons_only
                        || blocklist_requested_only
                        || roster_requested_only
                        || privacy_requested_only
                        || mix_capable_only
                        || primary_one_to_one
                        || available_only
                        || available_nonnegative_only
                        || !exclude_jids.is_empty()
                        || carbon_muc_scope.is_some()
                        || !transport_receipt_stanza_valid)
                {
                    continue;
                }
                // This is intentionally a separate contract from the
                // exact-resource policy/PAM receipt above. A durable MIX
                // event is a bare-JID message, is routed only to resources
                // with verified MIX support, and may be acknowledged after
                // any one such resource obtains true transport ownership.
                // Reject every other combination rather than letting a
                // signed-but-malformed payload silently downgrade to an
                // in-memory `try_send` acknowledgement.
                if mix_transport_receipt_required
                    && (transport_receipt_required
                        || !is_message_stanza
                        || !matches!(
                            resolved_message_delivery,
                            Some(ResolvedNodeMessageDelivery::Mix(_))
                        )
                        || !mix_capable_only
                        || crate::jid::CanonicalJid::parse(target)
                            .map_or(true, |jid| jid.resourcepart().is_some())
                        || carbons_only
                        || blocklist_requested_only
                        || roster_requested_only
                        || privacy_requested_only
                        || primary_one_to_one
                        || available_only
                        || available_nonnegative_only
                        || expected_user_id.is_some()
                        || expected_auth_generation.is_some()
                        || roster_version.is_some()
                        || roster_annotated_stanza.is_some()
                        || !exclude_jids.is_empty()
                        || carbon_muc_scope.is_some())
                {
                    continue;
                }
                // A typed MIX contract is never a hint.  Requiring the
                // matching receipt flag in both directions prevents a
                // signed-but-malformed command from taking the volatile
                // queue branch while carrying a live recipient lease.
                if matches!(
                    resolved_message_delivery,
                    Some(ResolvedNodeMessageDelivery::Mix(_))
                ) != mix_transport_receipt_required
                {
                    continue;
                }
                let mix_request_id = if mix_transport_receipt_required {
                    match json["request_id"]
                        .as_str()
                        .and_then(|value| uuid::Uuid::parse_str(value).ok())
                    {
                        Some(request_id) => Some(request_id),
                        None => continue,
                    }
                } else {
                    None
                };
                let mut targets = dispatch.session_entries_for(target);
                if (primary_one_to_one || available_only || available_nonnegative_only)
                    && !target.contains('/')
                {
                    targets.retain(|(_, session)| {
                        session.available.load(Ordering::Relaxed)
                            && (!available_nonnegative_only
                                || session.priority.load(Ordering::Relaxed) >= 0)
                    });
                }
                if primary_one_to_one && !target.contains('/') {
                    targets.sort_by(|(left_jid, left), (right_jid, right)| {
                        right
                            .priority
                            .load(Ordering::Relaxed)
                            .cmp(&left.priority.load(Ordering::Relaxed))
                            .then_with(|| left_jid.cmp(right_jid))
                    });
                }
                for (jid, session) in targets {
                    if !direct_delivery_contract_valid
                        || (is_message_stanza && resolved_message_delivery.is_none())
                    {
                        break;
                    }
                    if exclude_jids.contains(&jid)
                        || !delivery_user_identity_matches(
                            expected_user_id,
                            expected_auth_generation,
                            session.user_id,
                            session.auth_generation,
                        )
                        || (carbons_only
                            && !session.carbons.load(std::sync::atomic::Ordering::Acquire))
                        || (blocklist_requested_only
                            && !session.blocklist_requested.load(Ordering::Acquire))
                        || (roster_requested_only
                            && !session.roster_requested.load(Ordering::Acquire))
                        || (privacy_requested_only
                            && !session.privacy_requested.load(Ordering::Acquire))
                        || carbon_muc_scope.as_ref().is_some_and(|(room, nick)| {
                            session
                                .muc_memberships
                                .get(room)
                                .is_none_or(|membership| membership.nick != *nick)
                        })
                    {
                        continue;
                    }
                    if !blocklist_requested_only
                        && !roster_requested_only
                        && !privacy_requested_only
                    {
                        if let Some((peer, kind)) = privacy_peer_kind.as_ref() {
                            match message_policy
                                .privacy_allows_session(&session, peer, *kind)
                                .await
                            {
                                Ok(true) => {}
                                Ok(false) => continue,
                                Err(error) => {
                                    // Delivery policy reads are fail closed.
                                    // A database outage must never turn a deny
                                    // list into an allow list on another node.
                                    tracing::warn!(?error, %jid, "privacy policy lookup failed during clustered delivery");
                                    continue;
                                }
                            }
                        }
                    }
                    if mix_capable_only {
                        match mix_caps.capability(&jid) {
                            crate::state::cluster_listener_mix_caps::ClusterMixCapability::Supported => {
                                mix_supported = mix_supported.saturating_add(1);
                            }
                            crate::state::cluster_listener_mix_caps::ClusterMixCapability::Unsupported => {
                                mix_unsupported = mix_unsupported.saturating_add(1);
                                continue;
                            }
                            crate::state::cluster_listener_mix_caps::ClusterMixCapability::Unknown => {
                                mix_unknown = mix_unknown.saturating_add(1);
                                continue;
                            }
                        }
                    }
                    let delivery = if blocklist_requested_only
                        || roster_requested_only
                        || privacy_requested_only
                    {
                        crate::xmpp::xml_util::set_to(stanza, &jid)
                    } else {
                        node_delivery_stanza(stanza, carbons_only, &jid)
                    };
                    let durable_delivery = if is_message_stanza {
                        match resolved_message_delivery {
                            Some(ResolvedNodeMessageDelivery::Volatile) => None,
                            Some(ResolvedNodeMessageDelivery::Durable(durable))
                                if durable.recipient_id == session.user_id =>
                            {
                                Some(durable)
                            }
                            Some(ResolvedNodeMessageDelivery::Durable(_))
                            | Some(ResolvedNodeMessageDelivery::Mix(_))
                            | None => None,
                        }
                    } else {
                        None
                    };
                    let mix_delivery = if is_message_stanza {
                        match resolved_message_delivery {
                            Some(ResolvedNodeMessageDelivery::Mix(source)) => Some(source),
                            Some(ResolvedNodeMessageDelivery::Volatile)
                            | Some(ResolvedNodeMessageDelivery::Durable(_))
                            | None => None,
                        }
                    } else {
                        None
                    };
                    let accepted = if roster_requested_only {
                        let version = roster_version
                            .expect("cluster roster shape validated before session fanout");
                        let annotated = roster_annotated_stanza
                            .map(|stanza| crate::xmpp::xml_util::set_to(stanza, &jid));
                        match session.roster_sync.route(
                            &session.roster_requested,
                            &session.mix_roster_annotations,
                            version,
                            delivery.clone(),
                            annotated,
                        ) {
                            northstar_roster_application::RosterPushDisposition::NotInterested => {
                                false
                            }
                            northstar_roster_application::RosterPushDisposition::Buffered => true,
                            northstar_roster_application::RosterPushDisposition::Deliver(
                                stanza,
                            ) => {
                                if session.sender.try_send(stanza).is_ok() {
                                    true
                                } else {
                                    session.sender.disconnect_backpressured_transport();
                                    session.disconnect.cancel();
                                    false
                                }
                            }
                            northstar_roster_application::RosterPushDisposition::Overflow => {
                                session.sender.disconnect_backpressured_transport();
                                session.disconnect.cancel();
                                false
                            }
                        }
                    } else if let (Some(source), Some(request_id)) = (mix_delivery, mix_request_id)
                    {
                        // Rotate the signed source into this node's durable
                        // fence before putting it on a local C2S output.  No
                        // acknowledgement is emitted until that output has
                        // itself transferred to its socket/SM/BOSH owner.
                        let remote_source = match message_policy
                            .transfer_mix_delivery(
                                source,
                                dispatch.node_id(),
                                request_id,
                                MIX_CLUSTER_HANDOFF_TTL_SECONDS,
                            )
                            .await
                        {
                            Ok(source) => source,
                            Err(error) => {
                                tracing::warn!(
                                    ?error,
                                    delivery_id = %source.delivery_id,
                                    "failed to establish remote MIX ownership fence"
                                );
                                break;
                            }
                        };
                        match try_send_cluster_mix_transport(
                            &session.sender,
                            &session.disconnect,
                            delivery.clone(),
                            remote_source,
                        )
                        .await
                        {
                            Ok(crate::outbound::MixTransportCompletion::SocketFenced {
                                ..
                            }) => {
                                mix_handoff = Some(ClusterMixHandoff::SocketFenced);
                                true
                            }
                            Ok(crate::outbound::MixTransportCompletion::SmPersisted { .. }) => {
                                mix_handoff = Some(ClusterMixHandoff::SmPersisted);
                                true
                            }
                            Ok(crate::outbound::MixTransportCompletion::BoshPersisted {
                                ..
                            }) => {
                                mix_handoff = Some(ClusterMixHandoff::BoshPersisted);
                                true
                            }
                            Err(error) => {
                                tracing::warn!(
                                    ?error,
                                    delivery_id = %remote_source.delivery_id,
                                    "remote MIX transport failed before durable ownership"
                                );
                                if let Err(release_error) = message_policy
                                    .release_mix_delivery(
                                        remote_source,
                                        dispatch.node_id(),
                                        request_id,
                                    )
                                    .await
                                {
                                    tracing::error!(
                                        ?release_error,
                                        delivery_id = %remote_source.delivery_id,
                                        "failed to release unowned remote MIX hand-off"
                                    );
                                }
                                false
                            }
                        }
                    } else if transport_receipt_required {
                        let (receipt_tx, mut receipt_rx) = tokio::sync::mpsc::unbounded_channel();
                        match session
                            .sender
                            .try_send_with_transport_receipt(delivery.clone(), receipt_tx)
                        {
                            Ok(()) => match tokio::time::timeout(
                                DELIVERY_TRANSPORT_RECEIPT_TIMEOUT,
                                receipt_rx.recv(),
                            )
                            .await
                            {
                                Ok(Some(())) => true,
                                Ok(None) => false,
                                Err(_) => {
                                    session.sender.disconnect_backpressured_transport();
                                    session.disconnect.cancel();
                                    false
                                }
                            },
                            Err(_) => {
                                session.sender.disconnect_backpressured_transport();
                                session.disconnect.cancel();
                                false
                            }
                        }
                    } else if let Some(durable) = durable_delivery {
                        session
                            .sender
                            .try_send_durable(delivery.clone(), durable)
                            .is_ok()
                    } else {
                        session.sender.try_send(delivery.clone()).is_ok()
                    };
                    if accepted {
                        if is_message_stanza {
                            message_policy.record_online_queue_acceptance(
                                durable_delivery.is_some() || mix_delivery.is_some(),
                            );
                        }
                        delivered += 1;
                        accepted_full_jid.get_or_insert(jid);
                        if primary_one_to_one || mix_delivery.is_some() {
                            break;
                        }
                    }
                }
            }
        }

        let ack = json["request_id"]
            .as_str()
            .filter(|request_id| uuid::Uuid::parse_str(request_id).is_ok())
            .zip(
                json["ack_nonce"]
                    .as_str()
                    .filter(|nonce| (32..=128).contains(&nonce.len())),
            )
            .map(|(request_id, nonce)| NodeDeliveryAck {
                request_id: request_id.to_owned(),
                nonce: nonce.to_owned(),
                node_id: dispatch.node_id().to_owned(),
                delivered,
                accepted_full_jid,
                mix_supported,
                mix_unsupported,
                mix_unknown,
                control_processed,
                control_outcome,
                delivery: acknowledged_delivery,
                mix_handoff,
            });
        let authority = ListenerCommandAuthority {
            generation: candidate_generation,
            rotation_epoch,
            envelope,
        };
        if responses.items.is_empty() {
            if let Some(ack) = ack {
                publish_listener_ack(&admission, &security, &source_node, ack, &authority).await?;
            }
        } else {
            // Only remote receipt waits leave the sequential command turn.
            // Both peers can therefore execute each other's leaf deliveries
            // even when they simultaneously handle presence probes.
            continuations.push(complete_listener_responses(
                ListenerResponseContext {
                    admission: Arc::clone(&admission),
                    security: Arc::clone(&security),
                    message_policy: Arc::clone(&message_policy),
                    sender: Arc::clone(&presence_sender),
                },
                authority,
                responses,
                source_node,
                ack,
            ))?;
        }
    }
}
