//! ProtocolSession entry points for MIX IQs, messages and presence.

use super::*;

/// Deliver the latest persisted roster change between `user` and the MIX
/// channel (XEP-0405). The stored change decides whether the item is removed,
/// so `_removed` is unused; a joined membership adds its participant id.
pub(super) async fn push_mix_roster_update(
    state: &Arc<AppState>,
    user: &crate::services::mix::MixAccount,
    channel_jid: &str,
    _removed: bool,
) -> Result<()> {
    let Some(change) = state
        .mix_service()
        .latest_roster_change_for_contact(user.id, channel_jid)
        .await?
    else {
        return Ok(());
    };
    let participant_id = if change.removed {
        None
    } else {
        let participant_id = state
            .mix_service()
            .pam_membership(user.id, channel_jid)
            .await?
            .filter(|membership| membership.state == "joined")
            .and_then(|membership| membership.participant_id);
        participant_id
    };
    super::super::roster::deliver_roster_change(
        state,
        user.id,
        &user.username,
        &change,
        participant_id.as_deref(),
    )
    .await
}

impl ProtocolSession {
    pub(crate) fn mix_domain(&self) -> String {
        local_mix_domain(&self.state)
    }

    /// Intercept MIX/PAM IQs before ordinary entity and PubSub routing.
    pub(crate) async fn try_mix_iq(&self, raw: &str) -> Result<Option<Action>> {
        if let Some(action) = self.try_mix_iq_relay(raw).await? {
            return Ok(Some(action));
        }
        if !mix_iq_route_candidate(raw, &self.mix_domain()) {
            return Ok(None);
        }
        let Some(request) = parse_iq(raw)? else {
            return Ok(None);
        };
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Some(Action::Send(iq_error_to(
                &request.id,
                request.to.as_deref().unwrap_or(self.state.local_domain()),
                request.from.as_deref().unwrap_or_default(),
                "auth",
                "not-authorized",
            ))));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Some(Action::Send(iq_error_to(
                &request.id,
                self.state.local_domain(),
                "",
                "auth",
                "not-authorized",
            ))));
        };
        let actor_bare = format!("{}@{}", user.username, self.state.local_domain());
        if let Some(asserted) = request.from.as_deref() {
            let asserted = northstar_xmpp_types::jid::canonicalize(asserted).ok();
            if asserted.as_deref() != Some(full_jid)
                && asserted.as_deref() != Some(actor_bare.as_str())
            {
                return Ok(Some(Action::Send(iq_error_to(
                    &request.id,
                    request.to.as_deref().unwrap_or(self.state.local_domain()),
                    full_jid,
                    "auth",
                    "not-authorized",
                ))));
            }
        }
        let own_target = request.to.as_deref().is_some_and(|to| {
            CanonicalJid::parse_bare(to).is_ok_and(|target| target.to_string() == actor_bare)
        });
        if matches!(
            request.operation,
            IqOperation::PamJoin { .. } | IqOperation::PamLeave { .. }
        ) {
            if !own_target || request.kind != "set" {
                return Ok(Some(Action::Send(iq_error_to(
                    &request.id,
                    &actor_bare,
                    full_jid,
                    "modify",
                    "bad-request",
                ))));
            }
            return self
                .handle_pam_request(
                    request,
                    user.id,
                    &user.username,
                    &actor_bare,
                    full_jid,
                    Sha256::digest(raw.as_bytes()).into(),
                )
                .await
                .map(Some);
        }
        let to = request.to.as_deref().unwrap_or_default();
        if !CanonicalJid::parse(to).is_ok_and(|target| target.domainpart() == self.mix_domain()) {
            return Ok(None);
        }
        self.handle_local_mix_iq(request, &actor_bare, full_jid)
            .await
            .map(Some)
    }

    pub(super) async fn try_mix_iq_relay(&self, raw: &str) -> Result<Option<Action>> {
        let Some(request) = parse_relay_iq(raw)? else {
            return Ok(None);
        };
        if request.kind != "get" || request.request.is_none() {
            return Ok(None);
        }
        let target = match northstar_xmpp_types::jid::CanonicalJid::parse(&request.to) {
            Ok(target) if target.localpart().is_some() => target,
            _ => return Ok(None),
        };
        let (_target_id, channel_jid) = match decode_participant_jid(&target.bare()) {
            Ok(decoded) => decoded,
            Err(_) => return Ok(None),
        };
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Some(Action::Send(relay_error(
                &request.id,
                &request.to,
                &request.from,
                "auth",
                "not-authorized",
            ))));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Some(Action::Send(relay_error(
                &request.id,
                &request.to,
                &request.from,
                "auth",
                "not-authorized",
            ))));
        };
        if !request.from.is_empty() && request.from != full_jid {
            return Ok(Some(Action::Send(relay_error(
                &request.id,
                &request.to,
                full_jid,
                "auth",
                "not-authorized",
            ))));
        }
        let channel_address = CanonicalJid::parse_bare(&channel_jid)?;
        let channel_domain = channel_address.domainpart();
        if channel_domain == self.mix_domain() {
            let response = handle_channel_relay_request(&self.state, &request, full_jid).await?;
            return Ok(Some(if response.is_empty() {
                Action::None
            } else {
                Action::Send(response)
            }));
        }
        let membership = self
            .state
            .mix_service()
            .pam_membership(user.id, &channel_jid)
            .await?;
        if !membership.is_some_and(|membership| membership.state == "joined")
            || self
                .state
                .mix_service()
                .is_blocked(user.id, &channel_jid)
                .await?
            || !self.state.federation_domain_allowed(channel_domain)
        {
            return Ok(Some(Action::Send(relay_error(
                &request.id,
                &request.to,
                full_jid,
                "auth",
                "forbidden",
            ))));
        }
        let relay_id = Uuid::new_v4().to_string();
        if !register_mix_iq_relay(
            &self.state,
            relay_id.clone(),
            MixIqRelayStage::Participant {
                requester_full_jid: full_jid.to_owned(),
                original_id: request.id.clone(),
                expected_from: request.to.clone(),
                channel_jid: channel_jid.clone(),
            },
        ) {
            return Ok(Some(Action::Send(relay_error(
                &request.id,
                &request.to,
                full_jid,
                "wait",
                "resource-constraint",
            ))));
        }
        let outbound = relay_iq_xml(&request, &relay_id, full_jid, &request.to);
        if !self
            .state
            .federation_outbox()
            .send(
                channel_domain,
                outbound,
                Some(CanonicalJid::parse(full_jid)?.bare()),
            )
            .await
        {
            self.state.pending_mix_iq().remove(&relay_id);
            return Ok(Some(Action::Send(relay_error(
                &request.id,
                &request.to,
                full_jid,
                "wait",
                "remote-server-timeout",
            ))));
        }
        Ok(Some(Action::None))
    }

    pub(super) async fn handle_pam_request(
        &self,
        request: OwnedIq,
        user_id: Uuid,
        username: &str,
        actor_bare: &str,
        full_jid: &str,
        request_digest: [u8; 32],
    ) -> Result<Action> {
        match request.operation {
            IqOperation::PamJoin { channel, join } => {
                let channel_address = match CanonicalJid::parse_bare(&channel) {
                    Ok(channel) if channel.localpart().is_some() => channel,
                    _ => {
                        return Ok(Action::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "modify",
                            "jid-malformed",
                        )));
                    }
                };
                let channel = channel_address.to_string();
                let domain = channel_address.domainpart();
                if domain == self.mix_domain() {
                    let channel_localpart = channel_address
                        .localpart()
                        .expect("MIX channel localpart was checked above");
                    let Some(mix_channel) = self
                        .state
                        .mix_service()
                        .mix_channel(domain, channel_localpart)
                        .await?
                    else {
                        return Ok(Action::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    match self
                        .state
                        .mix_service()
                        .join_mix_channel(
                            mix_channel.id,
                            JoinMixRequest {
                                actor_jid: actor_bare.to_owned(),
                                nick: join.nick.clone(),
                                nodes: join.nodes.clone(),
                                pam_user_id: Some(user_id),
                                invitation: join.invitation.clone(),
                                preference: join.preference.clone(),
                                anonymous_profile: join.anonymous_profile,
                            },
                            None,
                        )
                        .await?
                    {
                        JoinChannelOutcome::Joined {
                            participant,
                            preference,
                            subscriptions,
                            newly_joined: _,
                            roster_change,
                        } => {
                            if let Some(change) = roster_change.as_ref() {
                                let participant_id = participant.participant_id.to_string();
                                self.push_roster_change(
                                    user_id,
                                    username,
                                    change,
                                    Some(&participant_id),
                                )
                                .await?;
                            }
                            let payload = XmlElement::namespaced("client-join", PAM_NS)
                                .validated_fragment(&pam_join_payload(
                                    &channel,
                                    &participant,
                                    &subscriptions,
                                    join.preference.as_ref().map(|_| &preference),
                                    join.anonymous_profile,
                                )?)?
                                .finish();
                            Ok(Action::Send(iq_result_to(
                                &request.id,
                                actor_bare,
                                full_jid,
                                &payload,
                            )))
                        }
                        outcome => Ok(Action::Send(join_error(
                            &request.id,
                            actor_bare,
                            full_jid,
                            outcome,
                        ))),
                    }
                } else {
                    match self
                        .state
                        .mix_service()
                        .lookup_remote_pam_operation(
                            user_id,
                            full_jid,
                            &request.id,
                            &request_digest,
                        )
                        .await?
                    {
                        PamOperationReplay::Replay(response) => return Ok(Action::Send(response)),
                        PamOperationReplay::Pending => {
                            self.state.federation_outbox().wake_outbox();
                            return Ok(Action::None);
                        }
                        PamOperationReplay::Conflict => {
                            return Ok(Action::Send(iq_error_to(
                                &request.id,
                                actor_bare,
                                full_jid,
                                "cancel",
                                "conflict",
                            )));
                        }
                        PamOperationReplay::Miss => {}
                    }
                    // Exact retries are journal reads, not new federation
                    // attempts. A later policy change must not replace the
                    // original byte-stable result or strand a pending request.
                    if !self.state.federation_domain_allowed(domain) {
                        return Ok(Action::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "cancel",
                            "remote-server-not-found",
                        )));
                    }
                    let federation_id = Uuid::new_v4().to_string();
                    let mut join_element = XmlElement::namespaced("join", CORE_NS);
                    for node in &join.nodes {
                        join_element.push_child(XmlElement::new("subscribe").attr("node", node));
                    }
                    if let Some(nick) = join.nick.as_deref() {
                        join_element.push_child(XmlElement::new("nick").text(nick.to_owned()));
                    }
                    let outbound = XmlElement::namespaced("iq", "jabber:server")
                        .attr("type", "set")
                        .attr("from", actor_bare)
                        .attr("to", &channel)
                        .attr("id", &federation_id)
                        .child(join_element)
                        .finish();
                    let admitted = self
                        .state
                        .mix_service()
                        .begin_remote_pam_join(BeginRemotePamJoin {
                            user_id,
                            actor_jid: actor_bare.to_owned(),
                            channel_jid: channel.clone(),
                            nick: join.nick.clone(),
                            nodes: join.nodes.clone(),
                            request_id: federation_id,
                            client_request_id: request.id.clone(),
                            requester_full_jid: full_jid.to_owned(),
                            request_digest,
                            remote_domain: domain.to_owned(),
                            outbound_stanza: outbound,
                            policy: self.state.federation_outbox().outbox_policy(),
                        })
                        .await?;
                    match admitted {
                        PamOperationReplay::Replay(response) => return Ok(Action::Send(response)),
                        PamOperationReplay::Conflict => {
                            return Ok(Action::Send(iq_error_to(
                                &request.id,
                                actor_bare,
                                full_jid,
                                "cancel",
                                "conflict",
                            )));
                        }
                        PamOperationReplay::Pending => {
                            self.state.federation_outbox().wake_outbox();
                        }
                        PamOperationReplay::Miss => {
                            return Ok(Action::Send(iq_error_to(
                                &request.id,
                                actor_bare,
                                full_jid,
                                "wait",
                                "resource-constraint",
                            )));
                        }
                    }
                    Ok(Action::None)
                }
            }
            IqOperation::PamLeave { channel } => {
                let channel_address = match CanonicalJid::parse_bare(&channel) {
                    Ok(channel) if channel.localpart().is_some() => channel,
                    _ => {
                        return Ok(Action::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "modify",
                            "jid-malformed",
                        )));
                    }
                };
                let channel = channel_address.to_string();
                let domain = channel_address.domainpart();
                if domain == self.mix_domain() {
                    let channel_localpart = channel_address
                        .localpart()
                        .expect("MIX channel localpart was checked above");
                    let Some(mix_channel) = self
                        .state
                        .mix_service()
                        .mix_channel(domain, channel_localpart)
                        .await?
                    else {
                        return Ok(Action::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    let Some(left) = self
                        .state
                        .mix_service()
                        .leave_mix_channel(mix_channel.id, actor_bare, Some(user_id), None)
                        .await?
                    else {
                        return Ok(Action::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    let roster_change = left.roster_change.clone();
                    if let Some(change) = roster_change.as_ref() {
                        self.push_roster_change(user_id, username, change, None)
                            .await?;
                    }
                    let payload = XmlElement::namespaced("client-leave", PAM_NS)
                        .attr("channel", &channel)
                        .child(XmlElement::namespaced("leave", CORE_NS))
                        .finish();
                    Ok(Action::Send(iq_result_to(
                        &request.id,
                        actor_bare,
                        full_jid,
                        &payload,
                    )))
                } else {
                    match self
                        .state
                        .mix_service()
                        .lookup_remote_pam_operation(
                            user_id,
                            full_jid,
                            &request.id,
                            &request_digest,
                        )
                        .await?
                    {
                        PamOperationReplay::Replay(response) => return Ok(Action::Send(response)),
                        PamOperationReplay::Pending => {
                            self.state.federation_outbox().wake_outbox();
                            return Ok(Action::None);
                        }
                        PamOperationReplay::Conflict => {
                            return Ok(Action::Send(iq_error_to(
                                &request.id,
                                actor_bare,
                                full_jid,
                                "cancel",
                                "conflict",
                            )));
                        }
                        PamOperationReplay::Miss => {}
                    }
                    if !self.state.federation_domain_allowed(domain) {
                        return Ok(Action::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "cancel",
                            "remote-server-not-found",
                        )));
                    }
                    let federation_id = Uuid::new_v4().to_string();
                    let outbound = XmlElement::namespaced("iq", "jabber:server")
                        .attr("type", "set")
                        .attr("from", actor_bare)
                        .attr("to", &channel)
                        .attr("id", &federation_id)
                        .child(XmlElement::namespaced("leave", CORE_NS))
                        .finish();
                    let admitted = self
                        .state
                        .mix_service()
                        .begin_remote_pam_leave(BeginRemotePamLeave {
                            user_id,
                            actor_jid: actor_bare.to_owned(),
                            channel_jid: channel.clone(),
                            request_id: federation_id,
                            client_request_id: request.id.clone(),
                            requester_full_jid: full_jid.to_owned(),
                            request_digest,
                            remote_domain: domain.to_owned(),
                            outbound_stanza: outbound,
                            policy: self.state.federation_outbox().outbox_policy(),
                        })
                        .await?;
                    match admitted {
                        PamOperationReplay::Replay(response) => return Ok(Action::Send(response)),
                        PamOperationReplay::Conflict => {
                            return Ok(Action::Send(iq_error_to(
                                &request.id,
                                actor_bare,
                                full_jid,
                                "cancel",
                                "conflict",
                            )));
                        }
                        PamOperationReplay::Pending => self.state.federation_outbox().wake_outbox(),
                        PamOperationReplay::Miss => {
                            return Ok(Action::Send(iq_error_to(
                                &request.id,
                                actor_bare,
                                full_jid,
                                "cancel",
                                "item-not-found",
                            )));
                        }
                    }
                    Ok(Action::None)
                }
            }
            _ => unreachable!("PAM dispatcher only passes PAM requests"),
        }
    }

    pub(super) async fn handle_local_mix_iq(
        &self,
        request: OwnedIq,
        actor_bare: &str,
        reply_to: &str,
    ) -> Result<Action> {
        let from = request
            .to
            .as_deref()
            .unwrap_or(&self.mix_domain())
            .to_owned();
        if matches!(
            request.operation,
            IqOperation::Mam(_)
                | IqOperation::MamForm
                | IqOperation::MamMetadata
                | IqOperation::MamError(_)
        ) {
            return Ok(Action::SendMany(
                handle_mix_mam_iq(&self.state, &request, actor_bare, &from, reply_to).await?,
            ));
        }
        let response =
            handle_channel_iq(&self.state, &request, actor_bare, &from, reply_to, None).await?;
        Ok(Action::Send(response))
    }

    pub(crate) async fn try_mix_message(
        &self,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Option<Action>> {
        let Some(to) = root.attribute("to") else {
            return Ok(None);
        };
        if !CanonicalJid::parse(to).is_ok_and(|target| target.domainpart() == self.mix_domain()) {
            return Ok(None);
        }
        self.enter_frame_stage(Stage::MixPolicy);
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Some(Action::Send(stanza_error(
                root,
                "auth",
                "not-authorized",
            ))));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Some(Action::Send(stanza_error(
                root,
                "auth",
                "not-authorized",
            ))));
        };
        let actor_bare = format!("{}@{}", user.username, self.state.local_domain());
        let result = process_channel_message(
            &self.state,
            &actor_bare,
            full_jid,
            raw,
            Some(&self.frame_executions),
        )
        .await?;
        Ok(Some(result.map_or(Action::None, Action::Send)))
    }

    pub(crate) async fn try_mix_presence(
        &self,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Option<Action>> {
        let Some(to) = root.attribute("to") else {
            return Ok(None);
        };
        if !CanonicalJid::parse(to).is_ok_and(|target| target.domainpart() == self.mix_domain()) {
            return Ok(None);
        }
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Some(Action::Send(stanza_error(
                root,
                "auth",
                "not-authorized",
            ))));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Some(Action::Send(stanza_error(
                root,
                "auth",
                "not-authorized",
            ))));
        };
        let actor_bare = format!("{}@{}", user.username, self.state.local_domain());
        // Directed MIX presence and verified-caps fallback share the exact
        // resource epoch. Record only a successfully applied transition: an
        // error response must not suppress later initialisation. The set is
        // resource-owned and therefore disappears with the session rather
        // than accumulating in a process-global keyed lock/tombstone map.
        let mix_presence_epoch = Arc::clone(&self.presence.mix_presence_gate)
            .lock_owned()
            .await;
        if !mix_presence_route_is_current(
            &self.state,
            full_jid,
            self.connection_id,
            &self.presence.mix_presence_gate,
            false,
        ) {
            return Ok(Some(Action::None));
        }
        let result = process_channel_presence(&self.state, &actor_bare, full_jid, raw).await?;
        if result.is_none() {
            let target = CanonicalJid::parse_bare(to)?.to_string();
            match root.attribute("type").unwrap_or("available") {
                "unavailable" => {
                    self.presence
                        .mix_presence_fallback_suppressed
                        .insert(target);
                }
                "available" => {
                    self.presence
                        .mix_presence_fallback_suppressed
                        .remove(&target);
                }
                _ => {}
            }
        }
        drop(mix_presence_epoch);
        Ok(Some(result.map_or(Action::None, Action::Send)))
    }

    /// XEP-0405 participant-server fan-out for a broadcast presence.  Only a
    /// resource whose verified capabilities advertise MIX is represented in
    /// a channel's presence node.
    pub(crate) async fn forward_presence_to_mix_channels(
        &self,
        kind: &str,
        advertised_capability: MixSessionCapability,
        raw: &str,
    ) -> Result<()> {
        let (Some(user), Some(full_jid)) = (self.authenticated.as_ref(), self.full_jid.as_deref())
        else {
            return Ok(());
        };
        let action = mix_broadcast_presence_action(kind, advertised_capability);
        if action == MixBroadcastPresenceAction::Ignore {
            return Ok(());
        }
        let synthesized_unavailable;
        let projected = if action == MixBroadcastPresenceAction::Retract && kind != "unavailable" {
            synthesized_unavailable = XmlElement::namespaced("presence", "jabber:client")
                .attr("from", full_jid)
                .attr("type", "unavailable")
                .finish();
            synthesized_unavailable.as_str()
        } else {
            raw
        };
        let actor_bare = format!("{}@{}", user.username, self.state.local_domain());
        for membership in self.state.mix_service().pam_memberships(user.id).await? {
            if membership.state != "joined"
                || !membership
                    .subscriptions
                    .iter()
                    .any(|node| node == NODE_PRESENCE)
            {
                continue;
            }
            let Ok(channel) = CanonicalJid::parse_bare(&membership.channel_jid) else {
                tracing::warn!(channel = %membership.channel_jid, "ignored malformed persisted MIX membership JID");
                continue;
            };
            let domain = channel.domainpart();
            let directed = crate::services::xml_util::set_to(
                &crate::services::xml_util::set_from(projected, full_jid),
                &membership.channel_jid,
            );
            if domain == self.mix_domain() {
                let _ =
                    process_channel_presence(&self.state, &actor_bare, full_jid, &directed).await?;
            } else if self.state.federation_domain_allowed(domain) {
                let _ = self
                    .state
                    .federation_outbox()
                    .send(domain, directed, Some(actor_bare.clone()))
                    .await;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MixBroadcastPresenceAction {
    Publish,
    Retract,
    Ignore,
}

pub(super) fn mix_broadcast_presence_action(
    kind: &str,
    capability: MixSessionCapability,
) -> MixBroadcastPresenceAction {
    match (kind, capability) {
        ("available", MixSessionCapability::Supported) => MixBroadcastPresenceAction::Publish,
        ("available" | "unavailable", _) => MixBroadcastPresenceAction::Retract,
        _ => MixBroadcastPresenceAction::Ignore,
    }
}
