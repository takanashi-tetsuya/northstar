//! Federated MIX: authenticated remote actors, disco#info, IQs, IQ relay, messages and presence.

use super::*;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedMixIqActor {
    pub(super) bare: String,
    pub(super) reply_to: String,
}

pub(super) fn authenticated_actor(
    from: &str,
    authenticated_domain: &str,
) -> Result<AuthenticatedMixIqActor> {
    let actor = crate::jid::CanonicalJid::parse(from)?;
    anyhow::ensure!(
        actor.localpart().is_some(),
        "federated MIX actor requires a user JID"
    );
    anyhow::ensure!(
        same_jid_domain(actor.domainpart(), authenticated_domain),
        "federated MIX actor domain is not authenticated"
    );
    Ok(AuthenticatedMixIqActor {
        bare: actor.bare(),
        reply_to: actor.to_string(),
    })
}

pub(super) fn authenticated_mix_disco_requester(
    from: &str,
    authenticated_domain: &str,
) -> Result<AuthenticatedMixIqActor> {
    let actor = crate::jid::CanonicalJid::parse(from)?;
    anyhow::ensure!(
        same_jid_domain(actor.domainpart(), authenticated_domain),
        "federated MIX disco requester domain is not authenticated"
    );
    Ok(AuthenticatedMixIqActor {
        bare: actor.bare(),
        reply_to: actor.to_string(),
    })
}

pub(super) fn authenticated_full_actor(from: &str, authenticated_domain: &str) -> Result<String> {
    let actor = crate::jid::CanonicalJid::parse(from)?;
    anyhow::ensure!(
        actor.localpart().is_some(),
        "federated MIX actor requires a user JID"
    );
    anyhow::ensure!(
        actor.resourcepart().is_some(),
        "federated MIX message actor requires a full JID"
    );
    anyhow::ensure!(
        same_jid_domain(actor.domainpart(), authenticated_domain),
        "federated MIX actor domain is not authenticated"
    );
    Ok(actor.to_string())
}

pub(super) fn authenticated_mix_service(asserted_domain: &str, authenticated_domain: &str) -> bool {
    let Ok(authenticated_domain) = prepare_domainpart(authenticated_domain) else {
        return false;
    };
    prepare_domainpart(asserted_domain)
        .is_ok_and(|asserted| same_jid_domain(&asserted, &authenticated_domain))
}

pub(super) async fn federated_mix_disco_info(
    state: &Arc<AppState>,
    request: &MixDiscoInfoRequest,
    requester: &AuthenticatedMixIqActor,
) -> Result<String> {
    if let Some(condition) = request.error {
        return Ok(iq_error_to(
            &request.id,
            &request.to,
            &requester.reply_to,
            stanza_error_type(condition),
            condition,
        ));
    }
    if request.node.is_some() {
        return Ok(iq_error_to(
            &request.id,
            &request.to,
            &requester.reply_to,
            "cancel",
            "item-not-found",
        ));
    }
    let target = match CanonicalJid::parse(&request.to) {
        Ok(target)
            if target.resourcepart().is_none()
                && same_jid_domain(target.domainpart(), &local_mix_domain(state)) =>
        {
            target
        }
        _ => {
            return Ok(iq_error_to(
                &request.id,
                &request.to,
                &requester.reply_to,
                "cancel",
                "item-not-found",
            ));
        }
    };
    let muc_domain = local_muc_domain(state);
    let mirror = if let Some(localpart) = target.localpart() {
        let Some(channel) = state
            .mix_service()
            .mix_channel(target.domainpart(), localpart)
            .await?
        else {
            return Ok(iq_error_to(
                &request.id,
                &request.to,
                &requester.reply_to,
                "cancel",
                "item-not-found",
            ));
        };
        if !state
            .mix_service()
            .mix_channel_discoverable_to(&channel, &requester.bare)
            .await?
        {
            // Hidden channels deliberately use item-not-found so disco does
            // not become an existence oracle for remote domains.
            return Ok(iq_error_to(
                &request.id,
                &request.to,
                &requester.reply_to,
                "cancel",
                "item-not-found",
            ));
        }
        let linked = state.mix_muc_mirror_enabled()
            && state
                .mix_service()
                .mix_muc_mirror_for_mix(channel.id)
                .await?
                .is_some();
        let mirror = super::super::mix_muc::conditional_mirror_discovery_form(
            state.mix_muc_mirror_enabled(),
            linked,
            super::super::mix_muc::MirrorDirection::Muc,
            &muc_domain,
        );
        mix_channel_disco_info_payload(
            channel.name.as_deref().unwrap_or(&channel.localpart),
            channel.allow_user_message_retraction
                || channel.administrator_retraction_rights != "nobody",
            channel.allow_private_messages,
            state.xmpp_extension_enabled(northstar_xep_0313::XEP_ID),
            &mirror,
        )?
    } else {
        let linked = state.mix_muc_mirror_enabled()
            && state
                .mix_service()
                .mix_muc_mirror_service_complete(target.domainpart())
                .await?;
        let mirror = super::super::mix_muc::conditional_mirror_discovery_form(
            state.mix_muc_mirror_enabled(),
            linked,
            super::super::mix_muc::MirrorDirection::Muc,
            &muc_domain,
        );
        mix_service_disco_info_payload(state.server_name(), &mirror)?
    };
    Ok(iq_result_to(
        &request.id,
        &target.to_string(),
        &requester.reply_to,
        &mirror,
    ))
}

pub(super) fn pam_membership_receives(membership: &PamMembership, node: &str) -> bool {
    membership.state == "joined"
        && membership
            .subscriptions
            .iter()
            .any(|subscription| subscription == node)
}

pub(super) fn federated_mix_iq_is_mutation(request: &OwnedIq) -> bool {
    request.kind == "set" || matches!(&request.operation, IqOperation::Invite { .. })
}

/// S2S entry point.  The S2S layer must call this only after authenticating
/// `authenticated_domain`; the function independently verifies the stanza's
/// asserted `from` before creating or mutating a remote participant actor.
pub(crate) async fn federated_mix_iq(
    state: Arc<AppState>,
    authenticated_domain: &str,
    raw: String,
) -> Result<bool> {
    if let Some(request) = parse_relay_iq(&raw)? {
        if federated_mix_iq_relay(&state, authenticated_domain, request).await? {
            return Ok(true);
        }
    }
    if let Some(request) = parse_mix_disco_info(&raw)? {
        let requester = authenticated_mix_disco_requester(&request.from, authenticated_domain)?;
        let response = federated_mix_disco_info(&state, &request, &requester).await?;
        let _ = state
            .federation_outbox()
            .send(authenticated_domain, response, None)
            .await;
        return Ok(true);
    }
    let Some(request) = parse_iq(&raw)? else {
        return Ok(false);
    };
    let from = request.from.as_deref().unwrap_or_default();
    let to = request.to.as_deref().unwrap_or_default();
    let local_mix = local_mix_domain(&state);
    let to_jid = CanonicalJid::parse(to)?;
    if to_jid.domainpart() == local_mix {
        let actor = authenticated_actor(from, authenticated_domain)?;
        let mutation = federated_mix_iq_is_mutation(&request);
        let request_digest: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
        let federated_mutation = mutation.then(|| FederatedMixMutation {
            authenticated_domain: authenticated_domain.to_owned(),
            actor_jid: actor.reply_to.clone(),
            request_id: request.id.clone(),
            request_digest,
            addressed: to_jid.to_string(),
            reply_to: actor.reply_to.clone(),
            policy: state.federation_outbox().outbox_policy(),
        });
        if mutation {
            match state
                .mix_service()
                .federated_mix_iq_replay(
                    authenticated_domain,
                    &actor.reply_to,
                    &request.id,
                    &request_digest,
                )
                .await?
            {
                FederatedMixIqReplay::Replay(response) => {
                    state
                        .mix_service()
                        .enqueue_s2s_response_batch(
                            authenticated_domain,
                            &[response],
                            state.federation_outbox().outbox_policy(),
                        )
                        .await?;
                    state.federation_outbox().wake_outbox();
                    return Ok(true);
                }
                FederatedMixIqReplay::Conflict => {
                    let response = iq_error_to(
                        &request.id,
                        &to_jid.to_string(),
                        &actor.reply_to,
                        "cancel",
                        "conflict",
                    );
                    state
                        .mix_service()
                        .enqueue_s2s_response_batch(
                            authenticated_domain,
                            &[response],
                            state.federation_outbox().outbox_policy(),
                        )
                        .await?;
                    state.federation_outbox().wake_outbox();
                    return Ok(true);
                }
                FederatedMixIqReplay::Miss => {}
            }
        }
        if matches!(
            request.operation,
            IqOperation::Mam(_)
                | IqOperation::MamForm
                | IqOperation::MamMetadata
                | IqOperation::MamError(_)
        ) {
            let responses = handle_mix_mam_iq(
                &state,
                &request,
                &actor.bare,
                &to_jid.to_string(),
                &actor.reply_to,
            )
            .await?;
            // A MAM response is one ordered result stream followed by one
            // terminal IQ. Admit every stanza into the durable S2S outbox in
            // one transaction so a quota/backend failure can never expose a
            // prefix without its `fin`, nor a `fin` without every result.
            let policy = state.federation_outbox().outbox_policy();
            if let Err(error) = state
                .mix_service()
                .enqueue_s2s_response_batch(authenticated_domain, &responses, policy)
                .await
            {
                tracing::warn!(
                    domain = authenticated_domain,
                    request_id = %request.id,
                    ?error,
                    "federated MIX MAM stream was rejected atomically"
                );
                let _ = state
                    .federation_outbox()
                    .send(
                        authenticated_domain,
                        iq_error_to(
                            &request.id,
                            &to_jid.to_string(),
                            &actor.reply_to,
                            "wait",
                            "remote-server-timeout",
                        ),
                        None,
                    )
                    .await;
                return Ok(true);
            }
            state.federation_outbox().wake_outbox();
            return Ok(true);
        }
        let response = match handle_channel_iq(
            &state,
            &request,
            &actor.bare,
            &to_jid.to_string(),
            &actor.reply_to,
            federated_mutation.as_ref(),
        )
        .await
        {
            Ok(response) => response,
            Err(error) if mutation => {
                // A process/task can fail after the mutation transaction has
                // atomically committed its exact result (for example while
                // performing a non-authoritative local projection). Recover
                // that result rather than reporting failure or re-executing.
                match state
                    .mix_service()
                    .federated_mix_iq_replay(
                        authenticated_domain,
                        &actor.reply_to,
                        &request.id,
                        &request_digest,
                    )
                    .await?
                {
                    FederatedMixIqReplay::Replay(_) => {
                        tracing::warn!(
                            domain = authenticated_domain,
                            request_id = %request.id,
                            ?error,
                            "recovered committed federated MIX mutation result"
                        );
                        state.federation_outbox().wake_outbox();
                        return Ok(true);
                    }
                    FederatedMixIqReplay::Conflict => {
                        let conflict = iq_error_to(
                            &request.id,
                            &to_jid.to_string(),
                            &actor.reply_to,
                            "cancel",
                            "conflict",
                        );
                        state
                            .mix_service()
                            .enqueue_s2s_response_batch(
                                authenticated_domain,
                                &[conflict],
                                state.federation_outbox().outbox_policy(),
                            )
                            .await?;
                        state.federation_outbox().wake_outbox();
                        return Ok(true);
                    }
                    FederatedMixIqReplay::Miss => return Err(error),
                }
            }
            Err(error) => return Err(error),
        };
        if mutation {
            match state
                .mix_service()
                .federated_mix_iq_replay(
                    authenticated_domain,
                    &actor.reply_to,
                    &request.id,
                    &request_digest,
                )
                .await?
            {
                FederatedMixIqReplay::Replay(journaled) => {
                    anyhow::ensure!(
                        journaled == response,
                        "atomic federated MIX result differs from protocol result"
                    );
                    state.federation_outbox().wake_outbox();
                }
                FederatedMixIqReplay::Conflict => {
                    let conflict = iq_error_to(
                        &request.id,
                        &to_jid.to_string(),
                        &actor.reply_to,
                        "cancel",
                        "conflict",
                    );
                    state
                        .mix_service()
                        .enqueue_s2s_response_batch(
                            authenticated_domain,
                            &[conflict],
                            state.federation_outbox().outbox_policy(),
                        )
                        .await?;
                    state.federation_outbox().wake_outbox();
                }
                FederatedMixIqReplay::Miss => {
                    let response_kind = Document::parse(&response).ok().and_then(|document| {
                        document.root_element().attribute("type").map(str::to_owned)
                    });
                    anyhow::ensure!(
                        response_kind.as_deref() == Some("error"),
                        "successful federated MIX mutation lacked atomic result admission"
                    );
                    match state
                        .mix_service()
                        .admit_federated_mix_iq_result(
                            authenticated_domain,
                            &actor.reply_to,
                            &request.id,
                            &request_digest,
                            &response,
                            state.federation_outbox().outbox_policy(),
                        )
                        .await?
                    {
                        FederatedMixIqReplay::Replay(_) => state.federation_outbox().wake_outbox(),
                        FederatedMixIqReplay::Conflict => {
                            anyhow::bail!("federated MIX error result raced a changed request")
                        }
                        FederatedMixIqReplay::Miss => {
                            anyhow::bail!("federated MIX error result admission lost its row")
                        }
                    }
                }
            }
        } else {
            let _ = state
                .federation_outbox()
                .send(authenticated_domain, response, None)
                .await;
        }
        return Ok(true);
    }
    if same_jid_domain(to_jid.domainpart(), state.local_domain())
        && matches!(request.kind.as_str(), "result" | "error")
    {
        let from_jid = CanonicalJid::parse_bare(from)?;
        anyhow::ensure!(
            authenticated_mix_service(from_jid.domainpart(), authenticated_domain),
            "forged federated MIX response"
        );
        if to_jid.resourcepart().is_some() || to_jid.localpart().is_none() {
            return Ok(false);
        }
        let response_digest: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
        let outcome = if request.kind == "result" {
            let join = parse_remote_pam_success(&raw, from)?;
            state
                .mix_service()
                .complete_remote_pam_success(
                    authenticated_domain,
                    from,
                    to,
                    &request.id,
                    &response_digest,
                    join.as_ref().map(|join| RemotePamJoin {
                        participant_id: &join.participant_id,
                        subscriptions: &join.subscriptions,
                        nick: join.nick.as_deref(),
                    }),
                )
                .await?
        } else {
            let remote_error = parse_remote_iq_error(&raw)?;
            state
                .mix_service()
                .complete_remote_pam_error(
                    authenticated_domain,
                    from,
                    to,
                    &request.id,
                    &response_digest,
                    &remote_error.error_type,
                    &remote_error.condition,
                )
                .await?
        };
        match outcome {
            RemotePamCompletionOutcome::Applied(completion) => {
                debug_assert!(completion.applied);
                debug_assert!(!completion.response_xml.is_empty());
                if let (Some(membership), Some(removed)) =
                    (completion.membership.as_ref(), completion.roster_removed)
                {
                    if let Some(user) = state
                        .mix_service()
                        .find_enabled_user_by_id(membership.user_id)
                        .await?
                    {
                        if let Err(error) =
                            push_mix_roster_update(&state, &user, &membership.channel_jid, removed)
                                .await
                        {
                            tracing::warn!(?error, channel=%membership.channel_jid, "post-commit PAM roster push failed");
                        }
                    }
                }
            }
            RemotePamCompletionOutcome::Replay(completion) => {
                debug_assert!(!completion.applied);
                debug_assert!(!completion.response_xml.is_empty());
            }
            RemotePamCompletionOutcome::Missing => {}
            RemotePamCompletionOutcome::Conflict => {
                tracing::warn!(request_id=%request.id, from, to, "ignored conflicting remote PAM result replay");
            }
        }
        return Ok(true);
    }
    Ok(false)
}

pub(super) async fn federated_mix_iq_relay(
    state: &Arc<AppState>,
    authenticated_domain: &str,
    request: RelayIq,
) -> Result<bool> {
    if request.from.is_empty() {
        return Ok(false);
    }
    if matches!(request.kind.as_str(), "result" | "error") {
        let Some(pending) = state.pending_mix_iq().get(&request.id) else {
            return Ok(false);
        };
        if pending.expires_at <= Instant::now() {
            if let Some(expired) = state.pending_mix_iq().remove(&request.id) {
                expire_mix_iq_relay(&state.mix_iq_relay_route(), expired).await;
            }
            return Ok(true);
        }
        match pending.stage {
            MixIqRelayStage::Participant {
                requester_full_jid,
                original_id,
                expected_from,
                channel_jid,
            } => {
                if request.from != expected_from || request.to != requester_full_jid {
                    return Ok(true);
                }
                let source_domain = CanonicalJid::parse(&request.from)?.domainpart().to_owned();
                anyhow::ensure!(
                    authenticated_mix_service(&source_domain, authenticated_domain),
                    "forged MIX IQ participant response"
                );
                let requester = crate::jid::CanonicalJid::parse(&requester_full_jid)?;
                let Some(username) = requester.localpart() else {
                    state.pending_mix_iq().remove(&request.id);
                    return Ok(true);
                };
                let Some(user) = state.mix_service().find_enabled_user(username).await? else {
                    state.pending_mix_iq().remove(&request.id);
                    return Ok(true);
                };
                if !state
                    .mix_service()
                    .pam_membership(user.id, &channel_jid)
                    .await?
                    .is_some_and(|membership| membership.state == "joined")
                    || state
                        .mix_service()
                        .is_blocked(user.id, &channel_jid)
                        .await?
                {
                    state.pending_mix_iq().remove(&request.id);
                    return Ok(true);
                }
                if state.pending_mix_iq().remove(&request.id).is_none() {
                    return Ok(true);
                }
                let stanza =
                    relay_iq_xml(&request, &original_id, &expected_from, &requester_full_jid);
                deliver_mix_relay_stanza(state, &requester_full_jid, stanza).await;
                return Ok(true);
            }
            MixIqRelayStage::Channel {
                requester_full_jid,
                requester_encoded_jid,
                original_id,
                target_real_jid,
                target_encoded_jid,
                channel_jid,
            } => {
                if request.from != target_real_jid || request.to != requester_encoded_jid {
                    return Ok(true);
                }
                let source_domain = CanonicalJid::parse(&request.from)?.domainpart().to_owned();
                anyhow::ensure!(
                    same_jid_domain(&source_domain, authenticated_domain),
                    "forged MIX IQ target response"
                );
                let local_mix = local_mix_domain(state);
                let channel_address = CanonicalJid::parse_bare(&channel_jid)?;
                let Some(channel_localpart) = channel_address.localpart() else {
                    state.pending_mix_iq().remove(&request.id);
                    return Ok(true);
                };
                let Some(channel) = state
                    .mix_service()
                    .mix_channel(&local_mix, channel_localpart)
                    .await?
                else {
                    state.pending_mix_iq().remove(&request.id);
                    return Ok(true);
                };
                if state
                    .mix_service()
                    .mix_participant(
                        channel.id,
                        &CanonicalJid::parse(&requester_full_jid)?.bare(),
                    )
                    .await?
                    .is_none()
                {
                    state.pending_mix_iq().remove(&request.id);
                    return Ok(true);
                }
                if state.pending_mix_iq().remove(&request.id).is_none() {
                    return Ok(true);
                }
                let stanza = relay_iq_xml(
                    &request,
                    &original_id,
                    &target_encoded_jid,
                    &requester_full_jid,
                );
                deliver_mix_relay_stanza(state, &requester_full_jid, stanza).await;
                return Ok(true);
            }
        }
    }
    if request.kind != "get" {
        return Ok(false);
    }

    let local_mix = local_mix_domain(state);
    let to = crate::jid::CanonicalJid::parse(&request.to)?;
    if to.domainpart() == local_mix && decode_participant_jid(&to.bare()).is_ok() {
        let actor = crate::jid::CanonicalJid::parse(&request.from)?;
        anyhow::ensure!(
            actor.resourcepart().is_some()
                && same_jid_domain(actor.domainpart(), authenticated_domain),
            "federated MIX IQ requester is not an authenticated full JID"
        );
        let response = handle_channel_relay_request(state, &request, &request.from).await?;
        if !response.is_empty() {
            let _ = state
                .federation_outbox()
                .send(authenticated_domain, response, None)
                .await;
        }
        return Ok(true);
    }

    if same_jid_domain(to.domainpart(), state.local_domain()) {
        let source = crate::jid::CanonicalJid::parse(&request.from)?;
        let (_source_id, channel_jid) = decode_participant_jid(&source.bare())?;
        anyhow::ensure!(
            authenticated_mix_service(source.domainpart(), authenticated_domain),
            "federated MIX IQ source service is not authenticated"
        );
        let Some(username) = to.localpart() else {
            return Ok(false);
        };
        let Some(user) = state.mix_service().find_enabled_user(username).await? else {
            let response = relay_error(
                &request.id,
                &request.to,
                &request.from,
                "cancel",
                "item-not-found",
            );
            let _ = state
                .federation_outbox()
                .send(authenticated_domain, response, None)
                .await;
            return Ok(true);
        };
        if !state
            .mix_service()
            .pam_membership(user.id, &channel_jid)
            .await?
            .is_some_and(|membership| membership.state == "joined")
            || state
                .mix_service()
                .is_blocked(user.id, &channel_jid)
                .await?
            || (to.resourcepart().is_some() && state.sessions_for(&request.to).is_empty())
        {
            let response =
                relay_error(&request.id, &request.to, &request.from, "auth", "forbidden");
            let _ = state
                .federation_outbox()
                .send(authenticated_domain, response, None)
                .await;
            return Ok(true);
        }
        let payload = relay_vcard_payload(
            state,
            &user,
            request.request.as_ref().context("missing relay request")?,
        )
        .await?;
        let response = match payload {
            Ok(payload) => iq_result_to(&request.id, &request.to, &request.from, &payload),
            Err(condition) => {
                relay_error(&request.id, &request.to, &request.from, "cancel", condition)
            }
        };
        let _ = state
            .federation_outbox()
            .send(authenticated_domain, response, None)
            .await;
        return Ok(true);
    }
    Ok(false)
}

pub(crate) async fn federated_mix_message(
    state: Arc<AppState>,
    authenticated_domain: &str,
    raw: String,
) -> Result<bool> {
    let (from, to, id, kind, encrypted, reflected_identity, reflected_stanza_id, validation_error) = {
        let document = Document::parse(&raw).context("malformed federated MIX message")?;
        let root = document.root_element();
        if root.tag_name().name() != "message" {
            return Ok(false);
        }
        let validation_error = state.validate_routed_message(root).err().map(|condition| {
            (
                crate::services::xml_util::stanza_error_type(condition),
                condition,
            )
        });
        (
            root.attribute("from").unwrap_or_default().to_owned(),
            root.attribute("to").unwrap_or_default().to_owned(),
            root.attribute("id").unwrap_or_default().to_owned(),
            root.attribute("type").unwrap_or("normal").to_owned(),
            is_encrypted(root),
            validate_reflected_mix_identity(root),
            reflected_mix_stanza_id(root),
            validation_error,
        )
    };
    let local_mix = local_mix_domain(&state);
    let to_jid = CanonicalJid::parse(&to)?;
    if let Some((error_type, condition)) = validation_error {
        if kind != "error" {
            let response = message_error(&id, &to, &from, error_type, condition);
            let _ = state
                .federation_outbox()
                .send(authenticated_domain, response, None)
                .await;
        }
        return Ok(true);
    }
    if to_jid.domainpart() == local_mix {
        let actor_full = authenticated_full_actor(&from, authenticated_domain)?;
        let actor_bare = crate::jid::CanonicalJid::parse(&actor_full)?.bare();
        if let Some(error) =
            process_channel_message(&state, &actor_bare, &actor_full, &raw, None).await?
        {
            let _ = state
                .federation_outbox()
                .send(authenticated_domain, error, None)
                .await;
        }
        return Ok(true);
    }
    if same_jid_domain(to_jid.domainpart(), state.local_domain()) {
        if kind != "groupchat" {
            return Ok(false);
        }
        reflected_identity?;
        let authoritative_stanza_id = reflected_stanza_id?;
        let from_jid = crate::jid::CanonicalJid::parse(&from)?;
        let participant_id = from_jid
            .resourcepart()
            .context("reflected MIX message requires a stable participant resource")?;
        anyhow::ensure!(
            crate::services::mix::valid_stable_participant_id(participant_id),
            "invalid reflected MIX stable participant id"
        );
        anyhow::ensure!(
            from_jid.localpart().is_some(),
            "reflected MIX message requires a channel localpart"
        );
        anyhow::ensure!(
            authenticated_mix_service(from_jid.domainpart(), authenticated_domain),
            "forged federated MIX channel message"
        );
        let channel = from_jid.bare();
        let to_jid = crate::jid::CanonicalJid::parse_bare(&to)?;
        let Some(username) = to_jid.localpart() else {
            return Ok(false);
        };
        let Some(user) = state.mix_service().find_enabled_user(username).await? else {
            return Ok(true);
        };
        if !state
            .mix_service()
            .pam_membership(user.id, &channel)
            .await?
            .is_some_and(|membership| pam_membership_receives(&membership, NODE_MESSAGES))
        {
            return Ok(true);
        }
        if state.mix_service().is_blocked(user.id, &channel).await? {
            return Ok(true);
        }
        let personal_archive_id = Uuid::new_v4();
        let source_stanza_id = authoritative_stanza_id.to_string();
        let admission = state
            .mix_service()
            .archive_mix_message_once(
                personal_archive_id,
                user.id,
                &channel,
                authoritative_stanza_id,
                &raw,
                encrypted,
                Some(&source_stanza_id),
            )
            .await?;
        if matches!(admission, SourceArchiveAdmission::Replay(_)) {
            return Ok(true);
        }
        for (jid, session) in state.session_entries_for(&to_jid.to_string()) {
            if session_mix_capability(&state, &jid) == MixSessionCapability::Supported {
                let _ = session.sender.try_send(raw.clone());
            }
        }
        return Ok(true);
    }
    Ok(false)
}

pub(crate) async fn federated_mix_presence(
    state: Arc<AppState>,
    authenticated_domain: &str,
    raw: String,
) -> Result<bool> {
    let (from, to, kind, reflected_identity) = {
        let document = Document::parse(&raw).context("malformed federated MIX presence")?;
        let root = document.root_element();
        if root.tag_name().name() != "presence" {
            return Ok(false);
        }
        (
            root.attribute("from").unwrap_or_default().to_owned(),
            root.attribute("to").unwrap_or_default().to_owned(),
            root.attribute("type").unwrap_or("available").to_owned(),
            validate_reflected_mix_presence_identity(root),
        )
    };
    let to_jid = CanonicalJid::parse(&to)?;
    if kind == "probe" && same_jid_domain(to_jid.domainpart(), state.local_domain()) {
        let channel = crate::jid::CanonicalJid::parse_bare(&from)?;
        anyhow::ensure!(
            channel.localpart().is_some()
                && authenticated_mix_service(channel.domainpart(), authenticated_domain),
            "forged federated MIX presence probe"
        );
        let target = crate::jid::CanonicalJid::parse_bare(&to)?;
        let Some(username) = target.localpart() else {
            return Ok(false);
        };
        let Some(user) = state.mix_service().find_enabled_user(username).await? else {
            return Ok(true);
        };
        if !state
            .mix_service()
            .pam_membership(user.id, &channel.to_string())
            .await?
            .is_some_and(|membership| pam_membership_receives(&membership, NODE_PRESENCE))
            || state
                .mix_service()
                .is_blocked(user.id, &channel.to_string())
                .await?
        {
            return Ok(true);
        }
        for (full_jid, session) in state.session_entries_for(&to) {
            if session.available.load(std::sync::atomic::Ordering::Relaxed)
                && session_mix_capability(&state, &full_jid) == MixSessionCapability::Supported
            {
                let response = XmlElement::namespaced("presence", "jabber:client")
                    .attr("from", &full_jid)
                    .attr("to", channel.to_string())
                    .finish();
                let _ = state
                    .federation_outbox()
                    .send(authenticated_domain, response, Some(to.clone()))
                    .await;
            }
        }
        return Ok(true);
    }
    let from_jid = crate::jid::CanonicalJid::parse(&from)?;
    let local_mix = local_mix_domain(&state);
    if to_jid.domainpart() == local_mix {
        if from_jid.resourcepart().is_none() {
            // A bare-JID presence to a channel is a state refresh request.
            // The participant server can obtain authoritative presence with
            // MAM/PubSub; silently accepting it as a publication would create
            // an unbounded ghost item.
            return Ok(true);
        }
        let actor = authenticated_full_actor(&from, authenticated_domain)?;
        let _ = presence_children(&raw)?;
        let actor_bare = crate::jid::CanonicalJid::parse(&actor)?.bare();
        if let Some(error) = process_channel_presence(&state, &actor_bare, &actor, &raw).await? {
            let _ = state
                .federation_outbox()
                .send(authenticated_domain, error, None)
                .await;
        }
        return Ok(true);
    }
    if same_jid_domain(to_jid.domainpart(), state.local_domain()) {
        anyhow::ensure!(
            authenticated_mix_service(from_jid.domainpart(), authenticated_domain),
            "federated MIX presence domain is not authenticated"
        );
        if kind == "error" {
            for (_, session) in state.session_entries_for(&to) {
                let _ = session.sender.try_send(raw.clone());
            }
            return Ok(true);
        }
        let _ = presence_children(&raw)?;
        if from_jid.resourcepart().is_none() {
            return Ok(false);
        }
        reflected_identity?;
        let (_participant_id, channel_jid) = decode_participant_jid(&from_jid.bare())?;
        let to_jid = crate::jid::CanonicalJid::parse_bare(&to)?;
        let Some(username) = to_jid.localpart() else {
            return Ok(false);
        };
        let Some(user) = state.mix_service().find_enabled_user(username).await? else {
            return Ok(true);
        };
        if !state
            .mix_service()
            .pam_membership(user.id, &channel_jid)
            .await?
            .is_some_and(|membership| pam_membership_receives(&membership, NODE_PRESENCE))
            || state
                .mix_service()
                .is_blocked(user.id, &channel_jid)
                .await?
        {
            return Ok(true);
        }
        for (jid, session) in state.session_entries_for(&to_jid.to_string()) {
            if session_mix_capability(&state, &jid) == MixSessionCapability::Supported {
                let _ = session.sender.try_send(raw.clone());
            }
        }
        return Ok(true);
    }
    Ok(false)
}
