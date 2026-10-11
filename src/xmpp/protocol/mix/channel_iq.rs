//! Channel IQ handling: join, leave, nick, configuration and administration.

use super::*;

pub(super) fn join_error(id: &str, from: &str, to: &str, outcome: JoinChannelOutcome) -> String {
    let (kind, condition) = match outcome {
        JoinChannelOutcome::Banned => ("auth", "forbidden"),
        JoinChannelOutcome::NotAllowed => ("auth", "registration-required"),
        JoinChannelOutcome::Full => ("wait", "resource-constraint"),
        JoinChannelOutcome::MissingNick => ("modify", "not-acceptable"),
        JoinChannelOutcome::NickConflict => ("cancel", "conflict"),
        JoinChannelOutcome::Joined { .. } => unreachable!(),
    };
    iq_error_to(id, from, to, kind, condition)
}

pub(super) async fn handle_channel_iq(
    state: &Arc<AppState>,
    request: &OwnedIq,
    actor_bare: &str,
    addressed: &str,
    reply_to: &str,
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    let mix_domain = local_mix_domain(state);
    let target = match CanonicalJid::parse_bare(addressed) {
        Ok(target) => target,
        Err(_) => {
            return Ok(iq_error_to(
                &request.id,
                addressed,
                reply_to,
                "modify",
                "jid-malformed",
            ));
        }
    };
    let target_bare = target.to_string();
    let service_request = target.localpart().is_none() && target.domainpart() == mix_domain;
    if service_request {
        return match &request.operation {
            IqOperation::Create { channel } if request.kind == "set" => {
                match state
                    .mix_service()
                    .create_mix_channel(
                        &mix_domain,
                        channel.as_deref(),
                        actor_bare,
                        MAX_CHANNELS_PER_OWNER,
                        federated,
                    )
                    .await?
                {
                    (CreateChannelOutcome::Created(_), localpart) => {
                        let _ = super::super::mix_muc::maybe_link_local_mirror(
                            state, &localpart, actor_bare,
                        )
                        .await?;
                        let payload = XmlElement::namespaced("create", CORE_NS)
                            .attr("channel", &localpart)
                            .finish();
                        Ok(iq_result_to(&request.id, &mix_domain, reply_to, &payload))
                    }
                    (CreateChannelOutcome::Conflict, _) => Ok(iq_error_to(
                        &request.id,
                        &mix_domain,
                        reply_to,
                        "cancel",
                        "conflict",
                    )),
                    (CreateChannelOutcome::QuotaExceeded, _) => Ok(iq_error_to(
                        &request.id,
                        &mix_domain,
                        reply_to,
                        "wait",
                        "resource-constraint",
                    )),
                }
            }
            IqOperation::Destroy { channel } if request.kind == "set" => {
                let Some(channel) = state
                    .mix_service()
                    .mix_channel(&mix_domain, channel)
                    .await?
                else {
                    return Ok(iq_error_to(
                        &request.id,
                        &mix_domain,
                        reply_to,
                        "cancel",
                        "item-not-found",
                    ));
                };
                let local_users = state
                    .mix_service()
                    .local_pam_users_for_channel(&channel.jid())
                    .await?;
                if state
                    .mix_service()
                    .destroy_mix_channel(channel.id, actor_bare, federated)
                    .await?
                {
                    for user_id in local_users {
                        if let Some(user) =
                            state.mix_service().find_enabled_user_by_id(user_id).await?
                        {
                            push_mix_roster_update(state, &user, &channel.jid(), true).await?;
                        }
                    }
                    let payload = XmlElement::namespaced("destroy", CORE_NS)
                        .attr("channel", &channel.localpart)
                        .finish();
                    Ok(iq_result_to(&request.id, &mix_domain, reply_to, &payload))
                } else {
                    Ok(iq_error_to(
                        &request.id,
                        &mix_domain,
                        reply_to,
                        "auth",
                        "forbidden",
                    ))
                }
            }
            IqOperation::Ping
                if request.kind == "get"
                    && !state.xmpp_extension_enabled(northstar_xep_0199::XEP_ID) =>
            {
                Ok(iq_error_to(
                    &request.id,
                    &mix_domain,
                    reply_to,
                    "cancel",
                    "service-unavailable",
                ))
            }
            IqOperation::Ping if request.kind == "get" => {
                Ok(iq_result_to(&request.id, &mix_domain, reply_to, ""))
            }
            IqOperation::RegisterNick(requested) if request.kind == "set" => {
                let nick = requested
                    .clone()
                    .unwrap_or_else(|| Uuid::new_v4().to_string());
                match state
                    .mix_service()
                    .register_mix_nick(&mix_domain, actor_bare, &nick, federated)
                    .await?
                {
                    RegisterMixNickOutcome::Registered { nick: assigned } => {
                        let payload = XmlElement::namespaced("register", MISC_NS)
                            .child(XmlElement::new("nick").text(assigned))
                            .finish();
                        Ok(iq_result_to(&request.id, &mix_domain, reply_to, &payload))
                    }
                    RegisterMixNickOutcome::Conflict => Ok(iq_error_to(
                        &request.id,
                        &mix_domain,
                        reply_to,
                        "cancel",
                        "conflict",
                    )),
                }
            }
            _ => Ok(iq_error_to(
                &request.id,
                &mix_domain,
                reply_to,
                "cancel",
                "service-unavailable",
            )),
        };
    }
    let Some(channel_localpart) = target.localpart() else {
        return Ok(iq_error_to(
            &request.id,
            &target_bare,
            reply_to,
            "modify",
            "jid-malformed",
        ));
    };
    if target.domainpart() != mix_domain {
        return Ok(iq_error_to(
            &request.id,
            &target_bare,
            reply_to,
            "cancel",
            "item-not-found",
        ));
    }
    let Some(channel) = state
        .mix_service()
        .mix_channel(target.domainpart(), channel_localpart)
        .await?
    else {
        return Ok(iq_error_to(
            &request.id,
            &target_bare,
            reply_to,
            "cancel",
            "item-not-found",
        ));
    };
    match &request.operation {
        IqOperation::Join(join) if request.kind == "set" => {
            if federated.is_none()
                && request
                    .from
                    .as_deref()
                    .is_some_and(|from| from.contains('/'))
            {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "not-authorized",
                ));
            }
            match state
                .mix_service()
                .join_mix_channel(
                    channel.id,
                    JoinMixRequest {
                        actor_jid: actor_bare.to_owned(),
                        nick: join.nick.clone(),
                        nodes: join.nodes.clone(),
                        pam_user_id: None,
                        invitation: join.invitation.clone(),
                        preference: join.preference.clone(),
                        anonymous_profile: join.anonymous_profile,
                    },
                    federated,
                )
                .await?
            {
                JoinChannelOutcome::Joined {
                    participant,
                    preference,
                    subscriptions,
                    ..
                } => Ok(iq_result_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    &core_join_payload(
                        &participant,
                        &subscriptions,
                        join.preference.as_ref().map(|_| &preference),
                        join.anonymous_profile,
                    )?,
                )),
                outcome => Ok(join_error(&request.id, &channel.jid(), reply_to, outcome)),
            }
        }
        IqOperation::Leave if request.kind == "set" => {
            let Some(left) = state
                .mix_service()
                .leave_mix_channel(channel.id, actor_bare, None, federated)
                .await?
            else {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "cancel",
                    "item-not-found",
                ));
            };
            let _ = left;
            let payload = XmlElement::namespaced("leave", CORE_NS).finish();
            Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &payload,
            ))
        }
        IqOperation::SetNick(nick) if request.kind == "set" => {
            match state
                .mix_service()
                .set_mix_nick(channel.id, actor_bare, nick, federated)
                .await?
            {
                Ok(participant) => {
                    let payload = XmlElement::namespaced("setnick", CORE_NS)
                        .child(
                            XmlElement::new("nick")
                                .text(participant.nick.clone().unwrap_or_default()),
                        )
                        .finish();
                    Ok(iq_result_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        &payload,
                    ))
                }
                Err(SetNickError::NotParticipant) => Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                )),
                Err(SetNickError::Conflict) => Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "cancel",
                    "conflict",
                )),
            }
        }
        IqOperation::UpdateSubscription {
            subscribe,
            unsubscribe,
        } if request.kind == "set" => {
            let Some(outcome) = state
                .mix_service()
                .update_mix_subscriptions(channel.id, actor_bare, subscribe, unsubscribe, federated)
                .await?
            else {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            };
            let mut update = XmlElement::namespaced("update-subscription", CORE_NS);
            for node in &outcome.subscriptions {
                update.push_child(XmlElement::new("subscribe").attr("node", node));
            }
            Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &update.finish(),
            ))
        }
        IqOperation::PubSubGet { node, max } if request.kind == "get" => {
            pubsub_get(state, request, &channel, actor_bare, reply_to, node, *max).await
        }
        IqOperation::PubSubPublish {
            node,
            item_count,
            item_ids,
            fields,
            payloads,
        } if request.kind == "set" => {
            pubsub_publish(
                state,
                request,
                &channel,
                actor_bare,
                reply_to,
                node,
                *item_count,
                item_ids,
                fields,
                payloads,
                federated,
            )
            .await
        }
        IqOperation::PubSubRetract { node, item_ids } if request.kind == "set" => {
            pubsub_retract(
                state,
                PubSubRetractRequest {
                    request,
                    channel: &channel,
                    actor: actor_bare,
                    reply_to,
                    node,
                    item_ids,
                    federated,
                },
            )
            .await
        }
        IqOperation::Ping
            if request.kind == "get"
                && !state.xmpp_extension_enabled(northstar_xep_0199::XEP_ID) =>
        {
            Ok(iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "cancel",
                "service-unavailable",
            ))
        }
        IqOperation::Ping if request.kind == "get" => {
            Ok(iq_result_to(&request.id, &channel.jid(), reply_to, ""))
        }
        IqOperation::UserPreferenceGet if request.kind == "get" => {
            if state
                .mix_service()
                .mix_participant_preference(channel.id, actor_bare)
                .await?
                .is_none()
            {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            }
            let payload = XmlElement::namespaced("user-preference", ANON_NS)
                .validated_fragment(&preference_template_form())?
                .finish();
            Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &payload,
            ))
        }
        IqOperation::UserPreferenceSet(fields) if request.kind == "set" => {
            let current = state
                .mix_service()
                .mix_participant_preference(channel.id, actor_bare)
                .await?
                .unwrap_or_default();
            let preference = parse_preference_submission(fields, Some(&current))?;
            let Some(outcome) = state
                .mix_service()
                .update_mix_participant_preference(channel.id, actor_bare, &preference, federated)
                .await?
            else {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "modify",
                    "not-acceptable",
                ));
            };
            for (user_id, change) in &outcome.roster_changes {
                if let Some(user) = state
                    .mix_service()
                    .find_enabled_user_by_id(*user_id)
                    .await?
                {
                    super::super::roster::deliver_roster_change(
                        state,
                        *user_id,
                        &user.username,
                        change,
                        Some(&outcome.participant.participant_id.to_string()),
                    )
                    .await?;
                }
            }
            let preference_payload = XmlElement::namespaced("user-preference", ANON_NS)
                .validated_fragment(&preference_result_form(&preference))?
                .finish();
            Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &preference_payload,
            ))
        }
        IqOperation::Invite { invitee } if request.kind == "get" => {
            let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            if !state
                .mix_service()
                .issue_mix_invitation(
                    channel.id,
                    actor_bare,
                    invitee,
                    &token,
                    chrono::Duration::hours(1),
                    federated,
                )
                .await?
            {
                return Ok(iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                ));
            }
            let payload = XmlElement::namespaced("invite", MISC_NS)
                .child(
                    XmlElement::new("invitation")
                        .child(XmlElement::new("inviter").text(actor_bare.to_owned()))
                        .child(XmlElement::new("invitee").text(invitee.to_owned()))
                        .child(XmlElement::new("channel").text(channel.jid()))
                        .child(XmlElement::new("token").text(token)),
                )
                .finish();
            Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &payload,
            ))
        }
        _ => Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "cancel",
            "feature-not-implemented",
        )),
    }
}
