//! Channel IQ handling: join, leave, nick, configuration and administration.

use super::*;

mod create;
mod destroy;
mod invitation;
mod membership;
mod preference;

pub fn join_error(id: &str, from: &str, to: &str, outcome: JoinChannelOutcome) -> String {
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

pub async fn handle_channel_iq(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    actor_bare: &str,
    addressed: &str,
    reply_to: &str,
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    let mix_domain = local_mix_domain(state.local_domain());
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
                create::create_channel(
                    state,
                    request,
                    &mix_domain,
                    channel,
                    actor_bare,
                    reply_to,
                    federated,
                )
                .await
            }
            IqOperation::Destroy { channel } if request.kind == "set" => {
                destroy::destroy_channel(
                    state,
                    request,
                    &mix_domain,
                    channel,
                    actor_bare,
                    reply_to,
                    federated,
                )
                .await
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
            membership::join_channel(
                state, request, &channel, actor_bare, reply_to, join, federated,
            )
            .await
        }
        IqOperation::Leave if request.kind == "set" => {
            membership::leave_channel(state, request, &channel, actor_bare, reply_to, federated)
                .await
        }
        IqOperation::SetNick(nick) if request.kind == "set" => {
            membership::set_nick(
                state, request, &channel, actor_bare, reply_to, nick, federated,
            )
            .await
        }
        IqOperation::UpdateSubscription {
            subscribe,
            unsubscribe,
        } if request.kind == "set" => {
            membership::update_subscription(
                state,
                request,
                &channel,
                actor_bare,
                reply_to,
                subscribe,
                unsubscribe,
                federated,
            )
            .await
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
            preference::get_user_preference(state, request, &channel, actor_bare, reply_to).await
        }
        IqOperation::UserPreferenceSet(fields) if request.kind == "set" => {
            preference::set_user_preference(
                state, request, &channel, actor_bare, reply_to, fields, federated,
            )
            .await
        }
        IqOperation::IssueMixInvitation { invitee } => {
            invitation::invite(
                state,
                request,
                &channel,
                actor_bare,
                reply_to,
                invitee
                    .as_ref()
                    .context("MIX participants require a user bare JID")?,
                federated,
            )
            .await
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
