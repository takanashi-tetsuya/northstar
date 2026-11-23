//! Federated MIX: authenticated remote actors, disco#info, IQs, IQ relay, messages and presence.

use super::relay::relay_profile_reply;
use super::*;
use northstar_room_application::mix_service::{
    MixRelayProfileDenial, MixRelayProfileQuery, MixRelayProfileRequester, MixRelayProfileResult,
};

mod disco;
mod iq_dispatch;
mod pam_completion;
mod pam_ingress;
mod reflected_retraction;
mod relay_result;

pub use self::disco::federated_mix_disco_info;

#[derive(Debug, Eq, PartialEq)]
pub struct AuthenticatedMixIqActor {
    pub bare: String,
    pub reply_to: String,
}

pub fn authenticated_actor(
    from: &str,
    authenticated_domain: &str,
) -> Result<AuthenticatedMixIqActor> {
    let actor = northstar_xmpp_types::jid::CanonicalJid::parse(from)?;
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

pub fn authenticated_mix_disco_requester(
    from: &str,
    authenticated_domain: &str,
) -> Result<AuthenticatedMixIqActor> {
    let actor = northstar_xmpp_types::jid::CanonicalJid::parse(from)?;
    anyhow::ensure!(
        same_jid_domain(actor.domainpart(), authenticated_domain),
        "federated MIX disco requester domain is not authenticated"
    );
    Ok(AuthenticatedMixIqActor {
        bare: actor.bare(),
        reply_to: actor.to_string(),
    })
}

pub fn authenticated_full_actor(from: &str, authenticated_domain: &str) -> Result<String> {
    let actor = northstar_xmpp_types::jid::CanonicalJid::parse(from)?;
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

pub fn authenticated_mix_service(asserted_domain: &str, authenticated_domain: &str) -> bool {
    let Ok(authenticated_domain) = prepare_domainpart(authenticated_domain) else {
        return false;
    };
    prepare_domainpart(asserted_domain)
        .is_ok_and(|asserted| same_jid_domain(&asserted, &authenticated_domain))
}

pub fn pam_membership_receives(membership: &PamMembership, node: &str) -> bool {
    membership.state == "joined"
        && membership
            .subscriptions
            .iter()
            .any(|subscription| subscription == node)
}

pub fn federated_mix_iq_is_mutation(request: &OwnedIq) -> bool {
    !is_mix_mam_request(request)
        && (request.kind == "set" || matches!(&request.operation, IqOperation::Invite { .. }))
}

/// S2S entry point.  The S2S layer must call this only after authenticating
/// `authenticated_domain`; the function independently verifies the stanza's
/// asserted `from` before creating or mutating a remote participant actor.
pub async fn federated_mix_iq(
    state: Arc<impl MixHost>,
    authenticated_domain: &str,
    raw: String,
) -> Result<bool> {
    if let Some(request) = parse_relay_iq(&raw)? {
        if federated_mix_iq_relay(&state, authenticated_domain, request).await? {
            return Ok(true);
        }
    }
    if let Some(request) = parse_mix_disco_info(&raw)? {
        return iq_dispatch::dispatch_disco_info(&state, authenticated_domain, &request).await;
    }
    let Some(request) = parse_iq(&raw)? else {
        return Ok(false);
    };
    let from = request.from.as_deref().unwrap_or_default();
    let to = request.to.as_deref().unwrap_or_default();
    let local_mix = local_mix_domain(state.local_domain());
    let to_jid = CanonicalJid::parse(to)?;
    if to_jid.domainpart() == local_mix {
        let actor = authenticated_actor(from, authenticated_domain)?;
        if is_mix_mam_request(&request) {
            return iq_dispatch::dispatch_mam(
                &state,
                authenticated_domain,
                &request,
                &to_jid,
                actor,
            )
            .await;
        }
        return iq_dispatch::dispatch_channel_iq(
            &state,
            authenticated_domain,
            &raw,
            &request,
            &to_jid,
            actor,
        )
        .await;
    }
    if same_jid_domain(to_jid.domainpart(), state.local_domain())
        && matches!(request.kind.as_str(), "result" | "error")
    {
        return pam_completion::complete_pam_response(
            &state,
            authenticated_domain,
            &raw,
            &request,
            from,
            to,
            &to_jid,
        )
        .await;
    }
    Ok(false)
}

pub async fn federated_mix_iq_relay(
    state: &Arc<impl MixHost>,
    authenticated_domain: &str,
    request: RelayIq,
) -> Result<bool> {
    if request.from.is_empty() {
        return Ok(false);
    }
    if matches!(request.kind.as_str(), "result" | "error") {
        return relay_result::handle_relay_result(state, authenticated_domain, &request).await;
    }
    if request.kind != "get" {
        return Ok(false);
    }

    let local_mix = local_mix_domain(state.local_domain());
    let to = northstar_xmpp_types::jid::CanonicalJid::parse(&request.to)?;
    if to.domainpart() == local_mix && decode_participant_jid(&to.bare()).is_ok() {
        let actor = northstar_xmpp_types::jid::CanonicalJid::parse(&request.from)?;
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
        let source = northstar_xmpp_types::jid::CanonicalJid::parse(&request.from)?;
        let (_source_id, channel_jid) = decode_participant_jid(&source.bare())?;
        anyhow::ensure!(
            authenticated_mix_service(source.domainpart(), authenticated_domain),
            "federated MIX IQ source service is not authenticated"
        );
        if to.localpart().is_none() {
            return Ok(false);
        }
        let target_has_resource = to.resourcepart().is_some();
        let mut result = state
            .mix_service()
            .relay_profile_snapshot(MixRelayProfileQuery {
                channel: CanonicalJid::parse_bare(&channel_jid)?,
                requester: MixRelayProfileRequester::FederatedPam {
                    authenticated_service: authenticated_domain.to_owned(),
                },
                target: to,
                kind: request.request.context("missing relay request")?,
            })
            .await?;
        // Resource availability takes precedence over a missing profile for an admitted target.
        if !matches!(
            &result,
            MixRelayProfileResult::Denied(_) | MixRelayProfileResult::TargetMissing
        ) && target_has_resource
            && state.sessions_for(&request.to).is_empty()
        {
            result = MixRelayProfileResult::Denied(MixRelayProfileDenial::Forbidden);
        }
        let response = relay_profile_reply(&request.id, &request.to, &request.from, result)?;
        let _ = state
            .federation_outbox()
            .send(authenticated_domain, response, None)
            .await;
        return Ok(true);
    }
    Ok(false)
}

pub async fn federated_mix_message(
    state: Arc<impl MixHost>,
    authenticated_domain: &str,
    raw: String,
) -> Result<bool> {
    let local_mix = local_mix_domain(state.local_domain());
    let (
        from,
        to,
        id,
        kind,
        encrypted,
        reflected_identity,
        reflected_stanza_id,
        validation_error,
        claims_retraction,
        verified_target,
    ) = {
        let document = Document::parse(&raw).context("malformed federated MIX message")?;
        let root = document.root_element();
        if root.tag_name().name() != "message" {
            return Ok(false);
        }
        let validation_error = state.validate_routed_message(root).err().map(|condition| {
            (
                northstar_xml_builder::stanza::stanza_error_type(condition),
                condition,
            )
        });
        let reflected_stanza_id = reflected_mix_stanza_id(root);
        let claims_retraction = reflected_retraction::claims_retraction(root);
        let verified_target = if claims_retraction {
            reflected_stanza_id.as_ref().ok().and_then(|&action| {
                reflected_retraction::verified_target(
                    root,
                    action,
                    &local_mix,
                    authenticated_domain,
                )
            })
        } else {
            None
        };
        (
            root.attribute("from").unwrap_or_default().to_owned(),
            root.attribute("to").unwrap_or_default().to_owned(),
            root.attribute("id").unwrap_or_default().to_owned(),
            root.attribute("type").unwrap_or("normal").to_owned(),
            is_encrypted(root),
            validate_reflected_mix_identity(root),
            reflected_stanza_id,
            validation_error,
            claims_retraction,
            verified_target,
        )
    };
    let to_jid = CanonicalJid::parse(&to)?;
    let local_recipient = same_jid_domain(to_jid.domainpart(), state.local_domain());
    if local_recipient
        && claims_retraction
        && (verified_target.is_none() || reflected_identity.is_err() || validation_error.is_some())
    {
        return Ok(true);
    }
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
        let actor_bare = northstar_xmpp_types::jid::CanonicalJid::parse(&actor_full)?.bare();
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
    if local_recipient {
        return pam_ingress::admit_reflected_message(
            &state,
            authenticated_domain,
            raw,
            &from,
            &to,
            &kind,
            encrypted,
            reflected_identity,
            reflected_stanza_id,
            verified_target,
        )
        .await;
    }
    Ok(false)
}

pub async fn federated_mix_presence(
    state: Arc<impl MixHost>,
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
        let channel = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&from)?;
        anyhow::ensure!(
            channel.localpart().is_some()
                && authenticated_mix_service(channel.domainpart(), authenticated_domain),
            "forged federated MIX presence probe"
        );
        let target = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&to)?;
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
            if session.is_available()
                && state.session_mix_capability(&full_jid) == MixSessionCapability::Supported
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
    let from_jid = northstar_xmpp_types::jid::CanonicalJid::parse(&from)?;
    let local_mix = local_mix_domain(state.local_domain());
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
        let actor_bare = northstar_xmpp_types::jid::CanonicalJid::parse(&actor)?.bare();
        if let Some(error) = process_channel_presence(&state, &actor_bare, &actor, &raw).await? {
            let _ = state
                .federation_outbox()
                .send(authenticated_domain, error, None)
                .await;
        }
        return Ok(true);
    }
    if same_jid_domain(to_jid.domainpart(), state.local_domain()) {
        return pam_ingress::handle_reflected_presence(
            &state,
            authenticated_domain,
            raw,
            &from_jid,
            &to,
            &kind,
            reflected_identity,
        )
        .await;
    }
    Ok(false)
}
