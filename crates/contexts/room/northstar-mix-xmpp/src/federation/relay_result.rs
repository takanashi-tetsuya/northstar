use super::*;

#[allow(clippy::needless_return)]
pub(super) async fn handle_relay_result(
    state: &Arc<impl MixHost>,
    authenticated_domain: &str,
    request: &RelayIq,
) -> Result<bool> {
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
            let requester = northstar_xmpp_types::jid::CanonicalJid::parse(&requester_full_jid)?;
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
            let stanza = relay_iq_xml(request, &original_id, &expected_from, &requester_full_jid);
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
            let local_mix = local_mix_domain(state.local_domain());
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
                request,
                &original_id,
                &target_encoded_jid,
                &requester_full_jid,
            );
            deliver_mix_relay_stanza(state, &requester_full_jid, stanza).await;
            return Ok(true);
        }
    }
}
