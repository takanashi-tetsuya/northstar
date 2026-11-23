use super::*;
use northstar_room_core::mix_iq_relay::ResponseTake;

pub(super) async fn handle_relay_result(
    state: &Arc<impl MixHost>,
    authenticated_domain: &str,
    request: &RelayIq,
) -> Result<bool> {
    let index = state.pending_mix_iq();
    let Some(pending) = index.get(&request.id) else {
        return Ok(false);
    };
    let stanza = if pending.expires_at <= index.now() {
        None
    } else {
        Some(match &pending.stage {
            MixIqRelayStage::Participant {
                requester_full_jid,
                original_id,
                expected_from,
                ..
            } => {
                if request.from != *expected_from || request.to != *requester_full_jid {
                    return Ok(true);
                }
                let source = CanonicalJid::parse(&request.from)?;
                anyhow::ensure!(
                    authenticated_mix_service(source.domainpart(), authenticated_domain),
                    "forged MIX IQ participant response"
                );
                relay_iq_xml(request, original_id, expected_from, requester_full_jid)
            }
            MixIqRelayStage::Channel {
                requester_full_jid,
                requester_encoded_jid,
                original_id,
                target_real_jid,
                target_encoded_jid,
                ..
            } => {
                if request.from != *target_real_jid || request.to != *requester_encoded_jid {
                    return Ok(true);
                }
                let source = CanonicalJid::parse(&request.from)?;
                anyhow::ensure!(
                    same_jid_domain(source.domainpart(), authenticated_domain),
                    "forged MIX IQ target response"
                );
                relay_iq_xml(request, original_id, target_encoded_jid, requester_full_jid)
            }
        })
    };
    let Some(authority) = &pending.return_authority else {
        return Ok(true);
    };
    let current = state
        .mix_service()
        .relay_return_is_current(authority)
        .await?;
    match index.take_response(&request.id, &pending, index.now()) {
        ResponseTake::Response(_) if current => {
            if let Some(stanza) = stanza {
                state
                    .mix_iq_relay_route()
                    .deliver_return(&authority.exact_route, stanza)
                    .await;
            }
        }
        ResponseTake::Expired(expired) if current => {
            expire_mix_iq_relay(&state.mix_iq_relay_route(), expired).await;
        }
        _ => {}
    }
    Ok(true)
}
