use super::*;
use northstar_room_application::mix_service::{CommittedMixChange, RemotePamResponse};
use northstar_room_core::mix::{MixChannelAddress, MixRealJid};

mod join_evidence;

pub(super) async fn complete_pam_response(
    state: &Arc<impl MixHost>,
    authenticated_domain: &str,
    raw: &str,
    request: &OwnedIq,
    from: &str,
    to: &str,
    to_jid: &CanonicalJid,
) -> Result<bool> {
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
        let channel = MixChannelAddress::parse(from)?;
        let recipient = MixRealJid::parse(to)?;
        let join = join_evidence::parse_join_evidence(raw, &channel)?;
        state
            .mix_service()
            .complete_remote_pam_success_committed(
                RemotePamResponse {
                    authenticated_domain,
                    channel: &channel,
                    recipient: &recipient,
                    request_id: &request.id,
                    digest: &response_digest,
                },
                join.as_ref().map(join_evidence::ParsedJoin::evidence),
            )
            .await?
    } else {
        let remote_error = parse_remote_iq_error(raw)?;
        let outcome = state
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
            .await?;
        CommittedMixChange {
            outcome,
            roster: Vec::new(),
        }
    };
    match outcome.outcome {
        RemotePamCompletionOutcome::Applied(completion) => {
            debug_assert!(completion.applied);
            debug_assert!(!completion.response_xml.is_empty());
            for delta in &outcome.roster {
                if let Err(error) = push_mix_roster_update(state, delta).await {
                    tracing::warn!(?error, channel=%delta.change.contact_jid, "post-commit PAM roster push failed");
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
    Ok(true)
}

#[cfg(test)]
mod tests;
