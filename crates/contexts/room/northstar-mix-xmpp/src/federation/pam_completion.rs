use super::*;

#[allow(clippy::needless_return)]
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
        let join = parse_remote_pam_success(raw, from)?;
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
        let remote_error = parse_remote_iq_error(raw)?;
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
                        push_mix_roster_update(state, &user, &membership.channel_jid, removed).await
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
