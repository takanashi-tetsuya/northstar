use super::*;
use northstar_federation_core::S2sOutboxCapacityExceeded;
use northstar_room_application::mix_service::{
    FederatedMixIqAlreadyFinalized, FederatedMixIqConflict, MixMamAdmissionOutcome,
};

#[allow(clippy::needless_return)]
pub(super) async fn dispatch_disco_info(
    state: &Arc<impl MixHost>,
    authenticated_domain: &str,
    request: &MixDiscoInfoRequest,
) -> Result<bool> {
    let requester = authenticated_mix_disco_requester(&request.from, authenticated_domain)?;
    let response = federated_mix_disco_info(state, request, &requester).await?;
    let _ = state
        .federation_outbox()
        .send(authenticated_domain, response, None)
        .await;
    return Ok(true);
}

#[allow(clippy::needless_return)]
pub(super) async fn dispatch_mam(
    state: &Arc<impl MixHost>,
    authenticated_domain: &str,
    request: &OwnedIq,
    to_jid: &CanonicalJid,
    actor: AuthenticatedMixIqActor,
) -> Result<bool> {
    let addressed = to_jid.to_string();
    let reply = MixMamReply {
        request,
        addressed: &addressed,
        reply_to: &actor.reply_to,
    };
    let outbox = state.federation_outbox();
    let command = match reply.command(
        state.as_ref(),
        MixMamReadActor::Federated {
            bare_jid: actor.bare,
        },
    ) {
        Ok(command) => command,
        Err(response) => {
            let _ = outbox.send(authenticated_domain, response, None).await;
            return Ok(true);
        }
    };
    match state
        .mix_service()
        .admit_federated_mix_mam(
            command,
            authenticated_domain,
            outbox.outbox_policy(),
            |outcome| reply.render(outcome),
        )
        .await?
    {
        MixMamAdmissionOutcome::Queued => outbox.wake_outbox(),
        MixMamAdmissionOutcome::OutboxRejected(error) => {
            tracing::warn!(
                domain = authenticated_domain,
                request_id = %request.id,
                ?error,
                "federated MIX MAM stream was rejected atomically"
            );
            if error.downcast_ref::<S2sOutboxCapacityExceeded>().is_none() {
                let _ = outbox
                    .send(
                        authenticated_domain,
                        iq_error_to(
                            &request.id,
                            &addressed,
                            &actor.reply_to,
                            "wait",
                            "remote-server-timeout",
                        ),
                        None,
                    )
                    .await;
            }
        }
    }
    return Ok(true);
}

#[allow(clippy::needless_return)]
pub(super) async fn dispatch_channel_iq(
    state: &Arc<impl MixHost>,
    authenticated_domain: &str,
    raw: &str,
    request: &OwnedIq,
    to_jid: &CanonicalJid,
    actor: AuthenticatedMixIqActor,
) -> Result<bool> {
    let mutation = federated_mix_iq_is_mutation(request);
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
                enqueue_result(state, authenticated_domain, response).await?;
                return Ok(true);
            }
            FederatedMixIqReplay::Conflict => {
                send_conflict(state, authenticated_domain, request, to_jid, &actor).await?;
                return Ok(true);
            }
            FederatedMixIqReplay::Miss => {}
        }
    }
    let response = match handle_channel_iq(
        state,
        request,
        &actor.bare,
        &to_jid.to_string(),
        &actor.reply_to,
        federated_mutation.as_ref(),
    )
    .await
    {
        Ok(response) => response,
        Err(error) if admission_conflict(&error) == Some(FederatedMixIqReplay::Conflict) => {
            send_conflict(state, authenticated_domain, request, to_jid, &actor).await?;
            return Ok(true);
        }
        Err(error) if mutation => {
            if let Some(replay) = error.downcast_ref::<FederatedMixIqAlreadyFinalized>() {
                enqueue_result(state, authenticated_domain, replay.response().to_owned()).await?;
                return Ok(true);
            }
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
                    send_conflict(state, authenticated_domain, request, to_jid, &actor).await?;
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
                send_conflict(state, authenticated_domain, request, to_jid, &actor).await?;
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
                        send_conflict(state, authenticated_domain, request, to_jid, &actor).await?;
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

fn admission_conflict(error: &anyhow::Error) -> Option<FederatedMixIqReplay> {
    error
        .is::<FederatedMixIqConflict>()
        .then_some(FederatedMixIqReplay::Conflict)
}

async fn send_conflict(
    state: &Arc<impl MixHost>,
    authenticated_domain: &str,
    request: &OwnedIq,
    to_jid: &CanonicalJid,
    actor: &AuthenticatedMixIqActor,
) -> Result<()> {
    enqueue_result(
        state,
        authenticated_domain,
        conflict_response(request, to_jid, actor),
    )
    .await
}

async fn enqueue_result(
    state: &Arc<impl MixHost>,
    authenticated_domain: &str,
    response: String,
) -> Result<()> {
    state
        .mix_service()
        .enqueue_s2s_response_batch(
            authenticated_domain,
            &[response],
            state.federation_outbox().outbox_policy(),
        )
        .await?;
    state.federation_outbox().wake_outbox();
    Ok(())
}

fn conflict_response(
    request: &OwnedIq,
    to_jid: &CanonicalJid,
    actor: &AuthenticatedMixIqActor,
) -> String {
    iq_error_to(
        &request.id,
        &to_jid.to_string(),
        &actor.reply_to,
        "cancel",
        "conflict",
    )
}

#[cfg(test)]
mod tests;
