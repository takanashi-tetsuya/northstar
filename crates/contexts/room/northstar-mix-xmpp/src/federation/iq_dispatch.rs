use super::*;
use northstar_federation_core::S2sOutboxCapacityExceeded;
use northstar_room_application::mix_service::MixMamAdmissionOutcome;

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
