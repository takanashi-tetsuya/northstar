use super::*;

mod acknowledge;
mod delivery;
mod delivery_send;
mod envelope;
mod muc;
mod presence;
mod receive;
mod responses;
mod session;

use self::acknowledge::{acknowledge_listener_command, ListenerAckContext};
use self::envelope::{ListenerCommand, ListenerCommandFlags, VerifiedListenerEnvelope};
use self::receive::{
    ListenerInput, ListenerInputContext, ListenerSubscription, ReceivedListenerInput,
};
pub(super) use self::responses::{
    validate_listener_generation_health, ListenerCommandAuthority, ListenerContinuations,
    ListenerResponse, ListenerResponses,
};

/// The session's selected XEP-0016 list, cloned so no lock is held across an await.
fn active_privacy_list(active: &std::sync::RwLock<Option<String>>) -> Option<String> {
    active
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

#[cfg(test)]
pub(super) fn validate_listener_generation(
    cluster: &ClusterManager,
    generation: u64,
    rotation_epoch: u64,
) -> Result<()> {
    validate_listener_generation_health(&cluster.health, generation, rotation_epoch)
}

enum ListenerStep<T> {
    Next(T),
    Continue,
}

struct ListenerTurn {
    delivered: usize,
    accepted_full_jid: Option<String>,
    mix_supported: usize,
    mix_unsupported: usize,
    mix_unknown: usize,
    mix_handoff: Option<ClusterMixHandoff>,
    control_processed: Option<bool>,
    control_outcome: Option<ClusterControlOutcome>,
    acknowledged_delivery: Option<NodeDeliveryContract>,
    responses: ListenerResponses,
}

pub(super) async fn listen_once<A: ClusterAdapters>(
    transport: Arc<ClusterPubsubListenerTransport>,
    admission: Arc<ClusterListenerAdmission>,
    runtime: ClusterListenerRuntime<A>,
    cancel: CancellationToken,
    heartbeat: northstar_runtime::workers::WorkerHeartbeat,
) -> Result<()> {
    let ClusterListenerRuntime {
        message_policy,
        dispatch,
        muc_endpoints,
        muc_delivery,
        mix_caps,
        blocking,
        sm_muc_teardown,
        presence_sender,
        security,
    } = runtime;
    let client = transport
        .client
        .as_ref()
        .context("Redis listener started without a configured Redis client")?;
    // Register before any setup await: repeated failures can request rotation
    // without increasing the required generation again, so a fresh notified()
    // inside the loop could miss their notify_waiters() call.
    let rotation = transport.listener_rotation.notified();
    tokio::pin!(rotation);
    rotation.as_mut().enable();
    let (candidate_generation, rotation_epoch) = transport.health.begin_listener_attempt();
    let ListenerSubscription {
        mut redis_setup_timer,
        pubsub_conn,
        channel,
        probe_channel,
    } = receive::subscribe_listener(client, &transport, &message_policy).await?;
    let (_pubsub_sink, mut stream) = pubsub_conn.split();
    let (mut pending_probe, mut liveness) =
        receive::start_listener_probe(&transport, &probe_channel).await?;
    // No spawned tasks: dropping this listener synchronously drops every
    // outstanding receipt registration before a replacement listener starts.
    let mut continuations = ListenerContinuations::default();

    loop {
        // This connection must be allowed to receive its initial self-loop
        // before publishing its generation. Comparing the last completed
        // generation here would reject every startup and recovery attempt.
        if transport
            .health
            .listener_requires_rotation(candidate_generation)
        {
            anyhow::bail!("Redis PubSub listener rotation was requested");
        }
        let probe_deadline = pending_probe
            .as_ref()
            .map(|(_, deadline, _)| *deadline)
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400));
        let input = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            _ = &mut rotation => {
                anyhow::bail!("Redis PubSub listener rotation was requested");
            }
            result = continuations.next(), if !continuations.pending.is_empty() => ListenerInput::ResponseComplete(result),
            _ = liveness.tick() => ListenerInput::ProbeDue,
            _ = tokio::time::sleep_until(probe_deadline), if pending_probe.is_some() => {
                ListenerInput::ProbeTimedOut
            }
            message = stream.next() => ListenerInput::Message(message),
        };
        let payload = match receive::receive_listener_payload(
            input,
            ListenerInputContext {
                transport: &transport,
                probe_channel: &probe_channel,
                channel: &channel,
                pending_probe: &mut pending_probe,
                redis_setup_timer: &mut redis_setup_timer,
                heartbeat: &heartbeat,
            },
            (candidate_generation, rotation_epoch),
        )
        .await?
        {
            ReceivedListenerInput::Payload(payload) => payload,
            ReceivedListenerInput::Continue => continue,
            ReceivedListenerInput::Return(result) => return result,
        };
        let ListenerStep::Next(VerifiedListenerEnvelope {
            envelope,
            source_node,
            protocol_version,
        }) = envelope::verify_listener_envelope(
            &security,
            &admission,
            &payload,
            &channel,
            (candidate_generation, rotation_epoch),
        )
        .await?
        else {
            continue;
        };
        let json = &envelope.payload;
        let ListenerStep::Next(ListenerCommand {
            target,
            mut turn,
            flags,
        }) = envelope::prepare_listener_command(&admission, json, protocol_version)
        else {
            continue;
        };
        let ListenerCommandFlags {
            is_muc,
            is_muc_presence,
            is_muc_nickname_change,
            is_muc_role_change,
            is_muc_evict,
            is_muc_destroy,
            is_muc_operation_wake,
            is_muc_private,
            is_sm_muc_teardown,
            is_sm_session_teardown,
            is_account_generation_teardown,
            is_user_agent_replacement,
            is_session_termination,
            is_blocking_presence_change,
            is_presence_probe,
        } = flags;

        if is_muc_operation_wake {
            muc::wake_muc_operation(&dispatch, json, target, &mut turn);
        } else if is_session_termination {
            session::terminate_session(&dispatch, json, target, &mut turn).await?;
        } else if is_user_agent_replacement {
            session::replace_user_agent(&dispatch, json, target, &mut turn);
        } else if is_account_generation_teardown {
            session::teardown_account_generation(&dispatch, json, target, &mut turn);
        } else if is_sm_session_teardown {
            session::teardown_sm_session(&dispatch, json, target, &mut turn);
        } else if is_presence_probe {
            if let ListenerStep::Continue = presence::handle_presence_probe(
                &admission,
                &dispatch,
                &message_policy,
                &source_node,
                json,
                target,
                &mut turn,
            )
            .await?
            {
                continue;
            }
        } else if is_blocking_presence_change {
            presence::deliver_blocking_presence(&blocking, &source_node, json, target, &mut turn)
                .await;
        } else if is_sm_muc_teardown {
            session::teardown_sm_muc_session(&sm_muc_teardown, json, target, &mut turn).await;
        } else if is_muc_evict {
            muc::evict_muc_occupant(
                &dispatch,
                &muc_endpoints,
                &muc_delivery,
                json,
                target,
                &mut turn,
            )
            .await;
        } else if is_muc_destroy {
            muc::destroy_muc_room::<A>(&muc_endpoints, &muc_delivery, json, target, &mut turn)
                .await;
        } else if is_muc_role_change {
            muc::change_muc_role::<A>(&muc_endpoints, &muc_delivery, json, target, &mut turn).await;
        } else if is_muc_nickname_change {
            muc::change_muc_nickname::<A>(&muc_endpoints, &muc_delivery, json, target, &mut turn)
                .await;
        } else if is_muc_presence {
            muc::fan_out_muc_presence::<A>(&muc_endpoints, &muc_delivery, json, target, &mut turn)
                .await;
        } else if let Some(stanza) = json["stanza"].as_str() {
            let ListenerStep::Next((parsed_stanza, parsed_presence_authority)) =
                presence::validate_stanza_presence(
                    &admission,
                    &message_policy,
                    &source_node,
                    json,
                    target,
                    stanza,
                )
                .await
            else {
                continue;
            };
            let ListenerStep::Next((stanza_delivery, muc_senders)) =
                delivery::resolve_stanza_delivery(
                    &message_policy,
                    json,
                    target,
                    stanza,
                    &parsed_stanza,
                    (is_muc, is_muc_private),
                    &mut turn,
                )
                .await
            else {
                continue;
            };
            if is_muc_private {
                muc::deliver_muc_private_stanza::<A>(
                    &muc_endpoints,
                    &muc_delivery,
                    json,
                    target,
                    stanza,
                    &muc_senders,
                    &mut turn,
                )
                .await;
            } else if is_muc {
                muc::broadcast_muc_stanza::<A>(
                    &muc_endpoints,
                    &muc_delivery,
                    json,
                    target,
                    stanza,
                    &muc_senders,
                    &mut turn,
                )
                .await;
            } else {
                let ListenerStep::Next(options) = delivery::validate_direct_delivery(
                    json,
                    target,
                    stanza,
                    &parsed_stanza,
                    parsed_presence_authority,
                    &stanza_delivery,
                ) else {
                    continue;
                };
                delivery::fan_out_direct_delivery(
                    &dispatch,
                    &message_policy,
                    &mix_caps,
                    target,
                    &stanza_delivery,
                    &options,
                    &mut turn,
                )
                .await;
            }
        }

        acknowledge_listener_command(
            ListenerAckContext {
                admission: &admission,
                security: &security,
                message_policy: &message_policy,
                dispatch: &dispatch,
                presence_sender: &presence_sender,
            },
            (candidate_generation, rotation_epoch),
            envelope,
            source_node,
            turn,
            &mut continuations,
        )
        .await?;
    }
}
