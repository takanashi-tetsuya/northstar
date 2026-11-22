//! Drive the BOSH actor lifecycle and process requests in RID order.

use crate::host::BoshHost;
use crate::request_policy::{
    advance_bosh_key_sequence, bosh_request_shape_error, capture_bosh_stream, classify_rid,
    inactivity_deadline, replace_duplicate_responders, too_frequent_held_empty_request,
    valid_client_response_ack, validated_bosh_restart_target, within_polling_interval,
};
use crate::response_output::terminal_response;
use crate::{
    next_bosh_command, ownership, response_owner, BoshActor, BoshCommand, BoshHttpResponse,
    BoshRequest, HeldRequest, PendingRequest, RidDisposition, BOSH_BACKEND_OPERATION_TIMEOUT,
    MAX_RID,
};
use futures::FutureExt;
use northstar_stream::frame_execution::FrameFailure;
use northstar_stream::session::StreamSession;
use std::panic::AssertUnwindSafe;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

impl<H: BoshHost> BoshActor<H> {
    pub(super) async fn run(mut self) {
        let actor = AssertUnwindSafe(self.run_loop()).catch_unwind().await;
        let cleanup = AssertUnwindSafe(self.finish()).catch_unwind().await;
        match actor {
            Ok(()) => {
                if let Err(panic) = cleanup {
                    std::panic::resume_unwind(panic);
                }
            }
            Err(panic) => {
                if cleanup.is_err() {
                    tracing::error!(
                        session_id = %self.delivery_session_id,
                        "BOSH exact-once finalizer also panicked while unwinding an actor panic"
                    );
                }
                std::panic::resume_unwind(panic);
            }
        }
    }

    pub(super) fn begin_ownership_operation(
        &mut self,
        kind: northstar_delivery_core::bosh_ownership::OperationKind,
    ) -> northstar_delivery_core::bosh_ownership::Operation {
        // Vec::new allocates no transfer metadata here; per-item records are
        // created only inside the existing timed child. Cleanup keeps this
        // last observation and never rewrites it as a release receipt.
        let operation = northstar_delivery_core::bosh_ownership::Operation::new(
            northstar_delivery_core::bosh_ownership::Scope {
                session_id: self.delivery_session_id,
                ttl_seconds: self.delivery_fence_ttl_seconds,
                kind,
            },
        );
        self.ownership_operation = Some(operation.clone());
        operation
    }

    pub(super) async fn run_loop(&mut self) {
        let signals = self.protocol.termination_signals();
        let mut maintenance = tokio::time::interval(Duration::from_secs(1));
        maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut keep_running = true;
        while keep_running {
            // A selected operation keeps its existing completion/deadline.
            // At the next event boundary, overload wins over queued work.
            if self.overactivity.is_cancelled() {
                self.terminate_for_overactivity();
                break;
            }
            let now = Instant::now();
            let hold_deadline = self
                .held
                .as_ref()
                .map(|held| held.deadline)
                .unwrap_or(now + Duration::from_secs(86_400));
            let buffered_deadline = self
                .buffered
                .values()
                .map(|pending| pending.request.received_at + self.wait)
                .min()
                .unwrap_or(now + Duration::from_secs(86_400));
            let request_held = self.held.is_some() || !self.buffered.is_empty();
            let inactivity_deadline =
                inactivity_deadline(self.last_response, self.active_inactivity, request_held)
                    .unwrap_or(now + Duration::from_secs(86_400));
            let resource_bind_deadline = self
                .protocol
                .resource_bind_deadline()
                .unwrap_or(now + Duration::from_secs(86_400));
            tokio::select! {
                _ = self.actor_shutdown.cancelled() => {
                    // Root shutdown is a transport loss. Preserve negotiated
                    // XEP-0198 resumability while terminating held HTTP calls.
                    self.terminate_waiters("system-shutdown");
                    break;
                }
                _ = signals.backpressured() => {
                    tracing::warn!(peer_ip = %self.protocol.peer_ip(), "closed slow BOSH XMPP client after an ordered outbound delivery could not be queued; recoverable messages remain available for replay and committed state will resynchronize after reconnect");
                    self.terminate_waiters("policy-violation");
                    break;
                }
                _ = signals.revoked() => {
                    self.protocol.forbid_sm_resume();
                    self.terminate_waiters("system-shutdown");
                    break;
                }
                command = next_bosh_command(&mut self.commands, &self.overactivity) => {
                    match command {
                        Some(BoshCommand::Request { request, response }) => {
                            let operation = self.begin_ownership_operation(northstar_delivery_core::bosh_ownership::OperationKind::Request);
                            keep_running = match ownership::OperationRunner::new(operation.clone(), tokio::time::timeout(
                                BOSH_BACKEND_OPERATION_TIMEOUT,
                                self.accept_request(*request, response, &operation),
                            ))
                            .await
                            {
                                Ok(keep_running) => keep_running,
                                Err(_) => {
                                    tracing::warn!(session_id = %self.delivery_session_id, "BOSH backend request budget expired");
                                    false
                                }
                            };
                            if !keep_running {
                                self.protocol.forbid_sm_resume();
                            }
                        }
                        Some(BoshCommand::Overactivity) => {
                            self.terminate_for_overactivity();
                            keep_running = false;
                        }
                        None => break,
                    }
                }
                stanza = self.outbound.recv(), if self.has_output_capacity() => {
                    match stanza {
                        Some(stanza) => {
                            let operation = self.begin_ownership_operation(northstar_delivery_core::bosh_ownership::OperationKind::Outbound);
                            if !matches!(
                                ownership::OperationRunner::new(operation.clone(), tokio::time::timeout(
                                    BOSH_BACKEND_OPERATION_TIMEOUT,
                                    self.queue_outbound(stanza, &operation),
                                ))
                                .await,
                                Ok(true)
                            ) {
                                self.protocol.forbid_sm_resume();
                                self.terminate_waiters("policy-violation");
                                keep_running = false;
                            } else if self.held.is_some()
                                && !matches!(
                                    {
                                        let operation = self.begin_ownership_operation(northstar_delivery_core::bosh_ownership::OperationKind::HeldResponse);
                                        ownership::OperationRunner::new(operation.clone(), tokio::time::timeout(
                                            BOSH_BACKEND_OPERATION_TIMEOUT,
                                            self.finish_held(None, &operation),
                                        )).await
                                    },
                                    Ok(true)
                                )
                            {
                                self.protocol.forbid_sm_resume();
                                self.terminate_waiters("internal-server-error");
                                keep_running = false;
                            }
                        }
                        None => {
                            self.protocol.forbid_sm_resume();
                            self.terminate_waiters("internal-server-error");
                            keep_running = false;
                        }
                    }
                }
                _ = tokio::time::sleep_until(hold_deadline.into()), if self.held.is_some() => {
                    let operation = self.begin_ownership_operation(northstar_delivery_core::bosh_ownership::OperationKind::HeldResponse);
                    if !matches!(
                        ownership::OperationRunner::new(operation.clone(), tokio::time::timeout(
                            BOSH_BACKEND_OPERATION_TIMEOUT,
                            self.finish_held(None, &operation),
                        ))
                        .await,
                        Ok(true)
                    ) {
                        self.protocol.forbid_sm_resume();
                        self.terminate_waiters("internal-server-error");
                        keep_running = false;
                    }
                }
                _ = tokio::time::sleep_until(buffered_deadline.into()), if !self.buffered.is_empty() => {
                    self.expire_buffered_requests(Instant::now());
                }
                _ = tokio::time::sleep_until(inactivity_deadline.into()), if !request_held => {
                    keep_running = false;
                }
                _ = tokio::time::sleep_until(resource_bind_deadline.into()), if self.protocol.resource_bind_deadline().is_some() => {
                    self.protocol.forbid_sm_resume();
                    self.terminate_waiters("policy-violation");
                    keep_running = false;
                }
                _ = maintenance.tick() => {
                    if self.protocol.unauthenticated_timed_out(Instant::now()) {
                        self.terminate_waiters("policy-violation");
                        keep_running = false;
                    } else if self.protocol.has_sm_session()
                        && self.protocol.checkpoint_sm().await.is_err()
                    {
                        self.protocol.forbid_sm_resume();
                        self.terminate_waiters("internal-server-error");
                        keep_running = false;
                    }
                }
            }
        }
    }

    pub(super) async fn finish(&mut self) {
        if self.protocol.termination_signals().is_backpressured() {
            self.protocol.record_backpressure_disconnect();
        }
        // Stop admitting HTTP requests before durable/session finalization.
        // Every terminate, timeout, command-channel and backpressure exit
        // converges on this single exact-once actor epilogue.
        self.manager.remove(&self.session_key);
        match tokio::time::timeout(
            BOSH_BACKEND_OPERATION_TIMEOUT,
            self.replay_service
                .release_bosh_fences(self.delivery_session_id),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!(?error, session_id = %self.delivery_session_id, "failed to release BOSH durable delivery fences")
            }
            Err(_) => {
                tracing::error!(session_id = %self.delivery_session_id, "timed out releasing BOSH durable delivery fences")
            }
        }
        // The typed outcome records whether this actor owned cleanup or an SM
        // handoff already did; recoverable cleanup failures are observed by
        // ProtocolSession::finalize itself.
        let _ = self.protocol.finalize().await;
        self.protocol.record_bosh_session_closed();
    }

    pub(super) async fn accept_request(
        &mut self,
        request: BoshRequest,
        response: oneshot::Sender<BoshHttpResponse>,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) -> bool {
        if !valid_client_response_ack(
            self.client_acknowledgements,
            self.highest_responded,
            request.rid,
            request.ack,
        ) {
            let _ = response.send(terminal_response("bad-request"));
            self.terminate_waiters("other-request");
            return false;
        }
        let response = match response_owner::replay_cached(
            &mut self.replay,
            &request,
            response,
            &mut self.last_response,
            operation,
            &response_owner::ServiceReplay {
                service: &self.replay_service,
            },
        )
        .await
        {
            response_owner::ReplayOutcome::Miss(response) => response,
            response_owner::ReplayOutcome::Sent { terminate } => {
                if terminate {
                    self.terminate_waiters("other-request");
                }
                return !terminate;
            }
            response_owner::ReplayOutcome::Failed {
                responder,
                error: _error,
            } => {
                let _ = responder.send(terminal_response("internal-server-error"));
                self.protocol.forbid_sm_resume();
                self.terminate_waiters("internal-server-error");
                return false;
            }
        };
        if let Some(held) = self
            .held
            .as_mut()
            .filter(|held| held.pending.request.rid == request.rid)
        {
            if !replace_duplicate_responders(
                &mut held.pending,
                &request,
                response,
                &self.content_type,
            ) {
                self.terminate_waiters("other-request");
                return false;
            }
            return true;
        }
        if let Some(pending) = self.buffered.get_mut(&request.rid) {
            if !replace_duplicate_responders(pending, &request, response, &self.content_type) {
                self.terminate_waiters("other-request");
                return false;
            }
            return true;
        }
        match classify_rid(self.next_rid, request.rid) {
            RidDisposition::Expected | RidDisposition::BufferedOneAhead => {}
            RidDisposition::Old | RidDisposition::OutsideWindow => {
                let _ = response.send(terminal_response("item-not-found"));
                self.terminate_waiters("other-request");
                return false;
            }
        }
        self.highest_received = self.highest_received.max(request.rid);
        // Receiving the first valid request after a pause restores the
        // normal inactivity interval even when that RID has to wait for an
        // immediately preceding request to arrive.
        self.active_inactivity = self.inactivity;
        self.buffered.insert(
            request.rid,
            PendingRequest {
                request,
                responders: vec![response],
            },
        );

        loop {
            if let (Some(held), Some(next)) =
                (self.held.as_ref(), self.buffered.get(&self.next_rid))
            {
                if too_frequent_held_empty_request(
                    &held.pending.request,
                    &next.request,
                    self.polling,
                ) {
                    // With hold=1, receiving the second allowed request while
                    // the first is still held is normal only when the client
                    // has data to send. A second empty request inside the
                    // advertised polling interval is XEP-0124 overactivity.
                    self.protocol.forbid_sm_resume();
                    self.terminate_waiters("policy-violation");
                    return false;
                }
            }
            if self.held.is_some()
                && self
                    .buffered
                    .get(&self.next_rid)
                    .is_some_and(|pending| pending.request.terminate)
            {
                // XEP-0124 requires the terminate acknowledgement on the
                // oldest held HTTP connection and an empty response on the
                // terminating request's connection. Process the newer
                // request's payload first, but swap only the responders so
                // the two HTTP responses retain that prescribed placement.
                let mut oldest = self.held.take().expect("held request was checked").pending;
                let mut terminating = self
                    .buffered
                    .remove(&self.next_rid)
                    .expect("terminating request was checked");
                let final_rid = self.next_rid == MAX_RID;
                if !final_rid {
                    self.next_rid += 1;
                }
                std::mem::swap(&mut oldest.responders, &mut terminating.responders);
                let _ = self.process_pending(terminating, operation).await;
                if !self.finish_pending(oldest, None, false, operation).await {
                    self.protocol.forbid_sm_resume();
                }
                self.terminate_waiters("other-request");
                return false;
            }
            if self.held.is_some()
                && self.buffered.contains_key(&self.next_rid)
                && !self.finish_held(None, operation).await
            {
                self.protocol.forbid_sm_resume();
                self.terminate_waiters("internal-server-error");
                return false;
            }
            if self.held.is_some() {
                break;
            }
            let Some(pending) = self.buffered.remove(&self.next_rid) else {
                break;
            };
            let final_rid = self.next_rid == MAX_RID;
            if final_rid && !pending.request.terminate {
                let _ = self
                    .finish_pending(pending, Some("item-not-found"), false, operation)
                    .await;
                self.terminate_waiters("other-request");
                return false;
            }
            if !final_rid {
                self.next_rid += 1;
            }
            if !self.process_pending(pending, operation).await {
                self.terminate_waiters("other-request");
                return false;
            }
        }
        true
    }

    async fn process_pending(
        &mut self,
        pending: PendingRequest,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) -> bool {
        let request = &pending.request;
        self.active_inactivity = self.inactivity;
        if !advance_bosh_key_sequence(
            &mut self.expected_key,
            request.key.as_deref(),
            request.newkey.as_deref(),
        ) {
            let _ = self
                .finish_pending(pending, Some("item-not-found"), false, operation)
                .await;
            return false;
        }
        if let Some(condition) = bosh_request_shape_error(request, self.protocol.is_stream_open()) {
            let _ = self
                .finish_pending(pending, Some(condition), false, operation)
                .await;
            return false;
        }
        // A SID alone is insufficient when the negotiated SHA-1 key sequence
        // is active. Apply the client response acknowledgement only after the
        // request has passed both its key proof and structural checks.
        if let Err(error) = self
            .renew_and_apply_response_ack(request.ack, operation)
            .await
        {
            tracing::error!(?error, session_id = %self.delivery_session_id, ack = ?request.ack, "failed to commit authenticated BOSH response acknowledgement");
            let _ = self
                .finish_pending(pending, Some("internal-server-error"), false, operation)
                .await;
            return false;
        }

        if let Some(pause) = request.pause {
            if pause > self.max_pause {
                let _ = self
                    .finish_pending(pending, Some("policy-violation"), false, operation)
                    .await;
                return false;
            }
            self.last_empty_poll = None;
            self.active_inactivity = Duration::from_secs(pause);
            self.finish_pending_empty(pending, operation);
            return true;
        }

        if request.restart {
            if !request.payloads.is_empty() {
                tracing::debug!(
                    payloads = request.payloads.len(),
                    "ignored payloads attached to a BOSH stream restart"
                );
            }
            let domain = self.protocol.local_domain().to_owned();
            let restart_to = match validated_bosh_restart_target(request.to.as_deref(), &domain) {
                Ok(target) => target,
                Err(condition) => {
                    let _ = self
                        .finish_pending(pending, Some(condition), false, operation)
                        .await;
                    return false;
                }
            };
            if capture_bosh_stream(
                &mut self.protocol,
                Some(&restart_to),
                request.from.as_deref(),
                request.language.as_deref(),
            )
            .is_err()
            {
                let _ = self
                    .finish_pending(pending, Some("improper-addressing"), false, operation)
                    .await;
                return false;
            }
            if !self.push_output(self.protocol.features()) {
                let _ = self
                    .finish_pending(pending, Some("policy-violation"), false, operation)
                    .await;
                return false;
            }
        } else {
            let mut failure = None;
            for payload in &request.payloads {
                match self.protocol.process_frame(payload).await {
                    Ok(action) => {
                        if !self.apply_action(action, operation).await {
                            failure = Some("remote-stream-error");
                            break;
                        }
                    }
                    Err(FrameFailure::Backend(error)) => {
                        tracing::debug!(?error, "BOSH XMPP stanza processing failed");
                        failure = Some("internal-server-error");
                        break;
                    }
                    Err(FrameFailure::TimedOut) => {
                        tracing::warn!(session_id = %self.delivery_session_id, "BOSH stanza backend budget expired");
                        failure = Some("internal-server-error");
                        break;
                    }
                }
            }
            if let Some(condition) = failure {
                let _ = self
                    .finish_pending(pending, Some(condition), false, operation)
                    .await;
                return false;
            }
        }
        while self.has_output_capacity() {
            let Ok(stanza) = self.outbound.try_recv() else {
                break;
            };
            if !self.queue_outbound(stanza, operation).await {
                let _ = self
                    .finish_pending(pending, Some("policy-violation"), false, operation)
                    .await;
                return false;
            }
        }

        if request.terminate {
            self.protocol.forbid_sm_resume();
            let _ = self
                .finish_pending(pending, Some("terminate"), false, operation)
                .await;
            self.terminate_waiters("other-request");
            return false;
        }
        if !self.output.is_empty() || request.restart {
            // A non-empty response breaks the consecutive-empty-poll pair
            // defined by XEP-0124 section 12.
            self.last_empty_poll = None;
            if !self.finish_pending(pending, None, true, operation).await {
                return false;
            }
        } else if self.hold == 0 {
            if request.payloads.is_empty()
                && self.last_empty_poll.is_some_and(|previous| {
                    within_polling_interval(previous, request.received_at, self.polling)
                })
            {
                let _ = self
                    .finish_pending(pending, Some("policy-violation"), false, operation)
                    .await;
                return false;
            }
            self.last_empty_poll = request.payloads.is_empty().then_some(request.received_at);
            if !self.finish_pending(pending, None, true, operation).await {
                return false;
            }
        } else {
            self.held = Some(HeldRequest {
                pending,
                deadline: Instant::now() + self.wait,
            });
        }
        true
    }
}
