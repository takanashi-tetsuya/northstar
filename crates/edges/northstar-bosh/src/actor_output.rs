//! Record and queue actor output, complete responses, and terminate waiters.

use crate::host::BoshHost;
use crate::request_policy::{highest_contiguous_buffered_rid, take_expired_buffered};
use crate::response_output::{
    bosh_body_element, superseded_bosh_message_id, terminal_response_with_content,
};
use crate::{ownership, response_owner, BoshActor, BoshHttpResponse, PendingRequest};
use axum::body::Bytes;
use northstar_stream::session::StreamSession;
use std::time::Instant;

impl<H: BoshHost> BoshActor<H> {
    pub(super) async fn record_and_push(&mut self, stanza: String) -> bool {
        self.protocol.record_outbound(&stanza).await.is_ok() && self.push_output(stanza)
    }

    pub(super) async fn renew_and_apply_response_ack(
        &mut self,
        ack: Option<u64>,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) -> anyhow::Result<()> {
        response_owner::renew_and_acknowledge(
            &mut self.replay,
            ack,
            operation,
            &response_owner::ServiceReplay {
                service: &self.replay_service,
            },
        )
        .await
    }

    pub(super) async fn record_and_push_item(
        &mut self,
        item: northstar_stream::outbound::OutboundItem,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) -> bool {
        let mut output = ownership::Output {
            items: &mut self.output,
            bytes: &mut self.output_bytes,
            max_stanzas: self.max_output_stanzas,
            max_bytes: self.max_output_bytes,
        };
        let transfer = ownership::ServiceTransfer {
            service: &self.mix_service,
        };
        match ownership::record_and_push(
            &mut output,
            item,
            operation,
            &mut self.protocol,
            &transfer,
        )
        .await
        {
            Ok(accepted) => accepted,
            Err(ownership::RecordPushError::Record(error))
                if superseded_bosh_message_id(&error).is_some() =>
            {
                tracing::debug!(?error, "superseded durable BOSH/SM item skipped");
                true
            }
            Err(ownership::RecordPushError::Record(error)) => {
                tracing::error!(?error, "failed to record BOSH outbound item");
                false
            }
            Err(ownership::RecordPushError::Transfer { source, error }) => {
                tracing::error!(?error, delivery_id = %source.delivery_id, session_id = %self.delivery_session_id, "failed to persist MIX BOSH transport ownership");
                false
            }
        }
    }

    pub(super) async fn queue_outbound(
        &mut self,
        item: northstar_stream::outbound::OutboundItem,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) -> bool {
        // BOSH cannot prove an individual stanza reached the peer without
        // response/SM acknowledgement, so a durable row remains available for
        // safe replay even after the item leaves CSI's defer buffer.
        let Some(item) = self.protocol.csi_filter_outbound(item) else {
            return true;
        };
        self.record_and_push_item(item, operation).await
    }

    pub(super) fn push_output(&mut self, stanza: String) -> bool {
        self.push_output_item(northstar_stream::outbound::OutboundItem::plain(stanza))
    }

    pub(super) fn push_output_item(
        &mut self,
        item: northstar_stream::outbound::OutboundItem,
    ) -> bool {
        ownership::Output {
            items: &mut self.output,
            bytes: &mut self.output_bytes,
            max_stanzas: self.max_output_stanzas,
            max_bytes: self.max_output_bytes,
        }
        .push(item)
    }

    pub(super) fn has_output_capacity(&self) -> bool {
        self.output.len() < self.max_output_stanzas && self.output_bytes < self.max_output_bytes
    }

    pub(super) async fn finish_held(
        &mut self,
        condition: Option<&str>,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) -> bool {
        if let Some(held) = self.held.take() {
            return self
                .finish_pending(held.pending, condition, true, operation)
                .await;
        }
        true
    }

    pub(super) fn expire_buffered_requests(&mut self, now: Instant) {
        let expired = take_expired_buffered(&mut self.buffered, self.wait, now);
        if expired.is_empty() {
            return;
        }
        let recoverable = BoshHttpResponse {
            body: Bytes::from(
                bosh_body_element(None, false, None)
                    .attr("type", "error")
                    .finish(),
            ),
            content_type: self.content_type.clone(),
        };
        for pending in expired {
            for responder in pending.responders {
                let _ = responder.send(recoverable.clone());
            }
        }
        self.highest_received = self
            .buffered
            .keys()
            .next_back()
            .copied()
            .unwrap_or_else(|| self.next_rid.saturating_sub(1));
        self.last_response = now;
    }

    pub(super) async fn finish_pending(
        &mut self,
        pending: PendingRequest,
        condition: Option<&str>,
        cache: bool,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) -> bool {
        let rid = pending.request.rid;
        let metadata = response_owner::Metadata {
            rid,
            fingerprint: pending.request.fingerprint,
            cache: cache && condition.is_none() && pending.request.pause.is_none(),
        };
        let received_rid =
            highest_contiguous_buffered_rid(self.next_rid, self.highest_received, &self.buffered);
        let bound = response_owner::prepare(
            &mut response_owner::Fields {
                output: &mut self.output,
                output_bytes: &mut self.output_bytes,
                replay: &mut self.replay,
                governor: &self.sm_memory_governor,
                max_response_bytes: self.max_response_bytes,
                max_output_stanzas: self.max_output_stanzas,
                content_type: &self.content_type,
                received_rid,
            },
            metadata,
            condition,
            operation,
            &response_owner::ServiceReplay {
                service: &self.replay_service,
            },
        )
        .await;
        let bound = match bound {
            Ok(bound) => bound,
            Err(failure) => {
                match failure.stage {
                    response_owner::FailureStage::Construction => {
                        tracing::error!(error = ?failure.error, rid, "failed to construct bounded BOSH response")
                    }
                    response_owner::FailureStage::Binding => {
                        tracing::error!(error = ?failure.error, session_id = %self.delivery_session_id, rid, "failed to bind durable BOSH transport sources")
                    }
                    response_owner::FailureStage::Limit => {}
                }
                failure.send(pending.responders, &self.content_type);
                return false;
            }
        };
        let bound = match bound.for_connection(self.protocol.connection_id()) {
            Ok(bound) => bound,
            Err(_) => return false,
        };
        let exposed = match bound.expose(pending.responders) {
            Ok(exposed) => exposed,
            Err(error) => {
                tracing::error!(?error, rid, "BOSH bound response continuation was lost");
                return false;
            }
        };
        let ready = match exposed
            .publish_authentication(|owners| async {
                for owner in owners {
                    if !self
                        .protocol
                        .publish_committed_authentication_and_route(owner)
                        .await
                    {
                        return false;
                    }
                }
                true
            })
            .await
        {
            Ok(ready) => ready,
            Err(_) => return false,
        };
        ready
            .finish(
                &mut self.last_response,
                &mut self.highest_responded,
                &mut self.replay,
            )
            .is_ok()
    }

    pub(super) fn finish_pending_empty(
        &mut self,
        pending: PendingRequest,
        operation: &northstar_delivery_core::bosh_ownership::Operation,
    ) {
        response_owner::finish_empty_control(
            pending.request.rid,
            pending.responders,
            &self.content_type,
            &mut self.last_response,
            &mut self.highest_responded,
            operation,
        );
    }

    pub(super) fn terminate_for_overactivity(&mut self) {
        self.protocol.forbid_sm_resume();
        self.terminate_waiters("policy-violation");
    }

    pub(super) fn terminate_waiters(&mut self, condition: &str) {
        if let Some(held) = self.held.take() {
            let response = terminal_response_with_content(condition, &self.content_type);
            for responder in held.pending.responders {
                let _ = responder.send(response.clone());
            }
        }
        let response = terminal_response_with_content(condition, &self.content_type);
        for (_, pending) in std::mem::take(&mut self.buffered) {
            for responder in pending.responders {
                let _ = responder.send(response.clone());
            }
        }
    }
}
