//! Actual response selection, binding and cache continuations over the actor's
//! existing fields. Authentication publication remains in BoshActor.
use super::{
    bosh_body_element, bosh_response_bytes, bosh_unacknowledged_limit_exceeded,
    restore_response_items, restore_response_items_observed, superseded_bosh_message_id,
    take_response_payload, terminal_response_with_content, BoshHttpResponse, BoshRequest,
    BoshResponseBody, CachedResponse, RESPONSE_CACHE_SIZE,
};
use crate::{
    outbound::{BoshResponseOwnership, OutboundItem},
    services::{
        replay::{ReplayRepository, ReplayService},
        sm_capacity::SmMemoryGovernor,
    },
};
use anyhow::Result;
use axum::body::Bytes;
use northstar_delivery_core::bosh_ownership::{
    response::{self, AckRequest, BindRequest, RenewRequest, ResponseBuild, ResponseKind},
    Operation,
};
use std::{collections::VecDeque, future::Future, sync::Arc, time::Instant};
use tokio::sync::{mpsc, oneshot};
type Responder = oneshot::Sender<BoshHttpResponse>;

pub(super) trait ReplayPort {
    fn bind(
        &self,
        request: &BindRequest,
    ) -> impl Future<Output = Result<BoshResponseOwnership>> + Send;
    fn renew(&self, request: &RenewRequest) -> impl Future<Output = Result<()>> + Send;
    fn acknowledge(&self, request: &AckRequest) -> impl Future<Output = Result<()>> + Send;
    fn release(&self, session_id: uuid::Uuid) -> impl Future<Output = Result<()>> + Send;
}
pub(super) struct ServiceReplay<'a, R> {
    pub(super) service: &'a ReplayService<R>,
}
impl<R: ReplayRepository> ReplayPort for ServiceReplay<'_, R> {
    async fn bind(&self, request: &BindRequest) -> Result<BoshResponseOwnership> {
        self.service.bind_bosh_response_sources(request).await
    }
    async fn renew(&self, request: &RenewRequest) -> Result<()> {
        self.service.renew_bosh_fences(request).await
    }
    async fn acknowledge(&self, request: &AckRequest) -> Result<()> {
        self.service.acknowledge_bosh_responses(request).await
    }
    async fn release(&self, session_id: uuid::Uuid) -> Result<()> {
        self.service.release_bosh_fences(session_id).await
    }
}
pub(super) struct Fields<'a> {
    pub(super) output: &'a mut VecDeque<OutboundItem>,
    pub(super) output_bytes: &'a mut usize,
    pub(super) replay: &'a mut VecDeque<CachedResponse>,
    pub(super) governor: &'a Arc<SmMemoryGovernor>,
    pub(super) max_response_bytes: usize,
    pub(super) max_output_stanzas: usize,
    pub(super) content_type: &'a str,
    pub(super) received_rid: Option<u64>,
}
#[derive(Clone, Copy)]
pub(super) struct Metadata {
    pub(super) rid: u64,
    pub(super) fingerprint: [u8; 32],
    pub(super) cache: bool,
}
impl Fields<'_> {
    fn body(
        &mut self,
        condition: Option<&str>,
        terminate: bool,
        build: &ResponseBuild,
    ) -> Result<BoshResponseBody> {
        let (payload, sources, receipts, capacity, selected) = take_response_payload(
            self.output,
            self.output_bytes,
            self.max_response_bytes,
            self.governor,
        )?;
        let body = bosh_body_element(condition, terminate, self.received_rid);
        let body = match body.validated_fragment(&payload) {
            Ok(body) => body.finish(),
            Err(error) => {
                let count = selected.len();
                restore_response_items(self.output, self.output_bytes, selected, None);
                build.construction_restored(count);
                anyhow::bail!("malformed protocol output at BOSH boundary: {error}");
            }
        };
        Ok((
            BoshHttpResponse {
                body: bosh_response_bytes(body, capacity),
                content_type: self.content_type.to_owned(),
            },
            sources,
            receipts,
            selected,
        ))
    }
}
#[derive(Clone, Copy)]
pub(super) enum FailureStage {
    Construction,
    Limit,
    Binding,
}
pub(super) struct PreparationFailure {
    pub(super) stage: FailureStage,
    pub(super) condition: &'static str,
    pub(super) error: anyhow::Error,
    control: Option<response::ControlObservation>,
}
impl std::fmt::Debug for PreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoshResponsePreparationFailure")
            .field("condition", &self.condition)
            .finish_non_exhaustive()
    }
}
impl PreparationFailure {
    fn new(
        stage: FailureStage,
        condition: &'static str,
        error: anyhow::Error,
        build: Option<&ResponseBuild>,
    ) -> Self {
        Self {
            stage,
            condition,
            error,
            control: build.map(ResponseBuild::terminal_control),
        }
    }
    pub(super) fn send(self, responders: Vec<Responder>, content_type: &str) {
        let response = terminal_response_with_content(self.condition, content_type);
        for responder in responders {
            send_one(
                response.clone(),
                responder,
                || {
                    if let Some(control) = &self.control {
                        control.sending();
                    }
                },
                |accepted| {
                    if let Some(control) = &self.control {
                        control.sent(accepted);
                    }
                },
            );
        }
    }
}
/// Only this owning continuation may expose the selected response bytes.
pub(super) struct BoundResponse {
    metadata: Metadata,
    response: BoshHttpResponse,
    receipts: Vec<mpsc::UnboundedSender<()>>,
    ownership: Arc<BoshResponseOwnership>,
    bound: response::BoundResponse,
}
impl std::fmt::Debug for BoundResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoundBoshResponse { body and binding: [redacted] }")
    }
}
pub(super) struct ExposedResponse {
    metadata: Metadata,
    response: BoshHttpResponse,
    receipts: Vec<mpsc::UnboundedSender<()>>,
    ownership: Arc<BoshResponseOwnership>,
    exposure: response::Exposure,
    accepted: bool,
}
impl BoundResponse {
    pub(super) fn expose(self, responders: Vec<Responder>) -> Result<ExposedResponse> {
        let exposure = self.bound.begin_exposure()?;
        let mut accepted = false;
        for responder in responders {
            accepted |= send_one(
                self.response.clone(),
                responder,
                || exposure.sending(),
                |accepted| exposure.sent(accepted),
            );
        }
        Ok(ExposedResponse {
            metadata: self.metadata,
            response: self.response,
            receipts: self.receipts,
            ownership: self.ownership,
            exposure,
            accepted,
        })
    }
}
impl ExposedResponse {
    pub(super) fn any_accepted(&self) -> bool {
        self.accepted
    }
    pub(super) fn finish(
        self,
        last_response: &mut Instant,
        highest_responded: &mut u64,
        replay: &mut VecDeque<CachedResponse>,
    ) -> Result<()> {
        let bookkeeping = self.exposure.begin_bookkeeping()?;
        update_response_position(last_response, highest_responded, self.metadata.rid);
        bookkeeping.updated();
        if self.metadata.cache {
            let response_bytes = self.response.body.len();
            replay.push_back(CachedResponse {
                rid: self.metadata.rid,
                fingerprint: self.metadata.fingerprint,
                response: self.response,
                durable_ownership: self.ownership,
                transport_receipts: self.receipts,
                owned_at: Instant::now(),
                response_bytes,
                replays: 0,
            });
            bookkeeping.cached();
        }
        Ok(())
    }
}
pub(super) async fn prepare<P: ReplayPort>(
    fields: &mut Fields<'_>,
    metadata: Metadata,
    condition: Option<&str>,
    operation: &Operation,
    port: &P,
) -> Result<BoundResponse, PreparationFailure> {
    let selects_output = condition.is_none() || condition == Some("remote-stream-error");
    let lineage = if selects_output {
        fields
            .output
            .iter()
            .map(|item| item.durable_source)
            .collect()
    } else {
        vec![]
    };
    let build = operation
        .begin_response(
            metadata.rid,
            if selects_output {
                ResponseKind::Payload
            } else {
                ResponseKind::TerminalControl
            },
            lineage,
        )
        .map_err(|error| {
            PreparationFailure::new(
                FailureStage::Construction,
                "internal-server-error",
                error.into(),
                None,
            )
        })?;
    let mut superseded_rebuilds = 0;
    loop {
        let built = if condition == Some("remote-stream-error") {
            fields.body(condition, true, &build)
        } else if condition == Some("terminate") {
            Ok((
                BoshHttpResponse {
                    body: Bytes::from(bosh_body_element(None, true, None).finish()),
                    content_type: fields.content_type.to_owned(),
                },
                vec![],
                vec![],
                VecDeque::new(),
            ))
        } else if let Some(condition) = condition {
            Ok((
                terminal_response_with_content(condition, fields.content_type),
                vec![],
                vec![],
                VecDeque::new(),
            ))
        } else {
            fields.body(None, false, &build)
        };
        let (response, sources, receipts, selected) = built.map_err(|error| {
            PreparationFailure::new(
                FailureStage::Construction,
                "internal-server-error",
                error,
                Some(&build),
            )
        })?;
        if metadata.cache {
            while fields.replay.len() >= RESPONSE_CACHE_SIZE
                && fields.replay.front().is_some_and(|cached| {
                    cached.durable_ownership.is_empty() && cached.transport_receipts.is_empty()
                })
            {
                fields.replay.pop_front();
                build.empty_cache_evicted();
            }
            if bosh_unacknowledged_limit_exceeded(
                fields.replay,
                response.body.len(),
                Instant::now(),
            ) {
                // Preserve the existing unobserved release await before the
                // terminal response; a returned unit is not a release receipt.
                let _ = port.release(operation.session_id()).await;
                return Err(PreparationFailure::new(
                    FailureStage::Limit,
                    "policy-violation",
                    anyhow::anyhow!("BOSH unacknowledged response limit exceeded"),
                    Some(&build),
                ));
            }
        }
        let request = build
            .attempt(sources, selected.iter().map(|item| item.durable_source))
            .map_err(|error| {
                PreparationFailure::new(
                    FailureStage::Binding,
                    "internal-server-error",
                    error.into(),
                    Some(&build),
                )
            })?;
        let result = if request.sources().is_empty() {
            Ok(BoshResponseOwnership::default())
        } else {
            port.bind(&request).await
        };
        match result {
            Ok(ownership) => {
                let bound = request.returned(ownership).map_err(|error| {
                    PreparationFailure::new(
                        FailureStage::Binding,
                        "internal-server-error",
                        error.into(),
                        Some(&build),
                    )
                })?;
                let ownership = bound.ownership().clone();
                return Ok(BoundResponse {
                    metadata,
                    response,
                    receipts,
                    ownership,
                    bound,
                });
            }
            Err(error) => {
                if let Some(message_id) = superseded_bosh_message_id(&error) {
                    if let Ok(restoration) = request.supersession(message_id) {
                        let mut removed_indices = Vec::with_capacity(selected.len());
                        let removed = restore_response_items_observed(
                            fields.output,
                            fields.output_bytes,
                            selected,
                            Some(message_id),
                            |offset| removed_indices.push(restoration.selected_indices()[offset]),
                        );
                        restoration.restored(removed_indices).map_err(|error| {
                            PreparationFailure::new(
                                FailureStage::Binding,
                                "internal-server-error",
                                error.into(),
                                Some(&build),
                            )
                        })?;
                        if removed && superseded_rebuilds < fields.max_output_stanzas {
                            superseded_rebuilds += 1;
                            tracing::debug!(target: "rust_xmpp_server::bosh", %message_id, rid = metadata.rid, "superseded durable BOSH item removed before response exposure");
                            continue;
                        }
                    }
                }
                return Err(PreparationFailure::new(
                    FailureStage::Binding,
                    "internal-server-error",
                    error,
                    Some(&build),
                ));
            }
        }
    }
}

// Raw exposure stays private. Durable payloads enter through BoundResponse;
// the pause wrapper below constructs only its fixed empty control response.
fn send_one(
    response: BoshHttpResponse,
    responder: Responder,
    entering: impl FnOnce(),
    returned: impl FnOnce(bool),
) -> bool {
    entering();
    let accepted = responder.send(response).is_ok();
    returned(accepted);
    accepted
}
fn update_response_position(last_response: &mut Instant, highest_responded: &mut u64, rid: u64) {
    *last_response = Instant::now();
    *highest_responded = (*highest_responded).max(rid);
}
pub(super) fn finish_empty_control(
    rid: u64,
    responders: Vec<Responder>,
    content_type: &str,
    last_response: &mut Instant,
    highest_responded: &mut u64,
    operation: &Operation,
) {
    let control = operation.observe_empty_control(rid);
    let response = BoshHttpResponse {
        body: Bytes::from(bosh_body_element(None, false, None).finish()),
        content_type: content_type.to_owned(),
    };
    for responder in responders {
        send_one(
            response.clone(),
            responder,
            || control.sending(),
            |accepted| control.sent(accepted),
        );
    }
    update_response_position(last_response, highest_responded, rid);
    control.updated();
}

pub(super) enum ReplayOutcome {
    Miss(Responder),
    Sent {
        terminate: bool,
    },
    Failed {
        responder: Responder,
        error: anyhow::Error,
    },
}
pub(super) async fn replay_cached<P: ReplayPort>(
    replay: &mut VecDeque<CachedResponse>,
    request: &BoshRequest,
    responder: Responder,
    last_response: &mut Instant,
    operation: &Operation,
    port: &P,
) -> ReplayOutcome {
    let Some((reply, terminate, ownership)) = super::replay_response(replay, request) else {
        return ReplayOutcome::Miss(responder);
    };
    if terminate {
        // The existing selector constructs the terminal control; no cached
        // payload or durable bind continuation enters this branch.
        let control = operation.observe_terminal_control(request.rid);
        send_one(
            reply,
            responder,
            || control.sending(),
            |accepted| control.sent(accepted),
        );
        return ReplayOutcome::Sent { terminate: true };
    }
    let renewal = match operation.begin_renew(Some((request.rid, ownership))) {
        Ok(renewal) => renewal,
        Err(error) => {
            return ReplayOutcome::Failed {
                responder,
                error: error.into(),
            }
        }
    };
    if let Err(error) = port.renew(&renewal).await {
        return ReplayOutcome::Failed { responder, error };
    }
    let exposure = match renewal
        .returned()
        .and_then(|renewed| renewed.begin_replay())
    {
        Ok(exposure) => exposure,
        Err(error) => {
            return ReplayOutcome::Failed {
                responder,
                error: error.into(),
            }
        }
    };
    send_one(
        reply,
        responder,
        || exposure.sending(),
        |accepted| exposure.sent(accepted),
    );
    *last_response = Instant::now();
    exposure.updated();
    ReplayOutcome::Sent { terminate: false }
}
pub(super) async fn renew_and_acknowledge<P: ReplayPort>(
    replay: &mut VecDeque<CachedResponse>,
    ack: Option<u64>,
    operation: &Operation,
    port: &P,
) -> Result<()> {
    // Preserve renewal even for None or empty cache/source membership.
    let request = operation.begin_renew(None)?;
    port.renew(&request).await?;
    let renewed = request.returned()?;
    if let Some(rid) = ack {
        let request = renewed.begin_ack(rid)?;
        port.acknowledge(&request).await?;
        let acknowledged = request.returned()?;
        while replay
            .front()
            .is_some_and(|cached| cached.rid <= acknowledged.rid())
        {
            if let Some(cached) = replay.pop_front() {
                acknowledged.evicted();
                for receipt in cached.transport_receipts {
                    acknowledged.sending_receipt();
                    let accepted = receipt.send(()).is_ok();
                    acknowledged.receipt_sent(accepted);
                }
            }
        }
    }
    Ok(())
}
