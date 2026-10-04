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
                        // Retain capacity proportional to actual removals, not
                        // every selected peer on each successive rebuild.
                        let mut removed_indices = Vec::new();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::{
        DurableDelivery, DurableDeliverySuperseded, MixDelivery, TransportOwnershipSource as Source,
    };
    use northstar_delivery_core::bosh_ownership::{OperationKind, Scope, Terminal};
    use std::{
        collections::BTreeSet,
        pin::Pin,
        sync::Mutex,
        task::{Context, Poll, Waker},
    };
    use uuid::Uuid;

    fn operation() -> Operation {
        Operation::new(Scope {
            session_id: Uuid::from_u128(501),
            ttl_seconds: 600,
            kind: OperationKind::Request,
        })
    }
    fn c2s(id: u128) -> DurableDelivery {
        DurableDelivery {
            recipient_id: Uuid::from_u128(502),
            message_id: Uuid::from_u128(id),
            claim_id: Some(Uuid::from_u128(503)),
        }
    }
    fn mix() -> MixDelivery {
        MixDelivery {
            delivery_id: Uuid::from_u128(504),
            lease_token: Uuid::from_u128(505),
        }
    }
    fn request(rid: u64) -> BoshRequest {
        super::super::parse_body(
            &format!(
                "<body xmlns='http://jabber.org/protocol/httpbind' rid='{rid}' sid='fixture'/>"
            ),
            64,
        )
        .unwrap()
    }
    fn metadata(rid: u64) -> Metadata {
        Metadata {
            rid,
            fingerprint: request(rid).fingerprint,
            cache: true,
        }
    }
    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }
    fn membership(sources: &[Source]) -> BoshResponseOwnership {
        BoshResponseOwnership {
            c2s_message_ids: sources
                .iter()
                .filter_map(|source| source.c2s().map(|source| source.message_id))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            mix_delivery_ids: sources
                .iter()
                .filter_map(|source| source.mix().map(|source| source.delivery_id))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        }
    }
    #[derive(Clone, Copy, Default, Eq, PartialEq)]
    enum Cut {
        #[default]
        Success,
        BeforeCommit,
        DuringCommit,
        CommitError,
        AfterReceiptPending,
        AfterReceiptError,
        BareSuccess,
        WrongReturn,
        WrongReceipt,
        Superseded,
        SupersededAfterEntry,
        SupersededAfterReceipt,
        SupersededMissing,
    }
    struct FakeReplay {
        binds: Mutex<VecDeque<Cut>>,
        renew: Cut,
        ack: Cut,
        deleted: Vec<response::DeletedSource>,
        events: Mutex<Vec<&'static str>>,
        bound_sources: Mutex<Vec<Vec<Source>>>,
        expected: Mutex<Vec<Option<(u64, BoshResponseOwnership)>>>,
        other: Operation,
    }
    impl Default for FakeReplay {
        fn default() -> Self {
            Self {
                binds: Mutex::new(VecDeque::new()),
                renew: Cut::Success,
                ack: Cut::Success,
                deleted: vec![],
                events: Mutex::new(vec![]),
                bound_sources: Mutex::new(vec![]),
                expected: Mutex::new(vec![]),
                other: operation(),
            }
        }
    }
    impl FakeReplay {
        fn bind_cuts(cuts: impl IntoIterator<Item = Cut>) -> Self {
            Self {
                binds: Mutex::new(cuts.into_iter().collect()),
                ..Self::default()
            }
        }
        async fn commit(&self, cut: Cut, event: &'static str) -> std::io::Result<()> {
            self.events.lock().unwrap().push(event);
            if cut == Cut::DuringCommit {
                std::future::pending::<()>().await;
            }
            if cut == Cut::CommitError || cut == Cut::SupersededAfterEntry {
                return Err(std::io::Error::other("controlled COMMIT reply loss"));
            }
            Ok(())
        }
        async fn after_receipt(cut: Cut) -> Result<()> {
            // These cuts are deliberately synthetic post-receipt continuations,
            // not additional awaits in the real SQL wrappers.
            if cut == Cut::AfterReceiptPending {
                std::future::pending::<()>().await;
            }
            if cut == Cut::AfterReceiptError {
                anyhow::bail!("controlled post-receipt error");
            }
            Ok(())
        }
    }
    impl ReplayPort for FakeReplay {
        async fn bind(&self, request: &BindRequest) -> Result<BoshResponseOwnership> {
            self.events.lock().unwrap().push("bind");
            request.validate_for_io()?;
            assert_eq!(request.session_id(), Uuid::from_u128(501));
            assert_eq!(request.ttl_seconds(), 600);
            self.bound_sources
                .lock()
                .unwrap()
                .push(request.sources().to_vec());
            let cut = self.binds.lock().unwrap().pop_front().unwrap_or_default();
            let receipt = membership(request.sources());
            let stale = || {
                request
                    .sources()
                    .iter()
                    .find_map(|source| source.c2s())
                    .unwrap()
                    .message_id
            };
            if cut == Cut::BeforeCommit {
                anyhow::bail!("controlled pre-COMMIT error");
            }
            if cut == Cut::Superseded || cut == Cut::SupersededMissing {
                return Err(DurableDeliverySuperseded {
                    message_id: if cut == Cut::SupersededMissing {
                        Uuid::nil()
                    } else {
                        stale()
                    },
                }
                .into());
            }
            if cut == Cut::BareSuccess {
                return Ok(receipt);
            }
            let other = if cut == Cut::WrongReceipt {
                Some(
                    self.other
                        .begin_response(
                            request.rid(),
                            ResponseKind::Payload,
                            request.sources().iter().copied().map(Some).collect(),
                        )?
                        .attempt(
                            request.sources().to_vec(),
                            request.sources().iter().copied().map(Some),
                        )?,
                )
            } else {
                None
            };
            let result = response::bind_commit_observed(
                self.commit(cut, "bind_commit"),
                other.as_ref().unwrap_or(request),
                receipt.clone(),
            )
            .await;
            if cut == Cut::SupersededAfterEntry || cut == Cut::SupersededAfterReceipt {
                if cut == Cut::SupersededAfterEntry {
                    assert!(result.is_err());
                } else {
                    result?;
                }
                return Err(DurableDeliverySuperseded {
                    message_id: stale(),
                }
                .into());
            }
            result?;
            Self::after_receipt(cut).await?;
            if cut == Cut::WrongReturn {
                return Ok(BoshResponseOwnership::default());
            }
            Ok(receipt)
        }
        async fn renew(&self, request: &RenewRequest) -> Result<()> {
            self.events.lock().unwrap().push("renew");
            request.validate_for_io()?;
            self.expected
                .lock()
                .unwrap()
                .push(request.expected().map(|(rid, value)| (rid, value.clone())));
            if self.renew == Cut::BeforeCommit {
                anyhow::bail!("renew pre-COMMIT");
            }
            if self.renew == Cut::BareSuccess {
                return Ok(());
            }
            let other = if self.renew == Cut::WrongReceipt {
                Some(
                    self.other.begin_renew(
                        request
                            .expected()
                            .map(|(rid, value)| (rid, Arc::new(value.clone()))),
                    )?,
                )
            } else {
                None
            };
            response::renew_commit_observed(
                self.commit(self.renew, "renew_commit"),
                other.as_ref().unwrap_or(request),
            )
            .await?;
            Self::after_receipt(self.renew).await
        }
        async fn acknowledge(&self, request: &AckRequest) -> Result<()> {
            self.events.lock().unwrap().push("ack");
            request.validate_for_io()?;
            if self.ack == Cut::BeforeCommit {
                anyhow::bail!("ACK pre-COMMIT");
            }
            if self.ack == Cut::BareSuccess {
                return Ok(());
            }
            let other = if self.ack == Cut::WrongReceipt {
                let renew = self.other.begin_renew(None)?;
                response::renew_commit_observed(async { Ok::<_, std::io::Error>(()) }, &renew)
                    .await?;
                Some(renew.returned()?.begin_ack(request.rid())?)
            } else {
                None
            };
            response::ack_commit_observed(
                self.commit(self.ack, "ack_commit"),
                other.as_ref().unwrap_or(request),
                self.deleted.clone(),
            )
            .await?;
            Self::after_receipt(self.ack).await
        }
        async fn release(&self, session_id: Uuid) -> Result<()> {
            assert_eq!(session_id, Uuid::from_u128(501));
            self.events.lock().unwrap().push("release");
            // Existing policy deliberately ignores this result. No release
            // receipt is fabricated in the observed response operation.
            anyhow::bail!("controlled ignored release error")
        }
    }
    struct Harness {
        output: VecDeque<OutboundItem>,
        bytes: usize,
        replay: VecDeque<CachedResponse>,
        governor: Arc<SmMemoryGovernor>,
        max_bytes: usize,
        max_stanzas: usize,
    }
    impl Harness {
        fn new(items: impl IntoIterator<Item = OutboundItem>) -> Self {
            let output: VecDeque<_> = items.into_iter().collect();
            let bytes = output.iter().map(|item| item.stanza.len()).sum();
            Self {
                output,
                bytes,
                replay: VecDeque::new(),
                governor: SmMemoryGovernor::new(
                    1024 * 1024,
                    256 * 1024,
                    16,
                    256 * 1024,
                    Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default()),
                )
                .unwrap(),
                max_bytes: 64 * 1024,
                max_stanzas: 512,
            }
        }
        async fn prepare(
            &mut self,
            operation: &Operation,
            port: &FakeReplay,
            rid: u64,
            condition: Option<&str>,
        ) -> Result<BoundResponse, PreparationFailure> {
            prepare(
                &mut Fields {
                    output: &mut self.output,
                    output_bytes: &mut self.bytes,
                    replay: &mut self.replay,
                    governor: &self.governor,
                    max_response_bytes: self.max_bytes,
                    max_output_stanzas: self.max_stanzas,
                    content_type: "text/xml; charset=utf-8",
                    received_rid: Some(rid),
                },
                metadata(rid),
                condition,
                operation,
                port,
            )
            .await
        }
    }
    fn durable_item(id: u128) -> OutboundItem {
        OutboundItem::durable(
            format!("<message id='{id}'><body>private payload</body></message>"),
            c2s(id),
        )
    }
    fn cache(rid: u64, receipts: Vec<mpsc::UnboundedSender<()>>) -> CachedResponse {
        CachedResponse {
            rid,
            fingerprint: request(rid).fingerprint,
            response: BoshHttpResponse {
                body: Bytes::from_static(
                    b"<body xmlns='http://jabber.org/protocol/httpbind'><message/></body>",
                ),
                content_type: "text/xml; charset=utf-8".to_owned(),
            },
            durable_ownership: Arc::new(BoshResponseOwnership::default()),
            transport_receipts: receipts,
            owned_at: Instant::now(),
            response_bytes: 64,
            replays: 0,
        }
    }
    fn body(response: &BoshHttpResponse) -> &str {
        std::str::from_utf8(&response.body).unwrap()
    }

    #[tokio::test]
    async fn exact_bind_exposure_and_cache_share_bytes_membership_and_real_receipts() {
        let operation = operation();
        let port = FakeReplay::default();
        let (receipt, mut received) = mpsc::unbounded_channel();
        let (mix_item, _handoff) =
            OutboundItem::durable_mix("<message id='mix'/>".to_owned(), mix());
        let mut harness = Harness::new([
            durable_item(506),
            OutboundItem::with_transport_receipt("<presence/>".to_owned(), receipt),
            mix_item,
        ]);
        let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
        assert!(harness.output.is_empty());
        assert_eq!(harness.bytes, 0);
        let debug = format!("{bound:?}");
        assert!(!debug.contains("private payload"));
        assert!(!debug.contains(&mix().lease_token.to_string()));
        assert_eq!(
            port.bound_sources.lock().unwrap()[0],
            [Source::C2s(c2s(506)), Source::Mix(mix())]
        );
        let retained = operation.snapshot();
        assert!(Arc::ptr_eq(
            retained.responses[0].attempts[0].returned.as_ref().unwrap(),
            &bound.ownership
        ));
        assert!(!Arc::ptr_eq(
            match &retained.responses[0].attempts[0].knowledge {
                response::BindKnowledge::ReceiptKnown(value) => value,
                _ => panic!("missing receipt"),
            },
            &bound.ownership
        ));
        let pointer = bound.response.body.as_ptr();
        let (first, first_rx) = oneshot::channel();
        let (second, second_rx) = oneshot::channel();
        let exposed = bound.expose(vec![first, second]).unwrap();
        assert!(exposed.any_accepted());
        assert!(harness.replay.is_empty());
        let first = first_rx.await.unwrap();
        let second = second_rx.await.unwrap();
        assert_eq!(first.body.as_ptr(), pointer);
        assert_eq!(second.body.as_ptr(), pointer);
        assert!(body(&first).contains("private payload"));
        assert!(received.try_recv().is_err());
        let mut last = Instant::now();
        let mut highest = 0;
        exposed
            .finish(&mut last, &mut highest, &mut harness.replay)
            .unwrap();
        assert_eq!(highest, 10);
        assert_eq!(harness.replay[0].response.body.as_ptr(), pointer);
        assert_eq!(harness.replay[0].transport_receipts.len(), 1);
        assert_eq!(operation.summary().responses.accepted_responders, 2);
        assert_eq!(operation.summary().responses.cached, 1);
        assert_eq!(*port.events.lock().unwrap(), ["bind", "bind_commit"]);
    }

    #[tokio::test]
    async fn bind_cut_owner_retains_unknown_or_receipt_without_exposure_or_cache() {
        for cut in [
            Cut::BeforeCommit,
            Cut::DuringCommit,
            Cut::CommitError,
            Cut::AfterReceiptPending,
            Cut::AfterReceiptError,
        ] {
            let operation = operation();
            let port = FakeReplay::bind_cuts([cut]);
            let mut harness = Harness::new([durable_item(506)]);
            let mut runner = Box::pin(super::super::ownership::OperationRunner::new(
                operation.clone(),
                tokio::time::timeout(super::super::BOSH_BACKEND_OPERATION_TIMEOUT, async {
                    harness.prepare(&operation, &port, 10, None).await.is_ok()
                }),
            ));
            let polled = poll_once(runner.as_mut());
            let pending = matches!(cut, Cut::DuringCommit | Cut::AfterReceiptPending);
            assert_eq!(polled.is_pending(), pending);
            if !pending {
                assert!(matches!(polled, Poll::Ready(Ok(false))));
            }
            drop(runner);
            assert!(harness.replay.is_empty());
            assert!(harness.output.is_empty());
            let summary = operation.summary();
            assert_eq!(
                summary.terminal,
                Some(if pending {
                    Terminal::Cancelled
                } else {
                    Terminal::Returned
                })
            );
            assert_eq!(
                summary.keep_running,
                if pending { None } else { Some(false) }
            );
            assert_eq!(
                summary.responses.bind_receipts,
                usize::from(matches!(
                    cut,
                    Cut::AfterReceiptPending | Cut::AfterReceiptError
                ))
            );
            assert_eq!(
                summary.responses.bind_unknown,
                usize::from(matches!(cut, Cut::DuringCommit | Cut::CommitError))
            );
            assert_eq!(summary.responses.accepted_responders, 0);
            assert_eq!(summary.responses.cached, 0);
        }
    }

    #[tokio::test]
    async fn bare_wrong_invocation_and_mismatched_bind_returns_cannot_expose() {
        for cut in [Cut::BareSuccess, Cut::WrongReceipt, Cut::WrongReturn] {
            let operation = operation();
            let port = FakeReplay::bind_cuts([cut]);
            let mut harness = Harness::new([durable_item(506)]);
            let failure = harness
                .prepare(&operation, &port, 10, None)
                .await
                .unwrap_err();
            let (tx, rx) = oneshot::channel();
            failure.send(vec![tx], "text/xml");
            let response = rx.await.unwrap();
            assert!(body(&response).contains("internal-server-error"));
            assert!(!body(&response).contains("private payload"));
            let snapshot = operation.snapshot();
            let attempt = &snapshot.responses[0].attempts[0];
            assert!(attempt.returned.is_some());
            assert!(!attempt.return_matches);
            assert_eq!(
                snapshot.summary().responses.bind_receipts,
                usize::from(cut == Cut::WrongReturn)
            );
            assert!(!snapshot.responses[0].exposure_entered);
            assert_eq!(snapshot.responses[0].control_accepted, 1);
            assert!(harness.replay.is_empty());
        }
    }

    #[tokio::test]
    async fn responder_refusal_and_abandoned_post_exposure_continuation_remain_distinct() {
        for abandon in [false, true] {
            let operation = operation();
            let port = FakeReplay::default();
            let mut harness = Harness::new([durable_item(506)]);
            let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
            let (tx, rx) = oneshot::channel();
            if !abandon {
                drop(rx);
            }
            let exposed = bound.expose(vec![tx]).unwrap();
            assert_eq!(exposed.any_accepted(), abandon);
            if abandon {
                // This is the real exposed continuation dropped at the actor's
                // existing later publication boundary, without a fake callback.
                drop(exposed);
                operation.retire(Terminal::Cancelled);
            } else {
                let mut last = Instant::now();
                let mut highest = 0;
                exposed
                    .finish(&mut last, &mut highest, &mut harness.replay)
                    .unwrap();
                assert_eq!(highest, 10);
            }
            assert_eq!(harness.replay.len(), usize::from(!abandon));
            let snapshot = operation.snapshot();
            assert_eq!(
                snapshot.responses[0].accepted_responders,
                usize::from(abandon)
            );
            assert_eq!(
                snapshot.responses[0].refused_responders,
                usize::from(!abandon)
            );
            assert_eq!(snapshot.responses[0].bookkeeping, !abandon);
        }
    }

    #[tokio::test]
    async fn typed_supersession_restores_peers_and_removes_every_matching_message() {
        // A controlled typed-adapter result exercises the actual restoration
        // predicate across duplicate IDs. Real bind SQL rejects duplicates
        // before row inspection; this is not a reachable SQL supersession case.
        let operation = operation();
        let port = FakeReplay::bind_cuts([Cut::Superseded]);
        let (receipt, mut received) = mpsc::unbounded_channel();
        let different_claim = DurableDelivery {
            recipient_id: Uuid::from_u128(599),
            claim_id: Some(Uuid::from_u128(598)),
            ..c2s(506)
        };
        let mut harness = Harness::new([
            OutboundItem::with_transport_receipt("<presence id='before'/>".to_owned(), receipt),
            durable_item(506),
            OutboundItem::durable(
                "<message id='same-id-other-claim'/>".to_owned(),
                different_claim,
            ),
            durable_item(507),
            OutboundItem::plain("<presence id='after'/>".to_owned()),
        ]);
        let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
        let text = body(&bound.response);
        assert!(!text.contains("id='506'"));
        assert!(!text.contains("same-id-other-claim"));
        assert!(text.find("before").unwrap() < text.find("507").unwrap());
        assert!(text.find("507").unwrap() < text.find("after").unwrap());
        assert_eq!(bound.receipts.len(), 1);
        assert!(received.try_recv().is_err());
        assert_eq!(bound.ownership.c2s_message_ids, [Uuid::from_u128(507)]);
        let snapshot = operation.snapshot();
        let attempts = &snapshot.responses[0].attempts;
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].removed_indices, [2, 1]);
        assert!(attempts[0].sources.is_none());
        assert!(attempts[0].restore_matches);
        assert_eq!(
            port.bound_sources.lock().unwrap()[1],
            [Source::C2s(c2s(507))]
        );
        assert_eq!(harness.bytes, 0);
    }

    #[tokio::test]
    async fn supersession_after_commit_knowledge_never_restores_or_rebuilds() {
        for cut in [Cut::SupersededAfterEntry, Cut::SupersededAfterReceipt] {
            let operation = operation();
            let port = FakeReplay::bind_cuts([cut]);
            let mut harness = Harness::new([
                durable_item(506),
                OutboundItem::plain("<presence/>".to_owned()),
            ]);
            assert!(harness.prepare(&operation, &port, 10, None).await.is_err());
            assert!(harness.output.is_empty());
            assert_eq!(harness.bytes, 0);
            let snapshot = operation.snapshot();
            let attempts = &snapshot.responses[0].attempts;
            assert_eq!(attempts.len(), 1);
            assert!(!attempts[0].restored);
            assert_eq!(
                snapshot.summary().responses.bind_unknown,
                usize::from(cut == Cut::SupersededAfterEntry)
            );
            assert_eq!(
                snapshot.summary().responses.bind_receipts,
                usize::from(cut == Cut::SupersededAfterReceipt)
            );
            assert_eq!(*port.events.lock().unwrap(), ["bind", "bind_commit"]);
        }
    }

    #[tokio::test]
    async fn missing_supersession_and_rebuild_exhaustion_preserve_actual_restoration() {
        for missing in [false, true] {
            let operation = operation();
            let port = FakeReplay::bind_cuts([if missing {
                Cut::SupersededMissing
            } else {
                Cut::Superseded
            }]);
            let mut harness = Harness::new([durable_item(506), durable_item(507)]);
            // Controlled exhaustion of the existing configurable loop guard;
            // no new production limit or alternate restoration algorithm.
            harness.max_stanzas = 0;
            assert!(harness.prepare(&operation, &port, 10, None).await.is_err());
            assert_eq!(harness.output.len(), if missing { 2 } else { 1 });
            assert_eq!(
                harness.bytes,
                harness
                    .output
                    .iter()
                    .map(|item| item.stanza.len())
                    .sum::<usize>()
            );
            let snapshot = operation.snapshot();
            let attempt = &snapshot.responses[0].attempts[0];
            assert!(attempt.restored);
            assert!(attempt.restore_matches);
            assert_eq!(attempt.removed_indices.len(), usize::from(!missing));
            assert_eq!(snapshot.responses[0].attempts.len(), 1);
        }
    }

    #[tokio::test]
    async fn repeated_single_removals_retain_linear_measured_vector_capacity() {
        for count in [16usize, 64] {
            let operation = operation();
            let port = FakeReplay::bind_cuts(std::iter::repeat_n(Cut::Superseded, count));
            let mut harness =
                Harness::new((0..count).map(|index| durable_item(1_000 + index as u128)));
            let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
            assert!(bound.ownership.is_empty());
            // Read the live retained allocation, not a Snapshot clone that
            // could shrink Vec spare capacity and conceal a quadratic history.
            let summary = operation.summary().responses;
            let mut one = Vec::<usize>::new();
            for index in 0..1 {
                one.push(index);
            }
            assert_eq!(summary.restored_indices, count);
            assert_eq!(summary.retained_removal_capacity, one.capacity() * count);
            assert!(summary.retained_removal_capacity < count * (count + 1) / 2);
            let snapshot = operation.snapshot();
            assert_eq!(snapshot.responses[0].attempts.len(), count + 1);
            assert!(snapshot.responses[0].attempts[..count]
                .iter()
                .all(|attempt| attempt.sources.is_none()));
            assert_eq!(snapshot.responses[0].lineage.len(), count);
            // This reports retained usize capacity only, not allocator/RSS.
            println!(
                "BOSH removal storage: count={count}, capacity={}, element_bytes={}",
                summary.retained_removal_capacity,
                std::mem::size_of::<usize>()
            );
        }
    }

    #[tokio::test]
    async fn malformed_output_restores_same_items_and_byte_limit_precedes_selection() {
        let operation = operation();
        let port = FakeReplay::default();
        let malformed = OutboundItem::plain("<message>".to_owned());
        let pointer = malformed.stanza.as_ptr();
        let mut harness = Harness::new([malformed, durable_item(506)]);
        assert!(harness.prepare(&operation, &port, 10, None).await.is_err());
        assert_eq!(harness.output.len(), 2);
        assert_eq!(harness.output[0].stanza.as_ptr(), pointer);
        assert_eq!(operation.snapshot().responses[0].construction_restored, 2);
        assert!(port.events.lock().unwrap().is_empty());
        let mut harness = Harness::new([durable_item(506)]);
        harness.max_bytes = 256;
        let bytes = harness.bytes;
        assert!(harness.prepare(&operation, &port, 11, None).await.is_err());
        assert_eq!(harness.output.len(), 1);
        assert_eq!(harness.bytes, bytes);
        assert!(port.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn plain_payload_and_pause_control_keep_distinct_no_bind_paths() {
        let operation = operation();
        let port = FakeReplay::default();
        let mut harness = Harness::new([OutboundItem::plain("<presence/>".to_owned())]);
        let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
        assert!(bound.ownership.is_empty());
        assert!(port.events.lock().unwrap().is_empty());
        drop(bound);
        let (tx, rx) = oneshot::channel();
        let mut last = Instant::now();
        let mut highest = 3;
        finish_empty_control(
            11,
            vec![tx],
            "text/xml",
            &mut last,
            &mut highest,
            &operation,
        );
        let empty = rx.await.unwrap();
        assert!(!body(&empty).contains("presence"));
        assert_eq!(highest, 11);
        assert!(harness.replay.is_empty());
        let snapshot = operation.snapshot();
        assert_eq!(snapshot.responses[1].kind, ResponseKind::EmptyControl);
        assert!(snapshot.responses[1].attempts.is_empty());
        assert_eq!(snapshot.responses[1].control_accepted, 1);
    }

    #[tokio::test]
    async fn unacknowledged_limit_preserves_release_before_terminal_without_bind() {
        let operation = operation();
        let port = FakeReplay::default();
        let mut harness = Harness::new([durable_item(506)]);
        for rid in [8, 9] {
            let mut cached = cache(rid, vec![]);
            cached.durable_ownership = Arc::new(BoshResponseOwnership {
                c2s_message_ids: vec![Uuid::from_u128(rid as u128)],
                mix_delivery_ids: vec![],
            });
            harness.replay.push_back(cached);
        }
        let failure = harness
            .prepare(&operation, &port, 10, None)
            .await
            .unwrap_err();
        assert!(matches!(failure.stage, FailureStage::Limit));
        assert_eq!(*port.events.lock().unwrap(), ["release"]);
        assert_eq!(harness.replay.len(), 2);
        assert!(harness.output.is_empty());
        assert!(operation.snapshot().responses[0].attempts.is_empty());
        let (tx, rx) = oneshot::channel();
        failure.send(vec![tx], "text/xml");
        assert!(body(&rx.await.unwrap()).contains("policy-violation"));
    }

    #[tokio::test]
    async fn cached_replay_renews_exact_membership_and_same_bytes_without_fresh_ack() {
        let operation = operation();
        let port = FakeReplay::default();
        let mut cached = cache(10, vec![]);
        cached.durable_ownership =
            Arc::new(membership(&[Source::C2s(c2s(506)), Source::Mix(mix())]));
        let expected = cached.durable_ownership.clone();
        let pointer = cached.response.body.as_ptr();
        let mut replay = VecDeque::from([cached]);
        let mut last = Instant::now();
        let (tx, rx) = oneshot::channel();
        assert!(matches!(
            replay_cached(&mut replay, &request(10), tx, &mut last, &operation, &port).await,
            ReplayOutcome::Sent { terminate: false }
        ));
        assert_eq!(rx.await.unwrap().body.as_ptr(), pointer);
        assert_eq!(replay[0].replays, 1);
        assert_eq!(
            *port.expected.lock().unwrap(),
            [Some((10, expected.as_ref().clone()))]
        );
        assert_eq!(*port.events.lock().unwrap(), ["renew", "renew_commit"]);
        let snapshot = operation.snapshot();
        assert!(snapshot.acknowledgements.is_empty());
        assert_eq!(snapshot.renewals[0].replay_accepted, 1);
        assert!(snapshot.renewals[0].replay_bookkeeping);
    }

    #[tokio::test]
    async fn replay_policy_controls_and_renewal_failure_never_expose_cached_payload() {
        for mode in 0..5 {
            let operation = operation();
            let port = FakeReplay {
                renew: if mode == 3 {
                    Cut::BareSuccess
                } else {
                    Cut::BeforeCommit
                },
                ..FakeReplay::default()
            };
            let mut cached = cache(10, vec![]);
            let mut input = request(10);
            if mode == 0 {
                input.fingerprint[0] ^= 1;
            }
            if mode == 1 {
                cached.replays = super::super::MAX_RESPONSE_REPLAYS;
            }
            if mode == 4 {
                input.rid = 11;
            }
            let mut replay = VecDeque::from([cached]);
            let mut last = Instant::now();
            let before_last = last;
            let (tx, mut rx) = oneshot::channel();
            match replay_cached(&mut replay, &input, tx, &mut last, &operation, &port).await {
                ReplayOutcome::Sent { terminate } => {
                    assert!(mode < 2 && terminate);
                    let response = rx.await.unwrap();
                    assert!(!body(&response).contains("<message"));
                    assert!(port.events.lock().unwrap().is_empty());
                    assert_eq!(
                        operation.snapshot().responses[0].kind,
                        ResponseKind::TerminalControl
                    );
                }
                ReplayOutcome::Failed {
                    responder,
                    error: _,
                } => {
                    assert!(mode == 2 || mode == 3);
                    assert!(rx.try_recv().is_err());
                    drop(responder);
                    assert_eq!(replay[0].replays, 1);
                    assert_eq!(operation.snapshot().renewals[0].replay_calls, 0);
                }
                ReplayOutcome::Miss(responder) => {
                    assert_eq!(mode, 4);
                    drop(responder);
                    assert!(port.events.lock().unwrap().is_empty());
                }
            }
            assert_eq!(last, before_last);
        }
    }

    #[tokio::test]
    async fn fresh_ack_renews_then_applies_cache_and_each_actual_receipt_result() {
        let operation = operation();
        let port = FakeReplay {
            deleted: vec![
                response::DeletedSource::C2s {
                    recipient_id: c2s(506).recipient_id,
                    message_id: c2s(506).message_id,
                },
                response::DeletedSource::Mix(mix()),
            ],
            ..FakeReplay::default()
        };
        let (good, mut got) = mpsc::unbounded_channel();
        let (closed, closed_rx) = mpsc::unbounded_channel();
        drop(closed_rx);
        let mut replay = VecDeque::from([cache(9, vec![good, closed]), cache(11, vec![])]);
        renew_and_acknowledge(&mut replay, Some(10), &operation, &port)
            .await
            .unwrap();
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].rid, 11);
        assert!(got.try_recv().is_ok());
        assert!(got.try_recv().is_err());
        assert_eq!(
            *port.events.lock().unwrap(),
            ["renew", "renew_commit", "ack", "ack_commit"]
        );
        let snapshot = operation.snapshot();
        let ack = &snapshot.acknowledgements[0];
        assert_eq!(ack.knowledge, response::Knowledge::ReceiptKnown);
        assert_eq!(ack.cache_evictions, 1);
        assert_eq!(ack.receipt_calls, 2);
        assert_eq!(ack.receipts_sent, 1);
        assert_eq!(ack.receipts_refused, 1);
        assert_eq!(snapshot.summary().responses.deleted, 2);
    }

    #[tokio::test]
    async fn none_and_empty_source_ack_preserve_existing_persistence_paths() {
        for ack in [None, Some(10)] {
            let operation = operation();
            let port = FakeReplay::default();
            let (tx, mut rx) = mpsc::unbounded_channel();
            let mut replay = VecDeque::from([cache(10, vec![tx])]);
            renew_and_acknowledge(&mut replay, ack, &operation, &port)
                .await
                .unwrap();
            assert_eq!(replay.is_empty(), ack.is_some());
            assert_eq!(rx.try_recv().is_ok(), ack.is_some());
            assert_eq!(operation.summary().responses.renew_receipts, 1);
            assert_eq!(
                operation.summary().responses.ack_receipts,
                usize::from(ack.is_some())
            );
            assert_eq!(operation.summary().responses.deleted, 0);
            assert_eq!(
                port.events.lock().unwrap().len(),
                if ack.is_some() { 4 } else { 2 }
            );
        }
    }

    #[tokio::test]
    async fn ack_or_renewal_unknown_mismatch_and_postreceipt_drop_preserve_cache() {
        for renewal in [false, true] {
            for cut in [
                Cut::BeforeCommit,
                Cut::DuringCommit,
                Cut::CommitError,
                Cut::AfterReceiptPending,
                Cut::AfterReceiptError,
                Cut::BareSuccess,
                Cut::WrongReceipt,
            ] {
                let operation = operation();
                let port = FakeReplay {
                    renew: if renewal { cut } else { Cut::Success },
                    ack: if renewal { Cut::Success } else { cut },
                    ..FakeReplay::default()
                };
                let (tx, mut rx) = mpsc::unbounded_channel();
                let mut replay = VecDeque::from([cache(10, vec![tx])]);
                let mut runner = Box::pin(super::super::ownership::OperationRunner::new(
                    operation.clone(),
                    tokio::time::timeout(super::super::BOSH_BACKEND_OPERATION_TIMEOUT, async {
                        renew_and_acknowledge(&mut replay, Some(10), &operation, &port)
                            .await
                            .is_ok()
                    }),
                ));
                let polled = poll_once(runner.as_mut());
                assert_eq!(
                    polled.is_pending(),
                    matches!(cut, Cut::DuringCommit | Cut::AfterReceiptPending)
                );
                drop(runner);
                assert_eq!(replay.len(), 1);
                assert!(rx.try_recv().is_err());
                let snapshot = operation.snapshot();
                assert_eq!(snapshot.summary().responses.evictions, 0);
                assert_eq!(snapshot.summary().responses.receipt_sends, 0);
                if renewal {
                    assert!(snapshot.acknowledgements.is_empty());
                    assert_eq!(
                        snapshot.summary().responses.renew_receipts,
                        usize::from(matches!(
                            cut,
                            Cut::AfterReceiptPending | Cut::AfterReceiptError
                        ))
                    );
                } else {
                    assert_eq!(
                        snapshot.summary().responses.ack_receipts,
                        usize::from(matches!(
                            cut,
                            Cut::AfterReceiptPending | Cut::AfterReceiptError
                        ))
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn real_resume_governor_holds_follow_shared_response_bytes_until_last_drop() {
        let operation = operation();
        let port = FakeReplay::default();
        let metrics = Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default());
        let governor =
            SmMemoryGovernor::new(1024 * 1024, 256 * 1024, 16, 256 * 1024, metrics.clone())
                .unwrap();
        let source = VecDeque::from([crate::outbound::SmUnackedStanza::plain(
            "<message><body>".to_owned() + &"x".repeat(4096) + "</body></message>",
        )]);
        let action = crate::xmpp::protocol::ResumePayload::from_sm_unacked(
            &governor,
            "<resumed xmlns='urn:xmpp:sm:3' h='0' previd='fixture'/>".to_owned(),
            vec![],
            &source,
            false,
        )
        .unwrap();
        let mut harness = Harness::new([]);
        harness.governor = governor;
        assert!(super::super::queue_bosh_resume_payload(
            &mut harness.output,
            &mut harness.bytes,
            16,
            64 * 1024,
            action.into_transport_parts()
        ));
        assert!(Arc::ptr_eq(
            harness.output[0].transient_sm_capacity.as_ref().unwrap(),
            harness.output[1].transient_sm_capacity.as_ref().unwrap()
        ));
        let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
        let retained = metrics
            .reserved_bytes
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(retained > 0);
        let (tx, rx) = oneshot::channel();
        let exposed = bound.expose(vec![tx]).unwrap();
        let transport = rx.await.unwrap();
        let pointer = transport.body.as_ptr();
        let mut last = Instant::now();
        let mut highest = 0;
        exposed
            .finish(&mut last, &mut highest, &mut harness.replay)
            .unwrap();
        assert_eq!(harness.replay[0].response.body.as_ptr(), pointer);
        assert_eq!(
            metrics
                .reserved_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            retained
        );
        harness.replay.clear();
        assert_eq!(
            metrics
                .reserved_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            retained
        );
        drop(transport);
        assert_eq!(
            metrics
                .reserved_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn real_governor_rejection_preserves_fifo_before_response_buffer_allocation() {
        let operation = operation();
        let port = FakeReplay::default();
        let metrics = Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default());
        let governor =
            SmMemoryGovernor::new(1024 * 1024, 256 * 1024, 16, 256 * 1024, metrics.clone())
                .unwrap();
        let hold = Arc::new(governor.try_reserve_transient(512).unwrap());
        let mut harness = Harness::new([OutboundItem::resume_fragment(
            "<presence/>".to_owned(),
            hold.clone(),
        )]);
        harness.governor = governor.clone();
        let blocker = governor.try_reserve_transient(1024 * 1024 - 512).unwrap();
        let pointer = harness.output[0].stanza.as_ptr();
        let before_bytes = harness.bytes;
        assert!(harness.prepare(&operation, &port, 10, None).await.is_err());
        assert_eq!(harness.output.len(), 1);
        assert_eq!(harness.output[0].stanza.as_ptr(), pointer);
        assert_eq!(harness.bytes, before_bytes);
        assert!(port.events.lock().unwrap().is_empty());
        assert!(operation.snapshot().responses[0].attempts.is_empty());
        drop(blocker);
        harness.output.clear();
        drop(hold);
        assert_eq!(
            metrics
                .reserved_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }
}
