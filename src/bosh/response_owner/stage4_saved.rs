//! Test-only BOSH ownership over finite IO/repository replies.
#![cfg(test)]
use super::*;
use crate::bosh::ownership::{
    self, OperationRunner, Output, RecordPort, ServiceTransfer, TransferPort,
};
use crate::services::{
    mix::{MixRepository, MixService},
    replay::ReplayService,
    sm_capacity::SmCapacityMetrics,
};
use crate::stage4_replay as wire;
use crate::xmpp::auth_publication::stage4_saved::{
    facts as observed, AuthRead, Capture, Publisher,
};
use anyhow::{ensure, Result};
use northstar_delivery_core::bosh_ownership::{OperationKind, Scope};
use std::task::Poll;
use uuid::Uuid;
mod facts;
#[cfg(test)]
mod ordinary;
mod repository;
pub(crate) type Driven<T> = std::result::Result<Result<T>, wire::BudgetStop>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BoshSite(wire::PollSite);
impl BoshSite {
    pub(crate) fn new(ordinal: u8) -> std::result::Result<Self, wire::DriverConfigurationError> {
        wire::PollSite::new(wire::DriverOwner::Bosh, ordinal).map(Self)
    }
}

/// Finite actor fields, never a fake AppState or another BOSH policy engine.
/// Observational item keys contain values only; they grant no transfer rights.
pub(crate) struct Session {
    input: wire::BoshSessionInput,
    output: VecDeque<OutboundItem>,
    output_bytes: usize,
    replay: VecDeque<CachedResponse>,
    governor: Arc<SmMemoryGovernor>,
    last_response: Instant,
    highest_responded: u64,
    observed_items: Vec<(
        u8,
        String,
        Option<crate::outbound::TransportOwnershipSource>,
        Option<Uuid>,
    )>,
    observed_items_valid: bool,
    auth_lane: bool,
    reads: Vec<AuthRead>,
    publisher: Publisher,
    recorder: Capture,
    used_response: bool,
    used_ack: bool,
    last_selection: Option<SelectionObservation>,
}
pub(crate) struct ResponseRun {
    pub(crate) returned: Option<bool>,
    pub(crate) dropped: bool,
}
impl Session {
    pub(crate) fn new(input: wire::BoshSessionInput, recorder: Capture) -> Result<Self> {
        let g = &input.governor;
        let governor = SmMemoryGovernor::new(
            g.max_bytes as usize,
            g.max_recovery_bytes as usize,
            g.max_recovery_jobs as usize,
            g.max_snapshot_bytes as usize,
            Arc::new(SmCapacityMetrics::default()),
        )?;
        Ok(Self {
            input,
            output: VecDeque::new(),
            output_bytes: 0,
            replay: VecDeque::new(),
            governor,
            last_response: Instant::now(),
            highest_responded: 0,
            observed_items: vec![],
            observed_items_valid: true,
            auth_lane: false,
            reads: vec![],
            publisher: Publisher::empty(),
            recorder,
            used_response: false,
            used_ack: false,
            last_selection: None,
        })
    }
    pub(crate) fn session_id(&self) -> Uuid {
        self.input.session_id.0
    }
    pub(crate) fn connection_id(&self) -> Uuid {
        self.input.connection_id.0
    }
    fn key(
        item: &OutboundItem,
    ) -> (
        String,
        Option<crate::outbound::TransportOwnershipSource>,
        Option<Uuid>,
    ) {
        (
            item.stanza.clone(),
            item.durable_source,
            item.auth_publication()
                .and_then(|h| h.join_observation().snapshot().introduced)
                .map(|j| j.control),
        )
    }
    fn register_key(
        &mut self,
        (xml, source, control): (
            String,
            Option<crate::outbound::TransportOwnershipSource>,
            Option<Uuid>,
        ),
        ordinal: u8,
    ) {
        if !self.observed_items_valid
            || self.observed_items.len() >= 4
            || self
                .observed_items
                .iter()
                .any(|(o, x, s, c)| *o == ordinal || (x == &xml && *s == source && *c == control))
        {
            self.observed_items_valid = false;
            observed::lost(&self.recorder);
            return;
        }
        self.observed_items.push((ordinal, xml, source, control));
    }
    fn ordinal(&self, item: &OutboundItem) -> Result<u8> {
        ensure!(
            self.observed_items_valid,
            "ambiguous actual FIFO observation"
        );
        let (xml, source, control) = Self::key(item);
        let matches: Vec<_> = self
            .observed_items
            .iter()
            .filter(|(_, x, s, c)| x == &xml && *s == source && *c == control)
            .collect();
        ensure!(
            matches.len() == 1,
            "actual FIFO item has missing or ambiguous ordinal"
        );
        Ok(matches[0].0)
    }
    fn push(&mut self, item: OutboundItem, ordinal: u8) -> Result<()> {
        self.register_key(Self::key(&item), ordinal);
        let mut output = Output {
            items: &mut self.output,
            bytes: &mut self.output_bytes,
            max_stanzas: 4,
            max_bytes: self.input.max_output_bytes as usize,
        };
        ensure!(
            output.push(item),
            "bounded actual FIFO refused supplied item"
        );
        Ok(())
    }
    pub(crate) fn push_plain(&mut self, actual_xml: String, ordinal: u8) -> Result<()> {
        self.push(OutboundItem::plain(actual_xml), ordinal)
    }
    pub(crate) fn push_auth(
        &mut self,
        item: OutboundItem,
        read: AuthRead,
        publisher: Publisher,
        ordinal: u8,
    ) -> Result<()> {
        let holder = item
            .auth_publication()
            .ok_or_else(|| anyhow::anyhow!("actual item missing holder"))?;
        holder.validate_connection(self.connection_id())?;
        match holder.join_observation().snapshot().introduced {
            Some(actual)
                if actual.control == read.control()
                    && publisher.contains_control(actual.control) => {}
            _ => observed::lost(&self.recorder),
        }
        if self.reads.iter().any(|r| r.control() == read.control()) {
            observed::lost(&self.recorder);
        }
        self.push(item, ordinal)?;
        self.auth_lane = true;
        if self.reads.len() < 2 {
            self.reads.push(read);
        } else {
            observed::lost(&self.recorder);
        }
        self.publisher.append(publisher)
    }
    pub(crate) async fn push_mix<R: MixRepository>(
        &mut self,
        item: OutboundItem,
        ordinal: u8,
        site: BoshSite,
        service: &MixService<R>,
    ) -> Driven<bool> {
        let owner_ordinal = site.0.owner_ordinal();
        if item.auth_publication().is_some() {
            return Ok(Err(anyhow::anyhow!("MIX lane contains auth holder")));
        }
        let association = observed::project(&self.recorder, || {
            Ok(wire::BoshAssociation::Outbound(observed::queue_item(
                &item,
                self.connection_id(),
                ordinal,
            )?))
        });
        let operation = Operation::new(Scope {
            session_id: self.session_id(),
            ttl_seconds: self.input.ttl_seconds,
            kind: OperationKind::Outbound,
        });
        self.capture_operation(
            &operation,
            owner_ordinal,
            &association,
            wire::Cut::Introduction,
        );
        struct Unmanaged;
        impl RecordPort for Unmanaged {
            async fn record(&mut self, _: &OutboundItem) -> Result<bool> {
                Ok(false)
            }
        }
        struct ObservedTransfer<'a, R> {
            service: &'a MixService<R>,
            recorder: Capture,
            ordinal: u8,
        }
        impl<R: MixRepository> TransferPort for ObservedTransfer<'_, R> {
            async fn transfer(
                &self,
                request: &northstar_delivery_core::bosh_ownership::TransferRequest,
            ) -> Result<crate::outbound::MixDelivery> {
                let capture = |returned_source| {
                    observed::emit(
                        &self.recorder,
                        wire::Fact::Bosh(wire::BoshFact::Transfer(wire::BoshTransferCall {
                            owner_ordinal: self.ordinal,
                            source: observed::mix(request.source()),
                            returned_source,
                        })),
                    )
                };
                capture(wire::Nullable::Null(()));
                let returned = ServiceTransfer {
                    service: self.service,
                }
                .transfer(request)
                .await;
                capture(observed::nullable(
                    returned.as_ref().ok().copied().map(observed::mix),
                ));
                returned
            }
        }
        let mut unmanaged = Unmanaged;
        let transfer_recorder = self.recorder.clone();
        let driver_recorder = self.recorder.clone();
        let (result, returned) = {
            let mut output = Output {
                items: &mut self.output,
                bytes: &mut self.output_bytes,
                max_stanzas: 2,
                max_bytes: self.input.max_output_bytes as usize,
            };
            let mut returned = None;
            let mut call = Box::pin(OperationRunner::new(
                operation.clone(),
                tokio::time::timeout(crate::bosh::BOSH_BACKEND_OPERATION_TIMEOUT, async {
                    let result = ownership::record_and_push(
                        &mut output,
                        item,
                        &operation,
                        &mut unmanaged,
                        &ObservedTransfer {
                            service,
                            recorder: transfer_recorder,
                            ordinal: owner_ordinal,
                        },
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("actual BOSH item transfer failed"));
                    let accepted = result.as_ref().is_ok_and(|accepted| *accepted);
                    returned = Some(result);
                    accepted
                }),
            ));
            let result = std::future::poll_fn(|cx| {
                match wire::driver::poll_once(&driver_recorder, site.0, call.as_mut(), cx) {
                    Ok(actual) => actual.map(Ok),
                    Err(stop) => Poll::Ready(Err(stop)),
                }
            })
            .await;
            drop(call);
            (result, returned)
        };
        self.capture_operation(
            &operation,
            owner_ordinal,
            &association,
            wire::Cut::AfterRunnerDrop,
        );
        let result = match result {
            Ok(actual) => actual,
            Err(stop) => return Err(stop),
        };
        if result.is_err() {
            return Ok(Err(anyhow::anyhow!("BOSH transfer timed out")));
        }
        let accepted = match returned {
            Some(Ok(actual)) => actual,
            Some(Err(error)) => return Ok(Err(error)),
            None => return Ok(Err(anyhow::anyhow!("BOSH transfer return missing"))),
        };
        if accepted {
            if let Some(key) = self.output.back().map(Self::key) {
                self.register_key(key, ordinal);
            } else {
                observed::lost(&self.recorder);
            }
        }
        Ok(Ok(accepted))
    }
    fn capture_operation(
        &self,
        operation: &Operation,
        ordinal: u8,
        association: &Option<wire::BoshAssociation<wire::EvidenceId>>,
        cut: wire::Cut,
    ) {
        let Some(association) = association else {
            observed::lost(&self.recorder);
            return;
        };
        observed::observe(&self.recorder, || {
            Ok(wire::Fact::Bosh(wire::BoshFact::Snapshot(
                wire::BoshCapture {
                    owner_ordinal: ordinal,
                    association: association.clone(),
                    cut,
                    snapshot: facts::snapshot(operation.snapshot())?,
                },
            )))
        })
    }
    pub(crate) fn capture(&self, cut: wire::Cut) {
        if cut != wire::Cut::AfterRunnerDrop {
            observed::observe(&self.recorder, || {
                let fifo = self
                    .output
                    .iter()
                    .map(|item| {
                        observed::queue_item(item, self.connection_id(), self.ordinal(item)?)
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(wire::Fact::Bosh(wire::BoshFact::Queue(
                    wire::BoshQueueCapture {
                        session: observed::id(self.session_id()),
                        connection: observed::id(self.connection_id()),
                        cut,
                        fifo: wire::List::new(fifo)?,
                        output_bytes: observed::count(self.output_bytes)?,
                        highest_responded: self.highest_responded,
                    },
                )))
            });
        }
        // Full response bytes appear once at accepted receiver and once in
        // actual cache. Do not repeat a ~16 KiB body at every read-only cut.
        if matches!(
            cut,
            wire::Cut::BeforePoll
                | wire::Cut::BeforeFinish
                | wire::Cut::AfterFinish
                | wire::Cut::AfterTeardown
        ) {
            observed::observe(&self.recorder, || {
                let entries = self
                    .replay
                    .iter()
                    .map(|cache| -> Result<_> {
                        Ok(wire::CacheEntry {
                            rid: cache.rid,
                            fingerprint: wire::Hex::of(&cache.fingerprint)?,
                            membership: facts::membership(&cache.durable_ownership)?,
                            body_hex: wire::Bytes::of(&cache.response.body)?,
                            response_bytes: observed::count(cache.response_bytes)?,
                            replays: u32::from(cache.replays),
                            transport_receipt_count: observed::count(
                                cache.transport_receipts.len(),
                            )?,
                        })
                    })
                    .collect::<Result<_>>()?;
                Ok(wire::Fact::Bosh(wire::BoshFact::Cache(
                    wire::CacheCapture {
                        session: observed::id(self.session_id()),
                        connection: observed::id(self.connection_id()),
                        cut,
                        entries: wire::List::new(entries)?,
                    },
                )))
            });
        }
        for read in &self.reads {
            read.capture(cut);
        }
    }
    fn request_association(
        &self,
        input: &wire::BoshRequest,
        request: &BoshRequest,
    ) -> Result<wire::BoshAssociation<wire::EvidenceId>> {
        Ok(wire::BoshAssociation::Request(
            wire::BoshRequestAssociation {
                session: observed::id(self.session_id()),
                connection: wire::Nullable::Value(observed::id(self.connection_id())),
                rid: request.rid,
                ack: observed::nullable(request.ack),
                sid: observed::nullable(request.sid.as_ref().map(wire::Text::new).transpose()?),
                fingerprint: wire::Hex::of(&request.fingerprint)?,
                request_xml: input.request_xml.clone(),
            },
        ))
    }
    fn responders(
        input: &wire::BoshRequest,
    ) -> (
        Vec<Responder>,
        Vec<(u8, oneshot::Receiver<BoshHttpResponse>)>,
    ) {
        let mut senders = vec![];
        let mut receivers = vec![];
        for (ordinal, behavior) in input.responders.as_slice().iter().enumerate() {
            let (sender, receiver) = oneshot::channel();
            senders.push(sender);
            match behavior {
                wire::Responder::Open => receivers.push((ordinal as u8, receiver)),
                wire::Responder::Dropped => drop(receiver),
            }
        }
        (senders, receivers)
    }
    fn capture_receivers(
        &self,
        receivers: &mut [(u8, oneshot::Receiver<BoshHttpResponse>)],
        owner: u8,
        rid: u64,
    ) {
        for (ordinal, receiver) in receivers {
            observed::observe(&self.recorder, || {
                let result = match receiver.try_recv() {
                    Ok(response) => wire::ResponseResult::Received(wire::BodyBytes {
                        body_hex: wire::Bytes::of(&response.body)?,
                    }),
                    Err(oneshot::error::TryRecvError::Empty) => {
                        wire::ResponseResult::Empty(wire::Empty {})
                    }
                    Err(oneshot::error::TryRecvError::Closed) => {
                        wire::ResponseResult::Closed(wire::Empty {})
                    }
                };
                Ok(wire::Fact::Bosh(wire::BoshFact::Receiver(
                    wire::BoshResponseReceiver {
                        session: observed::id(self.session_id()),
                        connection: wire::Nullable::Value(observed::id(self.connection_id())),
                        owner_ordinal: owner,
                        rid,
                        receiver_ordinal: *ordinal,
                        result,
                    },
                )))
            });
        }
    }
    pub(crate) async fn respond(
        &mut self,
        site: BoshSite,
        drive: wire::AuthDrive,
    ) -> Driven<ResponseRun> {
        let owner_ordinal = site.0.owner_ordinal();
        if self.used_response {
            return Ok(Err(anyhow::anyhow!("finite session response repeated")));
        }
        self.used_response = true;
        let input = self.input.response.clone();
        let request = match crate::bosh::parse_body(input.request_xml.as_str(), 4) {
            Ok(request) => request,
            Err(e) => return Ok(Err(anyhow::anyhow!("BOSH request parse: {e}"))),
        };
        let association = observed::project(&self.recorder, || {
            self.request_association(&input, &request)
        });
        let operation = Operation::new(Scope {
            session_id: self.session_id(),
            ttl_seconds: self.input.ttl_seconds,
            kind: OperationKind::Request,
        });
        let service = ReplayService::new(
            repository::Repository {
                session: self.session_id(),
                ordinal: owner_ordinal,
                bind: self.input.bind.clone(),
                ack: None,
                recorder: self.recorder.clone(),
                used: Arc::new(std::sync::Mutex::new([false; 3])),
            },
            "stage4.example.test",
            1,
        );
        self.capture(wire::Cut::BeforePoll);
        self.capture_operation(
            &operation,
            owner_ordinal,
            &association,
            wire::Cut::Introduction,
        );
        let recorder = self.recorder.clone();
        let paused_reads = self.reads.clone();
        let operation_child = operation.clone();
        let association_child = association.clone();
        let mut call = Box::pin(OperationRunner::new(
            operation.clone(),
            tokio::time::timeout(crate::bosh::BOSH_BACKEND_OPERATION_TIMEOUT, async {
                let result: Result<bool> = async {
                    let mut fields = Fields {
                        output: &mut self.output,
                        output_bytes: &mut self.output_bytes,
                        replay: &mut self.replay,
                        governor: &self.governor,
                        max_response_bytes: self.input.max_response_bytes as usize,
                        max_output_stanzas: 4,
                        content_type: input.content_type.as_str(),
                        received_rid: Some(request.rid),
                    };
                    let bound = prepare(
                        &mut fields,
                        Metadata {
                            rid: request.rid,
                            fingerprint: request.fingerprint,
                            cache: true,
                        },
                        None,
                        &operation_child,
                        &ServiceReplay { service: &service },
                    )
                    .await
                    .map_err(|f| f.error)?;
                    let selection = bound.selection_observation();
                    self.last_selection = Some(selection.clone());
                    let bound = bound.for_connection(self.connection_id())?;
                    observed::observe(&self.recorder, || {
                        facts::selection(selection.snapshot(), wire::Cut::BeforePublish)
                    });
                    let (responders, mut receivers) = Self::responders(&input);
                    let exposed = bound.expose(responders)?;
                    self.capture_receivers(&mut receivers, owner_ordinal, request.rid);
                    self.capture(wire::Cut::BeforePublish);
                    self.capture_operation(
                        &operation_child,
                        owner_ordinal,
                        &association_child,
                        wire::Cut::BeforePublish,
                    );
                    let session_id = self.session_id();
                    let recorder = self.recorder.clone();
                    let ready = exposed
                        .publish_authentication(|owners| {
                            self.publisher.publish(
                                owners,
                                Some(session_id),
                                Some(request.rid),
                                &recorder,
                            )
                        })
                        .await;
                    // This capture is outside the callback. In the exact later
                    // bypass mutant it records selected B still NotStarted.
                    observed::observe(&self.recorder, || {
                        facts::selection(selection.snapshot(), wire::Cut::BeforeFinish)
                    });
                    self.capture(wire::Cut::BeforeFinish);
                    self.capture_operation(
                        &operation_child,
                        owner_ordinal,
                        &association_child,
                        wire::Cut::BeforeFinish,
                    );
                    let Ok(ready) = ready else { return Ok(false) };
                    ready.finish(
                        &mut self.last_response,
                        &mut self.highest_responded,
                        &mut self.replay,
                    )?;
                    self.capture(wire::Cut::AfterFinish);
                    self.capture_operation(
                        &operation_child,
                        owner_ordinal,
                        &association_child,
                        wire::Cut::AfterFinish,
                    );
                    Ok(true)
                }
                .await;
                if result.is_err() {
                    observed::lost(&self.recorder);
                }
                result.unwrap_or(false)
            }),
        ));
        let polled = std::future::poll_fn(|cx| match wire::driver::poll_once(&recorder, site.0, call.as_mut(), cx) {
            Err(stop) => Poll::Ready(Err(stop)),
            Ok(Poll::Ready(actual)) => Poll::Ready(Ok(Poll::Ready(actual))),
            Ok(Poll::Pending) if drive == wire::AuthDrive::DropPublicationCommit && paused_reads.iter().any(|read| read.live_snapshot().publication == crate::services::authentication::publication::Knowledge::CommitCallEntered) => Poll::Ready(Ok(Poll::Pending)),
            Ok(Poll::Pending) => Poll::Pending,
        }).await;
        let polled = match polled {
            Ok(actual) => actual,
            Err(stop) => {
                drop(call);
                self.capture(wire::Cut::AfterRunnerDrop);
                self.capture_operation(
                    &operation,
                    owner_ordinal,
                    &association,
                    wire::Cut::AfterRunnerDrop,
                );
                for read in &self.reads {
                    read.capture_frame_quiescent(wire::Cut::AfterRunnerDrop);
                }
                return Err(stop);
            }
        };
        let (returned, dropped) = match polled {
            Poll::Ready(Ok(value)) => (Some(value), false),
            Poll::Ready(Err(_)) => {
                observed::lost(&recorder);
                (None, false)
            }
            Poll::Pending => (None, true),
        };
        // All mutable futures are still owned by call and are not being polled.
        // No production/helper task is spawned by this finite adapter. The
        // clones below are inert reads, not retained runnable continuations.
        if dropped {
            for read in &paused_reads {
                read.capture(wire::Cut::AfterPoll);
                read.capture_frame_quiescent(wire::Cut::AfterPoll);
            }
            if drive == wire::AuthDrive::DropPublicationCommit && !paused_reads.iter().any(|read| read.live_snapshot().publication == crate::services::authentication::publication::Knowledge::CommitCallEntered) { observed::lost(&recorder); }
        }
        // No retained spawned task exists. Dropping this owning future drops
        // its publication runner and COMMIT child before OperationRunner retires.
        drop(call);
        if dropped && drive != wire::AuthDrive::DropPublicationCommit {
            observed::lost(&recorder);
        }
        self.capture(wire::Cut::AfterRunnerDrop);
        self.capture_operation(
            &operation,
            owner_ordinal,
            &association,
            wire::Cut::AfterRunnerDrop,
        );
        for read in &self.reads {
            read.capture_frame_quiescent(wire::Cut::AfterRunnerDrop);
        }
        Ok(Ok(ResponseRun { returned, dropped }))
    }
    pub(crate) async fn acknowledge(
        &mut self,
        input: &wire::BoshAckInput,
        site: BoshSite,
    ) -> Driven<()> {
        let owner_ordinal = site.0.owner_ordinal();
        if !(self.used_response && !self.used_ack && self.output.is_empty() && !self.auth_lane) {
            return Ok(Err(anyhow::anyhow!(
                "ACK requires the one completed independent MIX response with empty FIFO"
            )));
        }
        self.used_ack = true;
        let request = match crate::bosh::parse_body(input.request.request_xml.as_str(), 4) {
            Ok(request) => request,
            Err(e) => return Ok(Err(anyhow::anyhow!("BOSH ACK parse: {e}"))),
        };
        if request.ack != Some(input.acknowledged_rid) {
            return Ok(Err(anyhow::anyhow!("actual ACK field mismatch")));
        }
        if !crate::bosh::valid_client_response_ack(
            true,
            self.highest_responded,
            request.rid,
            request.ack,
        ) {
            return Ok(Err(anyhow::anyhow!(
                "actual ACK is outside responded RID window"
            )));
        }
        let association = observed::project(&self.recorder, || {
            self.request_association(&input.request, &request)
        });
        let operation = Operation::new(Scope {
            session_id: self.session_id(),
            ttl_seconds: self.input.ttl_seconds,
            kind: OperationKind::Request,
        });
        let service = ReplayService::new(
            repository::Repository {
                session: self.session_id(),
                ordinal: owner_ordinal,
                bind: self.input.bind.clone(),
                ack: Some(input.clone()),
                recorder: self.recorder.clone(),
                used: Arc::new(std::sync::Mutex::new([false; 3])),
            },
            "stage4.example.test",
            1,
        );
        self.capture_operation(
            &operation,
            owner_ordinal,
            &association,
            wire::Cut::Introduction,
        );
        let mut returned = None;
        let recorder = self.recorder.clone();
        let mut call = Box::pin(OperationRunner::new(
            operation.clone(),
            tokio::time::timeout(crate::bosh::BOSH_BACKEND_OPERATION_TIMEOUT, async {
                let result: Result<()> = async {
                    renew_and_acknowledge(
                        &mut self.replay,
                        request.ack,
                        &operation,
                        &ServiceReplay { service: &service },
                    )
                    .await?;
                    // Normal empty response helper path, with no pause substitute.
                    // Immediate response is a supplied helper environment (the
                    // actor's hold=0/no prior empty-poll violation corresponds);
                    // this does not execute actor admission/holding policy.
                    let mut fields = Fields {
                        output: &mut self.output,
                        output_bytes: &mut self.output_bytes,
                        replay: &mut self.replay,
                        governor: &self.governor,
                        max_response_bytes: self.input.max_response_bytes as usize,
                        max_output_stanzas: 2,
                        content_type: input.request.content_type.as_str(),
                        received_rid: Some(request.rid),
                    };
                    let bound = prepare(
                        &mut fields,
                        Metadata {
                            rid: request.rid,
                            fingerprint: request.fingerprint,
                            cache: true,
                        },
                        None,
                        &operation,
                        &ServiceReplay { service: &service },
                    )
                    .await
                    .map_err(|f| f.error)?;
                    let selection = bound.selection_observation();
                    self.last_selection = Some(selection.clone());
                    let bound = bound.for_connection(self.connection_id())?;
                    observed::observe(&self.recorder, || {
                        facts::selection(selection.snapshot(), wire::Cut::BeforePublish)
                    });
                    let (responders, mut receivers) = Self::responders(&input.request);
                    let exposed = bound.expose(responders)?;
                    self.capture_receivers(&mut receivers, owner_ordinal, request.rid);
                    let session_id = self.session_id();
                    let recorder = self.recorder.clone();
                    let ready = exposed
                        .publish_authentication(|owners| {
                            self.publisher.publish(
                                owners,
                                Some(session_id),
                                Some(request.rid),
                                &recorder,
                            )
                        })
                        .await?;
                    observed::observe(&self.recorder, || {
                        facts::selection(selection.snapshot(), wire::Cut::BeforeFinish)
                    });
                    self.capture_operation(
                        &operation,
                        owner_ordinal,
                        &association,
                        wire::Cut::BeforeFinish,
                    );
                    self.capture(wire::Cut::BeforeFinish);
                    ready.finish(
                        &mut self.last_response,
                        &mut self.highest_responded,
                        &mut self.replay,
                    )?;
                    self.capture(wire::Cut::AfterFinish);
                    Ok(())
                }
                .await;
                let ok = result.is_ok();
                returned = Some(result);
                ok
            }),
        ));
        let result = std::future::poll_fn(|cx| {
            match wire::driver::poll_once(&recorder, site.0, call.as_mut(), cx) {
                Ok(actual) => actual.map(Ok),
                Err(stop) => Poll::Ready(Err(stop)),
            }
        })
        .await;
        drop(call);
        self.capture_operation(
            &operation,
            owner_ordinal,
            &association,
            wire::Cut::AfterRunnerDrop,
        );
        let actual = match result {
            Ok(actual) => actual,
            Err(stop) => return Err(stop),
        };
        if let Err(error) = actual {
            return Ok(Err(error.into()));
        }
        Ok(returned.unwrap_or_else(|| Err(anyhow::anyhow!("actual BOSH ACK return absent"))))
    }
    pub(crate) fn teardown(mut self) -> Result<()> {
        self.capture(wire::Cut::BeforeTeardown);
        self.output.clear();
        self.output_bytes = 0;
        self.replay.clear();
        self.publisher = Publisher::empty();
        // Only inert read cells remain. B's queued-pending cut above is distinct
        // from this later real holder destruction and Abandoned terminal.
        self.capture(wire::Cut::AfterTeardown);
        Ok(())
    }
}
