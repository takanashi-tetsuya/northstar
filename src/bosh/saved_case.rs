//! Test-only bridge over the actor's actual item, response and cache helpers.
//! Request admission/HTTP/auth policy is outside this fixed controlled profile.
use super::{
    ownership, response_owner, BoshHttpResponse, BoshRequest, CachedResponse,
    BOSH_BACKEND_OPERATION_TIMEOUT,
};
use crate::{
    direct_replay as wire,
    outbound::{
        BoshResponseOwnership, MixDelivery, MixTransportCompletion, OutboundItem,
        TransportOwnershipSource as Source,
    },
    services::sm_capacity::SmMemoryGovernor,
};
use anyhow::{Context, Result};
use northstar_delivery_core::bosh_ownership::{self as core, response as response_core};
use std::{
    collections::VecDeque,
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::Poll,
    time::Instant,
};
use tokio::sync::{mpsc, oneshot};

type Sequence = Arc<Mutex<wire::Sequence>>;
fn next(sequence: &Sequence) -> u32 {
    sequence.lock().unwrap().next()
}
fn count(value: usize) -> u32 {
    u32::try_from(value).expect("bounded BOSH observation count")
}
fn source(value: MixDelivery) -> wire::Source {
    Source::Mix(value).into()
}
fn membership(value: &BoshResponseOwnership) -> wire::Membership {
    wire::Membership {
        c2s_message_ids: value
            .c2s_message_ids
            .iter()
            .copied()
            .map(wire::Id)
            .collect(),
        mix_delivery_ids: value
            .mix_delivery_ids
            .iter()
            .copied()
            .map(wire::Id)
            .collect(),
    }
}
fn actual_membership(value: &wire::Membership) -> BoshResponseOwnership {
    BoshResponseOwnership {
        c2s_message_ids: value.c2s_message_ids.iter().map(|id| id.0).collect(),
        mix_delivery_ids: value.mix_delivery_ids.iter().map(|id| id.0).collect(),
    }
}
fn deleted(value: response_core::DeletedSource) -> wire::DeletedSource {
    match value {
        response_core::DeletedSource::C2s {
            recipient_id,
            message_id,
        } => wire::DeletedSource::C2s {
            recipient_id: wire::Id(recipient_id),
            message_id: wire::Id(message_id),
        },
        response_core::DeletedSource::Mix(value) => wire::DeletedSource::Mix {
            delivery_id: wire::Id(value.delivery_id),
            lease_token: wire::Id(value.lease_token),
        },
    }
}
fn actual_deleted(value: &wire::DeletedSource) -> response_core::DeletedSource {
    match value {
        wire::DeletedSource::C2s {
            recipient_id,
            message_id,
        } => response_core::DeletedSource::C2s {
            recipient_id: recipient_id.0,
            message_id: message_id.0,
        },
        wire::DeletedSource::Mix {
            delivery_id,
            lease_token,
        } => response_core::DeletedSource::Mix(MixDelivery {
            delivery_id: delivery_id.0,
            lease_token: lease_token.0,
        }),
    }
}
fn knowledge(value: response_core::Knowledge) -> &'static str {
    match value {
        response_core::Knowledge::NoCommitRequested => "NoCommitRequested",
        response_core::Knowledge::CommitCallEntered => "CommitCallEntered",
        response_core::Knowledge::ReceiptKnown => "ReceiptKnown",
    }
}
fn expected(value: Option<(u64, &BoshResponseOwnership)>) -> Option<wire::BoshExpected> {
    value.map(|(rid, value)| wire::BoshExpected {
        rid,
        membership: membership(value),
    })
}
fn state(operation: &core::Operation) -> wire::BoshState {
    let value = operation.snapshot();
    wire::BoshState {
        scope: wire::BoshScope {
            session_id: wire::Id(value.scope.session_id),
            ttl_seconds: value.scope.ttl_seconds,
            kind: match value.scope.kind {
                core::OperationKind::Outbound => "Outbound",
                core::OperationKind::Request => "Request",
                core::OperationKind::HeldResponse => "HeldResponse",
            },
        },
        transfers: value
            .transfers
            .iter()
            .map(|value| wire::BoshTransferSnapshot {
                source: source(value.source),
                knowledge: match value.knowledge {
                    core::TransferKnowledge::NoCommitRequested => {
                        wire::BoshTransferKnowledge::NoCommitRequested
                    }
                    core::TransferKnowledge::CommitCallEntered(value) => {
                        wire::BoshTransferKnowledge::CommitCallEntered {
                            source: source(value),
                        }
                    }
                    core::TransferKnowledge::ReceiptKnown(value) => {
                        wire::BoshTransferKnowledge::ReceiptKnown {
                            source: source(value),
                        }
                    }
                },
                returned_source: value.returned_source.map(source),
                return_matches_receipt: value.return_matches_receipt,
                local_entered: value.local_entered,
                source_applied: value.source_applied,
                notification_attempted: value.notification_attempted,
                queue_accepted: value.queue_accepted,
            })
            .collect(),
        responses: value
            .responses
            .iter()
            .map(|value| wire::BoshResponseSnapshot {
                rid: value.rid,
                kind: match value.kind {
                    response_core::ResponseKind::Payload => "Payload",
                    response_core::ResponseKind::TerminalControl => "TerminalControl",
                    response_core::ResponseKind::EmptyControl => "EmptyControl",
                },
                lineage: value
                    .lineage
                    .iter()
                    .map(|value| value.map(Into::into))
                    .collect(),
                removed: value.removed.clone(),
                attempts: value
                    .attempts
                    .iter()
                    .map(|value| wire::BoshBindAttempt {
                        selected_end: value.selected_end.map(count),
                        selected_len: count(value.selected_len),
                        sources: value
                            .sources
                            .as_ref()
                            .map(|values| values.iter().copied().map(Into::into).collect()),
                        knowledge: match &value.knowledge {
                            response_core::BindKnowledge::NotRequired => {
                                wire::BoshBindKnowledge::NotRequired
                            }
                            response_core::BindKnowledge::NoCommitRequested => {
                                wire::BoshBindKnowledge::NoCommitRequested
                            }
                            response_core::BindKnowledge::CommitCallEntered(value) => {
                                wire::BoshBindKnowledge::CommitCallEntered {
                                    membership: membership(value),
                                }
                            }
                            response_core::BindKnowledge::ReceiptKnown(value) => {
                                wire::BoshBindKnowledge::ReceiptKnown {
                                    membership: membership(value),
                                }
                            }
                        },
                        returned: value.returned.as_ref().map(|value| membership(value)),
                        return_matches: value.return_matches,
                        superseded_message: value.superseded_message.map(wire::Id),
                        restored: value.restored,
                        restore_matches: value.restore_matches,
                        removed_indices: value.removed_indices.iter().copied().map(count).collect(),
                    })
                    .collect(),
                construction_restored: count(value.construction_restored),
                exposure_entered: value.exposure_entered,
                responder_calls: count(value.responder_calls),
                accepted_responders: count(value.accepted_responders),
                refused_responders: count(value.refused_responders),
                control_calls: count(value.control_calls),
                control_accepted: count(value.control_accepted),
                control_refused: count(value.control_refused),
                empty_cache_evictions: count(value.empty_cache_evictions),
                bookkeeping: value.bookkeeping,
                cached: value.cached,
            })
            .collect(),
        renewals: value
            .renewals
            .iter()
            .map(|value| wire::BoshRenewSnapshot {
                expected: expected(
                    value
                        .expected
                        .as_ref()
                        .map(|(rid, value)| (*rid, value.as_ref())),
                ),
                knowledge: knowledge(value.knowledge),
                returned: value.returned,
                return_matches: value.return_matches,
                ack_issued: value.ack_issued,
                replay_calls: count(value.replay_calls),
                replay_accepted: count(value.replay_accepted),
                replay_refused: count(value.replay_refused),
                replay_bookkeeping: value.replay_bookkeeping,
            })
            .collect(),
        acknowledgements: value
            .acknowledgements
            .iter()
            .map(|value| wire::BoshAckSnapshot {
                rid: value.rid,
                knowledge: knowledge(value.knowledge),
                deleted: value
                    .deleted
                    .as_ref()
                    .map(|values| values.iter().copied().map(deleted).collect()),
                returned: value.returned,
                return_matches: value.return_matches,
                cache_evictions: count(value.cache_evictions),
                receipt_calls: count(value.receipt_calls),
                receipts_sent: count(value.receipts_sent),
                receipts_refused: count(value.receipts_refused),
            })
            .collect(),
        terminal: value.terminal.map(|value| match value {
            core::Terminal::Returned => "Returned",
            core::Terminal::TimedOut => "TimedOut",
            core::Terminal::Cancelled => "Cancelled",
            core::Terminal::Panicked => "Panicked",
        }),
        keep_running: value.keep_running,
    }
}
struct OwnerLog {
    operation: core::Operation,
    index: u32,
    sequence: Sequence,
    association: Mutex<Option<wire::BoshAssociation>>,
    prefixes: Mutex<Vec<wire::BoshPrefix>>,
    polls: Mutex<Vec<wire::DriverPoll>>,
}
impl OwnerLog {
    fn new(
        session_id: uuid::Uuid,
        ttl_seconds: u64,
        kind: core::OperationKind,
        index: u32,
        sequence: Sequence,
    ) -> Self {
        // No retained item/request allocation precedes the existing timer.
        Self {
            operation: core::Operation::new(core::Scope {
                session_id,
                ttl_seconds,
                kind,
            }),
            index,
            sequence,
            association: Mutex::new(None),
            prefixes: Mutex::new(vec![]),
            polls: Mutex::new(vec![]),
        }
    }
    fn outbound(&self, index: usize, item: &OutboundItem) {
        *self.association.lock().unwrap() = Some(wire::BoshAssociation::Outbound {
            item_index: count(index),
            item: slot(item),
        });
    }
    fn request(&self, phase: &'static str, request: &BoshRequest) {
        *self.association.lock().unwrap() = Some(wire::BoshAssociation::Request {
            phase,
            rid: request.rid,
            ack: request.ack,
            sid: request.sid.clone(),
            fingerprint_hex: wire::hex(&request.fingerprint),
        });
    }
    fn prefix(&self) {
        self.prefixes.lock().unwrap().push(wire::BoshPrefix {
            seq: next(&self.sequence),
            state: state(&self.operation),
        });
    }
    fn evidence(&self) -> Result<wire::BoshOwnerEvidence> {
        Ok(wire::BoshOwnerEvidence {
            owner_index: self.index,
            association: self
                .association
                .lock()
                .unwrap()
                .clone()
                .context("BOSH child never captured its association")?,
            state: state(&self.operation),
            prefixes: self.prefixes.lock().unwrap().clone(),
            polls: self.polls.lock().unwrap().clone(),
        })
    }
}
struct Shared {
    sequence: Sequence,
    evidence: Mutex<wire::BoshEvidence>,
    pending_bind: AtomicBool,
}
impl Shared {
    fn cache(&self, cache: &VecDeque<CachedResponse>) {
        self.evidence
            .lock()
            .unwrap()
            .cache_history
            .push(wire::BoshCacheHistory {
                seq: next(&self.sequence),
                entries: cache
                    .iter()
                    .map(|entry| wire::BoshCacheEntry {
                        rid: entry.rid,
                        fingerprint_hex: wire::hex(&entry.fingerprint),
                        membership: membership(&entry.durable_ownership),
                        body_hex: wire::hex(&entry.response.body),
                        response_bytes: count(entry.response_bytes),
                        replays: u32::from(entry.replays),
                        transport_receipt_count: count(entry.transport_receipts.len()),
                    })
                    .collect(),
            });
    }
}
struct Port<'a> {
    shared: &'a Shared,
    owner: &'a OwnerLog,
    transfer: Option<&'a wire::MixTransfer>,
    bind: Option<&'a wire::Bind>,
    renewal: Option<wire::CommitCut>,
    ack: Option<&'a wire::FreshAck>,
}
impl Port<'_> {
    async fn commit(&self, cut: wire::CommitCut, bind: bool) -> Result<()> {
        // Called inside the actual wrapper's future, after COMMIT entry.
        self.owner.prefix();
        match cut {
            wire::CommitCut::Complete => Ok(()),
            wire::CommitCut::Error => anyhow::bail!("controlled BOSH COMMIT error"),
            wire::CommitCut::Pending => {
                if bind {
                    self.shared.pending_bind.store(true, Ordering::SeqCst);
                }
                std::future::pending().await
            }
        }
    }
}
impl ownership::TransferPort for Port<'_> {
    async fn transfer(&self, request: &core::TransferRequest) -> Result<MixDelivery> {
        let index = {
            let mut evidence = self.shared.evidence.lock().unwrap();
            let index = evidence.transfer_calls.len();
            evidence.transfer_calls.push(wire::BoshTransferCall {
                seq: next(&self.shared.sequence),
                owner_index: self.owner.index,
                source: source(request.source()),
                returned_source: None,
            });
            index
        };
        let result = async {
            anyhow::ensure!(
                self.shared.evidence.lock().unwrap().transfer_calls[..index]
                    .iter()
                    .all(|call| call.owner_index != self.owner.index),
                "repeated BOSH transfer call has no declared reply"
            );
            request.validate_for_io()?;
            let reply = self.transfer.context("unexpected BOSH MIX transfer")?;
            let Source::Mix(current) = reply.returned_source.actual() else {
                anyhow::bail!("non-MIX transfer result");
            };
            core::transfer_commit_observed(self.commit(reply.commit, false), request, current)
                .await
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            self.owner.prefix();
            Ok(current)
        }
        .await;
        self.shared.evidence.lock().unwrap().transfer_calls[index].returned_source =
            result.as_ref().ok().copied().map(source);
        result
    }
}
impl response_owner::ReplayPort for Port<'_> {
    async fn bind(&self, request: &response_core::BindRequest) -> Result<BoshResponseOwnership> {
        let index = {
            let mut evidence = self.shared.evidence.lock().unwrap();
            let index = evidence.bind_calls.len();
            evidence.bind_calls.push(wire::BoshBindCall {
                seq: next(&self.shared.sequence),
                owner_index: self.owner.index,
                rid: request.rid(),
                sources: request.sources().iter().copied().map(Into::into).collect(),
                returned_membership: None,
            });
            index
        };
        let result = async {
            anyhow::ensure!(
                self.shared.evidence.lock().unwrap().bind_calls[..index]
                    .iter()
                    .all(|call| call.owner_index != self.owner.index),
                "repeated BOSH bind call has no declared reply"
            );
            request.validate_for_io()?;
            let reply = self.bind.context("unexpected BOSH response bind")?;
            // Prepare the controlled SQL result from the actual selected sources,
            // independently of the separately returned adapter membership.
            let mut receipt = BoshResponseOwnership::default();
            for source in request.sources() {
                match source {
                    Source::C2s(value) => receipt.c2s_message_ids.push(value.message_id),
                    Source::Mix(value) => receipt.mix_delivery_ids.push(value.delivery_id),
                }
            }
            response_core::bind_commit_observed(self.commit(reply.commit, true), request, receipt)
                .await
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            self.owner.prefix();
            Ok(actual_membership(&reply.returned_membership))
        }
        .await;
        self.shared.evidence.lock().unwrap().bind_calls[index].returned_membership =
            result.as_ref().ok().map(membership);
        result
    }
    async fn renew(&self, request: &response_core::RenewRequest) -> Result<()> {
        let index = {
            let mut evidence = self.shared.evidence.lock().unwrap();
            let index = evidence.renew_calls.len();
            evidence.renew_calls.push(wire::BoshRenewCall {
                seq: next(&self.shared.sequence),
                owner_index: self.owner.index,
                expected: expected(request.expected()),
                returned: None,
            });
            index
        };
        let result = async {
            anyhow::ensure!(
                self.shared.evidence.lock().unwrap().renew_calls[..index]
                    .iter()
                    .all(|call| call.owner_index != self.owner.index),
                "repeated BOSH renew call has no declared reply"
            );
            request.validate_for_io()?;
            let cut = self.renewal.context("unexpected BOSH renewal")?;
            response_core::renew_commit_observed(self.commit(cut, false), request)
                .await
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            self.owner.prefix();
            Ok(())
        }
        .await;
        self.shared.evidence.lock().unwrap().renew_calls[index].returned = Some(result.is_ok());
        result
    }
    async fn acknowledge(&self, request: &response_core::AckRequest) -> Result<()> {
        let index = {
            let mut evidence = self.shared.evidence.lock().unwrap();
            let index = evidence.ack_calls.len();
            evidence.ack_calls.push(wire::BoshAckCall {
                seq: next(&self.shared.sequence),
                owner_index: self.owner.index,
                rid: request.rid(),
                returned: None,
            });
            index
        };
        let result = async {
            anyhow::ensure!(
                self.shared.evidence.lock().unwrap().ack_calls[..index]
                    .iter()
                    .all(|call| call.owner_index != self.owner.index),
                "repeated BOSH acknowledge call has no declared reply"
            );
            request.validate_for_io()?;
            let reply = self.ack.context("unexpected BOSH ACK")?;
            response_core::ack_commit_observed(
                self.commit(reply.ack_commit, false),
                request,
                reply.deleted.iter().map(actual_deleted).collect(),
            )
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
            self.owner.prefix();
            Ok(())
        }
        .await;
        self.shared.evidence.lock().unwrap().ack_calls[index].returned = Some(result.is_ok());
        result
    }
    async fn release(&self, _: uuid::Uuid) -> Result<()> {
        anyhow::bail!("fixed BOSH profile unexpectedly requested release")
    }
}
fn slot(item: &OutboundItem) -> wire::Slot {
    wire::Slot {
        xml: item.stanza.clone(),
        source: item.durable_source.map(Into::into),
    }
}
async fn drive(
    log: &OwnerLog,
    shared: &Shared,
    drop_bind: bool,
    child: impl Future<Output = Result<bool>>,
) -> Result<bool> {
    let mut error = None;
    let child = async {
        match child.await {
            Ok(keep_running) => keep_running,
            Err(value) => {
                error = Some(value);
                false
            }
        }
    };
    let mut runner = Box::pin(ownership::OperationRunner::new(
        log.operation.clone(),
        tokio::time::timeout(BOSH_BACKEND_OPERATION_TIMEOUT, child),
    ));
    let actual = futures::poll!(&mut runner);
    log.polls
        .lock()
        .unwrap()
        .push(shared.sequence.lock().unwrap().polled(&actual));
    drop(runner);
    log.prefix(); // The timed child has been destroyed and the owner retired.
    shared.evidence.lock().unwrap().owners.push(log.evidence()?);
    if let Some(error) = error {
        return Err(error);
    }
    match actual {
        Poll::Pending if drop_bind && shared.pending_bind.load(Ordering::SeqCst) => Ok(true),
        Poll::Ready(Ok(true)) if !drop_bind => Ok(false),
        Poll::Ready(Ok(false)) => anyhow::bail!("BOSH helper stopped before the declared boundary"),
        Poll::Ready(Err(_)) => anyhow::bail!("unexpected BOSH timed child expiry"),
        _ => anyhow::bail!("BOSH owner did not reach its declared ready/pending cut"),
    }
}
struct Receivers {
    mix: Option<(uuid::Uuid, oneshot::Receiver<MixTransportCompletion>)>,
    transport: Option<mpsc::UnboundedReceiver<()>>,
}
impl Receivers {
    fn mix(&mut self, shared: &Shared) {
        let Some((delivery_id, mut receiver)) = self.mix.take() else {
            return;
        };
        let result = match receiver.try_recv() {
            Ok(MixTransportCompletion::SmPersisted { session_id }) => {
                wire::MixHandoffResult::SmPersisted {
                    session_id: wire::Id(session_id),
                }
            }
            Ok(MixTransportCompletion::BoshPersisted { session_id }) => {
                wire::MixHandoffResult::BoshPersisted {
                    session_id: wire::Id(session_id),
                }
            }
            Ok(MixTransportCompletion::SocketFenced { connection_id }) => {
                wire::MixHandoffResult::SocketFenced {
                    connection_id: wire::Id(connection_id),
                }
            }
            Err(oneshot::error::TryRecvError::Empty) => wire::MixHandoffResult::Empty,
            Err(oneshot::error::TryRecvError::Closed) => wire::MixHandoffResult::Closed,
        };
        shared
            .evidence
            .lock()
            .unwrap()
            .mix_handoffs
            .push(wire::MixHandoff {
                seq: next(&shared.sequence),
                delivery_id: wire::Id(delivery_id),
                result,
            });
    }
    fn transport(&mut self, index: usize, shared: &Shared) {
        let Some(receiver) = self.transport.as_mut() else {
            return;
        };
        let result = match receiver.try_recv() {
            Ok(()) => "Received",
            Err(mpsc::error::TryRecvError::Empty) => "Empty",
            Err(mpsc::error::TryRecvError::Disconnected) => "Closed",
        };
        shared
            .evidence
            .lock()
            .unwrap()
            .transport_receipts
            .push(wire::BoshTransportReceipt {
                seq: next(&shared.sequence),
                item_index: count(index),
                result,
            });
    }
}
fn item(value: &wire::Item) -> Result<(OutboundItem, Receivers)> {
    match value {
        wire::Item::Plain {
            xml,
            transport_receipt,
        } => {
            let mut item = OutboundItem::plain(xml.clone());
            let transport = if *transport_receipt {
                let (sender, receiver) = mpsc::unbounded_channel();
                item.transport_receipt = Some(sender);
                Some(receiver)
            } else {
                None
            };
            Ok((
                item,
                Receivers {
                    mix: None,
                    transport,
                },
            ))
        }
        wire::Item::Mix { xml, source } => {
            let Source::Mix(source) = source.actual() else {
                anyhow::bail!("literal MIX item has non-MIX source");
            };
            let (item, receiver) = OutboundItem::durable_mix(xml.clone(), source);
            Ok((
                item,
                Receivers {
                    mix: Some((source.delivery_id, receiver)),
                    transport: None,
                },
            ))
        }
    }
}
type ResponseSenders = Vec<oneshot::Sender<BoshHttpResponse>>;
type ResponseReceivers = Vec<(u32, oneshot::Receiver<BoshHttpResponse>)>;
fn responders(values: &[wire::Responder]) -> (ResponseSenders, ResponseReceivers) {
    let mut senders = vec![];
    let mut receivers = vec![];
    for (index, value) in values.iter().enumerate() {
        let (sender, receiver) = oneshot::channel();
        senders.push(sender);
        match value {
            wire::Responder::Open => receivers.push((count(index), receiver)),
            wire::Responder::Dropped => drop(receiver),
        }
    }
    (senders, receivers)
}
fn observe_responses(
    receivers: ResponseReceivers,
    log: &OwnerLog,
    rid: u64,
    phase: &'static str,
    shared: &Shared,
) {
    for (receiver_index, mut receiver) in receivers {
        let result = match receiver.try_recv() {
            Ok(response) => wire::BoshResponseResult::Received {
                body_hex: wire::hex(&response.body),
            },
            Err(oneshot::error::TryRecvError::Empty) => wire::BoshResponseResult::Empty,
            Err(oneshot::error::TryRecvError::Closed) => wire::BoshResponseResult::Closed,
        };
        shared
            .evidence
            .lock()
            .unwrap()
            .response_receivers
            .push(wire::BoshResponseReceiver {
                seq: next(&shared.sequence),
                owner_index: log.index,
                rid,
                phase,
                receiver_index,
                result,
            });
    }
}

/// The sole saved entry lends its actual SM recorder and routed item here.
/// No duplicate actor, request dispatcher, or production persistence capability.
pub(crate) async fn run<R: ownership::RecordPort>(
    case: &wire::Case,
    target: OutboundItem,
    record: &mut R,
    governor: &Arc<SmMemoryGovernor>,
    sequence: Sequence,
) -> Result<(wire::BoshEvidence, bool)> {
    let wire::RecipientOwner::Bosh {
        session_id,
        ttl_seconds,
        max_output_stanzas,
        max_output_bytes,
        max_response_bytes,
        content_type,
        received_rid,
        extra_items,
        mix_transfer,
        request_xml,
        initial_renewal,
        bind,
        responders: responder_scripts,
        cached_replay,
        fresh_ack,
        ..
    } = &case.recipient_owner
    else {
        anyhow::bail!("BOSH bridge received another owner");
    };
    let shared = Shared {
        sequence: sequence.clone(),
        evidence: Mutex::new(wire::BoshEvidence::default()),
        pending_bind: AtomicBool::new(false),
    };
    let mut output = VecDeque::new();
    let mut output_bytes = 0;
    let mut cache = VecDeque::new();
    let mut last_response = Instant::now();
    let mut highest_responded = 0;
    let mut items = VecDeque::from([(
        target,
        Receivers {
            mix: None,
            transport: None,
        },
    )]);
    for value in extra_items {
        items.push_back(item(value)?);
    }
    let mut retained_receivers = vec![];
    let mut owner_index = 0;
    while let Some((item, mut receivers)) = items.pop_front() {
        let log = OwnerLog::new(
            session_id.0,
            *ttl_seconds,
            core::OperationKind::Outbound,
            owner_index,
            sequence.clone(),
        );
        let port = Port {
            shared: &shared,
            owner: &log,
            transfer: mix_transfer.get(),
            bind: None,
            renewal: None,
            ack: None,
        };
        let child = async {
            log.outbound(owner_index as usize, &item);
            ownership::record_and_push(
                &mut ownership::Output {
                    items: &mut output,
                    bytes: &mut output_bytes,
                    max_stanzas: *max_output_stanzas as usize,
                    max_bytes: *max_output_bytes as usize,
                },
                item,
                &log.operation,
                record,
                &port,
            )
            .await
            .map_err(|error| match error {
                ownership::RecordPushError::Record(error) => error,
                ownership::RecordPushError::Transfer { error, .. } => error,
            })
        };
        drive(&log, &shared, false, child).await?;
        receivers.mix(&shared);
        receivers.transport(owner_index as usize, &shared);
        retained_receivers.push(receivers);
        owner_index += 1;
    }
    let request =
        super::parse_body(request_xml, *max_output_stanzas as usize).map_err(anyhow::Error::msg)?;
    let log = OwnerLog::new(
        session_id.0,
        *ttl_seconds,
        core::OperationKind::Request,
        owner_index,
        sequence.clone(),
    );
    let port = Port {
        shared: &shared,
        owner: &log,
        transfer: None,
        bind: bind.get(),
        renewal: Some(*initial_renewal),
        ack: None,
    };
    let (senders, receivers) = responders(responder_scripts);
    let drop_bind = matches!(case.drive, wire::Drive::DropBoshBindCommit { .. });
    let child = async {
        log.request("Initial", &request);
        response_owner::renew_and_acknowledge(&mut cache, request.ack, &log.operation, &port)
            .await?;
        let bound = response_owner::prepare(
            &mut response_owner::Fields {
                output: &mut output,
                output_bytes: &mut output_bytes,
                replay: &mut cache,
                governor,
                max_response_bytes: *max_response_bytes as usize,
                max_output_stanzas: *max_output_stanzas as usize,
                content_type,
                received_rid: Some(*received_rid),
            },
            response_owner::Metadata {
                rid: request.rid,
                fingerprint: request.fingerprint,
                cache: true,
            },
            None,
            &log.operation,
            &port,
        )
        .await
        .map_err(|failure| failure.error)?;
        log.prefix(); // Bound (or honestly NotRequired), before responder exposure.
        let exposed = bound.expose(senders)?;
        log.prefix(); // Actual send results, before bookkeeping/cache.
                      // This profile has no pending authentication publication. The actor's
                      // publication check/await is not replaced with a fake successful port.
        exposed.finish(&mut last_response, &mut highest_responded, &mut cache)?;
        shared.cache(&cache);
        Ok(true)
    };
    let dropped = drive(&log, &shared, drop_bind, child).await?;
    observe_responses(receivers, &log, request.rid, "Initial", &shared);
    if !dropped {
        if let Some(reply) = cached_replay.get() {
            owner_index += 1;
            let request = super::parse_body(&reply.request_xml, *max_output_stanzas as usize)
                .map_err(anyhow::Error::msg)?;
            let log = OwnerLog::new(
                session_id.0,
                *ttl_seconds,
                core::OperationKind::Request,
                owner_index,
                sequence.clone(),
            );
            let port = Port {
                shared: &shared,
                owner: &log,
                transfer: None,
                bind: None,
                renewal: Some(reply.renewal),
                ack: None,
            };
            let (mut senders, receivers) = responders(&[reply.responder]);
            let sender = senders.pop().expect("one declared replay responder");
            let child = async {
                log.request("Replay", &request);
                match response_owner::replay_cached(
                    &mut cache,
                    &request,
                    sender,
                    &mut last_response,
                    &log.operation,
                    &port,
                )
                .await
                {
                    response_owner::ReplayOutcome::Sent { terminate: false } => {}
                    response_owner::ReplayOutcome::Sent { terminate: true } => {
                        anyhow::bail!("saved replay unexpectedly terminated")
                    }
                    response_owner::ReplayOutcome::Miss(_) => {
                        anyhow::bail!("saved replay missed its actual cache")
                    }
                    response_owner::ReplayOutcome::Failed { error, .. } => return Err(error),
                }
                shared.cache(&cache);
                Ok(true)
            };
            drive(&log, &shared, false, child).await?;
            observe_responses(receivers, &log, request.rid, "Replay", &shared);
        }
        if let Some(reply) = fresh_ack.get() {
            owner_index += 1;
            let request = super::parse_body(&reply.request_xml, *max_output_stanzas as usize)
                .map_err(anyhow::Error::msg)?;
            let log = OwnerLog::new(
                session_id.0,
                *ttl_seconds,
                core::OperationKind::Request,
                owner_index,
                sequence.clone(),
            );
            let port = Port {
                shared: &shared,
                owner: &log,
                transfer: None,
                bind: None,
                renewal: Some(reply.renewal),
                ack: Some(reply),
            };
            let child = async {
                log.request("FreshAck", &request);
                response_owner::renew_and_acknowledge(
                    &mut cache,
                    request.ack,
                    &log.operation,
                    &port,
                )
                .await?;
                shared.cache(&cache);
                Ok(true)
            };
            drive(&log, &shared, false, child).await?;
        }
    }
    for (index, receiver) in retained_receivers.iter_mut().enumerate() {
        receiver.transport(index, &shared);
    }
    let mut evidence = shared.evidence.into_inner().unwrap();
    anyhow::ensure!(
        evidence.transfer_calls.len() == usize::from(mix_transfer.get().is_some())
            && evidence.bind_calls.len() == usize::from(bind.get().is_some())
            && evidence.renew_calls.len()
                == 1 + usize::from(cached_replay.get().is_some())
                    + usize::from(fresh_ack.get().is_some())
            && evidence.ack_calls.len() == usize::from(fresh_ack.get().is_some()),
        "unconsumed BOSH persistence reply"
    );
    evidence.fifo_after = output.iter().map(slot).collect();
    evidence.output_bytes = count(output_bytes);
    evidence.highest_responded = highest_responded;
    Ok((evidence, dropped))
}

fn governor_equal(left: &wire::Governor, right: &wire::Governor) -> bool {
    left.max_bytes == right.max_bytes
        && left.max_recovery_bytes == right.max_recovery_bytes
        && left.max_recovery_jobs == right.max_recovery_jobs
        && left.max_snapshot_bytes == right.max_snapshot_bytes
}
fn profile_request(
    xml: &str,
    max_stanzas: u32,
    rid: u64,
    ack: Option<u64>,
) -> Result<BoshRequest, wire::Rejection> {
    if xml.len() > 4096 {
        return Err(wire::Rejection::Limit);
    }
    let request = super::parse_body(xml, max_stanzas as usize)
        .map_err(|_| wire::Rejection::IdentityBinding)?;
    if request.rid != rid
        || request.ack != ack
        || request.sid.as_deref() != Some("case-session")
        || !request.payloads.is_empty()
        || request.to.is_some()
        || request.from.is_some()
        || request.wait.is_some()
        || request.hold.is_some()
        || request.ver.is_some()
        || request.content.is_some()
        || request.key.is_some()
        || request.newkey.is_some()
        || request.pause.is_some()
        || request.terminate
        || request.restart
        || request.xmpp_version.is_some()
        || request.language.is_some()
    {
        return Err(wire::Rejection::IdentityBinding);
    }
    Ok(request)
}
/// Pure fixed-profile role/cut validation, before any frame, owner or port.
/// This is not BOSH HTTP/session admission and adds no product input policy.
pub(crate) fn validate(
    case: &wire::Case,
    item_count: usize,
    mut xml_bytes: usize,
) -> Result<(), wire::Rejection> {
    use wire::Rejection::{IdentityBinding, Limit};
    let wire::RecipientOwner::Bosh {
        frame_id,
        session_id,
        ttl_seconds,
        max_output_stanzas,
        max_output_bytes,
        max_response_bytes,
        content_type,
        received_rid,
        governor,
        extra_items,
        recording,
        mix_transfer,
        request_xml,
        initial_renewal,
        bind,
        responders,
        cached_replay,
        fresh_ack,
    } = &case.recipient_owner
    else {
        return Err(wire::Rejection::UnsupportedOwner);
    };
    if case.originals.len() != 1
        || case.originals[0].frame_id != *frame_id
        || Some(session_id) != case.identities.bosh_session_id.get()
        || case.identities.connection_id.get().is_none()
        || case.identities.native_claim_id.get().is_some()
        || *ttl_seconds != 100
        || *received_rid != 100
        || *max_output_stanzas != 4
        || *max_output_bytes != 65_536
        || *max_response_bytes != 65_536
        || content_type != "text/xml; charset=utf-8"
        || *initial_renewal != wire::CommitCut::Complete
    {
        return Err(IdentityBinding);
    }
    if extra_items.len() > 3
        || item_count + extra_items.len() > 4
        || responders.is_empty()
        || responders.len() > 2
        || governor.max_bytes < governor.max_snapshot_bytes
        || governor.max_recovery_bytes < governor.max_snapshot_bytes
        || governor.max_recovery_jobs == 0
        || governor.max_snapshot_bytes == 0
    {
        return Err(Limit);
    }
    let wire::Transaction::Stored {
        recipient_id,
        delivery_id,
        ..
    } = &case.direct_repository[0].transaction
    else {
        return Err(IdentityBinding);
    };
    if case.direct_repository[0].commit != wire::CommitCut::Complete
        || case.direct_repository[0].admitted_mode != wire::Mode::Live
        || !matches!(
            case.direct_repository[0].completion,
            wire::Completion::Return {
                mode: wire::Mode::Live
            }
        )
    {
        return Err(IdentityBinding);
    }
    let mut mix = None;
    for value in extra_items {
        let xml = match value {
            wire::Item::Plain { xml, .. } => xml,
            wire::Item::Mix { xml, source } => {
                let wire::Source::Mix {
                    delivery_id,
                    lease_token,
                } = source
                else {
                    return Err(IdentityBinding);
                };
                if mix.is_some()
                    || Some(delivery_id) != case.identities.mix_delivery_id.get()
                    || Some(lease_token) != case.identities.mix_old_token.get()
                {
                    return Err(IdentityBinding);
                }
                mix = Some(source.actual());
                xml
            }
        };
        xml_bytes += xml.len();
        if xml.len() > 4096 {
            return Err(Limit);
        }
        let document = roxmltree::Document::parse(xml).map_err(|_| IdentityBinding)?;
        if document.root_element().tag_name().name() != "message"
            || document.root_element().tag_name().namespace() != Some("jabber:client")
        {
            return Err(IdentityBinding);
        }
    }
    let sm_managed = match recording.as_ref() {
        wire::BoshRecording::Disabled {} => {
            if case.identities.sm_session_id.get().is_some() {
                return Err(IdentityBinding);
            }
            false
        }
        wire::BoshRecording::PersistedSm {
            connection_id,
            config,
            record_replies,
        } => {
            if Some(connection_id) != case.identities.connection_id.get()
                || config.session_id.get() != case.identities.sm_session_id.get()
                || config.session_id.get().is_none()
                || !config.enabled
                || !config.resume_allowed
                || config.outbound_h != config.acked_h
                || config.peer_ip.parse::<std::net::IpAddr>().is_err()
                || !governor_equal(governor, &config.governor)
                || record_replies.len() != 1 + extra_items.len()
                || mix.is_some()
                || record_replies.iter().any(|reply| {
                    !reply.updated
                        || reply.commit != wire::CommitCut::Complete
                        || !reply.rotations.is_empty()
                })
            {
                return Err(IdentityBinding);
            }
            true
        }
    };
    if let Some(previous) = mix {
        let reply = mix_transfer.get().ok_or(IdentityBinding)?;
        let wire::Source::Mix {
            delivery_id,
            lease_token,
        } = &reply.returned_source
        else {
            return Err(IdentityBinding);
        };
        if reply.commit != wire::CommitCut::Complete
            || Some(delivery_id) != case.identities.mix_delivery_id.get()
            || Some(lease_token) != case.identities.mix_new_token.get()
            || reply.returned_source.actual() == previous
        {
            return Err(IdentityBinding);
        }
    } else if mix_transfer.get().is_some()
        || [
            case.identities.mix_delivery_id.get(),
            case.identities.mix_old_token.get(),
            case.identities.mix_new_token.get(),
        ]
        .iter()
        .any(Option::is_some)
    {
        return Err(IdentityBinding);
    }
    let dropped = matches!(&case.drive, wire::Drive::DropBoshBindCommit { frame_id: target } if target == frame_id);
    if !dropped && !matches!(case.drive, wire::Drive::Complete {}) {
        return Err(IdentityBinding);
    }
    if sm_managed {
        if bind.get().is_some() || dropped {
            return Err(IdentityBinding);
        }
    } else {
        let reply = bind.get().ok_or(IdentityBinding)?;
        let expected_mix: Vec<_> = case
            .identities
            .mix_delivery_id
            .get()
            .copied()
            .into_iter()
            .collect();
        if reply.returned_membership.c2s_message_ids != [*delivery_id]
            || reply.returned_membership.mix_delivery_ids != expected_mix
            || reply.commit
                != if dropped {
                    wire::CommitCut::Pending
                } else {
                    wire::CommitCut::Complete
                }
        {
            return Err(IdentityBinding);
        }
    }
    let request = profile_request(request_xml, *max_output_stanzas, 100, None)?;
    xml_bytes += request_xml.len();
    if dropped && (cached_replay.get().is_some() || fresh_ack.get().is_some()) {
        return Err(IdentityBinding);
    }
    if let Some(reply) = cached_replay.get() {
        let replay = profile_request(&reply.request_xml, *max_output_stanzas, 100, None)?;
        if reply.renewal != wire::CommitCut::Complete || request.fingerprint != replay.fingerprint {
            return Err(IdentityBinding);
        }
        xml_bytes += reply.request_xml.len();
    }
    if let Some(reply) = fresh_ack.get() {
        profile_request(&reply.request_xml, *max_output_stanzas, 101, Some(100))?;
        if reply.renewal != wire::CommitCut::Complete
            || reply.ack_commit != wire::CommitCut::Complete
        {
            return Err(IdentityBinding);
        }
        let mut expected_deleted = vec![];
        if !sm_managed {
            expected_deleted.push(response_core::DeletedSource::C2s {
                recipient_id: recipient_id.0,
                message_id: delivery_id.0,
            });
            if let Some(reply) = mix_transfer.get() {
                let Source::Mix(source) = reply.returned_source.actual() else {
                    return Err(IdentityBinding);
                };
                expected_deleted.push(response_core::DeletedSource::Mix(source));
            }
        }
        if reply.deleted.iter().map(actual_deleted).collect::<Vec<_>>() != expected_deleted {
            return Err(IdentityBinding);
        }
        xml_bytes += reply.request_xml.len();
    }
    if xml_bytes > 16_384 {
        return Err(Limit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sequence() -> Sequence {
        Arc::new(Mutex::new(wire::Sequence::default()))
    }
    fn shared(sequence: &Sequence) -> Shared {
        Shared {
            sequence: sequence.clone(),
            evidence: Mutex::new(wire::BoshEvidence::default()),
            pending_bind: AtomicBool::new(false),
        }
    }
    fn governor() -> Arc<SmMemoryGovernor> {
        SmMemoryGovernor::new(
            65_536,
            32_768,
            4,
            32_768,
            Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default()),
        )
        .unwrap()
    }
    const REQUEST: &str =
        "<body xmlns='http://jabber.org/protocol/httpbind' sid='case-session' rid='100'/>";

    // Isolated parser/role comparisons: no Case, frame, port or saved workload.
    #[test]
    fn request_roles_and_all_four_shared_governor_limits_are_checked() {
        let request = profile_request(REQUEST, 4, 100, None).unwrap();
        assert_eq!(
            wire::hex(&request.fingerprint),
            wire::digest(REQUEST.as_bytes())
        );
        assert_eq!(request.sid.as_deref(), Some("case-session"));
        assert!(profile_request(REQUEST, 4, 101, None).is_err());
        assert!(profile_request(REQUEST, 4, 100, Some(100)).is_err());
        let value = wire::Governor {
            max_bytes: 65_536,
            max_recovery_bytes: 32_768,
            max_recovery_jobs: 4,
            max_snapshot_bytes: 32_768,
        };
        assert!(governor_equal(&value, &value.clone()));
        for index in 0..4 {
            let mut changed = value.clone();
            match index {
                0 => changed.max_bytes += 1,
                1 => changed.max_recovery_bytes += 1,
                2 => changed.max_recovery_jobs += 1,
                _ => changed.max_snapshot_bytes += 1,
            };
            assert!(!governor_equal(&value, &changed));
        }
    }

    // Actual private response/receiver component, with a source-less literal.
    // It does not invoke run(), the direct application or a saved Case.
    #[tokio::test]
    async fn plain_response_uses_empty_bind_and_surviving_receiver_indices() {
        let sequence = sequence();
        let shared = shared(&sequence);
        let log = OwnerLog::new(
            uuid::Uuid::from_u128(5),
            100,
            core::OperationKind::Request,
            0,
            sequence,
        );
        let request = profile_request(REQUEST, 4, 100, None).unwrap();
        let port = Port {
            shared: &shared,
            owner: &log,
            transfer: None,
            bind: None,
            renewal: None,
            ack: None,
        };
        let mut output = VecDeque::from([OutboundItem::plain(
            "<message xmlns='jabber:client' id='component'/>".into(),
        )]);
        let mut output_bytes = output[0].stanza.len();
        let mut cache = VecDeque::new();
        let governor = governor();
        let mut last_response = Instant::now();
        let mut highest_responded = 0;
        let (senders, receivers) = responders(&[wire::Responder::Dropped, wire::Responder::Open]);
        let child = async {
            log.request("Initial", &request);
            let bound = response_owner::prepare(
                &mut response_owner::Fields {
                    output: &mut output,
                    output_bytes: &mut output_bytes,
                    replay: &mut cache,
                    governor: &governor,
                    max_response_bytes: 65_536,
                    max_output_stanzas: 4,
                    content_type: "text/xml; charset=utf-8",
                    received_rid: Some(100),
                },
                response_owner::Metadata {
                    rid: request.rid,
                    fingerprint: request.fingerprint,
                    cache: true,
                },
                None,
                &log.operation,
                &port,
            )
            .await
            .map_err(|error| error.error)?;
            log.prefix();
            let exposed = bound.expose(senders)?;
            log.prefix();
            exposed.finish(&mut last_response, &mut highest_responded, &mut cache)?;
            shared.cache(&cache);
            Ok(true)
        };
        assert!(!drive(&log, &shared, false, child).await.unwrap());
        observe_responses(receivers, &log, 100, "Initial", &shared);
        let facts = shared.evidence.lock().unwrap();
        assert!(facts.bind_calls.is_empty());
        assert_eq!(facts.response_receivers.len(), 1);
        assert_eq!(facts.response_receivers[0].receiver_index, 1);
        assert!(matches!(
            facts.response_receivers[0].result,
            wire::BoshResponseResult::Received { .. }
        ));
        let response = &facts.owners[0].state.responses[0];
        assert!(matches!(
            response.attempts[0].knowledge,
            wire::BoshBindKnowledge::NotRequired
        ));
        assert_eq!(
            (response.accepted_responders, response.refused_responders),
            (1, 1)
        );
        assert!(response.cached && response.bookkeeping);
        assert_eq!(facts.owners[0].state.terminal, Some("Returned"));
        assert_eq!(
            facts.owners[0].prefixes.last().unwrap().state.terminal,
            Some("Returned")
        );
        assert!(facts.owners[0]
            .polls
            .iter()
            .all(|poll| poll.result == "Ready"));
        assert_eq!(highest_responded, 100);
        assert_eq!(cache.len(), 1);
        assert!(output.is_empty());
        assert_eq!(output_bytes, 0);
    }

    // One component COMMIT cut over actual preparation/runner/core wrapper.
    // No MIX transfer, original/application/native path or full saved case.
    #[tokio::test]
    async fn cancelled_bind_retains_entry_and_selected_item_drop_before_terminal() {
        let sequence = sequence();
        let shared = shared(&sequence);
        let log = OwnerLog::new(
            uuid::Uuid::from_u128(5),
            100,
            core::OperationKind::Request,
            0,
            sequence,
        );
        let request = profile_request(REQUEST, 4, 100, None).unwrap();
        let delivery = crate::outbound::DurableDelivery {
            recipient_id: uuid::Uuid::from_u128(2),
            message_id: uuid::Uuid::from_u128(13),
            claim_id: Some(uuid::Uuid::from_u128(13)),
        };
        let reply = wire::Bind {
            commit: wire::CommitCut::Pending,
            returned_membership: wire::Membership {
                c2s_message_ids: vec![wire::Id(delivery.message_id)],
                mix_delivery_ids: vec![],
            },
        };
        let port = Port {
            shared: &shared,
            owner: &log,
            transfer: None,
            bind: Some(&reply),
            renewal: None,
            ack: None,
        };
        let mut output = VecDeque::from([OutboundItem::durable(
            "<message xmlns='jabber:client' id='component'/>".into(),
            delivery,
        )]);
        let mut output_bytes = output[0].stanza.len();
        let mut cache = VecDeque::new();
        let governor = governor();
        let child = async {
            log.request("Initial", &request);
            let _bound = response_owner::prepare(
                &mut response_owner::Fields {
                    output: &mut output,
                    output_bytes: &mut output_bytes,
                    replay: &mut cache,
                    governor: &governor,
                    max_response_bytes: 65_536,
                    max_output_stanzas: 4,
                    content_type: "text/xml; charset=utf-8",
                    received_rid: Some(100),
                },
                response_owner::Metadata {
                    rid: request.rid,
                    fingerprint: request.fingerprint,
                    cache: true,
                },
                None,
                &log.operation,
                &port,
            )
            .await
            .map_err(|error| error.error)?;
            Ok(true)
        };
        assert!(drive(&log, &shared, true, child).await.unwrap());
        let facts = shared.evidence.lock().unwrap();
        let owner = &facts.owners[0];
        assert_eq!(owner.polls.len(), 1);
        assert_eq!(owner.polls[0].result, "Pending");
        assert_eq!(owner.state.terminal, Some("Cancelled"));
        assert_eq!(owner.state.keep_running, None);
        assert!(matches!(
            owner.state.responses[0].attempts[0].knowledge,
            wire::BoshBindKnowledge::CommitCallEntered { .. }
        ));
        assert!(owner.state.responses[0].attempts[0].returned.is_none());
        assert!(!owner.state.responses[0].exposure_entered && !owner.state.responses[0].cached);
        assert_eq!(owner.prefixes.len(), 2);
        assert!(owner.prefixes[0].state.terminal.is_none());
        assert_eq!(owner.prefixes[1].state.terminal, Some("Cancelled"));
        assert!(output.is_empty() && cache.is_empty());
        assert_eq!(output_bytes, 0);
        assert_eq!(governor.metrics().reserved_bytes.load(Ordering::SeqCst), 0);
    }
}
