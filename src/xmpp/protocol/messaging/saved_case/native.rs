//! Native, stream-management and replacement delivery ports and scripted writers.

use super::*;

pub(super) fn native_state(
    observation: &northstar_delivery_core::native_write::Observation,
) -> wire::NativeState {
    use northstar_delivery_core::native_write as n;
    let state = observation.snapshot();
    let fact = |fact: n::AckFact| wire::NativeFact {
        source: fact.source.into(),
        disposition: match fact.disposition {
            n::AckDisposition::Deleted => "Deleted",
            n::AckDisposition::AbsentUnclaimed => "AbsentUnclaimed",
            n::AckDisposition::NoMatchingMix => "NoMatchingMix",
        },
    };
    wire::NativeState {
        original: state.original.map(Into::into),
        preparation: match state.preparation {
            n::Preparation::NotStarted => "NotStarted",
            n::Preparation::Recording => "Recording",
            n::Preparation::FenceCallEntered => "FenceCallEntered",
            n::Preparation::Prepared => "Prepared",
            n::Preparation::Superseded => "Superseded",
            n::Preparation::Failed => "Failed",
        },
        managed_by_sm: state.managed_by_sm,
        fence_entered: state.fence_entered,
        returned_fence: state.returned_fence.map(Into::into),
        writer_entered: state.writer_entered,
        writer_result: state.writer_result.map(|value| match value {
            n::WriterResult::FullWrite => "FullWrite",
            n::WriterResult::Failed => "Failed",
        }),
        write_decision: state.write_decision.map(|value| match value {
            n::WriteDecision::Written => "Written",
            n::WriteDecision::Withhold => "Withhold",
        }),
        ack: match state.ack {
            n::AckKnowledge::NotRequested => wire::NativeAckKnowledge::NotRequested,
            n::AckKnowledge::NoCommitRequested => wire::NativeAckKnowledge::NoCommitRequested,
            n::AckKnowledge::CommitCallEntered(value) => {
                wire::NativeAckKnowledge::CommitCallEntered { fact: fact(value) }
            }
            n::AckKnowledge::ReceiptKnown(value) => {
                wire::NativeAckKnowledge::ReceiptKnown { fact: fact(value) }
            }
        },
        ack_returned: state.ack_returned,
        terminal: state.terminal.map(|value| match value {
            n::Terminal::Returned => "Returned",
            n::Terminal::Cancelled => "Cancelled",
            n::Terminal::Panicked => "Panicked",
        }),
    }
}
pub(super) struct NativeLog {
    pub(super) observation: northstar_delivery_core::native_write::Observation,
    pub(super) sequence: Sequence,
    pub(super) prefixes: Mutex<Vec<wire::NativePrefix>>,
    pub(super) writes: Mutex<Vec<wire::WriteCall>>,
    pub(super) flushes: Mutex<Vec<wire::FlushCall>>,
    pub(super) acks: Mutex<Vec<wire::AckCall>>,
    pub(super) ack_pending: AtomicBool,
}
impl NativeLog {
    pub(super) fn prefix(&self) {
        let state = native_state(&self.observation);
        let seq = next(&self.sequence);
        self.prefixes
            .lock()
            .unwrap()
            .push(wire::NativePrefix { seq, state });
    }
}

#[derive(Default)]
pub(super) struct SmMetadata {
    pub(super) peer_ip: Option<std::net::IpAddr>,
    pub(super) available: Option<Arc<AtomicBool>>,
    pub(super) carbons: AtomicBool,
    pub(super) priority: std::sync::atomic::AtomicI16,
    pub(super) blocklist: AtomicBool,
    pub(super) roster: AtomicBool,
    pub(super) privacy: std::sync::RwLock<Option<String>>,
    pub(super) privacy_requested: AtomicBool,
    pub(super) rooms: dashmap::DashMap<String, crate::state::JoinedMucMembership>,
    pub(super) directed: dashmap::DashSet<String>,
    pub(super) presence: std::sync::RwLock<Option<String>>,
}
impl SmMetadata {
    pub(super) fn view(&self) -> crate::xmpp::protocol::sm_owner::SmSnapshotView<'_> {
        crate::xmpp::protocol::sm_owner::SmSnapshotView {
            available: &self.available,
            carbons: &self.carbons,
            priority: &self.priority,
            blocklist_requested: &self.blocklist,
            roster_requested: &self.roster,
            privacy_active: &self.privacy,
            privacy_requested: &self.privacy_requested,
            peer_ip: self
                .peer_ip
                .as_ref()
                .unwrap_or(&std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            user_agent_id: &None,
            joined_rooms: &self.rooms,
            directed_presence: &self.directed,
            last_presence: &self.presence,
        }
    }
}
/// C13's single already-authorized replacement boundary. This is one bounded
/// committed-row view, not SQL locking, a lease clock, or a retry executor.
pub(super) struct ReplacementControl {
    pub(super) row: Arc<Mutex<Option<DurableDelivery>>>,
    pub(super) old_connection: Uuid,
    pub(super) new_connection: Uuid,
    pub(super) old: DurableDelivery,
    pub(super) replacement: DurableDelivery,
    pub(super) sequence: Sequence,
    pub(super) gate_sender: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    pub(super) gate_receiver: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    pub(super) waiting: AtomicBool,
    pub(super) events: Mutex<Vec<wire::RowEvent>>,
    pub(super) dequeued: Mutex<Option<(OutboundItem, wire::Dequeue)>>,
}
impl ReplacementControl {
    pub(super) fn new(
        row: Arc<Mutex<Option<DurableDelivery>>>,
        old_connection: Uuid,
        new_connection: Uuid,
        old: DurableDelivery,
        replacement: DurableDelivery,
        sequence: Sequence,
    ) -> Self {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        Self {
            row,
            old_connection,
            new_connection,
            old,
            replacement,
            sequence,
            gate_sender: Mutex::new(Some(sender)),
            gate_receiver: Mutex::new(Some(receiver)),
            waiting: AtomicBool::new(false),
            events: Mutex::new(vec![]),
            dequeued: Mutex::new(None),
        }
    }
    pub(super) async fn before_read(
        &self,
        connection: Uuid,
        source: DurableDelivery,
    ) -> Result<()> {
        if connection == self.old_connection {
            anyhow::ensure!(
                source == self.old,
                "old ACK source differs from its fenced invocation"
            );
            let receiver = self
                .gate_receiver
                .lock()
                .unwrap()
                .take()
                .context("old authority-read gate reused")?;
            self.waiting.store(true, Ordering::SeqCst);
            receiver
                .await
                .context("old authority-read gate was abandoned")?;
        } else {
            anyhow::ensure!(
                connection == self.new_connection && source == self.replacement,
                "replacement ACK source differs from its invocation"
            );
        }
        Ok(())
    }
    pub(super) fn replace_and_dequeue(&self, live_xml: &str) -> Result<()> {
        {
            let mut row = self.row.lock().unwrap();
            anyhow::ensure!(
                *row == Some(self.old),
                "replacement did not find the actual old fenced row"
            );
            *row = Some(self.replacement);
        }
        self.events.lock().unwrap().push(wire::RowEvent::Replace {
            seq: next(&self.sequence),
            recipient_id: wire::Id(self.old.recipient_id),
            message_id: wire::Id(self.old.message_id),
            before_claim_id: wire::Id(self.old.claim_id.context("old fenced claim missing")?),
            after_claim_id: wire::Id(
                self.replacement
                    .claim_id
                    .context("replacement claim missing")?,
            ),
        });
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let sender = OutboundSender::new(sender);
        sender
            .try_send_durable(live_xml.to_owned(), self.replacement)
            .map_err(|_| anyhow::anyhow!("replacement replay queue refused its item"))?;
        let item = receiver
            .try_recv()
            .context("replacement replay item was not dequeued")?;
        let observed = wire::Dequeue {
            seq: next(&self.sequence),
            source: item.durable_source.map(Into::into),
            xml: item.stanza.clone(),
        };
        anyhow::ensure!(
            self.dequeued
                .lock()
                .unwrap()
                .replace((item, observed))
                .is_none(),
            "replacement replay item was produced twice"
        );
        Ok(())
    }
    pub(super) fn release_old(&self) -> Result<()> {
        self.gate_sender
            .lock()
            .unwrap()
            .take()
            .context("old authority-read release reused")?
            .send(())
            .map_err(|_| anyhow::anyhow!("old owner dropped before release"))
    }
    pub(super) fn read(&self, source: DurableDelivery, current_claim: Option<Uuid>, matches: bool) {
        self.events
            .lock()
            .unwrap()
            .push(wire::RowEvent::AuthorityRead {
                seq: next(&self.sequence),
                source: TransportOwnershipSource::C2s(source).into(),
                current_claim_id: current_claim.map(wire::Id),
                matches,
            });
    }
    pub(super) fn delete_committed(&self, source: DurableDelivery) {
        let removed = self.row.lock().unwrap().take();
        assert!(
            removed == Some(source),
            "committed-view deletion changed its exact row"
        );
        self.events.lock().unwrap().push(wire::RowEvent::Delete {
            seq: next(&self.sequence),
            source: TransportOwnershipSource::C2s(source).into(),
        });
    }
}

pub(super) struct NativePort<'a> {
    pub(super) spec: Option<&'a wire::NativeSpec>,
    pub(super) connection_id: Uuid,
    pub(super) row: Arc<Mutex<Option<DurableDelivery>>>,
    pub(super) log: Arc<NativeLog>,
    pub(super) recorder: &'a mut sm::Recorder,
    pub(super) replacement: Option<Arc<ReplacementControl>>,
}
impl crate::xmpp::direct_delivery::DirectWritePort for NativePort<'_> {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        self.log.prefix();
        self.recorder.record(item).await
    }
    async fn fence_c2s(&self, source: DurableDelivery) -> Result<DurableDelivery> {
        self.log.prefix();
        let returned = self
            .spec
            .context("SM-owned source reached native fence")?
            .fence
            .returned_source
            .actual()
            .c2s()
            .ok_or_else(|| anyhow::anyhow!("wrong fence family"))?;
        let mut row = self.row.lock().unwrap();
        anyhow::ensure!(
            *row == Some(source),
            "controlled fence did not own current row"
        );
        *row = Some(returned);
        Ok(returned)
    }
    async fn fence_mix(
        &self,
        _: crate::xmpp::outbound::MixDelivery,
    ) -> Result<crate::xmpp::outbound::MixDelivery> {
        anyhow::bail!("unexpected native MIX fence")
    }
    async fn acknowledge_c2s(
        &self,
        request: &northstar_delivery_core::native_write::AckRequest,
    ) -> Result<()> {
        use northstar_delivery_core::native_write::{self, AckDisposition};
        request.validate_source(request.source())?;
        let source = request
            .source()
            .c2s()
            .ok_or_else(|| anyhow::anyhow!("wrong ACK source"))?;
        let seq = next(&self.log.sequence);
        let index = {
            let mut calls = self.log.acks.lock().unwrap();
            let index = calls.len();
            calls.push(wire::AckCall {
                seq,
                source: request.source().into(),
                returned: None,
            });
            index
        };
        self.log.prefix();
        let result: Result<()> = async {
            let ack_cut = self
                .spec
                .context("SM-owned source reached native ACK")?
                .ack
                .commit;
            if let Some(control) = &self.replacement {
                control.before_read(self.connection_id, source).await?;
            }
            let current = (*self.row.lock().unwrap())
                .ok_or_else(|| anyhow::anyhow!("claimed row missing"))?;
            anyhow::ensure!(
                current.recipient_id == source.recipient_id
                    && current.message_id == source.message_id,
                "controlled ACK row key mismatch"
            );
            let expected = source
                .claim_id
                .ok_or_else(|| anyhow::anyhow!("native saved fixture requires a fenced claim"))?;
            let matches = native_write::claimed_c2s_ack_matches(expected, current.claim_id);
            if let Some(control) = &self.replacement {
                control.read(source, current.claim_id, matches);
            }
            anyhow::ensure!(
                matches,
                "offline delivery claim was lost before acknowledgement"
            );
            let committed = native_write::commit_observed(
                async {
                    self.log.prefix();
                    match ack_cut {
                        wire::CommitCut::Pending => {
                            self.log.ack_pending.store(true, Ordering::SeqCst);
                            std::future::pending::<std::io::Result<()>>().await
                        }
                        wire::CommitCut::Error => {
                            Err(std::io::Error::other("controlled native ACK COMMIT error"))
                        }
                        wire::CommitCut::Complete => {
                            if self.replacement.is_none() {
                                *self.row.lock().unwrap() = None;
                            }
                            Ok(())
                        }
                    }
                },
                request,
                AckDisposition::Deleted,
            )
            .await
            .map_err(anyhow::Error::from);
            self.log.prefix();
            committed?;
            if let Some(control) = &self.replacement {
                // C13 models the committed view, not SQL's prospective DELETE.
                // Receipt is already retained; no await/cut precedes this update.
                control.delete_committed(source);
            }
            Ok(())
        }
        .await;
        self.log.acks.lock().unwrap()[index].returned = Some(result.is_ok());
        result
    }
    async fn acknowledge_mix(
        &self,
        _: &northstar_delivery_core::native_write::AckRequest,
    ) -> Result<bool> {
        anyhow::bail!("unexpected native MIX ACK")
    }
    fn connection_id(&self) -> Uuid {
        self.connection_id
    }
}

pub(super) struct ScriptedWriter<'a> {
    pub(super) script: &'a wire::WriteScript,
    pub(super) accepted: usize,
    pub(super) log: Arc<NativeLog>,
}
impl tokio::io::AsyncWrite for ScriptedWriter<'_> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let fail = self
            .script
            .fail_after_accepted_bytes
            .get()
            .map(|value| *value as usize);
        let seq = next(&self.log.sequence);
        if fail.is_some_and(|limit| self.accepted >= limit) {
            self.log.writes.lock().unwrap().push(wire::WriteCall {
                seq,
                offered_len: u32::try_from(bytes.len()).expect("bounded writer input"),
                offered_sha256: wire::digest(bytes),
                accepted_bytes_hex: String::new(),
                result: "Error",
            });
            return std::task::Poll::Ready(Err(std::io::Error::other("controlled write error")));
        }
        let count = bytes
            .len()
            .min(self.script.chunk_limit as usize)
            .min(fail.map_or(usize::MAX, |limit| limit - self.accepted));
        self.accepted += count;
        self.log.writes.lock().unwrap().push(wire::WriteCall {
            seq,
            offered_len: u32::try_from(bytes.len()).expect("bounded writer input"),
            offered_sha256: wire::digest(bytes),
            accepted_bytes_hex: wire::hex(&bytes[..count]),
            result: "Accepted",
        });
        std::task::Poll::Ready(Ok(count))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let success = self.script.flush == wire::Flush::Ok;
        let seq = next(&self.log.sequence);
        self.log.flushes.lock().unwrap().push(wire::FlushCall {
            seq,
            result: if success { "Ok" } else { "Error" },
        });
        std::task::Poll::Ready(if success {
            Ok(())
        } else {
            Err(std::io::Error::other("controlled flush error"))
        })
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::other("unexpected writer shutdown")))
    }
}

pub(super) struct NativePlan<'a> {
    pub(super) connection_id: wire::Id,
    pub(super) native: Option<&'a wire::NativeSpec>,
    pub(super) write: &'a wire::WriteScript,
    pub(super) replacement: Option<Arc<ReplacementControl>>,
}

#[derive(Default)]
pub(super) struct ItemReceivers {
    pub(super) mix: Option<(
        Uuid,
        tokio::sync::oneshot::Receiver<crate::xmpp::outbound::MixTransportCompletion>,
    )>,
    pub(super) ownership: Option<tokio::sync::mpsc::UnboundedReceiver<()>>,
}
impl ItemReceivers {
    pub(super) fn observe_mix(&mut self, sequence: &Sequence, output: &mut Vec<wire::MixHandoff>) {
        let Some((delivery_id, mut receiver)) = self.mix.take() else {
            return;
        };
        use crate::xmpp::outbound::MixTransportCompletion as Completion;
        let result = match receiver.try_recv() {
            Ok(Completion::SmPersisted { session_id }) => wire::MixHandoffResult::SmPersisted {
                session_id: wire::Id(session_id),
            },
            Ok(Completion::BoshPersisted { session_id }) => wire::MixHandoffResult::BoshPersisted {
                session_id: wire::Id(session_id),
            },
            Ok(Completion::SocketFenced { connection_id }) => {
                wire::MixHandoffResult::SocketFenced {
                    connection_id: wire::Id(connection_id),
                }
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => wire::MixHandoffResult::Empty,
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                wire::MixHandoffResult::Closed
            }
        };
        output.push(wire::MixHandoff {
            seq: next(sequence),
            delivery_id: wire::Id(delivery_id),
            result,
        });
    }
    pub(super) fn observe_ownership(
        &mut self,
        sequence: &Sequence,
    ) -> Vec<wire::ReceiptObservation> {
        self.ownership
            .as_mut()
            .map(|receiver| wire::ReceiptObservation {
                seq: next(sequence),
                result: match receiver.try_recv() {
                    Ok(()) => "Received",
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => "Empty",
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => "Closed",
                },
            })
            .into_iter()
            .collect()
    }
}
pub(super) fn fixture_item(value: &wire::Item) -> Result<(OutboundItem, ItemReceivers)> {
    let mut receivers = ItemReceivers::default();
    let item = match value {
        wire::Item::Plain {
            xml,
            transport_receipt: false,
        } => OutboundItem::plain(xml.clone()),
        wire::Item::Plain {
            xml,
            transport_receipt: true,
        } => {
            let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
            receivers.ownership = Some(receiver);
            OutboundItem::with_transport_receipt(xml.clone(), sender)
        }
        wire::Item::Mix { xml, source } => {
            let source = source
                .actual()
                .mix()
                .ok_or_else(|| anyhow::anyhow!("fixture MIX source family"))?;
            let (item, receiver) = OutboundItem::durable_mix(xml.clone(), source);
            receivers.mix = Some((source.delivery_id, receiver));
            item
        }
    };
    Ok((item, receivers))
}

pub(super) struct NativeInput<'a> {
    pub(super) case: &'a wire::Case,
    pub(super) frame_id: wire::Id,
    pub(super) plan: NativePlan<'a>,
    pub(super) item: OutboundItem,
    pub(super) row: Arc<Mutex<Option<DurableDelivery>>>,
    pub(super) sequence: Sequence,
}
