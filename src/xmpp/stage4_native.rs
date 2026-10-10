//! Test-only actual send/write_all/flush and direct lease ownership.
#![cfg(test)]
use super::auth_publication::{
    stage4_saved::{facts, Capture},
    OwnedPublication,
};
use super::direct_delivery::{DirectWriteLease, DirectWritePort, NativeWriteRunner};
use crate::xmpp::protocol::mix::stage4_saved::Service;
use crate::{
    outbound::{DurableDelivery, MixDelivery, OutboundItem},
    stage4_replay as wire,
};
use anyhow::{ensure, Result};
use northstar_delivery_core::native_write as actual;
use sha2::{Digest, Sha256};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::AsyncWrite;
use uuid::Uuid;
mod limits;
#[cfg(test)]
mod ordinary;
pub(crate) type Driven<T> = std::result::Result<Result<T>, wire::BudgetStop>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeSite(wire::PollSite);
impl NativeSite {
    pub(crate) fn new(
        item_ordinal: u8,
    ) -> std::result::Result<Self, wire::DriverConfigurationError> {
        wire::PollSite::new(wire::DriverOwner::Native, item_ordinal).map(Self)
    }
    pub(crate) fn item_ordinal(self) -> u8 {
        self.0.owner_ordinal()
    }
}

/// The dispatcher checks this while preparing sites/scripts, before owners.
/// This is internal preparation, not a domain/backend/IO or input verdict.
pub(crate) fn preparation_valid(_site: NativeSite, script: &wire::WriteScript) -> bool {
    (1..=wire::MAX_STANZA as u32).contains(&script.chunk_limit)
}

fn native_stop(recorder: &Capture, item: u8, calls: u8, flush: bool) -> wire::BudgetStop {
    // PollSite ordinals are validated (<5); independent counters are <=32/1.
    // The dispatcher validated the Native role before creating any owner.
    let value = wire::NativeResourceStop {
        item_ordinal: item,
        admitted_calls: calls,
    };
    wire::driver::latch_resource_stop(
        recorder,
        if flush {
            wire::ResourceStop::NativeFlush(value)
        } else {
            wire::ResourceStop::NativeWrite(value)
        },
    )
    .expect("prevalidated native site and independently bounded counter")
}

/// One bounded supplied IO device. Only poll_write accepted bytes count;
/// offered bytes, accepted bytes and flush are emitted independently.
pub(crate) struct MemoryWrite {
    script: wire::WriteScript,
    item: u8,
    accepted: usize,
    recorder: Capture,
    counters: limits::Counters,
}
impl MemoryWrite {
    pub(crate) fn new(script: wire::WriteScript, site: NativeSite, recorder: Capture) -> Self {
        assert!(
            preparation_valid(site, &script),
            "native site/script must be validated during preparation"
        );
        Self {
            script,
            item: site.item_ordinal(),
            accepted: 0,
            recorder,
            counters: limits::Counters::default(),
        }
    }
}
impl AsyncWrite for MemoryWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if !this.counters.enter_write() {
            native_stop(&this.recorder, this.item, this.counters.writes, false);
            return Poll::Pending;
        }
        let fail = this
            .script
            .fail_after_accepted_bytes
            .get()
            .is_some_and(|n| this.accepted >= *n as usize);
        let limit = this
            .script
            .fail_after_accepted_bytes
            .get()
            .map_or(usize::MAX, |n| (*n as usize).saturating_sub(this.accepted));
        let count = if fail {
            0
        } else {
            bytes.len().min(this.script.chunk_limit as usize).min(limit)
        };
        if this
            .counters
            .last_write_would_be_nonterminal(bytes.len(), count, fail)
        {
            // Pending accepts zero bytes. The owning poll_once sees the latch
            // immediately and drops this stack; no scheduled retry/call33.
            native_stop(&this.recorder, this.item, this.counters.writes, false);
            return Poll::Pending;
        }
        facts::observe(&this.recorder, || {
            Ok(wire::Fact::Native(wire::NativeFact::Write(
                wire::WriteCall {
                    item_ordinal: this.item,
                    offered_len: facts::count(bytes.len())?,
                    offered_sha256: wire::Hex::of(&Sha256::digest(bytes))?,
                    accepted_bytes_hex: wire::Bytes::of(&bytes[..count])?,
                    result: if fail {
                        wire::IoResult::Error
                    } else {
                        wire::IoResult::Ok
                    },
                },
            )))
        });
        if fail {
            Poll::Ready(Err(std::io::Error::other("supplied partial write error")))
        } else {
            this.accepted += count;
            Poll::Ready(Ok(count))
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let fail = this.script.flush == wire::FlushReply::Error;
        if !this.counters.enter_flush() {
            native_stop(&this.recorder, this.item, this.counters.flushes, true);
            return Poll::Pending;
        }
        facts::emit(
            &this.recorder,
            wire::Fact::Native(wire::NativeFact::Flush(wire::FlushCall {
                item_ordinal: this.item,
                result: if fail {
                    wire::IoResult::Error
                } else {
                    wire::IoResult::Ok
                },
            })),
        );
        Poll::Ready(if fail {
            Err(std::io::Error::other("supplied flush error"))
        } else {
            Ok(())
        })
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub(crate) async fn write_auth(
    item: OutboundItem,
    connection: Uuid,
    site: NativeSite,
    script: wire::WriteScript,
    recorder: Capture,
) -> Driven<OwnedPublication> {
    assert!(
        preparation_valid(site, &script),
        "native site/script must be validated during preparation"
    );
    if matches!(
        limits::preflight(&item.stanza, &script),
        Err(limits::PlanError::TooManyWrites { .. })
    ) {
        return Err(native_stop(&recorder, site.item_ordinal(), 0, false));
    }
    let mut call = Box::pin(write_auth_inner(
        item,
        connection,
        site,
        script,
        recorder.clone(),
    ));
    let result = std::future::poll_fn(|cx| {
        match wire::driver::poll_once(&recorder, site.0, call.as_mut(), cx) {
            Ok(actual) => actual.map(Ok),
            Err(stop) => Poll::Ready(Err(stop)),
        }
    })
    .await;
    drop(call);
    result
}
async fn write_auth_inner(
    item: OutboundItem,
    connection: Uuid,
    site: NativeSite,
    script: wire::WriteScript,
    recorder: Capture,
) -> Result<OwnedPublication> {
    let ordinal = site.item_ordinal();
    ensure!(
        item.durable_source.is_none(),
        "auth control unexpectedly has durable source"
    );
    let holder = item
        .auth_publication()
        .ok_or_else(|| anyhow::anyhow!("actual native item has no auth holder"))?
        .clone();
    let owner = facts::project(&recorder, || {
        let introduced = holder
            .join_observation()
            .snapshot()
            .introduced
            .ok_or_else(|| anyhow::anyhow!("missing auth introduction"))?;
        let frame = introduced
            .frame
            .ok_or_else(|| anyhow::anyhow!("missing observed auth frame"))?;
        Ok(wire::ItemOwner::Auth(wire::AuthItemOwner {
            frame: facts::id(frame),
            control: facts::id(introduced.control),
        }))
    });
    // Production auth does not create a direct-delivery observation. Explicit
    // None prevents confusing its holder transport with NativeWriteLease facts.
    if let Some(owner) = owner {
        facts::observe(&recorder, || {
            Ok(wire::Fact::Native(wire::NativeFact::Dequeue(
                wire::NativeDequeue {
                    owner: owner.clone(),
                    item: facts::queue_item(&item, connection, ordinal)?,
                },
            )))
        });
        facts::emit(
            &recorder,
            wire::Fact::Native(wire::NativeFact::Snapshot(wire::NativeCapture {
                connection: facts::id(connection),
                item_ordinal: ordinal,
                owner,
                cut: wire::Cut::BeforePoll,
                snapshot: wire::Nullable::Null(()),
            })),
        );
    }
    holder.validate_connection(connection)?;
    holder.validate_control(&item.stanza)?;
    holder.recording()?;
    // Finite profile supplies non-SM recording. No resume/SM retention claim.
    let mut io = MemoryWrite::new(script, site, recorder);
    let result = holder
        .write(item.stanza.clone(), |control| async move {
            super::send(&mut io, &control).await
        })
        .await;
    drop(item); // Drop the original item's holder alias before publication cut.
    result
}
struct Port<'a> {
    connection: Uuid,
    service: Option<&'a Service>,
    recorder: Capture,
    ordinal: u8,
}
impl DirectWritePort for Port<'_> {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        ensure!(
            item.auth_publication().is_none(),
            "auth item entered durable writer"
        );
        Ok(false)
    }
    async fn fence_c2s(&self, _: DurableDelivery) -> Result<DurableDelivery> {
        facts::lost(&self.recorder);
        anyhow::bail!("C2S durable source outside Stage4 composition")
    }
    async fn fence_mix(&self, source: MixDelivery) -> Result<MixDelivery> {
        self.service
            .ok_or_else(|| anyhow::anyhow!("actual MIX service absent"))?
            .fence_mix_socket_write(source)
            .await
    }
    async fn acknowledge_c2s(&self, _: &actual::AckRequest) -> Result<()> {
        facts::lost(&self.recorder);
        anyhow::bail!("C2S ACK outside Stage4 composition")
    }
    async fn acknowledge_mix(&self, request: &actual::AckRequest) -> Result<bool> {
        facts::emit(
            &self.recorder,
            wire::Fact::Native(wire::NativeFact::Ack(wire::NativeAckCall {
                item_ordinal: self.ordinal,
                source: facts::source(request.source()),
                returned: wire::Nullable::Null(()),
            })),
        );
        let result = self
            .service
            .ok_or_else(|| anyhow::anyhow!("actual MIX service absent"))?
            .acknowledge_mix_socket_write(request)
            .await;
        facts::emit(
            &self.recorder,
            wire::Fact::Native(wire::NativeFact::Ack(wire::NativeAckCall {
                item_ordinal: self.ordinal,
                source: facts::source(request.source()),
                returned: facts::nullable(result.as_ref().ok().copied()),
            })),
        );
        result
    }
    fn connection_id(&self) -> Uuid {
        self.connection
    }
}
pub(crate) async fn write_item(
    item: OutboundItem,
    connection: Uuid,
    site: NativeSite,
    owner: wire::ItemOwner<wire::EvidenceId>,
    script: wire::WriteScript,
    service: Option<&Service>,
    recorder: Capture,
) -> Driven<()> {
    assert!(
        preparation_valid(site, &script),
        "native site/script must be validated during preparation"
    );
    if matches!(
        limits::preflight(&item.stanza, &script),
        Err(limits::PlanError::TooManyWrites { .. })
    ) {
        return Err(native_stop(&recorder, site.item_ordinal(), 0, false));
    }
    let retained = std::sync::Arc::new(std::sync::Mutex::new(None));
    let mut call = Box::pin(write_item_inner(
        item,
        connection,
        site,
        owner.clone(),
        script,
        service,
        recorder.clone(),
        retained.clone(),
    ));
    let result = std::future::poll_fn(|cx| {
        match wire::driver::poll_once(&recorder, site.0, call.as_mut(), cx) {
            Ok(actual) => actual.map(Ok),
            Err(stop) => Poll::Ready(Err(stop)),
        }
    })
    .await;
    drop(call);
    if result.is_err() {
        let read = retained.lock().unwrap().clone();
        if let Some(read) = read {
            capture(
                &recorder,
                &read,
                &owner,
                connection,
                site.item_ordinal(),
                wire::Cut::AfterRunnerDrop,
            );
        }
    }
    result
}
#[allow(clippy::too_many_arguments)]
async fn write_item_inner(
    item: OutboundItem,
    connection: Uuid,
    site: NativeSite,
    owner: wire::ItemOwner<wire::EvidenceId>,
    script: wire::WriteScript,
    service: Option<&Service>,
    recorder: Capture,
    retained: std::sync::Arc<std::sync::Mutex<Option<actual::Observation>>>,
) -> Result<()> {
    let ordinal = site.item_ordinal();
    facts::observe(&recorder, || {
        Ok(wire::Fact::Native(wire::NativeFact::Dequeue(
            wire::NativeDequeue {
                owner: owner.clone(),
                item: facts::queue_item(&item, connection, ordinal)?,
            },
        )))
    });
    let observation = actual::Observation::new(item.durable_source);
    *retained.lock().unwrap() = Some(observation.clone());
    capture(
        &recorder,
        &observation,
        &owner,
        connection,
        ordinal,
        wire::Cut::Introduction,
    );
    let mut port = Port {
        connection,
        service,
        recorder: recorder.clone(),
        ordinal,
    };
    let mut io = MemoryWrite::new(script, site, recorder.clone());
    let result = NativeWriteRunner::new(observation.clone(), async {
        let lease = DirectWriteLease::prepare_with(&mut port, &item, &observation).await?;
        let written = lease.write(|stanza| super::send(&mut io, stanza)).await?;
        written.settle_with(&port).await;
        Ok(())
    })
    .await;
    // Runner has destroyed its whole child before retirement; item is retained
    // here only to make observer cuts explicit, with no other writer task.
    capture(
        &recorder,
        &observation,
        &owner,
        connection,
        ordinal,
        wire::Cut::AfterRunnerDrop,
    );
    drop(item);
    result
}
fn capture(
    recorder: &Capture,
    read: &actual::Observation,
    owner: &wire::ItemOwner<wire::EvidenceId>,
    connection: Uuid,
    ordinal: u8,
    cut: wire::Cut,
) {
    macro_rules! same { ($from:expr, $a:ident => $b:ident; $($v:ident),+) => { match $from { $(actual::$a::$v => wire::$b::$v),+ } }; }
    let s = read.snapshot();
    let ack = |f: actual::AckFact| wire::NativeAckFact {
        source: facts::source(f.source),
        disposition: same!(f.disposition, AckDisposition => AckDisposition; Deleted, AbsentUnclaimed, NoMatchingMix),
    };
    facts::emit(
        recorder,
        wire::Fact::Native(wire::NativeFact::Snapshot(wire::NativeCapture {
            connection: facts::id(connection),
            item_ordinal: ordinal,
            owner: owner.clone(),
            cut,
            snapshot: wire::Nullable::Value(wire::NativeSnapshot {
                original: facts::nullable(s.original.map(facts::source)),
                preparation: same!(s.preparation, Preparation => NativePreparation; NotStarted, Recording, FenceCallEntered, Prepared, Superseded, Failed),
                managed_by_sm: facts::nullable(s.managed_by_sm),
                fence_entered: s.fence_entered,
                returned_fence: facts::nullable(s.returned_fence.map(facts::source)),
                writer_entered: s.writer_entered,
                writer_result: facts::nullable(
                    s.writer_result
                        .map(|r| same!(r, WriterResult => WriterResult; FullWrite, Failed)),
                ),
                write_decision: facts::nullable(
                    s.write_decision
                        .map(|r| same!(r, WriteDecision => WriteDecision; Withhold, Written)),
                ),
                ack: match s.ack {
                    actual::AckKnowledge::NotRequested => {
                        wire::NativeAckKnowledge::NotRequested(wire::Empty {})
                    }
                    actual::AckKnowledge::NoCommitRequested => {
                        wire::NativeAckKnowledge::NoCommitRequested(wire::Empty {})
                    }
                    actual::AckKnowledge::CommitCallEntered(f) => {
                        wire::NativeAckKnowledge::CommitCallEntered(ack(f))
                    }
                    actual::AckKnowledge::ReceiptKnown(f) => {
                        wire::NativeAckKnowledge::ReceiptKnown(ack(f))
                    }
                },
                ack_returned: facts::nullable(s.ack_returned),
                terminal: facts::nullable(
                    s.terminal
                        .map(|t| same!(t, Terminal => CallTerminal; Returned, Cancelled, Panicked)),
                ),
            }),
        })),
    )
}
