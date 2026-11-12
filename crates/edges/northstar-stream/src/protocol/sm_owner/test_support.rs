//! The SM owner's in-memory ownership port and fixture. The stream's own SM tests drive every cut through it;
//! the transports' composition tests use the facade at the end.
// Items only the stream's own tests use are dead in a `test-support` build.
#![cfg_attr(not(test), allow(dead_code))]

use super::*;
use crate::outbound::{DurableDelivery, MixDelivery};
use northstar_delivery_core::sm_ownership::{CommitFact, MixRotation};
use northstar_session_application::sm::{SmMixLeaseRotation, SmQueueOwnershipResolution};
use northstar_session_application::sm_capacity::SmCapacityMetrics;
use std::collections::VecDeque;
use std::{sync::Mutex, task::Waker};

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(super) enum Cut {
    #[default]
    Success,
    BeforeCommit,
    DuringCommit,
    CommitError,
    TypedAfterCommitError,
    TypedAfterReceipt,
    AfterReceiptPending,
    AfterReceiptError,
    RollbackPending,
    RollbackError,
    RolledBack,
    Superseded,
    WrongReturnedRotation,
    MissingMix,
}
#[derive(Clone)]
pub(super) struct FakePort {
    pub(super) governor: Arc<SmMemoryGovernor>,
    pub(super) events: Arc<Mutex<Vec<&'static str>>>,
    pub(super) cut: Cut,
    pub(super) rotate: bool,
    pub(super) absent_unclaimed: bool,
    pub(super) injected_shrink_error: bool,
}
impl FakePort {
    pub(super) fn events(&self) -> Vec<&'static str> {
        self.events.lock().unwrap().clone()
    }
    pub(super) fn event(&self, event: &'static str) {
        self.events.lock().unwrap().push(event);
    }
    pub(super) fn mislabeled_supersession(&self, request: &sm_ownership::Request) -> anyhow::Error {
        let message_id = request
            .binding()
            .remaining
            .iter()
            .flatten()
            .find_map(|source| source.c2s())
            .unwrap()
            .message_id;
        crate::outbound::DurableDeliverySuperseded { message_id }.into()
    }
    pub(super) async fn commit(
        &self,
        request: &sm_ownership::Request,
        fact: CommitFact,
    ) -> Result<()> {
        self.event("commit");
        let committed = sm_ownership::commit_observed(
            async {
                if self.cut == Cut::DuringCommit {
                    std::future::pending::<()>().await;
                }
                if matches!(self.cut, Cut::CommitError | Cut::TypedAfterCommitError) {
                    return Err(std::io::Error::other("injected COMMIT response loss"));
                }
                Ok(())
            },
            request,
            fact,
        )
        .await;
        if self.cut == Cut::TypedAfterCommitError {
            assert!(committed.is_err());
            return Err(self.mislabeled_supersession(request));
        }
        committed?;
        self.event("receipt");
        if self.cut == Cut::TypedAfterReceipt {
            return Err(self.mislabeled_supersession(request));
        }
        // These cuts are synthetic: the current SQL adapter has no await
        // between its successful COMMIT callback and outcome conversion.
        if self.cut == Cut::AfterReceiptPending {
            std::future::pending::<()>().await;
        }
        if self.cut == Cut::AfterReceiptError {
            anyhow::bail!("injected post-receipt continuation error");
        }
        Ok(())
    }
}
impl SmOwnerPort for FakePort {
    fn recorded(&self) {
        self.event("record");
    }
    fn reserve_snapshot(&self, bytes: usize) -> Result<SmCapacityLease> {
        self.event("reserve_snapshot");
        Ok(self.governor.try_reserve_live(bytes)?)
    }
    fn grow(&self, lease: &SmCapacityLease, bytes: usize) -> Result<()> {
        self.event("grow");
        Ok(lease.try_grow_to(bytes)?)
    }
    fn shrink(&self, lease: &SmCapacityLease, bytes: usize) -> Result<()> {
        self.event("shrink");
        anyhow::ensure!(
            !self.injected_shrink_error,
            "injected capacity continuation failure"
        );
        Ok(lease.shrink_to(bytes)?)
    }
    async fn checkpoint(&self, prepared: &PreparedCheckpoint<'_>) -> Result<SmCheckpointOutcome> {
        self.event("checkpoint");
        prepared.validate_projection(
            prepared.session_id(),
            prepared.connection_id(),
            northstar_session_application::sm::ownership::SnapshotProjection::from(
                prepared.snapshot(),
            ),
            prepared.acknowledged(),
            prepared.policy(),
        )?;
        if self.cut == Cut::Superseded {
            let message_id = prepared
                .snapshot()
                .unacked
                .iter()
                .find_map(|entry| entry.source.and_then(TransportOwnershipSource::c2s))
                .unwrap()
                .message_id;
            return Err(crate::outbound::DurableDeliverySuperseded { message_id }.into());
        }
        if self.cut == Cut::BeforeCommit {
            anyhow::bail!("injected pre-COMMIT failure");
        }
        if matches!(
            self.cut,
            Cut::RollbackPending | Cut::RollbackError | Cut::RolledBack
        ) {
            self.event("rollback");
            sm_ownership::rollback_observed(
                async {
                    if self.cut == Cut::RollbackPending {
                        std::future::pending::<()>().await;
                    }
                    if self.cut == Cut::RollbackError {
                        return Err(std::io::Error::other("injected rollback response loss"));
                    }
                    Ok(())
                },
                prepared.request(),
            )
            .await?;
            return Ok(SmCheckpointOutcome {
                updated: false,
                ownership: SmQueueOwnershipResolution::default(),
            });
        }
        let rotations = if self.rotate {
            prepared
                .snapshot()
                .unacked
                .iter()
                .filter_map(|entry| entry.source.and_then(TransportOwnershipSource::mix))
                .map(|previous| MixRotation {
                    previous,
                    current: MixDelivery {
                        lease_token: Uuid::from_u128(999),
                        ..previous
                    },
                })
                .collect::<Vec<_>>()
        } else {
            vec![]
        };
        self.commit(
            prepared.request(),
            CommitFact::Checkpoint {
                rotations: rotations.clone(),
                settled: prepared
                    .acknowledged()
                    .iter()
                    .filter_map(|entry| entry.source)
                    .collect(),
            },
        )
        .await?;
        let mut returned = rotations;
        if self.cut == Cut::WrongReturnedRotation {
            returned[0].current.lease_token = Uuid::from_u128(998);
        }
        Ok(SmCheckpointOutcome {
            updated: true,
            ownership: SmQueueOwnershipResolution {
                mix_rotations: returned
                    .into_iter()
                    .map(|rotation| SmMixLeaseRotation {
                        previous: rotation.previous,
                        current: rotation.current,
                    })
                    .collect(),
            },
        })
    }
    async fn acknowledge_batch(&self, prepared: &PreparedBatch<'_>) -> Result<()> {
        self.event("batch");
        prepared.validate_sources(prepared.sources())?;
        if prepared.sources().is_empty() {
            prepared.request().no_persistence()?;
            return Ok(());
        }
        if self.cut == Cut::BeforeCommit || self.cut == Cut::MissingMix {
            anyhow::bail!("injected exact source authority rejection");
        }
        let mut deleted = vec![];
        let mut absent_unclaimed = vec![];
        for source in prepared.sources() {
            match source {
                TransportOwnershipSource::C2s(delivery)
                    if self.absent_unclaimed && delivery.claim_id.is_none() =>
                {
                    absent_unclaimed.push(*delivery)
                }
                _ => deleted.push(*source),
            }
        }
        self.commit(
            prepared.request(),
            CommitFact::UnpersistedAck {
                deleted,
                absent_unclaimed,
            },
        )
        .await
    }
}
#[derive(Default)]
pub(super) struct Metadata {
    pub(super) available: Option<Arc<AtomicBool>>,
    pub(super) carbons: AtomicBool,
    pub(super) priority: AtomicI16,
    pub(super) blocklist: AtomicBool,
    pub(super) roster: AtomicBool,
    pub(super) privacy: RwLock<Option<String>>,
    pub(super) privacy_requested: AtomicBool,
    pub(super) rooms: dashmap::DashMap<String, JoinedMucMembership>,
    pub(super) directed: dashmap::DashSet<String>,
    pub(super) presence: RwLock<Option<String>>,
}
impl Metadata {
    pub fn view(&self) -> SmSnapshotView<'_> {
        SmSnapshotView {
            available: &self.available,
            carbons: &self.carbons,
            priority: &self.priority,
            blocklist_requested: &self.blocklist,
            roster_requested: &self.roster,
            privacy_active: &self.privacy,
            privacy_requested: &self.privacy_requested,
            peer_ip: &TEST_IP,
            user_agent_id: &None,
            joined_rooms: &self.rooms,
            directed_presence: &self.directed,
            last_presence: &self.presence,
        }
    }
}
pub(super) const TEST_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
pub(super) struct Fixture {
    pub(super) sm: SmSubstate,
    pub(super) metadata: Metadata,
    pub(super) policy: SmRuntimePolicy,
    pub(super) port: FakePort,
}
impl Fixture {
    pub(super) fn new(persisted: bool, queue: Vec<SmUnackedStanza>) -> Self {
        let governor = SmMemoryGovernor::new(
            65_536,
            32_768,
            4,
            32_768,
            Arc::new(SmCapacityMetrics::default()),
        )
        .unwrap();
        let metadata = Metadata::default();
        let mut sm = SmSubstate {
            enabled: true,
            db_id: persisted.then(|| Uuid::from_u128(401)),
            resume_allowed: true,
            resume_timeout_seconds: 60,
            inbound_h: 2,
            outbound_h: 10 + queue.len() as u32,
            acked_h: 10,
            unacked: queue.into(),
            ..SmSubstate::default()
        };
        sm.capacity = Some(
            governor
                .try_reserve_live(metadata.view().resident_bytes(&sm).unwrap())
                .unwrap(),
        );
        Self {
            sm,
            metadata,
            policy: SmRuntimePolicy {
                session: northstar_session_application::sm::SmSessionPolicy {
                    require_same_device: true,
                    resume_timeout_seconds: 60,
                    live_lease_seconds: 30,
                    claim_lease_seconds: 10,
                    max_per_account: 4,
                    max_global: 100,
                },
                buffer: northstar_session_application::sm::SmBufferLimits {
                    max_unacked_stanzas: 32,
                    max_unacked_bytes: 16_384,
                    max_snapshot_bytes: 32_768,
                },
                ip_binding: "none".to_owned(),
            },
            port: FakePort {
                governor,
                events: Arc::new(Mutex::new(vec![])),
                cut: Cut::Success,
                rotate: false,
                absent_unclaimed: false,
                injected_shrink_error: false,
            },
        }
    }
    pub(super) fn turn(&mut self) -> SmTransportTurn<'_, FakePort> {
        SmTransportTurn {
            sm: &mut self.sm,
            view: self.metadata.view(),
            policy: &self.policy,
            connection_id: Uuid::from_u128(402),
            port: self.port.clone(),
        }
    }
    pub(super) async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        let mut turn = self.turn();
        let observation = turn.start(Purpose::Record);
        SmTurnRunner::new(observation.clone(), async move {
            let result = turn.record_item(item, &observation).await;
            if result.is_err() {
                observation.returned_error();
            }
            result
        })
        .await
    }
    pub(super) async fn ack(&mut self, h: u32) -> Result<bool> {
        let mut turn = self.turn();
        let observation = turn.start(Purpose::Acknowledge { h });
        SmTurnRunner::new(observation.clone(), async move {
            let result = turn.acknowledge(h, &observation).await;
            if result.is_err() {
                observation.returned_error();
            }
            result
        })
        .await
    }
    pub(super) fn snapshot(&self) -> sm_ownership::Snapshot {
        self.sm.current_operation.as_ref().unwrap().snapshot()
    }
}
pub fn c2s() -> DurableDelivery {
    DurableDelivery {
        recipient_id: Uuid::from_u128(501),
        message_id: Uuid::from_u128(502),
        claim_id: Some(Uuid::from_u128(503)),
    }
}
pub fn mix() -> MixDelivery {
    MixDelivery {
        delivery_id: Uuid::from_u128(601),
        lease_token: Uuid::from_u128(602),
    }
}
pub fn c2s_item() -> OutboundItem {
    OutboundItem::durable(
        "<message id='private-payload'><body>hello</body></message>".to_owned(),
        c2s(),
    )
}
pub(super) fn plain() -> SmUnackedStanza {
    SmUnackedStanza::plain("<presence/>".to_owned())
}
pub(super) fn mixed_queue() -> Vec<SmUnackedStanza> {
    vec![
        plain(),
        SmUnackedStanza::with_source(
            "<message id='c2s'/>".to_owned(),
            Some(TransportOwnershipSource::C2s(c2s())),
        ),
        plain(),
        SmUnackedStanza::with_source(
            "<message id='mix'/>".to_owned(),
            Some(TransportOwnershipSource::Mix(mix())),
        ),
    ]
}
pub(super) fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut TaskContext::from_waker(Waker::noop()))
}

/// A real SM transport turn over the in-memory ownership port, for the transports' composition tests
/// (northstar-c2s's native lease, northstar-bosh's response recording).
pub struct SmRecordFixture(Fixture);

impl SmRecordFixture {
    /// A persisted SM session with an empty queue. With `rotate`, the port returns MIX lease rotations.
    pub fn persisted(rotate: bool) -> Self {
        let mut fixture = Fixture::new(true, vec![]);
        fixture.port.rotate = rotate;
        Self(fixture)
    }

    /// A transport turn over the session.
    pub fn turn(&mut self) -> SmRecordTurn<'_> {
        SmRecordTurn(self.0.turn())
    }
}

/// One transport turn of [`SmRecordFixture`].
pub struct SmRecordTurn<'a>(SmTransportTurn<'a, FakePort>);

impl SmRecordTurn<'_> {
    /// Records `item` in one observed SM record turn, as a transport's record port does.
    pub async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        let observation = self.0.start(Purpose::Record);
        SmTurnRunner::new(observation.clone(), self.0.record_item(item, &observation)).await
    }

    /// The connection the turn belongs to.
    pub fn connection_id(&self) -> Uuid {
        self.0.connection_id
    }

    /// The snapshot of the turn's current SM operation.
    pub fn operation(&self) -> sm_ownership::Snapshot {
        self.0.sm.current_operation.as_ref().unwrap().snapshot()
    }

    /// The persisted SM session id.
    pub fn db_id(&self) -> Option<Uuid> {
        self.0.sm.db_id
    }

    /// The outbound stanza counter.
    pub fn outbound_h(&self) -> u32 {
        self.0.sm.outbound_h
    }

    /// The unacknowledged queue.
    pub fn unacked(&self) -> &VecDeque<crate::outbound::SmUnackedStanza> {
        &self.0.sm.unacked
    }
}
