use anyhow::Result;
use northstar_delivery_core::bosh_ownership::{
    response::{AckRequest, BindRequest, RenewRequest},
    BoshResponseOwnership,
};
use northstar_delivery_core::{DurableDelivery, TransportOwnershipSource as Source};
use northstar_session_application::replay::{
    OfflineReplayLeaseAcquire, PendingPresenceCursor, PendingPresencePage, ReplayLeaseRepository,
    ReplayPageOutcome, ReplayRepository, ReplaySession,
};
use northstar_time::{DateTime, Utc};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Outcome {
    Committed,
    Rejected,
    Pending,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Call {
    Bind {
        address: usize,
        session_id: Uuid,
        rid: u64,
        ttl_seconds: u64,
        sources: Vec<Source>,
    },
    Renew {
        address: usize,
        session_id: Uuid,
        ttl_seconds: u64,
        expected: Option<(u64, BoshResponseOwnership)>,
    },
    Acknowledge {
        address: usize,
        session_id: Uuid,
        rid: u64,
    },
    Release(Uuid),
    Dropped(&'static str),
}

#[derive(Clone)]
pub(super) struct ReplayStore {
    outcome: Outcome,
    calls: Arc<Mutex<Vec<Call>>>,
    trace: Option<super::actor_host::Trace>,
    outcomes: Arc<Mutex<BTreeMap<&'static str, Outcome>>>,
    gates: Arc<Mutex<BTreeMap<&'static str, Arc<tokio::sync::Semaphore>>>>,
}

impl ReplayStore {
    pub(super) fn new(outcome: Outcome) -> Self {
        Self {
            outcome,
            calls: Arc::new(Mutex::new(vec![])),
            trace: None,
            outcomes: Arc::new(Mutex::new(BTreeMap::new())),
            gates: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub(super) fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    pub(super) fn with_trace(trace: super::actor_host::Trace) -> Self {
        Self {
            trace: Some(trace),
            ..Self::new(Outcome::Committed)
        }
    }

    pub(super) fn set_outcome(&self, method: &'static str, outcome: Outcome) {
        self.outcomes.lock().unwrap().insert(method, outcome);
    }

    pub(super) fn gate(&self, method: &'static str) -> Arc<tokio::sync::Semaphore> {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        self.gates.lock().unwrap().insert(method, gate.clone());
        gate
    }

    fn record(&self, call: Call) {
        if let Some(trace) = &self.trace {
            trace.push(super::actor_host::Event::Replay(call.clone()));
        }
        self.calls.lock().unwrap().push(call);
    }

    async fn complete(&self, method: &'static str) -> Result<()> {
        let gate = self.gates.lock().unwrap().get(method).cloned();
        if let Some(gate) = gate {
            gate.acquire().await.unwrap().forget();
        }
        let outcome = self
            .outcomes
            .lock()
            .unwrap()
            .get(method)
            .copied()
            .unwrap_or(self.outcome);
        match outcome {
            Outcome::Committed => Ok(()),
            Outcome::Rejected => Err(std::io::Error::other("recorded replay failure").into()),
            Outcome::Pending => std::future::pending().await,
        }
    }
}

struct CallDrop<'a>(&'a ReplayStore, &'static str);

impl Drop for CallDrop<'_> {
    fn drop(&mut self) {
        self.0.record(Call::Dropped(self.1));
    }
}

impl ReplayLeaseRepository for ReplayStore {
    async fn username(&self, _: Uuid) -> Result<Option<String>> {
        panic!("unexpected replay username lookup")
    }

    async fn acquire_lease(
        &self,
        _: Uuid,
        _: &str,
        _: Uuid,
        _: Option<DateTime<Utc>>,
        _: i64,
    ) -> Result<OfflineReplayLeaseAcquire> {
        panic!("unexpected replay lease acquisition")
    }
}

impl ReplayRepository for ReplayStore {
    async fn claim_page(
        &self,
        _: &ReplaySession,
        _: Option<&str>,
        _: bool,
        _: i64,
    ) -> Result<ReplayPageOutcome> {
        panic!("unexpected replay page claim")
    }

    async fn renew_before_send(&self, _: &ReplaySession, _: Uuid, _: &[Uuid]) -> Result<bool> {
        panic!("unexpected replay page renewal")
    }

    async fn release_unsent(&self, _: &ReplaySession, _: Uuid, _: &[Uuid]) -> Result<u64> {
        panic!("unexpected replay page release")
    }

    async fn finish(&self, _: &ReplaySession) -> Result<bool> {
        panic!("unexpected replay session finish")
    }

    async fn pending_presence_page(
        &self,
        _: Uuid,
        _: &str,
        _: Option<&str>,
        _: Option<&PendingPresenceCursor>,
        _: &str,
    ) -> Result<PendingPresencePage> {
        panic!("unexpected pending presence page")
    }

    async fn fence_socket_write(&self, _: DurableDelivery) -> Result<DurableDelivery> {
        panic!("unexpected native socket fence")
    }

    async fn acknowledge_socket_write(
        &self,
        _: DurableDelivery,
        _: Option<&northstar_delivery_core::native_write::AckRequest>,
    ) -> Result<()> {
        panic!("unexpected native socket acknowledgement")
    }

    async fn bind_bosh_response_sources(
        &self,
        request: &BindRequest,
    ) -> Result<BoshResponseOwnership> {
        self.record(Call::Bind {
            address: std::ptr::from_ref(request) as usize,
            session_id: request.session_id(),
            rid: request.rid(),
            ttl_seconds: request.ttl_seconds(),
            sources: request.sources().to_vec(),
        });
        let _drop = CallDrop(self, "bind");
        request.validate_for_io()?;
        let ownership = BoshResponseOwnership {
            c2s_message_ids: request
                .sources()
                .iter()
                .filter_map(|source| source.c2s().map(|source| source.message_id))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            mix_delivery_ids: request
                .sources()
                .iter()
                .filter_map(|source| source.mix().map(|source| source.delivery_id))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        };
        self.complete("bind").await?;
        request.enter_commit(ownership.clone())?.received();
        Ok(ownership)
    }

    async fn renew_bosh_fences(&self, request: &RenewRequest) -> Result<()> {
        self.record(Call::Renew {
            address: std::ptr::from_ref(request) as usize,
            session_id: request.session_id(),
            ttl_seconds: request.ttl_seconds(),
            expected: request
                .expected()
                .map(|(rid, ownership)| (rid, ownership.clone())),
        });
        let _drop = CallDrop(self, "renew");
        request.validate_for_io()?;
        self.complete("renew").await?;
        request.enter_commit()?.received();
        Ok(())
    }

    async fn acknowledge_bosh_responses(&self, request: &AckRequest) -> Result<()> {
        self.record(Call::Acknowledge {
            address: std::ptr::from_ref(request) as usize,
            session_id: request.session_id(),
            rid: request.rid(),
        });
        let _drop = CallDrop(self, "acknowledge");
        request.validate_for_io()?;
        self.complete("acknowledge").await?;
        request.enter_commit(vec![])?.received();
        Ok(())
    }

    async fn release_bosh_fences(&self, session_id: Uuid) -> Result<()> {
        self.record(Call::Release(session_id));
        let _drop = CallDrop(self, "release");
        self.complete("release").await
    }
}
