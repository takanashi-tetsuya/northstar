use super::*;

#[derive(Clone, Copy)]
pub enum Answer {
    Worker,
    Pending,
    Permanent,
    Retry,
    Shutdown,
    Transfer,
}
#[derive(Clone, Copy)]
pub enum Renewal {
    Pending,
    Matched,
    Lost,
    Error,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyCall {
    Route(Box<mix_worker::Row>, String),
    Renew(MixDelivery),
    Settle(MixDelivery, i64, mix_worker::SettlementCommand),
}

struct EffectDrop {
    owner: mix_worker::Observation,
    marker: Arc<AtomicBool>,
}
impl Drop for EffectDrop {
    fn drop(&mut self) {
        assert!(
            !self.owner.snapshot().renewal_scope_closed,
            "effect destroyed before renewal scope closes"
        );
        assert_eq!(
            self.owner.snapshot().terminal,
            None,
            "effect destroyed before attempt retirement"
        );
        self.marker.store(true, Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct PolicyPort {
    pub owner: mix_worker::Observation,
    pub answer: Answer,
    pub log: Arc<Mutex<Vec<PolicyCall>>>,
    pub route_gate: Arc<Mutex<Option<Arc<tokio::sync::Semaphore>>>>,
    pub settle_gate: Arc<Mutex<Option<Arc<tokio::sync::Semaphore>>>>,
    pub renewal: Arc<Mutex<Renewal>>,
    pub matched: Arc<AtomicBool>,
    pub settle_error: Arc<AtomicBool>,
    pub settle_mismatch: Arc<AtomicBool>,
    pub route_dropped: Arc<AtomicBool>,
    pub renewal_dropped: Arc<AtomicBool>,
    pub settle_dropped: Arc<AtomicBool>,
    pub permit: Arc<tokio::sync::Semaphore>,
}
impl PolicyPort {
    pub fn calls(&self) -> Vec<PolicyCall> {
        self.log.lock().unwrap().clone()
    }
}
impl ClaimedMixDeliveryPort for PolicyPort {
    async fn route(
        &self,
        request: &mix_worker::RouteRequest,
    ) -> Result<ChannelStanzaDeliveryOutcome> {
        request.start()?;
        assert!(
            std::ptr::eq(request.row(), self.owner.row()),
            "same invocation row reaches route"
        );
        let _drop = EffectDrop {
            owner: self.owner.clone(),
            marker: self.route_dropped.clone(),
        };
        let _permit = self.permit.acquire().await.unwrap();
        self.log.lock().unwrap().push(PolicyCall::Route(
            Box::new(request.row().clone()),
            request.stanza().into(),
        ));
        wait_gate(&self.route_gate).await;
        match self.answer {
            Answer::Worker => Ok(ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker),
            Answer::Pending => Err(MixDeliveryRoutePending.into()),
            Answer::Permanent => Err(permanent_mix_delivery_error("policy-cancelled", "blocked")),
            Answer::Retry => anyhow::bail!("route failed"),
            Answer::Shutdown => Err(MixOutboxShutdown.into()),
            Answer::Transfer => {
                let local = request.local_request("bob@local.test/phone".into())?;
                local.start()?;
                local.enqueued()?;
                local.returned(mix_worker::LocalResult::Transferred(
                    mix_worker::TransferBoundary::SmPersisted(Uuid::from_u128(88)),
                ))?;
                Ok(ChannelStanzaDeliveryOutcome::TransferredToRecoverableTransport)
            }
        }
    }
    async fn renew(&self, request: &mix_worker::RenewalRequest) -> Result<bool> {
        let _drop = EffectDrop {
            owner: self.owner.clone(),
            marker: self.renewal_dropped.clone(),
        };
        self.log
            .lock()
            .unwrap()
            .push(PolicyCall::Renew(request.source()));
        let outcome = *self.renewal.lock().unwrap();
        if matches!(outcome, Renewal::Pending) {
            let _permit = self.permit.acquire().await.unwrap();
            std::future::pending::<()>().await;
        }
        request.start()?;
        if matches!(outcome, Renewal::Error) {
            request.failed()?;
            anyhow::bail!("renewal failed");
        }
        let matched = matches!(outcome, Renewal::Matched);
        let entered = request.enter_statement()?;
        request.received(entered, matched)?;
        Ok(request.returned(matched)?)
    }
    async fn settle(
        &self,
        request: &mix_worker::SettlementRequest,
    ) -> Result<mix_worker::SettlementResult> {
        assert!(self.owner.snapshot().renewal_scope_closed);
        assert_eq!(self.owner.snapshot().terminal, None);
        if self
            .calls()
            .iter()
            .any(|call| matches!(call, PolicyCall::Route(_, _)))
        {
            assert!(self.route_dropped.load(Ordering::SeqCst));
        }
        if self
            .calls()
            .iter()
            .any(|call| matches!(call, PolicyCall::Renew(_)))
        {
            assert!(self.renewal_dropped.load(Ordering::SeqCst));
        }
        request.start()?;
        let _drop = DropFlag(self.settle_dropped.clone());
        self.log.lock().unwrap().push(PolicyCall::Settle(
            request.source(),
            request.route_wake_generation(),
            request.command().clone(),
        ));
        wait_gate(&self.settle_gate).await;
        if self.settle_error.load(Ordering::SeqCst) {
            request.failed()?;
            anyhow::bail!("settlement failed");
        }
        if self.settle_mismatch.load(Ordering::SeqCst) {
            return Ok(mix_worker::SettlementResult::Ack(true));
        }
        let result = settlement_result(request.command(), self.matched.load(Ordering::SeqCst));
        settlement_receipt(request, result)?;
        Ok(request.returned(result)?)
    }
}

pub fn policy_run(
    row: mix_worker::Row,
    answer: Answer,
    cancel: CancellationToken,
) -> (mix_worker::Observation, PolicyPort, outbox::AttemptRun) {
    let owned = outbox::OwnedAttempt::new(attempt_from_row(row));
    let owner = owned.observation();
    let port = PolicyPort {
        owner: owner.clone(),
        answer,
        log: Arc::new(Mutex::new(vec![])),
        route_gate: Arc::new(Mutex::new(None)),
        settle_gate: Arc::new(Mutex::new(None)),
        renewal: Arc::new(Mutex::new(Renewal::Matched)),
        matched: Arc::new(AtomicBool::new(true)),
        settle_error: Arc::new(AtomicBool::new(false)),
        settle_mismatch: Arc::new(AtomicBool::new(false)),
        route_dropped: Arc::new(AtomicBool::new(false)),
        renewal_dropped: Arc::new(AtomicBool::new(false)),
        settle_dropped: Arc::new(AtomicBool::new(false)),
        permit: Arc::new(tokio::sync::Semaphore::new(1)),
    };
    let worker_port = port.clone();
    let run = owned.run(move |attempt, handle| {
        process_claimed_mix_delivery_with_port(worker_port, attempt, handle, cancel)
    });
    (owner, port, run)
}
