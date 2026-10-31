//! Controlled admission, direct-commit and route ports with their frame log.

use super::*;

pub(super) struct FrameLog {
    pub(super) owner: DirectOperationHandle,
    pub(super) sequence: Sequence,
    pub(super) prefixes: Mutex<Vec<wire::OriginalPrefix>>,
    pub(super) route: Mutex<wire::RouteEvidence>,
    pub(super) routing: AtomicBool,
    pub(super) direct_pending: AtomicBool,
    pub(super) rearm_pending: AtomicBool,
}
impl FrameLog {
    pub(super) fn prefix(&self) {
        let state = original_state(&self.owner);
        let seq = next(&self.sequence);
        self.prefixes
            .lock()
            .unwrap()
            .push(wire::OriginalPrefix { seq, state });
    }
}
pub(super) struct AdmissionPort<'a> {
    pub(super) plan: &'a wire::Admission,
    pub(super) log: Arc<FrameLog>,
}
impl MessageAdmissionRepository for AdmissionPort<'_> {
    async fn begin(
        &self,
        _: &MessageAdmissionRequest<'_>,
        observation: &AdmissionWitness,
    ) -> Result<MessageAdmissionStart> {
        let wire::Admission::Reserved {
            fence,
            requirement,
            begin_commit,
            ..
        } = self.plan
        else {
            anyhow::bail!("unexpected rated admission call");
        };
        let lease = northstar_abuse_application::guard::MessageAdmissionLease::new(
            wire::unhex(&fence.admission_key_hex).map_err(|_| anyhow::anyhow!("invalid fence"))?,
            wire::unhex(&fence.payload_mac_hex).map_err(|_| anyhow::anyhow!("invalid fence"))?,
            fence.lease_token.0,
            northstar_abuse_policy::MessageDedupeIdentity {
                identity_digest: wire::unhex(&fence.dedupe_digest_hex)
                    .map_err(|_| anyhow::anyhow!("invalid dedupe binding"))?,
                candidates: vec![],
            },
        );
        let fact = admission::CommitFact::Reserved(
            northstar_abuse_application::guard::acceptance_fence(&lease.acceptance()),
        );
        witness::saved_case_commit_observed(
            async {
                self.log.prefix();
                match begin_commit {
                    wire::CommitCut::Complete => Ok(()),
                    wire::CommitCut::Pending => std::future::pending().await,
                    wire::CommitCut::Error => anyhow::bail!("controlled admission COMMIT error"),
                }
            },
            observation,
            admission::TransactionScope::RatedBegin(admission::BeginCommitPurpose::NewReservation),
            fact,
        )
        .await?;
        self.log.prefix();
        Ok(MessageAdmissionStart::Proceed {
            lease: Some(lease),
            requirement: northstar_abuse_policy::WorkRequirement {
                action: requirement.action.clone(),
                step: requirement.step,
                work_factor: requirement.work_factor,
                max_work_factor: requirement.max_work_factor,
                hard_wait_seconds: requirement.hard_wait_seconds,
                retry_after_seconds: requirement.retry_after_seconds,
                cooldown_seconds: requirement.cooldown_seconds,
                approximate_max_device_seconds: requirement.approximate_max_device_seconds,
                notice: requirement.notice.clone(),
            },
        })
    }
    async fn accept(
        &self,
        acceptance: &northstar_abuse_application::guard::MessageAdmissionAcceptance<'_>,
        observation: &AdmissionWitness,
    ) -> Result<FinalizeDecision> {
        let wire::Admission::Reserved {
            finalize_commit, ..
        } = self.plan
        else {
            anyhow::bail!("unexpected finalization");
        };
        witness::saved_case_commit_observed(
            async {
                self.log.prefix();
                match finalize_commit {
                    wire::CommitCut::Complete => Ok(()),
                    wire::CommitCut::Pending => std::future::pending().await,
                    wire::CommitCut::Error => anyhow::bail!("controlled finalization COMMIT error"),
                }
            },
            observation,
            admission::TransactionScope::AdmissionFinalize,
            admission::CommitFact::Finalized {
                fence: northstar_abuse_application::guard::acceptance_fence(acceptance),
                result: admission::FinalizeSuccess::PendingAccepted,
            },
        )
        .await?;
        self.log.prefix();
        Ok(FinalizeDecision::AcceptPending)
    }
    async fn reconcile(&self, _: &admission::Effect) -> Result<admission::ReconcileResult> {
        anyhow::bail!("unexpected reconciliation")
    }
}
pub(super) struct DirectPort<'a> {
    pub(super) plan: &'a wire::DirectRepository,
    pub(super) log: Arc<FrameLog>,
    pub(super) row: Arc<Mutex<Option<DurableDelivery>>>,
}
impl PersonalMessageCommitRepository for DirectPort<'_> {
    type Error = anyhow::Error;
    async fn commit<'a>(
        &'a self,
        _: &'a ValidatedPersonalMessage<'a>,
    ) -> Result<northstar_message_core::MessageCommit> {
        anyhow::bail!("unexpected legacy application call")
    }
}
impl direct_commit::DirectCommitRepository for DirectPort<'_> {
    type Error = anyhow::Error;
    async fn commit_direct<'a>(
        &'a self,
        command: &'a ValidatedPersonalMessage<'a>,
        _: DirectSpoolEligibility,
        observer: Option<&'a dyn direct_commit::DirectCommitObserver>,
    ) -> Result<northstar_message_core::DirectPersonalMessageAdmission> {
        let outcome = match &self.plan.transaction {
            wire::Transaction::Stored {
                recipient_id,
                delivery_id,
                archive_ids,
                live_claim_id,
            } => direct_commit::TransactionOutcome::Stored {
                recipient_id: recipient_id.0,
                delivery_id: delivery_id.0,
                archive_ids: archive_ids.iter().map(|id| id.0).collect(),
                live_claim_id: live_claim_id.get().map(|id| id.0),
            },
            wire::Transaction::Replay { archive_ids } => {
                direct_commit::TransactionOutcome::Replay {
                    archive_ids: archive_ids.iter().map(|id| id.0).collect(),
                }
            }
            wire::Transaction::AccountUnavailable {} => {
                direct_commit::TransactionOutcome::AccountUnavailable
            }
        };
        crate::services::messaging::direct_workflow::commit_observed(
            async {
                self.log.prefix();
                match self.plan.commit {
                    wire::CommitCut::Pending => {
                        self.log.direct_pending.store(true, Ordering::SeqCst);
                        std::future::pending::<Result<()>>().await
                    }
                    wire::CommitCut::Error => anyhow::bail!("controlled direct COMMIT error"),
                    wire::CommitCut::Complete => {
                        if let direct_commit::TransactionOutcome::Stored {
                            recipient_id,
                            delivery_id,
                            live_claim_id,
                            ..
                        } = &outcome
                        {
                            *self.row.lock().unwrap() = Some(DurableDelivery {
                                recipient_id: *recipient_id,
                                message_id: *delivery_id,
                                claim_id: *live_claim_id,
                            });
                        }
                        Ok(())
                    }
                }
            },
            observer.ok_or_else(|| anyhow::anyhow!("missing prepared observer"))?,
            outcome.clone(),
            self.plan.admitted_mode.actual(),
        )
        .await?;
        self.log.prefix();
        let wire::Completion::Return { mode } = &self.plan.completion else {
            anyhow::bail!("controlled outer error after receipt");
        };
        let (commit, claim) = match outcome {
            direct_commit::TransactionOutcome::Stored {
                recipient_id,
                delivery_id,
                live_claim_id,
                ..
            } => (
                northstar_message_core::MessageCommit::Stored {
                    archive_written: !command.archives.is_empty(),
                    post_commit: MessagePostCommit::RouteLocalDelivery {
                        recipient_id,
                        delivery_id,
                    },
                },
                live_claim_id,
            ),
            direct_commit::TransactionOutcome::Replay { .. } => {
                (northstar_message_core::MessageCommit::Replay, None)
            }
            direct_commit::TransactionOutcome::AccountUnavailable => (
                northstar_message_core::MessageCommit::AccountUnavailable,
                None,
            ),
        };
        Ok(northstar_message_core::DirectPersonalMessageAdmission {
            commit,
            mode: mode.actual(),
            live_claim_id: claim,
        })
    }
}

pub(super) struct RoutePort<'a> {
    pub(super) plan: &'a wire::Route,
    pub(super) clustered: bool,
    pub(super) log: Arc<FrameLog>,
    pub(super) health: Mutex<VecDeque<wire::Mode>>,
    pub(super) remote: Mutex<VecDeque<bool>>,
}
impl OnlineRoutePort for RoutePort<'_> {
    type Session = OutboundSender;
    fn try_local(
        &self,
        session: &Self::Session,
        enqueue: RouteEnqueue,
    ) -> Result<(), RouteSendError> {
        let source = enqueue.item().durable_source.expect("direct item source");
        let xml = enqueue.item().stanza.clone();
        let result = session.try_send_route_item(enqueue);
        let label = match &result {
            Ok(()) => "Accepted",
            Err(RouteSendError::Full(_)) => "Full",
            Err(RouteSendError::Closed(_)) => "Closed",
            Err(RouteSendError::Binding(_)) => "BindingRejected",
        };
        let seq = next(&self.log.sequence);
        self.log.route.lock().unwrap().enqueue.push(wire::Enqueue {
            seq,
            source: source.into(),
            xml,
            result: label,
        });
        self.log.prefix();
        result
    }
    fn record_local_accept(&self, _: bool) {
        self.log.prefix();
    }
    async fn route_available_remote(
        &self,
        _: &str,
        _: &str,
        source: Option<DurableDelivery>,
    ) -> bool {
        let value = self
            .remote
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected remote route");
        let seq = next(&self.log.sequence);
        self.log
            .route
            .lock()
            .unwrap()
            .remote_calls
            .push(wire::RemoteCall {
                seq,
                source: TransportOwnershipSource::C2s(source.expect("durable remote source"))
                    .into(),
                returned: Some(value),
            });
        value
    }
    async fn route_remote_primary(
        &self,
        jid: &str,
        stanza: &str,
        source: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        OnlineRouteResult {
            delivered: self.route_available_remote(jid, stanza, source).await,
            accepted_full_jid: None,
        }
    }
}
impl FullJidFallbackPort for RoutePort<'_> {
    fn fallback_sessions(&self, _: &str) -> Vec<(String, Self::Session)> {
        vec![]
    }
    fn available_priority(&self, _: &Self::Session) -> Option<i16> {
        Some(0)
    }
    fn priority(&self, _: &Self::Session) -> i16 {
        0
    }
    async fn privacy_allows_fallback(&self, _: &Self::Session, _: &str) -> Result<bool> {
        anyhow::bail!("unexpected fallback privacy query")
    }
    fn post_accept_failed(&self) {
        self.log.prefix();
    }
}
impl DirectMessageRoutePort for RoutePort<'_> {
    fn direct_route_mode(&self) -> DirectPostCommitMode {
        if !self.log.routing.load(Ordering::SeqCst) {
            // The shared finalization await has returned before this actual
            // PostFinalize read. Capture its retained return, not a prediction.
            self.log.prefix();
        }
        let mode = self
            .health
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected health read");
        let seq = next(&self.log.sequence);
        self.log
            .route
            .lock()
            .unwrap()
            .health_reads
            .push(wire::HealthRead {
                seq,
                phase: if self.log.routing.load(Ordering::SeqCst) {
                    "Router"
                } else {
                    "PostFinalize"
                },
                mode,
            });
        mode.actual()
    }
    fn clustered_direct_routes(&self) -> bool {
        self.clustered
    }
    async fn rearm_direct_route(&self, source: DurableDelivery) {
        if !self.log.routing.load(Ordering::SeqCst) {
            // Initial recovery can bypass health. Its real permit is already
            // CallEntered; keep that state immediately before the port call.
            self.log.prefix();
        }
        let seq = next(&self.log.sequence);
        let index = {
            let mut route = self.log.route.lock().unwrap();
            let index = route.rearm_calls.len();
            route.rearm_calls.push(wire::RearmCall {
                seq,
                source: TransportOwnershipSource::C2s(source).into(),
                returned: false,
            });
            index
        };
        self.log.prefix();
        if self.plan.rearm == wire::Rearm::Pending {
            self.log.rearm_pending.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
        }
        self.log.route.lock().unwrap().rearm_calls[index].returned = true;
    }
}
