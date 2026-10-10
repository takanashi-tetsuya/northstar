//! Test-only Stage4 actual-owner adapter over finite supplied replies.
#![cfg(test)]
mod map;
mod repository;
mod routes;
#[cfg(test)]
mod tests;
use super::*;
use crate::services::mix::MixService;
use crate::stage4_replay as wire;
use crate::xmpp::frame_execution::{FrameExecution, SessionExecutions};
use anyhow::{ensure, Context, Result};
use northstar_room_application::mix as fg;
use northstar_room_core::mix as room;
pub(crate) use repository::ControlledRepository;
pub(crate) use routes::{RouteHandle, RouteMap};
use std::{
    future::Future,
    pin::Pin,
    sync::Mutex,
    task::{Context as TaskContext, Poll},
};
use tokio_util::sync::CancellationToken;
use wire::{driver, BudgetStop, DriverConfigurationError, PollSite};
pub(crate) type Recorder = driver::Capture;
pub(crate) type Driven<T> = std::result::Result<Result<T>, BudgetStop>;
// Prevalidated labels only, with no counter, permission or owning capability.
// Construct these before invoking any method that constructs a real owner.
#[derive(Clone, Copy)]
pub(crate) struct ClaimSites {
    claim: PollSite,
    worker: PollSite,
}
impl ClaimSites {
    pub(crate) fn new(ordinal: u8) -> std::result::Result<Self, DriverConfigurationError> {
        Ok(Self {
            claim: PollSite::new(wire::DriverOwner::Claim, ordinal)?,
            worker: PollSite::new(wire::DriverOwner::Worker, ordinal)?,
        })
    }
}
#[derive(Clone, Copy)]
pub(crate) struct ForegroundSite(PollSite);
impl ForegroundSite {
    pub(crate) fn new(ordinal: u8) -> std::result::Result<Self, DriverConfigurationError> {
        PollSite::new(wire::DriverOwner::Foreground, ordinal).map(Self)
    }
}

pub(crate) type Service = MixService<ControlledRepository>;

fn capture(recorder: &Recorder, fact: wire::Fact) {
    driver::emit(recorder, fact);
}
fn missing(recorder: &Recorder) {
    driver::lost(recorder);
}
fn observed(recorder: &Recorder, make: impl FnOnce() -> Result<wire::Fact>) {
    driver::emit_projected(recorder, make);
}
async fn supplied_commit(cut: wire::CommitCut) -> Result<()> {
    match cut {
        wire::CommitCut::Complete => Ok(()),
        wire::CommitCut::Pending => std::future::pending().await,
        wire::CommitCut::Error => anyhow::bail!("supplied repository failure"),
    }
}
fn source_input(v: &wire::MixSource<wire::Id>) -> crate::outbound::MixDelivery {
    crate::outbound::MixDelivery {
        delivery_id: v.delivery_id.0,
        lease_token: v.lease_token.0,
    }
}

#[derive(Clone)]
struct ClaimCapture {
    recorder: Recorder,
    owner: mix_worker::ClaimObservation,
    ordinal: u8,
    command: mix_worker::ClaimCommand,
}
impl ClaimCapture {
    fn snapshot(&self, cut: wire::Cut) {
        observed(&self.recorder, || {
            Ok(wire::Fact::Claim(wire::ClaimFact::Snapshot(
                wire::ClaimCapture {
                    claim_ordinal: self.ordinal,
                    cut,
                    command: wire::ClaimCommand {
                        limit: self.command.limit,
                        max_bytes: self.command.max_bytes,
                    },
                    snapshot: map::claim(&self.owner.snapshot())?,
                },
            )))
        })
    }
}
#[derive(Clone)]
struct WorkerCapture {
    recorder: Recorder,
    owner: mix_worker::Observation,
    ordinal: u8,
    stanza: Arc<Mutex<Option<String>>>,
    dequeue: Arc<Mutex<DequeueObservation>>,
}
// Data-only joins. Never retain OutboundItem or its one-use handoff capability:
// an extra clone would keep a dropped transport's oneshot sender alive.
#[derive(Clone)]
struct IssuedLocal {
    target: String,
    connection: Uuid,
    lifecycle: Arc<std::sync::atomic::AtomicU8>,
    source: crate::outbound::MixDelivery,
    stanza: String,
}
#[derive(Clone)]
struct ObservedDequeue {
    item_ordinal: u8,
    target: String,
    connection: Uuid,
    source: crate::outbound::MixDelivery,
    stanza: String,
}
#[derive(Default)]
struct DequeueObservation {
    issued: Option<IssuedLocal>,
    introduced: Option<ObservedDequeue>,
    rejected: bool,
    handoff_join_consumed: bool,
}
impl WorkerCapture {
    fn issue_local(&self, local: &mix_worker::LocalRequest, session: &crate::state::OnlineSession) {
        let result = (|| {
            let mut state = self.dequeue.lock().unwrap_or_else(|e| e.into_inner());
            if state.issued.is_some() || state.rejected {
                state.rejected = true;
                anyhow::bail!("local route association already introduced or rejected");
            }
            state.issued = Some(IssuedLocal {
                target: local.target().to_owned(),
                connection: session.connection_id,
                lifecycle: session.lifecycle.clone(),
                source: local.source(),
                stanza: local.stanza().to_owned(),
            });
            Ok(())
        })();
        if result.is_err() {
            missing(&self.recorder);
        }
    }
    fn handoff_ordinal(
        &self,
        local: &mix_worker::LocalRequest,
        session: &crate::state::OnlineSession,
    ) -> Option<u8> {
        let result = (|| {
            let mut state = self.dequeue.lock().unwrap_or_else(|e| e.into_inner());
            let matches = !state.rejected
                && !state.handoff_join_consumed
                && state.issued.as_ref().is_some_and(|issued| {
                    issued.target == local.target()
                        && issued.connection == session.connection_id
                        && Arc::ptr_eq(&issued.lifecycle, &session.lifecycle)
                        && issued.source == local.source()
                        && issued.stanza == local.stanza()
                });
            if !matches {
                state.rejected = true;
                anyhow::bail!("typed handoff has no matching issued local association");
            }
            let Some(introduced) = state.introduced.as_ref() else {
                state.rejected = true;
                anyhow::bail!("typed handoff has no observed dequeue introduction");
            };
            if introduced.target != local.target()
                || introduced.connection != session.connection_id
                || introduced.source != local.source()
                || introduced.stanza != local.stanza()
            {
                state.rejected = true;
                anyhow::bail!("typed handoff conflicts with observed dequeue introduction");
            }
            let ordinal = introduced.item_ordinal;
            state.handoff_join_consumed = true;
            Ok(ordinal)
        })();
        if result.is_err() {
            missing(&self.recorder);
        }
        result.ok()
    }
    fn snapshot(&self, cut: wire::Cut) {
        let stanza = self
            .stanza
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        observed(&self.recorder, || {
            Ok(wire::Fact::Worker(wire::WorkerFact::Snapshot(
                wire::WorkerCapture {
                    attempt_ordinal: self.ordinal,
                    cut,
                    row: map::row(self.owner.row())?,
                    route_stanza: map::optional(stanza.as_ref().map(wire::Text::new).transpose()?),
                    snapshot: map::worker(&self.owner.snapshot())?,
                },
            )))
        })
    }
}
#[derive(Clone)]
struct ForegroundCapture {
    recorder: Recorder,
    owner: fg::Observation,
    frame: Uuid,
    command: Arc<Mutex<Option<room::StoreCommand>>>,
}
impl ForegroundCapture {
    fn snapshot(&self, cut: wire::Cut) {
        observed(&self.recorder, || {
            Ok(wire::Fact::Foreground(wire::ForegroundFact::Snapshot(
                wire::ForegroundCapture {
                    frame: map::id(self.frame),
                    cut,
                    ingress: map::ingress(self.owner.ingress())?,
                    command: map::optional(
                        self.command
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .as_ref()
                            .map(map::command)
                            .transpose()?,
                    ),
                    snapshot: map::foreground(&self.owner.snapshot())?,
                },
            )))
        })
    }
}

/// The row is opaque outside this bridge. Fresh construction reads only the
/// actual accepted foreground projection; initial construction is explicitly
/// supplied environment. Neither path mints an OwnedAttempt.
#[derive(Clone)]
pub(crate) struct WorkerRow(Arc<mix_worker::Row>);
#[derive(Clone)]
pub(crate) struct Bridge {
    repository: ControlledRepository,
    service: Service,
    recorder: Recorder,
    active: Arc<std::sync::atomic::AtomicBool>,
}
struct WorkerLease(Arc<std::sync::atomic::AtomicBool>);
impl Drop for WorkerLease {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}
impl Bridge {
    pub(crate) fn new(configured_mix_domain: &str, recorder: Recorder) -> Result<Self> {
        let configured_domain = configured_mix_domain
            .strip_prefix("mix.")
            .context("configured MIX domain must have mix. prefix")?
            .to_owned();
        let repository = ControlledRepository(
            Arc::new(Mutex::new(repository::Supplied::default())),
            recorder.clone(),
        );
        let service = MixService::new_with_outbox_database_admission(
            repository.clone(),
            configured_domain,
            crate::abuse::test_mix_message_content_keyring(),
            crate::abuse::test_mix_retraction_content_keyring(),
            crate::services::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(4),
            "stage4_supplied".into(),
        )?;
        Ok(Self {
            repository,
            service,
            recorder,
            active: Arc::default(),
        })
    }
    pub(crate) fn service(&self) -> Service {
        self.service.clone()
    }
    pub(crate) fn supply_native(&self, input: &wire::DurableNative) -> Result<()> {
        let mut state = self.repository.0.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(
            state.native.is_none() && state.native_ack.is_none(),
            "native reply already outstanding"
        );
        state.native = Some(input.clone());
        Ok(())
    }
    pub(crate) fn supply_bosh_transfer(&self, input: &wire::BoshTransferReply) -> Result<()> {
        let mut state = self.repository.0.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(
            state.transfer.is_none(),
            "BOSH transfer reply already outstanding"
        );
        state.transfer = Some(input.clone());
        Ok(())
    }
    pub(crate) fn supply_defer(&self, cut: wire::CommitCut, updated: bool) -> Result<()> {
        let mut state = self.repository.0.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(
            state.settlement.is_none(),
            "settlement reply already outstanding"
        );
        state.settlement = Some((cut, updated));
        Ok(())
    }
    pub(crate) fn initial_row(&self, input: &wire::DeliveryRow<wire::Id>) -> Result<WorkerRow> {
        let row = Arc::new(mix_worker::Row {
            source: source_input(&input.source),
            event_id: input.event_id.0,
            channel_id: input.channel_id.0,
            channel_jid: input.channel_jid.as_str().into(),
            participant_id: input.participant_id.0,
            recipient_jid: input.recipient_jid.as_str().into(),
            recipient_nick: input.recipient_nick.get().map(|v| v.as_str().into()),
            stanza: input.stanza.as_str().into(),
            authoritative_stanza_id: input.authoritative_stanza_id.get().map(|v| v.0),
            archive: input.archive,
            encrypted: input.encrypted,
            attempt_count: input.attempt_count,
            route_wake_generation: input.route_wake_generation,
        });
        observed(&self.recorder, || {
            Ok(wire::Fact::Foreground(wire::ForegroundFact::InitialRow(
                wire::InitialRowLoaded {
                    input_row_ordinal: 0,
                    row_slot: 0,
                    actual_row: map::row(&row)?,
                },
            )))
        });
        Ok(WorkerRow(row))
    }
    pub(crate) fn replacement_row(
        &self,
        original: &WorkerRow,
        claim: &wire::ClaimInput,
    ) -> Result<WorkerRow> {
        ensure!(
            claim.lease_token.0 != original.0.source.lease_token,
            "replacement must have an independent claim fence"
        );
        let mut row = (*original.0).clone();
        row.source.lease_token = claim.lease_token.0;
        row.attempt_count = claim.attempt_count;
        row.route_wake_generation = claim.route_wake_generation;
        // This is the explicit supplied replacement claim row, not a replay
        // rewrite. All business/projection/archive fields remain from original.
        Ok(WorkerRow(Arc::new(row)))
    }
    pub(crate) async fn claim(
        &self,
        row: WorkerRow,
        input: &wire::WorkerAttemptInput,
        sites: ClaimSites,
        routes: RouteMap,
    ) -> Driven<WorkerRun> {
        let ordinal = sites.claim.owner_ordinal();
        let prepared = (|| -> Result<_> {
            ensure!(
                !self.active.swap(true, std::sync::atomic::Ordering::AcqRel),
                "a worker holder is already active on this bridge"
            );
            let lease = WorkerLease(self.active.clone());
            ensure!(
                row.0.source.lease_token == input.claim.lease_token.0
                    && row.0.attempt_count == input.claim.attempt_count
                    && row.0.route_wake_generation == input.claim.route_wake_generation,
                "claim row/input relationship"
            );
            let turn = outbox::ClaimTurn::new(input.claim.limit, input.claim.max_bytes)?;
            let claim = ClaimCapture {
                recorder: self.recorder.clone(),
                owner: turn.observation(),
                ordinal,
                command: mix_worker::ClaimCommand {
                    limit: input.claim.limit,
                    max_bytes: input.claim.max_bytes,
                },
            };
            {
                let mut state = self.repository.0.lock().unwrap_or_else(|e| e.into_inner());
                ensure!(
                    state.claim.is_none() && state.archive.is_none(),
                    "previous claim/archive supply outstanding"
                );
                state.last_claim_observation = Some(claim.owner.clone());
                state.claim = Some((row.0.clone(), input.claim.commit, claim.clone()));
                state.archive = Some(input.archive.clone());
                state.account = Some(input.route.enabled_account_id.0);
                state.privacy = Some(input.route.privacy_blocked);
            }
            Ok((lease, turn, claim))
        })();
        let (lease, turn, claim) = match prepared {
            Ok(v) => v,
            Err(error) => return Ok(Err(error)),
        };
        claim.snapshot(wire::Cut::Introduction);
        let service = self.service.clone();
        let mut run = Box::pin(turn.run(move |request, _| async move {
            service.claim_mix_deliveries_observed(&request).await
        }));
        // This is the sole charged boundary for ClaimRun. The dispatcher must
        // not charge the wrapper, and nested service awaits are not recharged.
        let outcome: Driven<Vec<outbox::OwnedAttempt>> = std::future::poll_fn(|cx| {
            match driver::poll_once(&self.recorder, sites.claim, run.as_mut(), cx) {
                Ok(Poll::Pending) => Poll::Pending,
                Ok(Poll::Ready(actual)) => Poll::Ready(Ok(actual)),
                Err(stop) => Poll::Ready(Err(stop)),
            }
        })
        .await;
        drop(run);
        claim.snapshot(wire::Cut::AfterRunnerDrop);
        // BudgetStop is propagated only after the real owner/child was dropped.
        // It is never an anyhow error or an observed repository failure.
        let outcome = outcome?;
        Ok((|| -> Result<WorkerRun> {
            let mut attempts = outcome?;
            ensure!(attempts.len() == 1, "finite claim returned wrong count");
            let owned = attempts.pop().context("accepted attempt missing")?;
            let owner = owned.observation();
            let same = std::ptr::eq(owner.row(), row.0.as_ref());
            observed(&self.recorder, || {
                Ok(wire::Fact::Claim(wire::ClaimFact::Attempt(
                    wire::ClaimAttemptJoin {
                        claim_ordinal: ordinal,
                        row_ordinal: 0,
                        attempt_ordinal: ordinal,
                        source: map::source(owner.row().source),
                        row: map::row(owner.row())?,
                        same_retained_row: wire::Nullable::Value(same),
                    },
                )))
            });
            let capture = WorkerCapture {
                recorder: self.recorder.clone(),
                owner,
                ordinal,
                stanza: Arc::new(Mutex::new(None)),
                dequeue: Arc::default(),
            };
            capture.snapshot(wire::Cut::Introduction);
            self.repository
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .worker = Some(capture.clone());
            let port = Port {
                service: self.service.clone(),
                routes,
                capture: capture.clone(),
            };
            let cancel = CancellationToken::new();
            let child_cancel = cancel.clone();
            let run = owned.run(move |attempt, handle| async move {
                process_claimed_mix_delivery_with_port(port, attempt, handle, child_cancel).await
            });
            Ok(WorkerRun {
                run: Some(run),
                capture,
                cancel,
                site: sites.worker,
                _lease: lease,
            })
        })())
    }
}

/// Poll this same future around transport work. It owns the route/renewal
/// children and cannot be reconstructed from a DTO or a completion enum.
pub(crate) struct WorkerRun {
    run: Option<outbox::AttemptRun>,
    capture: WorkerCapture,
    cancel: CancellationToken,
    site: PollSite,
    _lease: WorkerLease,
}
impl WorkerRun {
    pub(crate) fn cancel(&self) {
        self.cancel.cancel();
    }
    pub(crate) fn observation(&self) -> mix_worker::Observation {
        self.capture.owner.clone()
    }
    pub(crate) fn record_dequeued(
        &self,
        route: &RouteHandle,
        item_ordinal: u8,
        item: &crate::outbound::OutboundItem,
    ) {
        let result = (|| {
            let snap = self.capture.owner.snapshot();
            let local = snap.local.last().context("dequeue without local request")?;
            // Record the actual attempted introduction before checking its
            // join. A contradiction or repeated introduction remains visible.
            observed(&self.capture.recorder, || {
                Ok(wire::Fact::Worker(wire::WorkerFact::LocalQueue(
                    wire::LocalQueueJoin {
                        attempt_ordinal: self.capture.ordinal,
                        target: wire::Text::new(&local.target)?,
                        item: queue_item(item, item_ordinal, route.connection_id())?,
                    },
                )))
            });
            let mut state = self
                .capture
                .dequeue
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if state.rejected || state.introduced.is_some() || state.handoff_join_consumed {
                state.rejected = true;
                anyhow::bail!("dequeue association repeated or already rejected");
            }
            let issued = state
                .issued
                .as_ref()
                .context("dequeue without issued local association")?;
            ensure!(
                snap.terminal.is_none()
                    && local.started
                    && local.enqueued
                    && local.returned.is_none(),
                "dequeue is not at the pending local handoff cut"
            );
            ensure!(
                route.full_jid() == local.target
                    && route.full_jid() == issued.target
                    && route.connection_id() == issued.connection
                    && Arc::ptr_eq(&route.lifecycle(), &issued.lifecycle)
                    && item.mix_delivery() == Some(issued.source)
                    && item.mix_delivery() == Some(self.capture.owner.row().source)
                    && item.stanza == issued.stanza
                    && item.validate_durable_source_shape(),
                "local queue association mismatch"
            );
            state.introduced = Some(ObservedDequeue {
                item_ordinal,
                target: route.full_jid().to_owned(),
                connection: route.connection_id(),
                source: item.mix_delivery().context("dequeued MIX source absent")?,
                stanza: item.stanza.clone(),
            });
            Ok(())
        })();
        if result.is_err() {
            self.capture
                .dequeue
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .rejected = true;
            missing(&self.capture.recorder);
        }
    }
}
impl Future for WorkerRun {
    type Output = Driven<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.capture.snapshot(wire::Cut::BeforePoll);
        // Reserve before the actual AttemptRun poll, independent of sticky
        // semantic loss. poll_once releases Recorder's lock before polling.
        let polled = driver::poll_once(
            &this.capture.recorder,
            this.site,
            Pin::new(this.run.as_mut().expect("worker polled after completion")),
            cx,
        );
        match polled {
            Ok(Poll::Pending) => {
                this.capture.snapshot(wire::Cut::AfterPoll);
                Poll::Pending
            }
            Ok(Poll::Ready(actual)) => {
                drop(this.run.take());
                this.capture.snapshot(wire::Cut::AfterPoll);
                Poll::Ready(Ok(actual))
            }
            Err(stop) => {
                // Includes a nested resource latch discovered by poll_once.
                // Drop the entire real child before returning the typed stop.
                drop(this.run.take());
                this.capture.snapshot(wire::Cut::AfterRunnerDrop);
                Poll::Ready(Err(stop))
            }
        }
    }
}
impl Drop for WorkerRun {
    fn drop(&mut self) {
        drop(self.run.take());
        self.capture.snapshot(wire::Cut::AfterRunnerDrop);
    }
}

#[derive(Clone)]
struct Port {
    service: Service,
    routes: RouteMap,
    capture: WorkerCapture,
}
struct RouteChild {
    capture: WorkerCapture,
    disconnect: Option<CancellationToken>,
}
impl Drop for RouteChild {
    fn drop(&mut self) {
        observed(&self.capture.recorder, || {
            Ok(wire::Fact::Worker(wire::WorkerFact::ChildDrop(
                wire::RouteChildDrop {
                    attempt_ordinal: self.capture.ordinal,
                    disconnected: self
                        .disconnect
                        .as_ref()
                        .is_some_and(CancellationToken::is_cancelled),
                    snapshot: map::worker(&self.capture.owner.snapshot())?,
                },
            )))
        });
    }
}
impl ClaimedMixDeliveryPort for Port {
    async fn route(
        &self,
        request: &mix_worker::RouteRequest,
    ) -> Result<ChannelStanzaDeliveryOutcome> {
        request.start()?;
        *self
            .capture
            .stanza
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(request.stanza().to_owned());
        let mut child = RouteChild {
            capture: self.capture.clone(),
            disconnect: None,
        };
        self.capture.snapshot(wire::Cut::PortEntry);
        let recipient = CanonicalJid::parse(&request.row().recipient_jid)?;
        let username = recipient
            .localpart()
            .context("finite local recipient requires a localpart")?;
        observed(&self.capture.recorder, || {
            Ok(wire::Fact::Worker(wire::WorkerFact::Account(
                wire::AccountCall {
                    attempt_ordinal: self.capture.ordinal,
                    username: wire::Text::new(username)?,
                    returned: wire::Nullable::Null(()),
                },
            )))
        });
        let account_result = self.service.outbox_find_enabled_user(username).await;
        observed(&self.capture.recorder, || {
            let returned = match &account_result {
                Ok(Some(a)) => wire::AccountReturned::Found(wire::AccountIdentity {
                    id: map::id(a.id),
                    username: wire::Text::new(&a.username)?,
                }),
                Ok(None) => wire::AccountReturned::Absent(wire::Empty {}),
                Err(_) => wire::AccountReturned::Error(wire::Empty {}),
            };
            Ok(wire::Fact::Worker(wire::WorkerFact::Account(
                wire::AccountCall {
                    attempt_ordinal: self.capture.ordinal,
                    username: wire::Text::new(username)?,
                    returned: wire::Nullable::Value(returned),
                },
            )))
        });
        let account = account_result?.context("supplied local account absent")?;
        observed(&self.capture.recorder, || {
            Ok(wire::Fact::Worker(wire::WorkerFact::Privacy(
                wire::PrivacyCall {
                    attempt_ordinal: self.capture.ordinal,
                    owner_id: map::id(account.id),
                    candidate: wire::Text::new(&request.row().channel_jid)?,
                    returned: wire::Nullable::Null(()),
                },
            )))
        });
        let blocked = self
            .service
            .outbox_is_blocked(account.id, &request.row().channel_jid)
            .await;
        observed(&self.capture.recorder, || {
            let returned = match &blocked {
                Ok(value) => wire::PrivacyReturned::Outcome(wire::BoolValue { value: *value }),
                Err(_) => wire::PrivacyReturned::Error(wire::Empty {}),
            };
            Ok(wire::Fact::Worker(wire::WorkerFact::Privacy(
                wire::PrivacyCall {
                    attempt_ordinal: self.capture.ordinal,
                    owner_id: map::id(account.id),
                    candidate: wire::Text::new(&request.row().channel_jid)?,
                    returned: wire::Nullable::Value(returned),
                },
            )))
        });
        ensure!(!blocked?, "blocked route outside finite Stage4 inventory");
        let archive = request.archive_request(
            account.id,
            Uuid::new_v4(),
            request
                .row()
                .authoritative_stanza_id
                .map(|id| id.to_string()),
        )?;
        observed(&self.capture.recorder, || {
            Ok(wire::Fact::Worker(wire::WorkerFact::Archive(
                wire::ArchiveCall {
                    attempt_ordinal: self.capture.ordinal,
                    command: map::archive_command(archive.command())?,
                    returned: wire::Nullable::Null(()),
                },
            )))
        });
        let archived = self
            .service
            .outbox_archive_mix_message_once_observed(&archive)
            .await;
        let actual_return = request
            .observation()
            .snapshot()
            .archive
            .returned
            .map(map::archive_returned);
        observed(&self.capture.recorder, || {
            Ok(wire::Fact::Worker(wire::WorkerFact::Archive(
                wire::ArchiveCall {
                    attempt_ordinal: self.capture.ordinal,
                    command: map::archive_command(archive.command())?,
                    returned: map::optional(actual_return),
                },
            )))
        });
        archived?;
        let entries = self.routes.lookup(
            wire::RouteLookupOwner::Worker(wire::MixItemOwner {
                attempt_ordinal: self.capture.ordinal,
            }),
            &request.row().recipient_jid,
        );
        // Actual finite environment checks stay authoritative; only evidence
        // conversion and recording are non-interfering.
        ensure!(
            entries.len() <= 1,
            "finite MIX bridge cannot choose among routes"
        );
        if let Some((key, session)) = entries.into_iter().next() {
            let capability = self.routes.classify(
                self.capture.ordinal,
                &request.row().recipient_jid,
                &key,
                &session,
            );
            ensure!(
                matches!(capability, MixSessionCapability::Supported),
                "finite declared target is not eligible"
            );
            child.disconnect = Some(session.disconnect.clone());
            let local = request.local_request(key)?;
            self.capture.issue_local(&local, &session);
            let result =
                try_send_local_durable_mix_observed(&session.sender, &session.disconnect, &local)
                    .await;
            let received = match &result {
                Ok(crate::outbound::MixTransportCompletion::SocketFenced { connection_id }) => {
                    wire::HandoffResult::Received(map::boundary(
                        mix_worker::TransferBoundary::SocketFenced(*connection_id),
                    ))
                }
                Ok(crate::outbound::MixTransportCompletion::SmPersisted { session_id }) => {
                    wire::HandoffResult::Received(map::boundary(
                        mix_worker::TransferBoundary::SmPersisted(*session_id),
                    ))
                }
                Ok(crate::outbound::MixTransportCompletion::BoshPersisted { session_id }) => {
                    wire::HandoffResult::Received(map::boundary(
                        mix_worker::TransferBoundary::BoshPersisted(*session_id),
                    ))
                }
                Err(MixLocalTransportFailure::HandoffClosed) => {
                    wire::HandoffResult::Closed(wire::Empty {})
                }
                Err(_) => {
                    self.capture.snapshot(wire::Cut::PortReturn);
                    anyhow::bail!("local transport admission failed")
                }
            };
            // Real completion is independent of whether its data-only join can
            // be emitted. Missing/conflicting introduction never guesses 0.
            if let Some(item_ordinal) = self.capture.handoff_ordinal(&local, &session) {
                capture(
                    &self.capture.recorder,
                    wire::Fact::Worker(wire::WorkerFact::Handoff(wire::TypedHandoff {
                        attempt_ordinal: self.capture.ordinal,
                        item_ordinal,
                        source: map::source(local.source()),
                        received,
                    })),
                );
            }
            self.capture.snapshot(wire::Cut::PortReturn);
            match result {
                Ok(_) => Ok(ChannelStanzaDeliveryOutcome::TransferredToRecoverableTransport),
                Err(e) => Err(anyhow::anyhow!("{e}")),
            }
        } else {
            ensure!(
                classify_durable_mix_route(
                    true,
                    false,
                    DurableMixRouteAvailability::NoTarget,
                    false
                ) == DurableMixRouteDisposition::Park,
                "shared no-target classifier did not park"
            );
            self.capture.snapshot(wire::Cut::PortReturn);
            Err(MixDeliveryRoutePending.into())
        }
    }
    async fn renew(&self, request: &mix_worker::RenewalRequest) -> Result<bool> {
        self.capture.snapshot(wire::Cut::PortEntry);
        let result = self
            .service
            .renew_mix_delivery_lease_observed(request)
            .await;
        self.capture.snapshot(wire::Cut::PortReturn);
        result
    }
    async fn settle(
        &self,
        request: &mix_worker::SettlementRequest,
    ) -> Result<mix_worker::SettlementResult> {
        let at_entry = self.capture.owner.snapshot();
        let record = |returned: Option<mix_worker::SettlementReturned>| {
            observed(&self.capture.recorder, || {
                Ok(wire::Fact::Worker(wire::WorkerFact::Settlement(
                    wire::SettlementCall {
                        attempt_ordinal: self.capture.ordinal,
                        source: map::source(request.source()),
                        kind: map::settlement_kind(request.command().kind()),
                        command: map::settlement_command(request.command())?,
                        attempt_count: self.capture.owner.row().attempt_count,
                        route_wake_generation: request.route_wake_generation(),
                        at_entry: map::worker(&at_entry)?,
                        returned: map::optional(returned.map(map::settlement_returned)),
                    },
                )))
            })
        };
        record(None);
        let result = self.service.settle_mix_delivery_observed(request).await;
        record(
            self.capture
                .owner
                .snapshot()
                .settlement
                .and_then(|s| s.returned),
        );
        result
    }
}

pub(crate) fn queue_item(
    item: &crate::outbound::OutboundItem,
    ordinal: u8,
    connection: Uuid,
) -> Result<wire::QueueItem<wire::EvidenceId>> {
    // MIX bridge never accepts auth holders, avoiding a second auth observer.
    ensure!(
        item.auth_publication().is_none(),
        "MIX dequeue unexpectedly contains auth control"
    );
    Ok(wire::QueueItem {
        item_ordinal: ordinal,
        connection_id: map::id(connection),
        source: map::optional(item.durable_source.map(|s| match s {
            crate::outbound::TransportOwnershipSource::Mix(s) => wire::Source::Mix(map::source(s)),
            crate::outbound::TransportOwnershipSource::C2s(s) => {
                wire::Source::C2s(wire::C2sSource {
                    recipient_id: map::id(s.recipient_id),
                    message_id: map::id(s.message_id),
                    claim_id: map::optional(s.claim_id.map(map::id)),
                })
            }
        })),
        stanza: wire::Text::new(&item.stanza)?,
        auth_control: wire::Nullable::Null(()),
    })
}

fn ingress_input(v: &wire::MixIngress<wire::Id>) -> room::Ingress {
    room::Ingress {
        channel_id: v.channel_id.0,
        channel_jid: v.channel_jid.as_str().into(),
        actor_bare: v.actor_bare.as_str().into(),
        actor_full: v.actor_full.as_str().into(),
        children: v.children.as_str().into(),
        encrypted: v.encrypted,
        identity: v.identity.get().map(identity_input),
    }
}
fn identity_input(v: &wire::ReplayIdentityInput) -> room::ReplayIdentity {
    room::ReplayIdentity {
        client_id: v.client_id.as_str().into(),
        canonical_semantics: v
            .canonical_semantics
            .as_hex()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                // Bytes has already enforced bounded lowercase even-length hex before any owner.
                let pair = std::str::from_utf8(pair).expect("validated canonical hex is ASCII");
                u8::from_str_radix(pair, 16).expect("validated canonical hex pair")
            })
            .collect(),
    }
}
fn command_input(v: &wire::MixStoreCommand<wire::Id>) -> room::StoreCommand {
    room::StoreCommand {
        channel_id: v.channel_id.0,
        actor: v.actor.as_str().into(),
        item_id: v.item_id.0,
        payload: v.payload.as_str().into(),
        identity: v.identity.get().map(identity_input),
        delivery_payload: v.delivery_payload.as_str().into(),
        visible_jid: v.visible_jid.get().map(|v| v.as_str().into()),
        encrypted: v.encrypted,
    }
}
fn stored_input(v: &wire::Stored<wire::Id>) -> room::Stored {
    room::Stored {
        authoritative_id: v.authoritative_id.0,
        storage_id: v.storage_id.0,
        channel_id: v.channel_id.0,
        channel_jid: v.channel_jid.as_str().into(),
        projection: v.projection.get().map(|v| room::DeliveryProjection {
            event_id: v.event_id.0,
            channel_id: v.channel_id.0,
            channel_jid: v.channel_jid.as_str().into(),
            stanza_template: v.stanza_template.as_str().into(),
            authoritative_stanza_id: v.authoritative_stanza_id.get().map(|v| v.0),
            archive: v.archive,
            encrypted: v.encrypted,
            recipients: v
                .recipients
                .as_slice()
                .iter()
                .map(|v| room::RecipientProjection {
                    participant: room::Participant {
                        participant_id: v.participant.participant_id.0,
                        jid: v.participant.jid.as_str().into(),
                        nick: v.participant.nick.get().map(|v| v.as_str().into()),
                    },
                    delivery_id: v.delivery_id.0,
                    sequence: v.sequence,
                })
                .collect(),
        }),
    }
}
fn frame(input: &wire::Frame) -> FrameExecution {
    FrameExecution::for_saved_case(
        match input.transport {
            wire::TransportKind::Tcp => crate::xmpp::protocol::ClientTransport::Tcp,
            wire::TransportKind::Bosh => crate::xmpp::protocol::ClientTransport::Bosh,
        },
        input.input.as_str(),
        input.frame_id.0,
    )
}
fn frame_capture(recorder: &Recorder, frame: &FrameExecution, cut: wire::Cut) {
    // No tasks are spawned by this bridge. At each call all frame/runner
    // aliases are held by this synchronous single-driver call stack and none
    // are being polled. In particular no auth owner shares this foreground.
    let raw = frame.observation_for_saved_case();
    let direct = frame.direct_operation().snapshot();
    if direct.reservation.is_some() || direct.finalization.is_some() {
        // This finite MIX bridge has no generic admission mapper. Never turn
        // unexpected present admission evidence into a complete absent fact.
        missing(recorder);
    }
    let stages = [
        wire::FrameStage::Validation,
        wire::FrameStage::Handler,
        wire::FrameStage::SmCheckpoint,
        wire::FrameStage::AuthPublication,
        wire::FrameStage::CapsPublication,
        wire::FrameStage::ReplacementNotification,
        wire::FrameStage::MessagePolicy,
        wire::FrameStage::MessageAdmission,
        wire::FrameStage::MessageRouting,
        wire::FrameStage::MessageFollowup,
        wire::FrameStage::MucPolicy,
        wire::FrameStage::MucGateWait,
        wire::FrameStage::MucAuthority,
        wire::FrameStage::MucAdmission,
        wire::FrameStage::MucClusterFanout,
        wire::FrameStage::MucLocalFanout,
        wire::FrameStage::MixPolicy,
        wire::FrameStage::MixAdmission,
    ];
    let outcomes = [
        wire::FrameOutcome::Pending,
        wire::FrameOutcome::Completed,
        wire::FrameOutcome::BackendFailure,
        wire::FrameOutcome::TimedOut,
        wire::FrameOutcome::Cancelled,
        wire::FrameOutcome::Panicked,
        wire::FrameOutcome::IntegrityRejected,
        wire::FrameOutcome::CredentialRejected,
        wire::FrameOutcome::RouteRejected,
        wire::FrameOutcome::CompletedWithDeferredNotification,
    ];
    let stage = stages.get(usize::from(raw.stage_raw)).copied();
    let outcome = outcomes.get(usize::from(raw.outcome_raw)).copied();
    if stage.is_none() || outcome.is_none() {
        missing(recorder);
    }
    capture(
        recorder,
        wire::Fact::Frame(wire::FrameCapture {
            frame: map::id(raw.operation_id),
            cut,
            stage: map::optional(stage),
            outcome: map::optional(outcome),
            admission_begin: wire::Nullable::Null(()),
            admission_finalize: wire::Nullable::Null(()),
        }),
    )
}
impl Bridge {
    pub(crate) async fn fresh(
        &self,
        input: &wire::FreshForeground,
        origin: &wire::FreshProjectionOrigin,
        claim: &wire::ClaimInput,
        site: ForegroundSite,
    ) -> Driven<WorkerRow> {
        let prepared = (|| -> Result<_> {
            let frame = frame(&input.frame);
            let sessions = SessionExecutions::for_saved_frame(frame.clone());
            let prepared = self
                .service
                .prepare_mix_foreground(ingress_input(&input.ingress))?;
            let owner = sessions
                .mix_foreground(|| Ok(prepared))?
                .context("foreground owner absent")?;
            let command = command_input(&input.command);
            let context = ForegroundCapture {
                recorder: self.recorder.clone(),
                owner: owner.clone(),
                frame: frame.operation_id(),
                command: Arc::new(Mutex::new(None)),
            };
            {
                let mut state = self.repository.0.lock().unwrap_or_else(|e| e.into_inner());
                ensure!(
                    state.fresh.is_none() && state.replay.is_none(),
                    "foreground reply already outstanding"
                );
                state.fresh = Some((stored_input(&input.stored), input.commit));
                state.replay = input.ingress.identity.get().map(|_| None);
                state.foreground = Some(context.clone());
            }
            Ok((frame, sessions, owner, command, context))
        })();
        let (frame, _sessions, owner, command, context) = match prepared {
            Ok(v) => v,
            Err(error) => return Ok(Err(error)),
        };
        context.snapshot(wire::Cut::Introduction);
        frame_capture(&self.recorder, &frame, wire::Cut::Introduction);
        let service = self.service.clone();
        let child_frame = frame.clone();
        let child_owner = owner.clone();
        let child_capture = context.clone();
        let mut runner = Box::pin(frame.run(async move {
            child_frame.enter(Stage::MixPolicy);
            if let Some(read) = child_owner.replay_request()? {
                ensure!(
                    service.lookup_mix_message_replay_observed(&read).await? == room::Replay::Miss,
                    "fresh foreground did not read Miss"
                );
            }
            let request = child_owner.store_request(command)?;
            *child_capture
                .command
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(request.command().clone());
            child_frame.enter(Stage::MixAdmission);
            service.store_mix_message_observed(&request).await
        }));
        // This preserves Result<actual FrameRunner result, BudgetStop>. The
        // outer wrapper and nested service future are never double-charged.
        let returned = std::future::poll_fn(|cx| {
            match driver::poll_once(&self.recorder, site.0, runner.as_mut(), cx) {
                Ok(Poll::Pending) => Poll::Pending,
                Ok(Poll::Ready(actual)) => Poll::Ready(Ok(actual)),
                Err(stop) => Poll::Ready(Err(stop)),
            }
        })
        .await;
        drop(runner);
        context.snapshot(wire::Cut::AfterRunnerDrop);
        frame_capture(&self.recorder, &frame, wire::Cut::AfterRunnerDrop);
        let returned = returned?;
        Ok((|| -> Result<WorkerRow> {
            // Only a genuine FrameFailure enters this existing backend/error
            // path. BudgetStop has already taken the distinct outer return.
            let _admission =
                returned.map_err(|e| anyhow::anyhow!("foreground frame failed: {e:?}"))?;
            let snapshot = owner.snapshot();
            let fg::Knowledge::ReceiptKnown(stored) = snapshot.knowledge else {
                missing(&self.recorder);
                anyhow::bail!("accepted foreground projection receipt missing")
            };
            ensure!(
                matches!(snapshot.returned, Some(fg::Returned::AcceptedStored(id)) if id == stored.authoritative_id),
                "accepted foreground return mismatch"
            );
            let projection = stored
                .projection
                .as_ref()
                .context("accepted foreground projection absent")?;
            let recipient = projection
                .recipients
                .get(usize::from(origin.recipient_ordinal))
                .context("accepted projection recipient missing")?;
            let row = Arc::new(mix_worker::Row {
                source: crate::outbound::MixDelivery {
                    delivery_id: recipient.delivery_id,
                    lease_token: claim.lease_token.0,
                },
                event_id: projection.event_id,
                channel_id: projection.channel_id,
                channel_jid: projection.channel_jid.clone(),
                participant_id: recipient.participant.participant_id,
                recipient_jid: recipient.participant.jid.clone(),
                recipient_nick: recipient.participant.nick.clone(),
                stanza: projection.stanza_template.clone(),
                authoritative_stanza_id: projection.authoritative_stanza_id,
                archive: projection.archive,
                encrypted: projection.encrypted,
                attempt_count: claim.attempt_count,
                route_wake_generation: claim.route_wake_generation,
            });
            observed(&self.recorder, || {
                Ok(wire::Fact::Foreground(wire::ForegroundFact::ProjectionRow(
                    wire::ProjectionRowJoin {
                        foreground_frame: map::id(context.frame),
                        recipient_ordinal: origin.recipient_ordinal,
                        stored_authoritative_id: map::id(stored.authoritative_id),
                        row_slot: 0,
                        actual_row: map::row(&row)?,
                    },
                )))
            });
            ensure!(
                context.frame == origin.foreground_frame.0
                    && recipient.delivery_id == origin.declared_delivery_id.0,
                "projection declaration contradicts actual accepted row"
            );
            Ok(WorkerRow(row))
        })())
    }
    pub(crate) async fn replay(
        &self,
        input: &wire::ReplayForeground,
        site: ForegroundSite,
    ) -> Driven<Uuid> {
        let prepared = (|| -> Result<_> {
            let frame = frame(&input.frame);
            let sessions = SessionExecutions::for_saved_frame(frame.clone());
            let prepared = self
                .service
                .prepare_mix_foreground(ingress_input(&input.ingress))?;
            let owner = sessions
                .mix_foreground(|| Ok(prepared))?
                .context("foreground owner absent")?;
            let context = ForegroundCapture {
                recorder: self.recorder.clone(),
                owner: owner.clone(),
                frame: frame.operation_id(),
                command: Arc::new(Mutex::new(None)),
            };
            let hex = input.existing.semantic_mac.as_hex();
            let semantic_mac = hex
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| -> Result<u8> {
                    Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?)
                })
                .collect::<Result<Vec<_>>>()?;
            let raw = room::Existing {
                authoritative_id: input.existing.authoritative_id.0,
                semantic_key_id: input.existing.semantic_key_id.as_str().into(),
                semantic_mac,
                target_id: input.existing.target_id.get().map(|v| v.0),
            };
            {
                let mut state = self.repository.0.lock().unwrap_or_else(|e| e.into_inner());
                ensure!(
                    state.fresh.is_none() && state.replay.is_none(),
                    "foreground reply already outstanding"
                );
                state.replay = Some(Some(raw));
                state.foreground = Some(context.clone());
            }
            let request = owner.replay_request()?.context("replay identity absent")?;
            Ok((frame, sessions, context, request))
        })();
        let (frame, _sessions, context, request) = match prepared {
            Ok(v) => v,
            Err(error) => return Ok(Err(error)),
        };
        context.snapshot(wire::Cut::Introduction);
        frame_capture(&self.recorder, &frame, wire::Cut::Introduction);
        let service = self.service.clone();
        let child_frame = frame.clone();
        let mut runner = Box::pin(frame.run(async move {
            child_frame.enter(Stage::MixPolicy);
            service.lookup_mix_message_replay_observed(&request).await
        }));
        let returned = std::future::poll_fn(|cx| {
            match driver::poll_once(&self.recorder, site.0, runner.as_mut(), cx) {
                Ok(Poll::Pending) => Poll::Pending,
                Ok(Poll::Ready(actual)) => Poll::Ready(Ok(actual)),
                Err(stop) => Poll::Ready(Err(stop)),
            }
        })
        .await;
        drop(runner);
        context.snapshot(wire::Cut::AfterRunnerDrop);
        frame_capture(&self.recorder, &frame, wire::Cut::AfterRunnerDrop);
        let returned = returned?;
        Ok((|| -> Result<Uuid> {
            match returned.map_err(|e| anyhow::anyhow!("foreground frame failed: {e:?}"))? {
                room::Replay::Replay(id) => Ok(id),
                _ => anyhow::bail!("supplied commitment did not authenticate as Replay"),
            }
        })())
    }
}
