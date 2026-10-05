//! Per-control auth ownership. The FIFO marker is metadata; only the private
//! holder can transfer its actual credential receipt into publication.
use super::frame_execution::{FrameExecution, PublicationResult};
use crate::services::authentication::{
    publication::{Invocation, Observation, Terminal, Transport},
    AuthenticationResult, CredentialCommitReceipt,
};
use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, AtomicU8},
        Arc, Mutex,
    },
    task::{Context, Poll},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub(super) struct BoundRoute {
    pub(super) key: String,
    pub(super) user: Uuid,
    pub(super) generation: i64,
    pub(super) connection: Uuid,
    pub(super) lifecycle: Arc<AtomicU8>,
    pub(super) disconnect: CancellationToken,
}
pub(super) enum RouteIntent {
    Unbound,
    Bound(BoundRoute),
}
pub(crate) struct CapsIntent {
    pub(super) presence: String,
    pub(super) key: String,
    pub(super) connection: Uuid,
    pub(super) gate: Arc<tokio::sync::Mutex<()>>,
    pub(super) generation: Arc<AtomicU64>,
}
pub(super) struct NotificationIntent {
    pub(super) account: String,
    pub(super) user: Uuid,
    pub(super) device: Uuid,
    pub(super) excluded_key: String,
}
pub(super) struct CapturedEffects {
    pub(super) route: RouteIntent,
    pub(super) caps: Option<CapsIntent>,
    pub(super) notification: Option<NotificationIntent>,
}
impl CapturedEffects {
    fn validate(&self, receipt: &CredentialCommitReceipt, connection: Uuid) -> Result<()> {
        match &self.route {
            RouteIntent::Unbound => ensure!(
                receipt.staged_login_epoch().is_none()
                    && receipt.binding_publication().is_none()
                    && self.caps.is_none()
                    && self.notification.is_none(),
                "unbound auth control has bound effects"
            ),
            RouteIntent::Bound(route) => {
                ensure!(
                    route.connection == connection,
                    "auth route connection mismatch"
                );
                if let Some(stage) = receipt.staged_login_epoch() {
                    ensure!(
                        stage.connection_id == connection
                            && stage.user_id == route.user
                            && stage.auth_generation == route.generation,
                        "auth stage identity mismatch"
                    );
                    if let Some(notification) = &self.notification {
                        ensure!(
                            notification.device == stage.device_id,
                            "auth notification device mismatch"
                        );
                    }
                }
                if let Some(binding) = receipt.binding_publication() {
                    ensure!(
                        binding.connection_id == connection
                            && binding.user_id == route.user
                            && binding.full_jid == route.key,
                        "auth binding identity mismatch"
                    );
                }
                if let Some(caps) = &self.caps {
                    ensure!(
                        caps.connection == connection && caps.key == route.key,
                        "auth caps identity mismatch"
                    );
                }
                if let Some(notification) = &self.notification {
                    ensure!(
                        notification.user == route.user && notification.excluded_key == route.key,
                        "auth notification identity mismatch"
                    );
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct KnownCredentialOwner {
    receipt: Option<CredentialCommitReceipt>,
    origin: Option<FrameExecution>,
    connection: Uuid,
    observation: Observation,
}
impl KnownCredentialOwner {
    pub(super) fn from_returned(
        receipt: CredentialCommitReceipt,
        origin: Option<FrameExecution>,
        connection: Uuid,
    ) -> Self {
        let observation = Observation::returned_receipt(
            &receipt,
            origin.as_ref().map(FrameExecution::operation_id),
        );
        Self {
            receipt: Some(receipt),
            origin,
            connection,
            observation,
        }
    }
    pub(super) fn observation(&self) -> &Observation {
        &self.observation
    }
    pub(super) fn seal(
        mut self,
        control: &str,
        effects: CapturedEffects,
    ) -> Result<AuthControlHolder> {
        let receipt = self
            .receipt
            .as_ref()
            .expect("auth receipt consumed only by seal");
        effects.validate(receipt, self.connection)?;
        self.observation.sealed(
            matches!(&effects.route, RouteIntent::Bound(_)),
            effects.notification.is_some(),
        )?;
        let receipt = self.receipt.take().expect("validated auth receipt");
        Ok(AuthControlHolder(Arc::new(Holder {
            id: self.observation.snapshot().control,
            connection: self.connection,
            length: control.len(),
            digest: Sha256::digest(control.as_bytes()).into(),
            observation: self.observation.clone(),
            pending: Mutex::new(HolderState {
                pending: Some(PendingPublication {
                    receipt,
                    origin: self.origin.take(),
                    effects,
                }),
                phase: HolderPhase::Queued,
            }),
        })))
    }
}
impl Drop for KnownCredentialOwner {
    fn drop(&mut self) {
        if self.receipt.is_some() {
            self.observation.abandon();
        }
    }
}
struct PendingPublication {
    receipt: CredentialCommitReceipt,
    origin: Option<FrameExecution>,
    effects: CapturedEffects,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum HolderPhase {
    Queued,
    Recording,
    Writing,
    Written,
    BoshExposing(u64),
    BoshAccepted(u64),
    BoshRefused,
    Taken,
}
struct HolderState {
    pending: Option<PendingPublication>,
    phase: HolderPhase,
}
struct Holder {
    id: Uuid,
    connection: Uuid,
    length: usize,
    digest: [u8; 32],
    observation: Observation,
    pending: Mutex<HolderState>,
}
impl Drop for Holder {
    fn drop(&mut self) {
        if self.pending.get_mut().unwrap().pending.is_some() {
            self.observation.abandon();
        }
    }
}
#[derive(Clone)]
pub(crate) struct AuthControlHolder(Arc<Holder>);
impl std::fmt::Debug for AuthControlHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthControlHolder { control and receipt: [redacted] }")
    }
}
impl AuthControlHolder {
    pub(crate) fn validate_connection(&self, connection: Uuid) -> Result<()> {
        ensure!(
            self.0.connection == connection,
            "auth control belongs to another connection"
        );
        Ok(())
    }
    fn validates(&self, control: &str) -> bool {
        self.0.length == control.len()
            && self.0.digest == <[u8; 32]>::from(Sha256::digest(control.as_bytes()))
    }
    pub(crate) fn validate_control(&self, control: &str) -> Result<()> {
        ensure!(
            self.0.id == self.0.observation.snapshot().control,
            "auth control identity mismatch"
        );
        ensure!(self.validates(control), "sealed auth control bytes changed");
        Ok(())
    }
    pub(crate) fn recording(&self) -> Result<()> {
        let mut state = self.0.pending.lock().unwrap();
        ensure!(
            state.pending.is_some() && state.phase == HolderPhase::Queued,
            "auth control record already started"
        );
        self.0.observation.transport(Transport::Recording)?;
        state.phase = HolderPhase::Recording;
        Ok(())
    }
    pub(crate) async fn write<F: Future<Output = Result<()>>>(
        self,
        control: String,
        write: impl FnOnce(String) -> F,
    ) -> Result<OwnedPublication> {
        self.validate_control(&control)?;
        {
            let mut state = self.0.pending.lock().unwrap();
            ensure!(
                state.pending.is_some() && state.phase == HolderPhase::Recording,
                "auth control write already started or owner lost"
            );
            self.0.observation.transport(Transport::WriteEntered)?;
            state.phase = HolderPhase::Writing;
        }
        write(control).await?;
        {
            let mut state = self.0.pending.lock().unwrap();
            ensure!(
                state.pending.is_some() && state.phase == HolderPhase::Writing,
                "auth control write continuation lost"
            );
            self.0.observation.transport(Transport::Written)?;
            state.phase = HolderPhase::Written;
        }
        let selected = SelectedControls {
            holders: vec![self],
            exposed: false,
            proof: Some(TakeProof::NativeWritten),
        };
        let mut owned = selected.take_all()?;
        Ok(owned.pop().expect("one validated native auth control"))
    }
}

/// Metadata extracted from the actual final selected items. It owns aliases
/// only until successful exposure allows an all-or-none consuming transfer.
#[derive(Clone, Copy)]
enum TakeProof {
    NativeWritten,
    BoshAccepted(u64),
}
pub(crate) struct SelectedControls {
    holders: Vec<AuthControlHolder>,
    exposed: bool,
    proof: Option<TakeProof>,
}
impl SelectedControls {
    pub(crate) fn empty() -> Self {
        Self {
            holders: Vec::new(),
            exposed: false,
            proof: None,
        }
    }
    pub(crate) fn new<'a>(
        items: impl IntoIterator<Item = (&'a str, Option<&'a AuthControlHolder>)>,
    ) -> Result<Self> {
        let mut holders = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        let mut pointers = std::collections::BTreeSet::new();
        let mut connection = None;
        for (control, holder) in items {
            let Some(holder) = holder else {
                continue;
            };
            holder.validate_control(control)?;
            ensure!(
                ids.insert(holder.0.id) && pointers.insert(Arc::as_ptr(&holder.0) as usize),
                "duplicate auth control holder in selection"
            );
            ensure!(
                connection.is_none_or(|id| id == holder.0.connection),
                "mixed auth control connections"
            );
            connection = Some(holder.0.connection);
            holders.push(holder.clone());
        }
        Ok(Self {
            holders,
            exposed: false,
            proof: None,
        })
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.holders.is_empty()
    }
    pub(crate) fn observations(&self) -> Vec<Observation> {
        self.holders
            .iter()
            .map(|holder| holder.0.observation.clone())
            .collect()
    }
    pub(crate) fn validate_connection(&self, connection: Uuid) -> Result<()> {
        for holder in &self.holders {
            holder.validate_connection(connection)?;
        }
        Ok(())
    }
    pub(crate) fn begin_exposure(&mut self, rid: u64) -> Result<()> {
        ensure!(
            !self.exposed && self.proof.is_none(),
            "auth selection exposure already started"
        );
        let mut ordered: Vec<_> = self.holders.iter().collect();
        ordered.sort_by_key(|holder| holder.0.id);
        let mut guards = Vec::with_capacity(ordered.len());
        for holder in &ordered {
            guards.push(holder.0.pending.lock().unwrap());
        }
        for (holder, state) in ordered.iter().zip(&guards) {
            ensure!(
                state.pending.is_some()
                    && matches!(state.phase, HolderPhase::Queued | HolderPhase::Recording),
                "auth control exposure already started"
            );
            ensure!(
                holder.0.observation.snapshot().terminal.is_none(),
                "auth control retired before exposure"
            );
        }
        for (holder, state) in ordered.iter().zip(guards.iter_mut()) {
            holder
                .0
                .observation
                .transport(Transport::BoshExposureEntered { rid })?;
            state.phase = HolderPhase::BoshExposing(rid);
        }
        self.exposed = true;
        Ok(())
    }
    pub(crate) fn exposure(&mut self, rid: u64, accepted: bool) -> Result<()> {
        ensure!(
            self.exposed && self.proof.is_none(),
            "auth selection exposure continuation is late"
        );
        for holder in &self.holders {
            let mut state = holder.0.pending.lock().unwrap();
            ensure!(
                state.pending.is_some() && state.phase == HolderPhase::BoshExposing(rid),
                "auth exposure continuation is late"
            );
            holder.0.observation.transport(if accepted {
                Transport::BoshAccepted { rid }
            } else {
                Transport::BoshRefused { rid }
            })?;
            state.phase = if accepted {
                HolderPhase::BoshAccepted(rid)
            } else {
                HolderPhase::BoshRefused
            };
        }
        if accepted {
            self.proof = Some(TakeProof::BoshAccepted(rid));
        }
        Ok(())
    }
    pub(crate) fn take_all(mut self) -> Result<Vec<OwnedPublication>> {
        let proof = self
            .proof
            .ok_or_else(|| anyhow::anyhow!("auth selection has no transport continuation"))?;
        let mut sorted: Vec<_> = self.holders.iter().enumerate().collect();
        sorted.sort_by_key(|(_, holder)| holder.0.id);
        let mut guards = Vec::with_capacity(sorted.len());
        let mut owned = Vec::with_capacity(sorted.len());
        for (_, holder) in &sorted {
            guards.push(holder.0.pending.lock().unwrap());
        }
        for ((_, holder), pending) in sorted.iter().zip(&guards) {
            ensure!(
                match proof {
                    TakeProof::NativeWritten => pending.phase == HolderPhase::Written,
                    TakeProof::BoshAccepted(rid) => pending.phase == HolderPhase::BoshAccepted(rid),
                },
                "auth holder transport does not match this continuation"
            );
            let pending = pending
                .pending
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("auth holder was already consumed"))?;
            ensure!(
                holder.0.observation.snapshot().terminal.is_none(),
                "auth holder retired"
            );
            ensure!(
                matches!(
                    holder.0.observation.snapshot().transport,
                    Transport::Written | Transport::BoshAccepted { .. }
                ),
                "auth holder has no successful control transport"
            );
            pending
                .effects
                .validate(&pending.receipt, holder.0.connection)?;
        }
        for ((ordinal, holder), pending) in sorted.iter().zip(guards.iter_mut()) {
            pending.phase = HolderPhase::Taken;
            owned.push((
                *ordinal,
                OwnedPublication {
                    pending: pending
                        .pending
                        .take()
                        .expect("validated entire selected set"),
                    holder: (*holder).clone(),
                    managed: false,
                },
            ));
        }
        drop(guards);
        drop(sorted);
        self.holders.clear();
        owned.sort_by_key(|(ordinal, _)| *ordinal);
        Ok(owned.into_iter().map(|(_, owner)| owner).collect())
    }
}
impl Drop for SelectedControls {
    fn drop(&mut self) {
        if self.exposed {
            for holder in &self.holders {
                holder.0.observation.abandon();
            }
        }
    }
}

pub(crate) struct OwnedPublication {
    pending: PendingPublication,
    holder: AuthControlHolder,
    managed: bool,
}
impl OwnedPublication {
    pub(super) fn receipt(&self) -> &CredentialCommitReceipt {
        &self.pending.receipt
    }
    pub(super) fn observation(&self) -> &Observation {
        &self.holder.0.observation
    }
    pub(super) fn effects(&mut self) -> &mut CapturedEffects {
        &mut self.pending.effects
    }
    pub(super) fn origin(&self) -> Option<FrameExecution> {
        self.pending.origin.clone()
    }
    pub(super) fn connection(&self) -> Uuid {
        self.holder.0.connection
    }
    pub(super) async fn publish<P: PublicationPort>(self, port: &mut P) -> PublicationResult {
        self.run(|mut owner| async move { publish_owned(&mut owner, port).await })
            .await
    }
    pub(super) fn run<F: Future<Output = PublicationResult>>(
        mut self,
        run: impl FnOnce(Self) -> F,
    ) -> impl Future<Output = PublicationResult> {
        self.managed = true;
        let observation = self.observation().clone();
        PublicationRunner {
            child: Some(Box::pin(async move { run(self).await })),
            retirement: PublicationRetirement {
                observation,
                polling: false,
                finished: false,
            },
        }
    }
}

/// Narrow auth effects only. The production adapter supplies actual service,
/// exact-route, caps and notification operations; fakes drive this same order.
pub(super) trait PublicationPort: Send {
    fn connection(&self) -> Uuid;
    fn publish(
        &mut self,
        invocation: &Invocation<'_>,
    ) -> impl Future<Output = AuthenticationResult<Option<i64>>> + Send;
    fn epoch_and_mapping(&mut self, route: &BoundRoute, epoch: Option<i64>) -> bool;
    fn activate(&mut self, route: &BoundRoute) -> bool;
    fn caps(&mut self, intent: Option<CapsIntent>) -> impl Future<Output = ()> + Send;
    fn notify_local(&mut self, intent: &NotificationIntent, epoch: i64);
    fn notify_remote(
        &mut self,
        intent: &NotificationIntent,
        epoch: i64,
    ) -> impl Future<Output = Result<()>> + Send;
    fn rejected(&mut self, result: PublicationResult, error: Option<&anyhow::Error>);
    fn notification_deferred(&mut self, error: &anyhow::Error);
}

async fn publish_owned<P: PublicationPort>(
    owner: &mut OwnedPublication,
    port: &mut P,
) -> PublicationResult {
    if owner.connection() != port.connection() {
        port.rejected(PublicationResult::RouteRejected, None);
        return PublicationResult::RouteRejected;
    }
    let observation = owner.observation().clone();
    let epoch = {
        let invocation = match observation.begin(owner.receipt()) {
            Ok(invocation) => invocation,
            Err(_) => {
                port.rejected(PublicationResult::IntegrityRejected, None);
                return PublicationResult::IntegrityRejected;
            }
        };
        match port.publish(&invocation).await {
            AuthenticationResult::Authenticated(epoch)
                if observation.authenticated_return(epoch) =>
            {
                epoch
            }
            AuthenticationResult::BackendFailure(error) => {
                port.rejected(PublicationResult::BackendFailure, Some(&error));
                return PublicationResult::BackendFailure;
            }
            AuthenticationResult::Authenticated(_) | AuthenticationResult::IntegrityFailure => {
                port.rejected(PublicationResult::IntegrityRejected, None);
                return PublicationResult::IntegrityRejected;
            }
            _ => {
                port.rejected(PublicationResult::CredentialRejected, None);
                return PublicationResult::CredentialRejected;
            }
        }
    };
    let origin = owner.origin();
    let effects = owner.effects();
    let RouteIntent::Bound(route) = &effects.route else {
        observation.effects(|facts| facts.unbound = true);
        return PublicationResult::Completed;
    };
    let mapped = port.epoch_and_mapping(route, epoch);
    observation.effects(|facts| {
        facts.route_mapping = Some(mapped);
        facts.epoch_applied = mapped;
    });
    if !mapped {
        port.rejected(PublicationResult::RouteRejected, None);
        return PublicationResult::RouteRejected;
    }
    let activated = port.activate(route);
    observation.effects(|facts| facts.route_activation = Some(activated));
    if !activated {
        port.rejected(PublicationResult::RouteRejected, None);
        return PublicationResult::RouteRejected;
    }
    if let Some(origin) = &origin {
        origin.enter(super::frame_execution::Stage::CapsPublication);
    }
    observation.effects(|facts| facts.caps_entered = true);
    port.caps(effects.caps.take()).await;
    observation.effects(|facts| facts.caps_returned = true);
    if let (Some(intent), Some(epoch)) = (&effects.notification, epoch) {
        port.notify_local(intent, epoch);
        if let Some(origin) = &origin {
            origin.enter(super::frame_execution::Stage::ReplacementNotification);
        }
        observation.effects(|facts| facts.notification_entered = true);
        let result = port.notify_remote(intent, epoch).await;
        observation.effects(|facts| facts.notification_returned = Some(result.is_ok()));
        if let Err(error) = result {
            port.notification_deferred(&error);
            return PublicationResult::CompletedWithDeferredNotification;
        }
    }
    PublicationResult::Completed
}
impl Drop for OwnedPublication {
    fn drop(&mut self) {
        if !self.managed {
            self.observation().abandon();
        }
    }
}
struct PublicationRetirement {
    observation: Observation,
    polling: bool,
    finished: bool,
}
impl PublicationRetirement {
    fn finish(&mut self, terminal: Terminal) {
        if !self.finished {
            self.finished = true;
            self.observation.retire(terminal);
        }
    }
}
impl Drop for PublicationRetirement {
    fn drop(&mut self) {
        self.finish(if self.polling || std::thread::panicking() {
            Terminal::Panicked
        } else {
            Terminal::Cancelled
        });
    }
}
struct PublicationRunner<F> {
    child: Option<Pin<Box<F>>>,
    retirement: PublicationRetirement,
}
impl<F: Future<Output = PublicationResult>> Future for PublicationRunner<F> {
    type Output = PublicationResult;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.retirement.polling = true;
        match this
            .child
            .as_mut()
            .expect("auth publication polled after completion")
            .as_mut()
            .poll(cx)
        {
            Poll::Pending => {
                this.retirement.polling = false;
                Poll::Pending
            }
            Poll::Ready(mut result) => {
                drop(this.child.take());
                this.retirement.polling = false;
                if result.transport_succeeded()
                    && !this.retirement.observation.successful_completion(
                        result == PublicationResult::CompletedWithDeferredNotification,
                    )
                {
                    result = PublicationResult::IntegrityRejected;
                }
                this.retirement.finish(match result {
                    PublicationResult::Completed => Terminal::Completed,
                    PublicationResult::CompletedWithDeferredNotification => {
                        Terminal::DeferredNotification
                    }
                    _ => Terminal::Failed,
                });
                Poll::Ready(result)
            }
        }
    }
}
impl<F> Drop for PublicationRunner<F> {
    fn drop(&mut self) {
        drop(self.child.take());
        // The retirement field is destroyed after the child, even when its
        // destructor panics; a caught poll panic retains its polling marker.
    }
}

pub struct AuthReplies {
    pub(super) replies: Vec<String>,
    pub(super) holder: AuthControlHolder,
}
impl AuthReplies {
    pub(crate) fn into_parts(self) -> (Vec<String>, AuthControlHolder) {
        (self.replies, self.holder)
    }
}

#[cfg(test)]
pub(crate) use tests::{fixture_bound_control, fixture_control, publish_unbound_fixture};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::authentication::{
        publication::{HandlerReturn, Knowledge, Returned},
        BindingPublication, StagedLoginEpoch,
    };
    use std::{
        panic::AssertUnwindSafe,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        task::Waker,
    };

    pub(crate) fn fixture_control(
        control: &str,
        connection: Uuid,
    ) -> (AuthControlHolder, Observation) {
        let owner = KnownCredentialOwner::from_returned(
            CredentialCommitReceipt::new(None, None, None),
            None,
            connection,
        );
        let observation = owner.observation().clone();
        let holder = owner
            .seal(
                control,
                CapturedEffects {
                    route: RouteIntent::Unbound,
                    caps: None,
                    notification: None,
                },
            )
            .unwrap();
        (holder, observation)
    }
    pub(crate) fn fixture_bound_control(
        control: &str,
        connection: Uuid,
        notify: bool,
    ) -> (AuthControlHolder, Observation) {
        let user = Uuid::from_u128(303);
        let device = Uuid::from_u128(304);
        let receipt = CredentialCommitReceipt::new(
            None,
            Some(StagedLoginEpoch {
                operation_id: Uuid::from_u128(301),
                connection_id: connection,
                user_id: user,
                device_id: device,
                auth_generation: 2,
                epoch: 999,
            }),
            Some(BindingPublication {
                connection_id: connection,
                user_id: user,
                full_jid: "fixture@example.test/captured".to_owned(),
                lease_seconds: 120,
            }),
        );
        let owner = KnownCredentialOwner::from_returned(receipt, None, connection);
        let observation = owner.observation().clone();
        let route = BoundRoute {
            key: "fixture@example.test/captured".to_owned(),
            user,
            generation: 2,
            connection,
            lifecycle: Arc::new(AtomicU8::new(0)),
            disconnect: CancellationToken::new(),
        };
        let caps = CapsIntent {
            presence: "<presence/>".to_owned(),
            key: route.key.clone(),
            connection,
            gate: Arc::new(tokio::sync::Mutex::new(())),
            generation: Arc::new(AtomicU64::new(9)),
        };
        let notification = notify.then(|| NotificationIntent {
            account: "fixture@example.test".to_owned(),
            user,
            device,
            excluded_key: route.key.clone(),
        });
        let holder = owner
            .seal(
                control,
                CapturedEffects {
                    route: RouteIntent::Bound(route),
                    caps: Some(caps),
                    notification,
                },
            )
            .unwrap();
        (holder, observation)
    }
    #[derive(Clone, Copy, Default)]
    enum Cut {
        #[default]
        Success,
        BeforeCommit,
        CommitPending,
        CommitError,
        BareSuccess,
        WrongReturn,
        RouteRejected,
        CapsPending,
        NotifyError,
    }
    struct FakePort {
        connection: Uuid,
        cut: Cut,
        events: Vec<&'static str>,
        routes: Vec<String>,
        caps_generation: Option<u64>,
        notification: Option<(String, Uuid, Uuid, String, i64)>,
    }
    impl FakePort {
        fn new(connection: Uuid, cut: Cut) -> Self {
            Self {
                connection,
                cut,
                events: Vec::new(),
                routes: Vec::new(),
                caps_generation: None,
                notification: None,
            }
        }
    }
    impl PublicationPort for FakePort {
        fn connection(&self) -> Uuid {
            self.connection
        }
        async fn publish(
            &mut self,
            invocation: &Invocation<'_>,
        ) -> AuthenticationResult<Option<i64>> {
            self.events.push("service");
            invocation.enter_service().unwrap();
            let result = if matches!(self.cut, Cut::BeforeCommit) {
                AuthenticationResult::BackendFailure(anyhow::anyhow!(
                    "controlled pre-COMMIT failure"
                ))
            } else if invocation.receipt().staged_login_epoch().is_none()
                && invocation.receipt().binding_publication().is_none()
            {
                invocation.not_required().unwrap();
                AuthenticationResult::Authenticated(None)
            } else {
                invocation.enter_repository().unwrap();
                self.events.push("repository");
                if matches!(self.cut, Cut::BareSuccess) {
                    AuthenticationResult::Authenticated(Some(7))
                } else {
                    let cut = self.cut;
                    let committed = invocation
                        .commit(
                            async {
                                if matches!(cut, Cut::CommitPending) {
                                    std::future::pending::<()>().await;
                                }
                                if matches!(cut, Cut::CommitError) {
                                    return Err(std::io::Error::other(
                                        "controlled COMMIT reply loss",
                                    ));
                                }
                                Ok(())
                            },
                            Some(7),
                        )
                        .await;
                    match committed {
                        Ok(()) => AuthenticationResult::Authenticated(Some(
                            if matches!(cut, Cut::WrongReturn) {
                                8
                            } else {
                                7
                            },
                        )),
                        Err(error) => AuthenticationResult::BackendFailure(error.into()),
                    }
                }
            };
            // Preserve the actual fake adapter return even when it mismatches;
            // the shared production sequence must reject it before effects.
            let _ = invocation.returned(&result);
            result
        }
        fn epoch_and_mapping(&mut self, route: &BoundRoute, epoch: Option<i64>) -> bool {
            self.events.push("route");
            self.routes.push(route.key.clone());
            assert_eq!(route.connection, self.connection);
            assert_eq!(route.user, Uuid::from_u128(303));
            assert_eq!(route.generation, 2);
            assert_eq!(epoch, Some(7));
            !matches!(self.cut, Cut::RouteRejected)
        }
        fn activate(&mut self, route: &BoundRoute) -> bool {
            self.events.push("activate");
            assert_eq!(route.key, "fixture@example.test/captured");
            true
        }
        async fn caps(&mut self, intent: Option<CapsIntent>) {
            self.events.push("caps");
            let caps = intent.expect("captured resume caps intent");
            assert_eq!(caps.key, "fixture@example.test/captured");
            assert_eq!(caps.connection, self.connection);
            assert_eq!(caps.presence, "<presence/>");
            self.caps_generation = Some(caps.generation.load(Ordering::Acquire));
            if matches!(self.cut, Cut::CapsPending) {
                std::future::pending::<()>().await;
            }
        }
        fn notify_local(&mut self, intent: &NotificationIntent, epoch: i64) {
            self.events.push("local_notification");
            self.notification = Some((
                intent.account.clone(),
                intent.user,
                intent.device,
                intent.excluded_key.clone(),
                epoch,
            ));
        }
        async fn notify_remote(&mut self, _: &NotificationIntent, _: i64) -> Result<()> {
            self.events.push("remote_notification");
            if matches!(self.cut, Cut::NotifyError) {
                anyhow::bail!("controlled notification failure");
            }
            Ok(())
        }
        fn rejected(&mut self, _: PublicationResult, _: Option<&anyhow::Error>) {
            self.events.push("rejected");
        }
        fn notification_deferred(&mut self, _: &anyhow::Error) {
            self.events.push("deferred");
        }
    }
    pub(crate) async fn publish_unbound_fixture(owners: Vec<OwnedPublication>) -> bool {
        for owner in owners {
            let mut port = FakePort::new(owner.connection(), Cut::Success);
            if !owner.publish(&mut port).await.transport_succeeded() {
                return false;
            }
            assert_eq!(port.events, ["service"]);
        }
        true
    }
    fn selected(holders: &[(&str, &AuthControlHolder)], rid: u64) -> SelectedControls {
        let mut selected = SelectedControls::new(
            holders
                .iter()
                .map(|(control, holder)| (*control, Some(*holder))),
        )
        .unwrap();
        selected.begin_exposure(rid).unwrap();
        selected.exposure(rid, true).unwrap();
        selected
    }
    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[tokio::test]
    async fn sealed_bytes_and_aliases_cannot_start_another_native_write() {
        let (holder, observation) = fixture_control("<success/>", Uuid::from_u128(302));
        let alias = holder.clone();
        holder.recording().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = calls.clone();
        assert!(alias
            .clone()
            .write("<different/>".to_owned(), move |_| async move {
                observed_calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .await
            .is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        let owner = holder
            .write("<success/>".to_owned(), |_| async { Ok(()) })
            .await
            .unwrap();
        assert!(alias.recording().is_err());
        let observed_calls = calls.clone();
        assert!(alias
            .write("<success/>".to_owned(), move |_| async move {
                observed_calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .await
            .is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(observation.snapshot().transport, Transport::Written);
        assert!(publish_unbound_fixture(vec![owner]).await);
        assert_eq!(observation.snapshot().publication, Knowledge::NotRequired);
    }

    #[test]
    fn duplicate_ids_addresses_and_changed_controls_fail_before_holder_locks() {
        let connection = Uuid::from_u128(302);
        let (first, _) = fixture_control("<success/>", connection);
        let alias = first.clone();
        assert!(SelectedControls::new([
            ("<success/>", Some(&first)),
            ("<success/>", Some(&alias))
        ])
        .is_err());
        assert!(SelectedControls::new([("<changed/>", Some(&first))]).is_err());
        let (mut second, _) = fixture_control("<success/>", connection);
        let distinct = Arc::get_mut(&mut second.0).unwrap();
        distinct.id = first.0.id;
        distinct.observation = first.0.observation.clone();
        assert!(!Arc::ptr_eq(&first.0, &second.0));
        assert_eq!(
            SelectedControls::new([("<success/>", Some(&first)), ("<success/>", Some(&second))])
                .err()
                .unwrap()
                .to_string(),
            "duplicate auth control holder in selection"
        );
        assert!(first.0.pending.lock().unwrap().pending.is_some());
        assert!(second.0.pending.lock().unwrap().pending.is_some());
    }

    #[test]
    fn selection_requires_its_own_exposure_and_validates_every_holder_before_take() {
        let connection = Uuid::from_u128(302);
        let (first, _) = fixture_control("<success id='1'/>", connection);
        let (second, _) = fixture_control("<success id='2'/>", connection);
        let selection = selected(
            &[
                ("<success id='1'/>", &first),
                ("<success id='2'/>", &second),
            ],
            10,
        );
        let replacement = SelectedControls::new([("<success id='1'/>", Some(&first))]).unwrap();
        assert!(
            replacement.take_all().is_err(),
            "a fresh selection cannot steal prior exposure authority"
        );
        // Controlled stale state in the second holder must not consume the first.
        second.0.pending.lock().unwrap().phase = HolderPhase::Taken;
        assert!(selection.take_all().is_err());
        assert!(first.0.pending.lock().unwrap().pending.is_some());
        assert!(second.0.pending.lock().unwrap().pending.is_some());
    }

    #[tokio::test]
    async fn unbound_selected_control_does_not_take_queued_bind_owner() {
        let connection = Uuid::from_u128(302);
        let (unbound, u) = fixture_control("<success/>", connection);
        let (bound, b) = fixture_bound_control("<iq type='result'/>", connection, true);
        let prior = b.snapshot();
        let owners = selected(&[("<success/>", &unbound)], 10)
            .take_all()
            .unwrap();
        assert!(publish_unbound_fixture(owners).await);
        assert_eq!(u.snapshot().publication, Knowledge::NotRequired);
        assert_eq!(u.snapshot().terminal, Some(Terminal::Completed));
        assert_eq!(b.snapshot(), prior);
        assert!(bound.0.pending.lock().unwrap().pending.is_some());
    }

    #[tokio::test]
    async fn shared_sequence_uses_captured_effects_and_preserves_deferred_success() {
        for cut in [Cut::Success, Cut::NotifyError] {
            let connection = Uuid::from_u128(302);
            let (holder, observation) = fixture_bound_control("<success/>", connection, true);
            let mut owners = selected(&[("<success/>", &holder)], 10).take_all().unwrap();
            let mut port = FakePort::new(connection, cut);
            let result = owners.pop().unwrap().publish(&mut port).await;
            assert_eq!(
                result,
                if matches!(cut, Cut::NotifyError) {
                    PublicationResult::CompletedWithDeferredNotification
                } else {
                    PublicationResult::Completed
                }
            );
            assert_eq!(
                &port.events[..6],
                [
                    "service",
                    "repository",
                    "route",
                    "activate",
                    "caps",
                    "local_notification"
                ]
            );
            assert_eq!(port.caps_generation, Some(9));
            assert_eq!(
                port.notification,
                Some((
                    "fixture@example.test".to_owned(),
                    Uuid::from_u128(303),
                    Uuid::from_u128(304),
                    "fixture@example.test/captured".to_owned(),
                    7
                ))
            );
            assert_eq!(
                observation.snapshot().publication,
                Knowledge::ReceiptKnown(Some(7))
            );
            assert_eq!(
                observation.snapshot().returned,
                Some(Returned::Authenticated(Some(7)))
            );
            assert!(observation.completed());
        }
    }

    #[tokio::test]
    async fn failed_or_unwitnessed_publication_never_starts_route_effects() {
        for cut in [
            Cut::BeforeCommit,
            Cut::CommitError,
            Cut::BareSuccess,
            Cut::WrongReturn,
        ] {
            let connection = Uuid::from_u128(302);
            let (holder, observation) = fixture_bound_control("<success/>", connection, false);
            let owner = selected(&[("<success/>", &holder)], 10)
                .take_all()
                .unwrap()
                .pop()
                .unwrap();
            let mut port = FakePort::new(connection, cut);
            assert!(!owner.publish(&mut port).await.transport_succeeded());
            assert!(!port.events.contains(&"route"));
            assert_eq!(
                observation.snapshot().transport,
                Transport::BoshAccepted { rid: 10 }
            );
            assert_eq!(
                observation.snapshot().publication,
                match cut {
                    Cut::CommitError => Knowledge::CommitCallEntered,
                    Cut::WrongReturn => Knowledge::ReceiptKnown(Some(7)),
                    _ => Knowledge::BeforeCommit,
                }
            );
        }
    }

    #[tokio::test]
    async fn fifo_failure_keeps_completed_prefix_and_retires_only_selected_suffix() {
        let connection = Uuid::from_u128(302);
        let (u, u_observation) = fixture_control("<success id='u'/>", connection);
        let (b, b_observation) = fixture_bound_control("<success id='b'/>", connection, false);
        let (suffix, suffix_observation) = fixture_control("<success id='suffix'/>", connection);
        let (_queued, queued_observation) = fixture_control("<success id='queued'/>", connection);
        let prior = queued_observation.snapshot();
        let mut owners = selected(
            &[
                ("<success id='u'/>", &u),
                ("<success id='b'/>", &b),
                ("<success id='suffix'/>", &suffix),
            ],
            10,
        )
        .take_all()
        .unwrap()
        .into_iter();
        let mut port = FakePort::new(connection, Cut::RouteRejected);
        assert_eq!(
            owners.next().unwrap().publish(&mut port).await,
            PublicationResult::Completed
        );
        assert_eq!(
            owners.next().unwrap().publish(&mut port).await,
            PublicationResult::RouteRejected
        );
        drop(owners);
        assert_eq!(u_observation.snapshot().terminal, Some(Terminal::Completed));
        assert_eq!(
            b_observation.snapshot().publication,
            Knowledge::ReceiptKnown(Some(7))
        );
        assert_eq!(
            suffix_observation.snapshot().terminal,
            Some(Terminal::ExposedNotAttempted)
        );
        assert_eq!(
            suffix_observation.snapshot().publication,
            Knowledge::NotStarted
        );
        assert_eq!(queued_observation.snapshot(), prior);
    }

    #[test]
    fn commit_or_caps_cancel_keeps_transport_and_prior_publication_facts() {
        for cut in [Cut::CommitPending, Cut::CapsPending] {
            let connection = Uuid::from_u128(302);
            let (holder, observation) = fixture_bound_control("<success/>", connection, false);
            let owner = selected(&[("<success/>", &holder)], 10)
                .take_all()
                .unwrap()
                .pop()
                .unwrap();
            let mut port = FakePort::new(connection, cut);
            let mut future = Box::pin(owner.publish(&mut port));
            assert!(poll_once(future.as_mut()).is_pending());
            drop(future);
            let snapshot = observation.snapshot();
            assert_eq!(snapshot.terminal, Some(Terminal::Cancelled));
            assert_eq!(snapshot.transport, Transport::BoshAccepted { rid: 10 });
            assert_eq!(
                snapshot.publication,
                if matches!(cut, Cut::CommitPending) {
                    Knowledge::CommitCallEntered
                } else {
                    Knowledge::ReceiptKnown(Some(7))
                }
            );
            assert_eq!(
                snapshot.effects.caps_entered,
                matches!(cut, Cut::CapsPending)
            );
            assert!(!snapshot.effects.caps_returned);
        }
    }

    #[tokio::test]
    async fn completed_handler_transfers_publication_lifetime_to_its_control() {
        let execution = FrameExecution::for_saved_case(
            super::super::protocol::ClientTransport::Bosh,
            "<authenticate/>",
            Uuid::from_u128(350),
        );
        let owner = KnownCredentialOwner::from_returned(
            CredentialCommitReceipt::new(None, None, None),
            Some(execution.clone()),
            Uuid::from_u128(302),
        );
        let observation = owner.observation().clone();
        let wrong = FrameExecution::for_saved_case(
            super::super::protocol::ClientTransport::Bosh,
            "<iq/>",
            Uuid::from_u128(351),
        );
        assert_eq!(
            wrong
                .retain_auth_receipt(observation.clone())
                .unwrap_err()
                .to_string(),
            "auth receipt belongs to another frame"
        );
        wrong.run(async { Ok(()) }).await.unwrap();
        assert_eq!(observation.snapshot().handler, None);
        execution.retain_auth_receipt(observation.clone()).unwrap();
        let holder = execution
            .run(async move {
                owner.seal(
                    "<success/>",
                    CapturedEffects {
                        route: RouteIntent::Unbound,
                        caps: None,
                        notification: None,
                    },
                )
            })
            .await
            .unwrap();
        assert_eq!(
            observation.snapshot().handler,
            Some(HandlerReturn::Completed)
        );
        assert_eq!(observation.snapshot().terminal, None);
        assert_eq!(observation.snapshot().frame, Some(Uuid::from_u128(350)));
        let owners = selected(&[("<success/>", &holder)], 10).take_all().unwrap();
        assert!(publish_unbound_fixture(owners).await);
        assert_eq!(
            observation.snapshot().handler,
            Some(HandlerReturn::Completed)
        );
        assert_eq!(observation.snapshot().terminal, Some(Terminal::Completed));
    }

    #[derive(Default)]
    struct MemoryWrite {
        bytes: Vec<u8>,
        fail_at: Option<usize>,
        fail_flush: bool,
        flushes: usize,
    }
    impl tokio::io::AsyncWrite for MemoryWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if this.fail_at.is_some_and(|limit| this.bytes.len() >= limit) {
                return Poll::Ready(Err(std::io::Error::other("controlled partial write")));
            }
            let count = bytes.len().min(3).min(
                this.fail_at
                    .map_or(usize::MAX, |limit| limit - this.bytes.len()),
            );
            this.bytes.extend_from_slice(&bytes[..count]);
            Poll::Ready(Ok(count))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            this.flushes += 1;
            if this.fail_flush {
                Poll::Ready(Err(std::io::Error::other("controlled flush failure")))
            } else {
                Poll::Ready(Ok(()))
            }
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn actual_tcp_send_partial_and_flush_failure_never_publish_authentication() {
        for flush_failure in [false, true] {
            let connection = Uuid::from_u128(302);
            let (holder, observation) = fixture_bound_control("<success/>", connection, false);
            holder.recording().unwrap();
            let mut io = MemoryWrite {
                fail_at: (!flush_failure).then_some(1),
                fail_flush: flush_failure,
                ..MemoryWrite::default()
            };
            let writer = &mut io;
            let result = holder
                .write("<success/>".to_owned(), |control| async move {
                    super::super::send(writer, &control).await
                })
                .await;
            assert!(result.is_err());
            assert_eq!(
                io.bytes.len(),
                if flush_failure { "<success/>".len() } else { 1 }
            );
            assert_eq!(io.flushes, usize::from(flush_failure));
            assert_eq!(observation.snapshot().transport, Transport::WriteEntered);
            assert_eq!(observation.snapshot().publication, Knowledge::NotStarted);
        }
    }

    #[tokio::test]
    async fn actual_tcp_write_survives_publication_failure_and_caps_cancellation() {
        for cut in [Cut::BeforeCommit, Cut::CommitPending, Cut::CapsPending] {
            let connection = Uuid::from_u128(302);
            let (holder, observation) = fixture_bound_control("<success/>", connection, false);
            holder.recording().unwrap();
            let mut io = MemoryWrite::default();
            let writer = &mut io;
            let owner = holder
                .write("<success/>".to_owned(), |control| async move {
                    super::super::send(writer, &control).await
                })
                .await
                .unwrap();
            assert_eq!(io.bytes, b"<success/>");
            assert_eq!(io.flushes, 1);
            let mut port = FakePort::new(connection, cut);
            let mut future = Box::pin(owner.publish(&mut port));
            let polled = poll_once(future.as_mut());
            if matches!(cut, Cut::BeforeCommit) {
                assert!(matches!(
                    polled,
                    Poll::Ready(PublicationResult::BackendFailure)
                ));
            } else {
                assert!(polled.is_pending());
            }
            drop(future);
            let snapshot = observation.snapshot();
            assert_eq!(snapshot.transport, Transport::Written);
            assert_eq!(
                snapshot.publication,
                match cut {
                    Cut::BeforeCommit => Knowledge::BeforeCommit,
                    Cut::CommitPending => Knowledge::CommitCallEntered,
                    _ => Knowledge::ReceiptKnown(Some(7)),
                }
            );
            assert_eq!(
                snapshot.terminal,
                Some(if matches!(cut, Cut::BeforeCommit) {
                    Terminal::Failed
                } else {
                    Terminal::Cancelled
                })
            );
        }
    }

    #[tokio::test]
    async fn actual_websocket_live_write_gate_preserves_success_and_cancellation() {
        for cancel in [0, 1, 2, 3] {
            let connection = Uuid::from_u128(302);
            let (holder, observation) = fixture_control("<success/>", connection);
            holder.recording().unwrap();
            let shutdown = CancellationToken::new();
            let revoke = CancellationToken::new();
            let backpressure = CancellationToken::new();
            match cancel {
                1 => shutdown.cancel(),
                2 => revoke.cancel(),
                3 => backpressure.cancel(),
                _ => {}
            }
            let signals = super::super::protocol::SessionTerminationSignals::from_test_tokens(
                revoke,
                backpressure,
            );
            let cancellation = super::super::WebSocketSendCancellation {
                actor_shutdown: &shutdown,
                signals: &signals,
            };
            let polls = Arc::new(AtomicUsize::new(0));
            let write_polls = polls.clone();
            let result = holder
                .write("<success/>".to_owned(), |control| async move {
                    assert_eq!(control, "<success/>");
                    let sent = super::super::bounded_websocket_live_write(
                        async move {
                            write_polls.fetch_add(1, Ordering::Relaxed);
                            Ok::<(), std::io::Error>(())
                        },
                        &cancellation,
                    )
                    .await;
                    ensure!(sent, "controlled WS cancellation");
                    Ok(())
                })
                .await;
            assert_eq!(polls.load(Ordering::Relaxed), usize::from(cancel == 0));
            if cancel == 0 {
                assert!(publish_unbound_fixture(vec![result.unwrap()]).await);
                assert_eq!(observation.snapshot().transport, Transport::Written);
            } else {
                assert!(result.is_err());
                assert_eq!(observation.snapshot().publication, Knowledge::NotStarted);
            }
        }
    }

    struct PanicChild {
        _owner: OwnedPublication,
        ready: bool,
        panic_poll: bool,
        dropped: Arc<AtomicBool>,
    }
    impl Future for PanicChild {
        type Output = PublicationResult;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            if self.panic_poll {
                panic!("controlled auth poll panic");
            }
            if self.ready {
                Poll::Ready(PublicationResult::Completed)
            } else {
                Poll::Pending
            }
        }
    }
    impl Drop for PanicChild {
        fn drop(&mut self) {
            assert_eq!(
                self._owner.observation().snapshot().terminal,
                None,
                "child must be destroyed before publication retirement"
            );
            self.dropped.store(true, Ordering::Release);
            if !self.panic_poll {
                panic!("controlled auth child destructor panic");
            }
        }
    }
    #[test]
    fn publication_child_drop_and_caught_poll_panics_retire_after_destruction() {
        for (ready, panic_poll) in [(false, false), (true, false), (false, true)] {
            let connection = Uuid::from_u128(302);
            let (holder, observation) = fixture_control("<success/>", connection);
            let owner = selected(&[("<success/>", &holder)], 10)
                .take_all()
                .unwrap()
                .pop()
                .unwrap();
            let dropped = Arc::new(AtomicBool::new(false));
            let child_dropped = dropped.clone();
            let mut future = Box::pin(owner.run(move |owner| PanicChild {
                _owner: owner,
                ready,
                panic_poll,
                dropped: child_dropped,
            }));
            let polled = std::panic::catch_unwind(AssertUnwindSafe(|| poll_once(future.as_mut())));
            if ready || panic_poll {
                assert!(polled.is_err());
            } else {
                assert!(matches!(polled, Ok(Poll::Pending)));
            }
            let _ = std::panic::catch_unwind(AssertUnwindSafe(|| drop(future)));
            assert!(dropped.load(Ordering::Acquire));
            assert_eq!(observation.snapshot().terminal, Some(Terminal::Panicked));
        }
    }
}
