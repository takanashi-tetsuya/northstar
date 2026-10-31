//! Per-control auth ownership. The FIFO marker is metadata; only the private
//! holder can transfer its actual credential receipt into publication.
#[cfg(test)]
pub(crate) mod stage4_saved;

use super::frame_execution::{FrameExecution, PublicationResult};
use anyhow::{ensure, Result};
use northstar_auth_application::authentication::publication::{
    Invocation, Observation, Terminal, Transport,
};
use northstar_auth_application::authentication::{AuthenticationResult, CredentialCommitReceipt};
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

#[derive(Debug)]
struct CredentialHandoffIntegrity;
impl std::fmt::Display for CredentialHandoffIntegrity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("credential receipt handoff integrity failure")
    }
}
impl std::error::Error for CredentialHandoffIntegrity {}
pub(super) fn credential_handoff_failed(error: &anyhow::Error) -> bool {
    error.is::<CredentialHandoffIntegrity>()
}

// The mode and original frame are captured before the credential service is
// polled. Missing evidence after an observed call can never choose compatibility.
pub(super) struct CredentialAttempt {
    origin: Option<FrameExecution>,
    prepared: Option<northstar_auth_application::authentication::publication::PreparedCredential>,
    connection: Uuid,
}
impl CredentialAttempt {
    pub(super) fn new(
        origin: Option<FrameExecution>,
        connection: Uuid,
        kind: northstar_auth_application::authentication::publication::CredentialKind,
    ) -> Result<Self> {
        let prepared = origin
            .as_ref()
            .map(|frame| frame.prepare_credential(kind, connection))
            .transpose()?;
        Ok(Self {
            origin,
            prepared,
            connection,
        })
    }
    pub(super) fn prepared(
        &self,
    ) -> Option<&northstar_auth_application::authentication::publication::PreparedCredential> {
        self.prepared.as_ref()
    }
    pub(super) fn into_owner(
        self,
        receipt: CredentialCommitReceipt,
    ) -> Result<KnownCredentialOwner> {
        match (self.origin, self.prepared) {
            (Some(origin), Some(prepared)) => {
                KnownCredentialOwner::from_observed(receipt, origin, self.connection, &prepared)
            }
            (None, None) => Ok(KnownCredentialOwner::from_returned(
                receipt,
                None,
                self.connection,
            )),
            _ => Err(CredentialHandoffIntegrity.into()),
        }
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
    pub(super) fn from_observed(
        receipt: CredentialCommitReceipt,
        origin: FrameExecution,
        connection: Uuid,
        prepared: &northstar_auth_application::authentication::publication::PreparedCredential,
    ) -> Result<Self> {
        let credential = prepared
            .transfer(&receipt, origin.operation_id(), connection)
            .map_err(|_| CredentialHandoffIntegrity)?;
        let observation =
            Observation::observed_receipt(&receipt, origin.operation_id(), credential);
        Ok(Self {
            receipt: Some(receipt),
            origin: Some(origin),
            connection,
            observation,
        })
    }
    pub(super) fn origin(&self) -> Option<&FrameExecution> {
        self.origin.as_ref()
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
        let holder = AuthControlHolder(Arc::new(Holder {
            id: self.observation.snapshot().control,
            connection: self.connection,
            length: control.len(),
            digest: Sha256::digest(control.as_bytes()).into(),
            observation: self.observation.clone(),
            #[cfg(test)]
            joins: ControlJoinObservation(Arc::new(Mutex::new(ControlJoins::default()))),
            pending: Mutex::new(HolderState {
                pending: Some(PendingPublication {
                    receipt,
                    origin: self.origin.take(),
                    effects,
                }),
                phase: HolderPhase::Queued,
            }),
        }));
        #[cfg(test)]
        {
            let pending = holder.0.pending.lock().unwrap();
            holder.0.joins.0.lock().unwrap().introduced = Some(control_association(
                &holder.0,
                pending.pending.as_ref().expect("sealed auth receipt"),
            ));
        }
        Ok(holder)
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
// A read handle retains only fixed-size facts, never a holder or receipt.
// In particular, retaining it cannot delay abandonment of a queued owner.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControlAssociation {
    pub(crate) control: Uuid,
    pub(crate) connection: Uuid,
    pub(crate) frame: Option<Uuid>,
    pub(crate) receipt: Uuid,
    pub(crate) length: usize,
    pub(crate) digest: [u8; 32],
    pub(crate) publication:
        northstar_auth_application::authentication::publication::PublicationJoins,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ControlJoins {
    pub(crate) introduced: Option<ControlAssociation>,
    pub(crate) transferred: Option<ControlAssociation>,
}
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct ControlJoinObservation(Arc<Mutex<ControlJoins>>);
#[cfg(test)]
impl ControlJoinObservation {
    pub(crate) fn snapshot(&self) -> ControlJoins {
        *self.0.lock().unwrap()
    }
}
#[cfg(test)]
fn control_association(holder: &Holder, pending: &PendingPublication) -> ControlAssociation {
    ControlAssociation {
        control: holder.id,
        connection: holder.connection,
        frame: pending.origin.as_ref().map(FrameExecution::operation_id),
        receipt: pending.receipt.publication_identity(),
        length: holder.length,
        digest: holder.digest,
        publication: holder.observation.joins(),
    }
}
struct Holder {
    id: Uuid,
    connection: Uuid,
    length: usize,
    digest: [u8; 32],
    observation: Observation,
    #[cfg(test)]
    joins: ControlJoinObservation,
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
    #[cfg(test)]
    pub(crate) fn join_observation(&self) -> ControlJoinObservation {
        self.0.joins.clone()
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
            #[cfg(test)]
            {
                let owner = &owned.last().expect("transferred auth owner").1;
                holder.0.joins.0.lock().unwrap().transferred =
                    Some(control_association(&holder.0, &owner.pending));
            }
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
mod tests;
