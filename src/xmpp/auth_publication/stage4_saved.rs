//! Test-only credential and publication composition adapter.
//! Actual credential/service/holder/publication owners over finite replies.
#![cfg(test)]
use super::*;
use crate::outbound::OutboundItem;
use crate::services::authentication::publication::{CredentialKind, CredentialObservation};
use crate::services::authentication::{AuthenticationService, FastCommitPlan};
use crate::services::sm::{BindingFinalizationOutcome, SmService};
use crate::stage4_replay as wire;
use crate::xmpp::protocol::{mix::stage4_saved::RouteHandle, ClientTransport};
use std::collections::BTreeMap;

pub(crate) mod facts;
#[cfg(test)]
pub(crate) mod ordinary;
mod repository;
pub(crate) type Capture = Arc<Mutex<wire::Recorder>>;
pub(crate) type Driven<T> = std::result::Result<Result<T>, wire::BudgetStop>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CredentialSite(wire::PollSite);
impl CredentialSite {
    pub(crate) fn new(ordinal: u8) -> std::result::Result<Self, wire::DriverConfigurationError> {
        wire::PollSite::new(wire::DriverOwner::Credential, ordinal).map(Self)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PublicationSite(wire::PollSite);
impl PublicationSite {
    pub(crate) fn new(ordinal: u8) -> std::result::Result<Self, wire::DriverConfigurationError> {
        wire::PollSite::new(wire::DriverOwner::Publication, ordinal).map(Self)
    }
}

/// Runtime observation bundle only. Serializers receive projected facts,
/// never this object, receipt, holder, route handle or service.
#[derive(Clone)]
pub(crate) struct AuthRead {
    frame: FrameExecution,
    credential: CredentialObservation,
    publication: Observation,
    joins: ControlJoinObservation,
    recorder: Capture,
}
impl AuthRead {
    pub(crate) fn control(&self) -> Uuid {
        self.publication.snapshot().control
    }
    pub(crate) fn frame_id(&self) -> Uuid {
        self.frame.operation_id()
    }
    pub(crate) fn live_snapshot(&self) -> crate::services::authentication::publication::Snapshot {
        self.publication.snapshot()
    }
    pub(crate) fn publication_joins(
        &self,
    ) -> crate::services::authentication::publication::PublicationJoins {
        self.publication.joins()
    }
    pub(crate) fn credential_joins(
        &self,
    ) -> crate::services::authentication::publication::CredentialJoins {
        self.credential.joins()
    }
    pub(crate) fn capture(&self, cut: wire::Cut) {
        facts::emit(&self.recorder, facts::credential(&self.credential, cut));
        facts::observe(&self.recorder, || facts::holder(&self.joins, None, cut));
        facts::emit(&self.recorder, facts::publication(&self.publication, cut))
    }
    pub(crate) fn capture_frame_quiescent(&self, cut: wire::Cut) {
        // Shared test-only projection. Every caller must prove no child/task is
        // polling, no detached task exists, and all remaining clones are inert.
        // Raw frame outcome may still be Completed while live auth is Pending.
        let actual_admission = self.frame.direct_operation().snapshot();
        if actual_admission.reservation.is_some() || actual_admission.finalization.is_some() {
            // This auth slice has no admission operation or mapper. Unexpected
            // retained admission is loss, never a claimed complete null.
            facts::lost(&self.recorder);
        }
        crate::xmpp::stage4_frame_capture::capture_frame(
            &self.frame,
            cut,
            None,
            None,
            &self.recorder,
        );
    }
}
pub(crate) struct BuiltControl {
    pub(crate) item: OutboundItem,
    pub(crate) read: AuthRead,
    port: ControlledPort,
}
impl BuiltControl {
    pub(crate) fn split(self) -> (OutboundItem, AuthRead, Publisher) {
        let mut ports = BTreeMap::new();
        ports.insert(self.read.control(), self.port);
        (self.item, self.read, Publisher { ports })
    }
}
/// The control-ID key comes from the actual sealed introduction. No input ID
/// can create an owner or identify a callback that the mutant did not invoke.
pub(crate) struct Publisher {
    ports: BTreeMap<Uuid, ControlledPort>,
}
impl Publisher {
    pub(crate) fn empty() -> Self {
        Self {
            ports: BTreeMap::new(),
        }
    }
    pub(crate) fn contains_control(&self, control: Uuid) -> bool {
        self.ports.contains_key(&control)
    }
    pub(crate) fn append(&mut self, other: Self) -> Result<()> {
        ensure!(
            self.ports.len() + other.ports.len() <= 2,
            "finite auth publication owner cap"
        );
        for (id, port) in other.ports {
            ensure!(!self.ports.contains_key(&id), "duplicate actual auth owner");
            self.ports.insert(id, port);
        }
        Ok(())
    }
    pub(crate) async fn publish(
        &mut self,
        owners: Vec<OwnedPublication>,
        session: Option<Uuid>,
        rid: Option<u64>,
        recorder: &Capture,
    ) -> bool {
        // The callback is only recorded here, after production has invoked it.
        // Failure to describe this invocation cannot veto or replace it.
        let callback = facts::project(recorder, || {
            let mut invoked = Vec::new();
            let mut connection = None;
            for owner in &owners {
                connection = Some(owner.connection());
                let join = owner
                    .holder
                    .join_observation()
                    .snapshot()
                    .transferred
                    .ok_or_else(|| anyhow::anyhow!("missing transferred control observation"))?;
                invoked.push(facts::association(join)?);
            }
            let connection = connection
                .ok_or_else(|| anyhow::anyhow!("callback has no observed owner connection"))?;
            Ok(wire::PublicationCallback {
                connection: facts::id(connection),
                session: facts::nullable(session.map(facts::id)),
                rid: facts::nullable(rid),
                invoked_owners: wire::List::new(invoked)?,
                returned: wire::Nullable::Null(()),
            })
        });
        if let Some(callback) = &callback {
            facts::emit(
                recorder,
                wire::Fact::Control(wire::ControlFact::Callback(callback.clone())),
            );
        }
        // This is an actual finite effect-scope check, independent of every
        // observer result. Never consume an intended effect as a silent no-op.
        if owners.iter().any(|owner| {
            owner.pending.effects.caps.is_some() || owner.pending.effects.notification.is_some()
        }) {
            facts::lost(recorder);
            if let Some(mut callback) = callback {
                callback.returned = wire::Nullable::Value(false);
                facts::emit(
                    recorder,
                    wire::Fact::Control(wire::ControlFact::Callback(callback)),
                );
            }
            return false;
        }
        let mut returned = true;
        for owner in owners {
            let control = owner.observation().snapshot().control;
            let Some(mut port) = self.ports.remove(&control) else {
                facts::lost(recorder);
                return false;
            };
            let Some(origin) = owner.origin() else {
                facts::lost(recorder);
                return false;
            };
            // Real outer frame publication records typed failure/cancellation.
            returned &= origin.observe_publication(owner.publish(&mut port)).await;
            if !returned {
                break;
            }
        }
        if let Some(mut callback) = callback {
            callback.returned = wire::Nullable::Value(returned);
            facts::emit(
                recorder,
                wire::Fact::Control(wire::ControlFact::Callback(callback)),
            );
        }
        returned
    }
}

pub(crate) struct PublicationRun {
    pub(crate) returned: Option<bool>,
    pub(crate) dropped: bool,
}
/// The owned publication and every port future remain on this stack. No task
/// can progress them while the single manual poll is suspended for capture.
pub(crate) async fn publish_native(
    owner: OwnedPublication,
    read: &AuthRead,
    publisher: &mut Publisher,
    drive: wire::AuthDrive,
    recorder: &Capture,
    site: PublicationSite,
) -> Driven<PublicationRun> {
    if owner.observation().snapshot().control != read.control() {
        facts::lost(recorder);
    }
    read.capture(wire::Cut::BeforePublish);
    let mut call = Box::pin(publisher.publish(vec![owner], None, None, recorder));
    let polled = std::future::poll_fn(|cx| match wire::driver::poll_once(recorder, site.0, call.as_mut(), cx) {
        Err(stop) => Poll::Ready(Err(stop)),
        Ok(Poll::Ready(result)) => Poll::Ready(Ok(Poll::Ready(result))),
        Ok(Poll::Pending) if drive == wire::AuthDrive::DropPublicationCommit && read.live_snapshot().publication == crate::services::authentication::publication::Knowledge::CommitCallEntered => Poll::Ready(Ok(Poll::Pending)),
        Ok(Poll::Pending) => Poll::Pending,
    }).await;
    let polled = match polled {
        Ok(actual) => actual,
        Err(stop) => {
            drop(call);
            read.capture(wire::Cut::AfterRunnerDrop);
            read.capture_frame_quiescent(wire::Cut::AfterRunnerDrop);
            return Err(stop);
        }
    };
    read.capture(wire::Cut::AfterPoll);
    read.capture_frame_quiescent(wire::Cut::AfterPoll);
    let (returned, dropped) = match polled {
        Poll::Ready(returned) => (Some(returned), false),
        Poll::Pending => (None, true),
    };
    if dropped
        && (drive != wire::AuthDrive::DropPublicationCommit
            || read.live_snapshot().publication
                != crate::services::authentication::publication::Knowledge::CommitCallEntered)
    {
        facts::lost(recorder);
    }
    drop(call);
    read.capture(wire::Cut::AfterRunnerDrop);
    read.capture_frame_quiescent(wire::Cut::AfterRunnerDrop);
    Ok(Ok(PublicationRun { returned, dropped }))
}

pub(crate) async fn build(
    input: &wire::AuthInput,
    route: Option<RouteHandle>,
    recorder: Capture,
    site: CredentialSite,
) -> Driven<BuiltControl> {
    let mut call = Box::pin(build_inner(input, route, recorder.clone()));
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
async fn build_inner(
    input: &wire::AuthInput,
    route: Option<RouteHandle>,
    recorder: Capture,
) -> Result<BuiltControl> {
    if input.notification_expected {
        facts::lost(&recorder);
        anyhow::bail!("notification effects require reviewed explicit supplied endpoints");
    }
    let transport = match input.frame.transport {
        wire::TransportKind::Tcp => ClientTransport::Tcp,
        wire::TransportKind::Bosh => ClientTransport::Bosh,
    };
    let frame = FrameExecution::for_saved_case(
        transport,
        input.frame.input.as_str(),
        input.frame.frame_id.0,
    );
    let kind = match input.credential_kind {
        wire::CredentialKind::Binding => CredentialKind::Binding,
        wire::CredentialKind::UnboundFast => CredentialKind::UnboundFast,
    };
    let prepared = frame.prepare_credential(kind, input.frame.connection_id.0)?;
    let credential = prepared.observation();
    facts::emit(
        &recorder,
        facts::credential(&credential, wire::Cut::Introduction),
    );
    let repository = repository::Repository {
        input: input.clone(),
        credential: credential.clone(),
        publication: None,
        recorder: recorder.clone(),
    };
    let built = frame
        .run(async {
            let receipt = match &input.control {
                wire::ControlInput::Binding(_) => {
                    let binding = input
                        .binding
                        .get()
                        .ok_or_else(|| anyhow::anyhow!("binding input absent"))?;
                    let route = route.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("bound control requires actual pre-staged route")
                    })?;
                    ensure!(
                        route.connection_id() == input.frame.connection_id.0
                            && route.user_id() == input.user_id.0
                            && route.auth_generation() == input.auth_generation
                            && route.full_jid() == binding.full_jid.as_str(),
                        "staged route differs from original binding invocation"
                    );
                    // Service owns PreparedCredential binding and raw return capture.
                    let result =
                        SmService::new(repository.clone(), "stage4_saved_auth".to_owned())?
                            .finalize_binding_observed(
                                input.frame.connection_id.0,
                                input.user_id.0,
                                input.auth_generation,
                                binding.full_jid.as_str(),
                                binding.lease_seconds,
                                input.device_id.get().map(|v| v.0),
                                None,
                                Some(&prepared),
                            )
                            .await?;
                    let BindingFinalizationOutcome::Committed { receipt } = result else {
                        anyhow::bail!("finite binding reply did not commit")
                    };
                    receipt
                }
                wire::ControlInput::UnboundFast(_) => {
                    ensure!(
                        route.is_none(),
                        "unbound control cannot capture a bound route"
                    );
                    let service = auth_service(repository.clone());
                    let result = service
                        .commit_fast_with_login_epoch_observed(
                            input.user_id.0,
                            input.auth_generation,
                            &FastCommitPlan::default(),
                            None,
                            input.frame.connection_id.0,
                            Some(&prepared),
                        )
                        .await;
                    let AuthenticationResult::Authenticated(receipt) = result else {
                        anyhow::bail!("finite FAST reply did not commit")
                    };
                    receipt
                }
            };
            facts::emit(
                &recorder,
                facts::credential(&credential, wire::Cut::AfterPoll),
            );
            let owner = KnownCredentialOwner::from_observed(
                receipt,
                frame.clone(),
                input.frame.connection_id.0,
                &prepared,
            )?;
            let publication = owner.observation().clone();
            frame.retain_auth_receipt(publication.clone())?;
            let xml = control_xml(&input.control)?;
            let expected = match &input.control {
                wire::ControlInput::Binding(c) => c.xml.as_str(),
                wire::ControlInput::UnboundFast(c) => c.xml.as_str(),
            };
            // Builder output is authoritative. Literal mismatch stops before seal.
            ensure!(
                xml == expected,
                "saved control literal does not match actual builder bytes"
            );
            let effects = if let Some(route) = &route {
                CapturedEffects {
                    route: RouteIntent::Bound(BoundRoute {
                        key: route.full_jid().to_owned(),
                        user: route.user_id(),
                        generation: route.auth_generation(),
                        connection: route.connection_id(),
                        lifecycle: route.lifecycle(),
                        disconnect: route.disconnect(),
                    }),
                    caps: None,
                    notification: None,
                }
            } else {
                CapturedEffects {
                    route: RouteIntent::Unbound,
                    caps: None,
                    notification: None,
                }
            };
            let holder = owner.seal(&xml, effects)?;
            let joins = holder.join_observation();
            facts::observe(&recorder, || {
                facts::holder(&joins, Some(&xml), wire::Cut::Introduction)
            });
            facts::emit(
                &recorder,
                facts::publication(&publication, wire::Cut::Introduction),
            );
            Ok((
                OutboundItem::plain(xml).with_auth_publication(holder)?,
                publication,
                joins,
            ))
        })
        .await
        .map_err(|error| anyhow::anyhow!("credential frame failed: {error:?}"))?;
    let (item, publication, joins) = built;
    let read = AuthRead {
        frame,
        credential,
        publication: publication.clone(),
        joins,
        recorder: recorder.clone(),
    };
    read.capture(wire::Cut::AfterRunnerDrop);
    let mut publication_repository = repository;
    publication_repository.publication = Some(publication);
    Ok(BuiltControl {
        item,
        read,
        port: ControlledPort {
            connection: input.frame.connection_id.0,
            service: auth_service(publication_repository),
            route,
        },
    })
}
fn control_xml(control: &wire::ControlInput) -> Result<String> {
    match control {
        wire::ControlInput::Binding(control) => {
            // Actual shared builders. Inline assembly remains source
            // correspondence with misc::handle_bind, not handler execution.
            let payload = crate::xmpp::xml_builder::XmlElement::namespaced(
                "bind",
                "urn:ietf:params:xml:ns:xmpp-bind",
            )
            .child(
                crate::xmpp::xml_builder::XmlElement::new("jid")
                    .text(control.full_jid.as_str().to_owned()),
            )
            .finish();
            Ok(crate::xmpp::xml_util::iq_result(
                control.iq_id.as_str(),
                &payload,
            ))
        }
        wire::ControlInput::UnboundFast(control) => {
            crate::xmpp::protocol::sasl2::stage4_saved_success_xml(
                control.authorization_identifier.as_str(),
            )
        }
    }
}
fn auth_service(
    repository: repository::Repository,
) -> AuthenticationService<repository::Repository> {
    AuthenticationService::new(
        repository,
        Arc::new(zeroize::Zeroizing::new(vec![0; 32])),
        crate::auth::MIN_SCRAM_ITERATIONS,
        false,
    )
}
struct ControlledPort {
    connection: Uuid,
    service: AuthenticationService<repository::Repository>,
    route: Option<RouteHandle>,
}
impl PublicationPort for ControlledPort {
    fn connection(&self) -> Uuid {
        self.connection
    }
    async fn publish(&mut self, invocation: &Invocation<'_>) -> AuthenticationResult<Option<i64>> {
        self.service
            .publish_credential_commit_observed(invocation)
            .await
    }
    fn epoch_and_mapping(&mut self, captured: &BoundRoute, epoch: Option<i64>) -> bool {
        let Some(route) = &self.route else {
            return false;
        };
        if !same_route(route, captured) {
            return false;
        }
        route.epoch_and_mapping(epoch)
    }
    fn activate(&mut self, captured: &BoundRoute) -> bool {
        let Some(route) = &self.route else {
            return false;
        };
        same_route(route, captured) && route.activate()
    }
    async fn caps(&mut self, intent: Option<CapsIntent>) {
        assert!(
            intent.is_none(),
            "captured CAPS intent must be rejected by finite effect preflight"
        );
    }
    fn notify_local(&mut self, _: &NotificationIntent, _: i64) {
        unreachable!("notification intent must be rejected by finite effect preflight")
    }
    async fn notify_remote(&mut self, _: &NotificationIntent, _: i64) -> Result<()> {
        unreachable!("notification intent must be rejected by finite effect preflight")
    }
    fn rejected(&mut self, _: PublicationResult, _: Option<&anyhow::Error>) {}
    fn notification_deferred(&mut self, _: &anyhow::Error) {}
}
fn same_route(route: &RouteHandle, captured: &BoundRoute) -> bool {
    route.connection_id() == captured.connection
        && route.user_id() == captured.user
        && route.auth_generation() == captured.generation
        && route.full_jid() == captured.key
        && Arc::ptr_eq(&route.lifecycle(), &captured.lifecycle)
}
