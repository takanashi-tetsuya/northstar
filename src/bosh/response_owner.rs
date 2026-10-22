//! Actual response selection, binding and cache continuations over the actor's
//! existing fields. The selected auth control gates the actor's existing
//! publication callback after accepted exposure and before cache bookkeeping.
#[cfg(test)]
pub(crate) mod stage4_saved;

use super::{
    bosh_body_element, bosh_response_bytes, bosh_unacknowledged_limit_exceeded,
    restore_response_items, restore_response_items_observed, superseded_bosh_message_id,
    take_response_payload, terminal_response_with_content, BoshHttpResponse, BoshRequest,
    BoshResponseBody, CachedResponse, RESPONSE_CACHE_SIZE,
};
use crate::xmpp::auth_publication::{OwnedPublication, SelectedControls};
use crate::{
    services::{
        replay::{ReplayRepository, ReplayService},
        sm_capacity::SmMemoryGovernor,
    },
    xmpp::outbound::{BoshResponseOwnership, OutboundItem},
};
use anyhow::Result;
use axum::body::Bytes;
use northstar_delivery_core::bosh_ownership::{
    response::{self, AckRequest, BindRequest, RenewRequest, ResponseBuild, ResponseKind},
    Operation,
};
use std::{collections::VecDeque, future::Future, sync::Arc, time::Instant};
use tokio::sync::{mpsc, oneshot};
type Responder = oneshot::Sender<BoshHttpResponse>;

pub(super) trait ReplayPort {
    fn bind(
        &self,
        request: &BindRequest,
    ) -> impl Future<Output = Result<BoshResponseOwnership>> + Send;
    fn renew(&self, request: &RenewRequest) -> impl Future<Output = Result<()>> + Send;
    fn acknowledge(&self, request: &AckRequest) -> impl Future<Output = Result<()>> + Send;
    fn release(&self, session_id: uuid::Uuid) -> impl Future<Output = Result<()>> + Send;
}
pub(super) struct ServiceReplay<'a, R> {
    pub(super) service: &'a ReplayService<R>,
}
impl<R: ReplayRepository> ReplayPort for ServiceReplay<'_, R> {
    async fn bind(&self, request: &BindRequest) -> Result<BoshResponseOwnership> {
        self.service.bind_bosh_response_sources(request).await
    }
    async fn renew(&self, request: &RenewRequest) -> Result<()> {
        self.service.renew_bosh_fences(request).await
    }
    async fn acknowledge(&self, request: &AckRequest) -> Result<()> {
        self.service.acknowledge_bosh_responses(request).await
    }
    async fn release(&self, session_id: uuid::Uuid) -> Result<()> {
        self.service.release_bosh_fences(session_id).await
    }
}
pub(super) struct Fields<'a> {
    pub(super) output: &'a mut VecDeque<OutboundItem>,
    pub(super) output_bytes: &'a mut usize,
    pub(super) replay: &'a mut VecDeque<CachedResponse>,
    pub(super) governor: &'a Arc<SmMemoryGovernor>,
    pub(super) max_response_bytes: usize,
    pub(super) max_output_stanzas: usize,
    pub(super) content_type: &'a str,
    pub(super) received_rid: Option<u64>,
}
#[derive(Clone, Copy)]
pub(super) struct Metadata {
    pub(super) rid: u64,
    pub(super) fingerprint: [u8; 32],
    pub(super) cache: bool,
}
impl Fields<'_> {
    fn body(
        &mut self,
        condition: Option<&str>,
        terminate: bool,
        build: &ResponseBuild,
    ) -> Result<BoshResponseBody> {
        let (payload, sources, receipts, capacity, selected) = take_response_payload(
            self.output,
            self.output_bytes,
            self.max_response_bytes,
            self.governor,
        )?;
        let body = bosh_body_element(condition, terminate, self.received_rid);
        let body = match body.validated_fragment(&payload) {
            Ok(body) => body.finish(),
            Err(error) => {
                let count = selected.len();
                restore_response_items(self.output, self.output_bytes, selected, None);
                build.construction_restored(count);
                anyhow::bail!("malformed protocol output at BOSH boundary: {error}");
            }
        };
        Ok((
            BoshHttpResponse {
                body: bosh_response_bytes(body, capacity),
                content_type: self.content_type.to_owned(),
            },
            sources,
            receipts,
            selected,
        ))
    }
}
#[derive(Clone, Copy)]
pub(super) enum FailureStage {
    Construction,
    Limit,
    Binding,
}
pub(super) struct PreparationFailure {
    pub(super) stage: FailureStage,
    pub(super) condition: &'static str,
    pub(super) error: anyhow::Error,
    control: Option<response::ControlObservation>,
}
impl std::fmt::Debug for PreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoshResponsePreparationFailure")
            .field("condition", &self.condition)
            .finish_non_exhaustive()
    }
}
impl PreparationFailure {
    fn new(
        stage: FailureStage,
        condition: &'static str,
        error: anyhow::Error,
        build: Option<&ResponseBuild>,
    ) -> Self {
        Self {
            stage,
            condition,
            error,
            control: build.map(ResponseBuild::terminal_control),
        }
    }
    pub(super) fn send(self, responders: Vec<Responder>, content_type: &str) {
        let response = terminal_response_with_content(self.condition, content_type);
        for responder in responders {
            send_one(
                response.clone(),
                responder,
                || {
                    if let Some(control) = &self.control {
                        control.sending();
                    }
                },
                |accepted| {
                    if let Some(control) = &self.control {
                        control.sent(accepted);
                    }
                },
            );
        }
    }
}
// The closed Stage 4 profile needs at most four selected items per response.
// This is a test-observation bound, never a limit on production selection.
#[cfg(test)]
const MAX_SELECTED_FACTS: usize = 4;
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SelectionReadStatus {
    Complete,
    Incomplete {
        omitted_items: usize,
        missing_auth_associations: usize,
        connection_changed: bool,
    },
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SelectedItemSnapshot {
    // Ordinal in the actual final selection, not an inferred input queue index.
    pub(super) ordinal: usize,
    pub(super) source: Option<crate::xmpp::outbound::TransportOwnershipSource>,
    pub(super) utf8_length: usize,
    pub(super) sha256: [u8; 32],
    pub(super) auth_marker: bool,
    pub(super) sealed_association: Option<crate::xmpp::auth_publication::ControlAssociation>,
    pub(super) holder_joins: Option<crate::xmpp::auth_publication::ControlJoins>,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SelectionSnapshot {
    pub(super) session: uuid::Uuid,
    pub(super) rid: u64,
    pub(super) fingerprint: [u8; 32],
    pub(super) first_validated_connection: Option<uuid::Uuid>,
    pub(super) validated_connection: Option<uuid::Uuid>,
    pub(super) selected_count: usize,
    pub(super) status: SelectionReadStatus,
    pub(super) items: [Option<SelectedItemSnapshot>; MAX_SELECTED_FACTS],
}
#[cfg(test)]
struct SelectedItemRead {
    at_selection: SelectedItemSnapshot,
    joins: Option<crate::xmpp::auth_publication::ControlJoinObservation>,
}
#[cfg(test)]
struct SelectionState {
    session: uuid::Uuid,
    rid: u64,
    fingerprint: [u8; 32],
    first_validated_connection: Option<uuid::Uuid>,
    validated_connection: Option<uuid::Uuid>,
    selected_count: usize,
    status: SelectionReadStatus,
    items: [Option<SelectedItemRead>; MAX_SELECTED_FACTS],
}
// Retains only bounded facts and the existing read-only join cells. No holder,
// receipt, response bytes, publication Observation or consuming continuation is
// retained or exposed. Keeping this handle cannot delay holder abandonment.
#[cfg(test)]
#[derive(Clone)]
pub(super) struct SelectionObservation(Arc<std::sync::Mutex<SelectionState>>);
#[cfg(test)]
impl SelectionObservation {
    fn capture(
        selected: &VecDeque<OutboundItem>,
        operation: &Operation,
        metadata: Metadata,
    ) -> Self {
        use sha2::{Digest, Sha256};
        let mut missing_auth_associations = 0;
        let items: [Option<SelectedItemRead>; MAX_SELECTED_FACTS] =
            std::array::from_fn(|ordinal| {
                selected.get(ordinal).map(|item| {
                    let joins = item
                        .auth_publication()
                        .map(|holder| holder.join_observation());
                    let holder_joins = joins.as_ref().map(|joins| joins.snapshot());
                    let association = holder_joins.and_then(|joins| joins.introduced);
                    let auth_marker = item.is_bosh_auth_control();
                    if auth_marker && association.is_none() {
                        missing_auth_associations += 1;
                    }
                    SelectedItemRead {
                        at_selection: SelectedItemSnapshot {
                            ordinal,
                            source: item.durable_source,
                            utf8_length: item.stanza.len(),
                            sha256: Sha256::digest(item.stanza.as_bytes()).into(),
                            auth_marker,
                            sealed_association: association,
                            holder_joins,
                        },
                        joins,
                    }
                })
            });
        let omitted_items = selected.len().saturating_sub(MAX_SELECTED_FACTS);
        let status = if omitted_items == 0 && missing_auth_associations == 0 {
            SelectionReadStatus::Complete
        } else {
            SelectionReadStatus::Incomplete {
                omitted_items,
                missing_auth_associations,
                connection_changed: false,
            }
        };
        Self(Arc::new(std::sync::Mutex::new(SelectionState {
            session: operation.session_id(),
            rid: metadata.rid,
            fingerprint: metadata.fingerprint,
            first_validated_connection: None,
            validated_connection: None,
            selected_count: selected.len(),
            status,
            items,
        })))
    }
    pub(super) fn snapshot(&self) -> SelectionSnapshot {
        let state = self.0.lock().unwrap();
        SelectionSnapshot {
            session: state.session,
            rid: state.rid,
            fingerprint: state.fingerprint,
            first_validated_connection: state.first_validated_connection,
            validated_connection: state.validated_connection,
            selected_count: state.selected_count,
            status: state.status,
            items: std::array::from_fn(|ordinal| {
                state.items[ordinal].as_ref().map(|item| {
                    let mut snapshot = item.at_selection;
                    snapshot.holder_joins = item.joins.as_ref().map(|joins| joins.snapshot());
                    snapshot
                })
            }),
        }
    }
}

/// Only this owning continuation may expose the selected response bytes.
pub(super) struct BoundResponse {
    metadata: Metadata,
    response: BoshHttpResponse,
    receipts: Vec<mpsc::UnboundedSender<()>>,
    ownership: Arc<BoshResponseOwnership>,
    bound: response::BoundResponse,
    auth_control_selected: bool,
    auth_controls: SelectedControls,
    auth_connection: Option<uuid::Uuid>,
    #[cfg(test)]
    selection: SelectionObservation,
}
impl std::fmt::Debug for BoundResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoundBoshResponse { body and binding: [redacted] }")
    }
}
pub(super) struct ExposedResponse {
    metadata: Metadata,
    response: BoshHttpResponse,
    receipts: Vec<mpsc::UnboundedSender<()>>,
    ownership: Arc<BoshResponseOwnership>,
    exposure: response::Exposure,
    accepted: bool,
    auth_control_selected: bool,
    auth_controls: SelectedControls,
}
/// A consuming local continuation, not proof of SQL credential publication.
/// Only successful publication (or no selected auth control) creates it.
pub(super) struct PublicationReadyResponse {
    exposed: ExposedResponse,
}
impl BoundResponse {
    /// Retain before expose/publish; later snapshots do not need the callback.
    #[cfg(test)]
    pub(super) fn selection_observation(&self) -> SelectionObservation {
        self.selection.clone()
    }
    pub(super) fn for_connection(mut self, connection: uuid::Uuid) -> Result<Self> {
        self.auth_controls.validate_connection(connection)?;
        self.auth_connection = Some(connection);
        #[cfg(test)]
        {
            let mut selection = self.selection.0.lock().unwrap();
            if let Some(previous) = selection.validated_connection {
                if previous != connection {
                    let (omitted_items, missing_auth_associations) = match selection.status {
                        SelectionReadStatus::Complete => (0, 0),
                        SelectionReadStatus::Incomplete {
                            omitted_items,
                            missing_auth_associations,
                            ..
                        } => (omitted_items, missing_auth_associations),
                    };
                    selection.status = SelectionReadStatus::Incomplete {
                        omitted_items,
                        missing_auth_associations,
                        connection_changed: true,
                    };
                }
            } else {
                selection.first_validated_connection = Some(connection);
            }
            selection.validated_connection = Some(connection);
        }
        Ok(self)
    }
    pub(super) fn expose(mut self, responders: Vec<Responder>) -> Result<ExposedResponse> {
        anyhow::ensure!(
            self.auth_controls.is_empty() || self.auth_connection.is_some(),
            "auth response has no bound connection"
        );
        if let Some(connection) = self.auth_connection {
            self.auth_controls.validate_connection(connection)?;
        }
        self.auth_controls.begin_exposure(self.metadata.rid)?;
        let exposure = self.bound.begin_exposure()?;
        let mut accepted = false;
        for responder in responders {
            accepted |= send_one(
                self.response.clone(),
                responder,
                || exposure.sending(),
                |accepted| exposure.sent(accepted),
            );
        }
        self.auth_controls.exposure(self.metadata.rid, accepted)?;
        Ok(ExposedResponse {
            metadata: self.metadata,
            response: self.response,
            receipts: self.receipts,
            ownership: self.ownership,
            exposure,
            accepted,
            auth_control_selected: self.auth_control_selected,
            auth_controls: self.auth_controls,
        })
    }
}
impl ExposedResponse {
    #[cfg(test)]
    pub(super) fn any_accepted(&self) -> bool {
        self.accepted
    }
    pub(super) async fn publish_authentication<F: Future<Output = bool>>(
        mut self,
        publish: impl FnOnce(Vec<OwnedPublication>) -> F,
    ) -> Result<PublicationReadyResponse> {
        if self.auth_control_selected {
            anyhow::ensure!(self.accepted, "BOSH authentication control was not exposed");
            let selected = std::mem::replace(&mut self.auth_controls, SelectedControls::empty());
            let observations = selected.observations();
            let owners = selected.take_all()?;
            anyhow::ensure!(
                publish(owners).await,
                "BOSH authentication publication failed"
            );
            anyhow::ensure!(
                observations
                    .iter()
                    .all(|observation| observation.completed()),
                "BOSH auth callback did not complete its selected owners"
            );
        }
        Ok(PublicationReadyResponse { exposed: self })
    }

    /// Plain-response compatibility for the existing controlled delivery lane.
    /// A selected auth control cannot bypass the production publication gate.
    #[cfg(test)]
    pub(super) fn finish(
        self,
        last_response: &mut Instant,
        highest_responded: &mut u64,
        replay: &mut VecDeque<CachedResponse>,
    ) -> Result<()> {
        anyhow::ensure!(
            !self.auth_control_selected,
            "selected BOSH authentication control requires publication"
        );
        PublicationReadyResponse { exposed: self }.finish(last_response, highest_responded, replay)
    }
}
impl PublicationReadyResponse {
    pub(super) fn finish(
        self,
        last_response: &mut Instant,
        highest_responded: &mut u64,
        replay: &mut VecDeque<CachedResponse>,
    ) -> Result<()> {
        let ExposedResponse {
            metadata,
            response,
            receipts,
            ownership,
            exposure,
            ..
        } = self.exposed;
        let bookkeeping = exposure.begin_bookkeeping()?;
        update_response_position(last_response, highest_responded, metadata.rid);
        bookkeeping.updated();
        if metadata.cache {
            let response_bytes = response.body.len();
            replay.push_back(CachedResponse {
                rid: metadata.rid,
                fingerprint: metadata.fingerprint,
                response,
                durable_ownership: ownership,
                transport_receipts: receipts,
                owned_at: Instant::now(),
                response_bytes,
                replays: 0,
            });
            bookkeeping.cached();
        }
        Ok(())
    }
}
pub(super) async fn prepare<P: ReplayPort>(
    fields: &mut Fields<'_>,
    metadata: Metadata,
    condition: Option<&str>,
    operation: &Operation,
    port: &P,
) -> Result<BoundResponse, PreparationFailure> {
    let selects_output = condition.is_none() || condition == Some("remote-stream-error");
    let lineage = if selects_output {
        fields
            .output
            .iter()
            .map(|item| item.durable_source)
            .collect()
    } else {
        vec![]
    };
    let build = operation
        .begin_response(
            metadata.rid,
            if selects_output {
                ResponseKind::Payload
            } else {
                ResponseKind::TerminalControl
            },
            lineage,
        )
        .map_err(|error| {
            PreparationFailure::new(
                FailureStage::Construction,
                "internal-server-error",
                error.into(),
                None,
            )
        })?;
    let mut superseded_rebuilds = 0;
    loop {
        let built = if condition == Some("remote-stream-error") {
            fields.body(condition, true, &build)
        } else if condition == Some("terminate") {
            Ok((
                BoshHttpResponse {
                    body: Bytes::from(bosh_body_element(None, true, None).finish()),
                    content_type: fields.content_type.to_owned(),
                },
                vec![],
                vec![],
                VecDeque::new(),
            ))
        } else if let Some(condition) = condition {
            Ok((
                terminal_response_with_content(condition, fields.content_type),
                vec![],
                vec![],
                VecDeque::new(),
            ))
        } else {
            fields.body(None, false, &build)
        };
        let (response, sources, receipts, selected) = built.map_err(|error| {
            PreparationFailure::new(
                FailureStage::Construction,
                "internal-server-error",
                error,
                Some(&build),
            )
        })?;
        if metadata.cache {
            while fields.replay.len() >= RESPONSE_CACHE_SIZE
                && fields.replay.front().is_some_and(|cached| {
                    cached.durable_ownership.is_empty() && cached.transport_receipts.is_empty()
                })
            {
                fields.replay.pop_front();
                build.empty_cache_evicted();
            }
            if bosh_unacknowledged_limit_exceeded(
                fields.replay,
                response.body.len(),
                Instant::now(),
            ) {
                // Preserve the existing unobserved release await before the
                // terminal response; a returned unit is not a release receipt.
                let _ = port.release(operation.session_id()).await;
                return Err(PreparationFailure::new(
                    FailureStage::Limit,
                    "policy-violation",
                    anyhow::anyhow!("BOSH unacknowledged response limit exceeded"),
                    Some(&build),
                ));
            }
        }
        let request = build
            .attempt(sources, selected.iter().map(|item| item.durable_source))
            .map_err(|error| {
                PreparationFailure::new(
                    FailureStage::Binding,
                    "internal-server-error",
                    error.into(),
                    Some(&build),
                )
            })?;
        let result = if request.sources().is_empty() {
            Ok(BoshResponseOwnership::default())
        } else {
            port.bind(&request).await
        };
        match result {
            Ok(ownership) => {
                let bound = request.returned(ownership).map_err(|error| {
                    PreparationFailure::new(
                        FailureStage::Binding,
                        "internal-server-error",
                        error.into(),
                        Some(&build),
                    )
                })?;
                let ownership = bound.ownership().clone();
                if selected
                    .iter()
                    .any(|item| item.is_bosh_auth_control() != item.auth_publication().is_some())
                {
                    return Err(PreparationFailure::new(
                        FailureStage::Construction,
                        "internal-server-error",
                        anyhow::anyhow!("auth control marker and holder disagree"),
                        Some(&build),
                    ));
                }
                let auth_controls = SelectedControls::new(
                    selected
                        .iter()
                        .map(|item| (item.stanza.as_str(), item.auth_publication())),
                )
                .map_err(|error| {
                    PreparationFailure::new(
                        FailureStage::Construction,
                        "internal-server-error",
                        error,
                        Some(&build),
                    )
                })?;
                let auth_control_selected = !auth_controls.is_empty();
                #[cfg(test)]
                let selection = SelectionObservation::capture(&selected, operation, metadata);
                return Ok(BoundResponse {
                    metadata,
                    response,
                    receipts,
                    ownership,
                    bound,
                    auth_control_selected,
                    auth_controls,
                    auth_connection: None,
                    #[cfg(test)]
                    selection,
                });
            }
            Err(error) => {
                if let Some(message_id) = superseded_bosh_message_id(&error) {
                    if let Ok(restoration) = request.supersession(message_id) {
                        // Retain capacity proportional to actual removals, not
                        // every selected peer on each successive rebuild.
                        let mut removed_indices = Vec::new();
                        let removed = restore_response_items_observed(
                            fields.output,
                            fields.output_bytes,
                            selected,
                            Some(message_id),
                            |offset| removed_indices.push(restoration.selected_indices()[offset]),
                        );
                        restoration.restored(removed_indices).map_err(|error| {
                            PreparationFailure::new(
                                FailureStage::Binding,
                                "internal-server-error",
                                error.into(),
                                Some(&build),
                            )
                        })?;
                        if removed && superseded_rebuilds < fields.max_output_stanzas {
                            superseded_rebuilds += 1;
                            tracing::debug!(target: "rust_xmpp_server::bosh", %message_id, rid = metadata.rid, "superseded durable BOSH item removed before response exposure");
                            continue;
                        }
                    }
                }
                return Err(PreparationFailure::new(
                    FailureStage::Binding,
                    "internal-server-error",
                    error,
                    Some(&build),
                ));
            }
        }
    }
}

// Raw exposure stays private. Durable payloads enter through BoundResponse;
// the pause wrapper below constructs only its fixed empty control response.
fn send_one(
    response: BoshHttpResponse,
    responder: Responder,
    entering: impl FnOnce(),
    returned: impl FnOnce(bool),
) -> bool {
    entering();
    let accepted = responder.send(response).is_ok();
    returned(accepted);
    accepted
}
fn update_response_position(last_response: &mut Instant, highest_responded: &mut u64, rid: u64) {
    *last_response = Instant::now();
    *highest_responded = (*highest_responded).max(rid);
}
pub(super) fn finish_empty_control(
    rid: u64,
    responders: Vec<Responder>,
    content_type: &str,
    last_response: &mut Instant,
    highest_responded: &mut u64,
    operation: &Operation,
) {
    let control = operation.observe_empty_control(rid);
    let response = BoshHttpResponse {
        body: Bytes::from(bosh_body_element(None, false, None).finish()),
        content_type: content_type.to_owned(),
    };
    for responder in responders {
        send_one(
            response.clone(),
            responder,
            || control.sending(),
            |accepted| control.sent(accepted),
        );
    }
    update_response_position(last_response, highest_responded, rid);
    control.updated();
}

pub(super) enum ReplayOutcome {
    Miss(Responder),
    Sent {
        terminate: bool,
    },
    Failed {
        responder: Responder,
        error: anyhow::Error,
    },
}
pub(super) async fn replay_cached<P: ReplayPort>(
    replay: &mut VecDeque<CachedResponse>,
    request: &BoshRequest,
    responder: Responder,
    last_response: &mut Instant,
    operation: &Operation,
    port: &P,
) -> ReplayOutcome {
    let Some((reply, terminate, ownership)) = super::replay_response(replay, request) else {
        return ReplayOutcome::Miss(responder);
    };
    if terminate {
        // The existing selector constructs the terminal control; no cached
        // payload or durable bind continuation enters this branch.
        let control = operation.observe_terminal_control(request.rid);
        send_one(
            reply,
            responder,
            || control.sending(),
            |accepted| control.sent(accepted),
        );
        return ReplayOutcome::Sent { terminate: true };
    }
    let renewal = match operation.begin_renew(Some((request.rid, ownership))) {
        Ok(renewal) => renewal,
        Err(error) => {
            return ReplayOutcome::Failed {
                responder,
                error: error.into(),
            }
        }
    };
    if let Err(error) = port.renew(&renewal).await {
        return ReplayOutcome::Failed { responder, error };
    }
    let exposure = match renewal
        .returned()
        .and_then(|renewed| renewed.begin_replay())
    {
        Ok(exposure) => exposure,
        Err(error) => {
            return ReplayOutcome::Failed {
                responder,
                error: error.into(),
            }
        }
    };
    send_one(
        reply,
        responder,
        || exposure.sending(),
        |accepted| exposure.sent(accepted),
    );
    *last_response = Instant::now();
    exposure.updated();
    ReplayOutcome::Sent { terminate: false }
}
pub(super) async fn renew_and_acknowledge<P: ReplayPort>(
    replay: &mut VecDeque<CachedResponse>,
    ack: Option<u64>,
    operation: &Operation,
    port: &P,
) -> Result<()> {
    // Preserve renewal even for None or empty cache/source membership.
    let request = operation.begin_renew(None)?;
    port.renew(&request).await?;
    let renewed = request.returned()?;
    if let Some(rid) = ack {
        let request = renewed.begin_ack(rid)?;
        port.acknowledge(&request).await?;
        let acknowledged = request.returned()?;
        while replay
            .front()
            .is_some_and(|cached| cached.rid <= acknowledged.rid())
        {
            if let Some(cached) = replay.pop_front() {
                acknowledged.evicted();
                for receipt in cached.transport_receipts {
                    acknowledged.sending_receipt();
                    let accepted = receipt.send(()).is_ok();
                    acknowledged.receipt_sent(accepted);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
