//! Factual projections copy observed values, never expected input.
use super::*;
use crate::outbound::TransportOwnershipSource;
use crate::services::authentication::publication as actual;
use wire::EvidenceId as Id;

pub(crate) fn id(value: Uuid) -> Id {
    Id::observed(value)
}
pub(crate) fn nullable<T>(value: Option<T>) -> wire::Nullable<T> {
    value.map_or(wire::Nullable::Null(()), wire::Nullable::Value)
}
/// Observation failures never become service, IO or owner failures. These
/// concrete recorder-lock paths recover only to retain sticky loss; they do
/// not claim poison recovery for production owner/read cells.
pub(crate) fn emit(recorder: &Capture, fact: wire::Fact) {
    wire::driver::emit(recorder, fact);
}
pub(crate) fn lost(recorder: &Capture) {
    wire::driver::lost(recorder);
}
pub(crate) fn project<T>(recorder: &Capture, make: impl FnOnce() -> Result<T>) -> Option<T> {
    wire::driver::project(recorder, make)
}
pub(crate) fn observe(recorder: &Capture, make: impl FnOnce() -> Result<wire::Fact>) {
    wire::driver::emit_projected(recorder, make);
}
pub(crate) fn count(value: usize) -> Result<u32> {
    Ok(u32::try_from(value)?)
}
pub(crate) fn mix(value: crate::outbound::MixDelivery) -> wire::MixSource<Id> {
    wire::MixSource {
        delivery_id: id(value.delivery_id),
        lease_token: id(value.lease_token),
    }
}
pub(crate) fn source(value: TransportOwnershipSource) -> wire::Source<Id> {
    match value {
        TransportOwnershipSource::Mix(value) => wire::Source::Mix(mix(value)),
        TransportOwnershipSource::C2s(value) => wire::Source::C2s(wire::C2sSource {
            recipient_id: id(value.recipient_id),
            message_id: id(value.message_id),
            claim_id: nullable(value.claim_id.map(id)),
        }),
    }
}
macro_rules! same {
    ($from:expr, $a:ident::$t:ident => $b:ident::$u:ident; $($v:ident),+ $(,)?) => { match $from { $($a::$t::$v => $b::$u::$v),+ } };
}
fn kind(value: actual::CredentialKind) -> wire::ObservedCredentialKind {
    same!(value, actual::CredentialKind => wire::ObservedCredentialKind; Binding, UnboundFast, Resume)
}
fn handler(value: actual::HandlerReturn) -> wire::HandlerReturn {
    same!(value, actual::HandlerReturn => wire::HandlerReturn; Completed, Failed, TimedOut, Cancelled, Panicked)
}
fn call(value: actual::CredentialCall) -> wire::CredentialCall {
    same!(value, actual::CredentialCall => wire::CredentialCall; NotEntered, Entered, Ok, Err)
}
fn preparation(value: actual::PreparationResult) -> wire::PreparationResult {
    same!(value, actual::PreparationResult => wire::PreparationResult; NotEntered, Entered, Present, Absent, Err)
}
pub(crate) fn attempt(value: actual::CredentialAttemptJoin) -> wire::CredentialAttemptJoin<Id> {
    wire::CredentialAttemptJoin {
        attempt: id(value.attempt),
        frame: id(value.frame),
        connection: id(value.connection),
        ordinal: value.ordinal,
        kind: kind(value.kind),
    }
}
pub(crate) fn credential(read: &actual::CredentialObservation, cut: wire::Cut) -> wire::Fact {
    let s = read.snapshot();
    let j = read.joins();
    wire::Fact::Credential(wire::CredentialCapture {
        cut,
        snapshot: wire::CredentialSnapshot {
            attempt: id(s.attempt), frame: id(s.frame), connection: id(s.connection), ordinal: s.ordinal, kind: kind(s.kind),
            service_started: s.service_started, repository_started: s.repository_started, begin: call(s.begin),
            eligibility: match s.eligibility {
                actual::Eligibility::NotEntered => wire::Eligibility::NotEntered(wire::Empty {}),
                actual::Eligibility::Entered => wire::Eligibility::Entered(wire::Empty {}),
                actual::Eligibility::Returned(v) => wire::Eligibility::Returned(wire::NullableBool { value: nullable(v) }),
                actual::Eligibility::Err => wire::Eligibility::Err(wire::Empty {}),
            },
            transaction_returned: s.transaction_returned, preparation: s.preparation.map(preparation), stage_id: nullable(s.stage_id.map(id)),
            rollback: nullable(s.rollback.map(|(site, c)| wire::CredentialRollback {
                site: same!(site, actual::CredentialRollbackSite => wire::CredentialRollbackSite; GenerationRefused, FastExpired, BindingReservationLost, BindingStageMissing, BindingFastExpired, ResumeStageMissing, ResumeClaimLost, ResumeFastExpired, ResumePrivacyMissing), call: call(c),
            })),
            commit: call(s.commit), receipt_constructed: s.receipt_constructed,
            returned: nullable(s.returned.map(|v| same!(v, actual::CredentialReturned => wire::CredentialReturned; Authenticated, UnknownCredentials, Disabled, StaleGeneration, ExpiredCredentials, ReplayedCredentials, IntegrityFailure, BackendFailure, BindingCommitted, BindingCredentialsExpired, BindingReservationLost, ResumeCommitted, ResumeCredentialsExpired, ResumeClaimLost, ResumePrivacySelectionMissing, Error))),
            return_matches: s.return_matches, transferred: s.transferred, handler: nullable(s.handler.map(handler)),
            call_terminal: nullable(s.call_terminal.map(|v| same!(v, actual::CredentialTerminal => wire::CredentialTerminal; Returned, Cancelled, Panicked))),
            integrity_failure: s.integrity_failure,
        },
        joins: wire::Nullable::Value(wire::CredentialJoins { owner: attempt(j.owner), constructed_receipt: nullable(j.constructed_receipt.map(id)), returned_receipt: nullable(j.returned_receipt.map(id)), transferred_receipt: nullable(j.transferred_receipt.map(id)) }),
    })
}
pub(crate) fn publication_joins(j: actual::PublicationJoins) -> wire::PublicationJoins<Id> {
    wire::PublicationJoins {
        control: id(j.control),
        frame: nullable(j.frame.map(id)),
        receipt: id(j.receipt),
        credential: nullable(j.credential.map(attempt)),
        begun_receipt: nullable(j.begun_receipt.map(id)),
        bound_effects: j.bound_effects,
        notification_expected: j.notification_expected,
    }
}
pub(crate) fn association(j: ControlAssociation) -> Result<wire::ControlAssociation<Id>> {
    Ok(wire::ControlAssociation {
        control: id(j.control),
        connection: id(j.connection),
        frame: nullable(j.frame.map(id)),
        receipt: id(j.receipt),
        length: count(j.length)?,
        digest: wire::Hex::of(&j.digest)?,
        publication: publication_joins(j.publication),
    })
}
pub(crate) fn control_joins(j: ControlJoins) -> Result<wire::ControlJoins<Id>> {
    Ok(wire::ControlJoins {
        introduced: nullable(j.introduced.map(association).transpose()?),
        transferred: nullable(j.transferred.map(association).transpose()?),
    })
}
pub(crate) fn holder(
    read: &ControlJoinObservation,
    actual_xml: Option<&str>,
    cut: wire::Cut,
) -> Result<wire::Fact> {
    Ok(wire::Fact::Control(wire::ControlFact::Holder(
        wire::ControlCapture {
            cut,
            actual_xml: nullable(actual_xml.map(wire::Text::new).transpose()?),
            holder: wire::Nullable::Value(control_joins(read.snapshot())?),
        },
    )))
}
pub(crate) fn publication(read: &actual::Observation, cut: wire::Cut) -> wire::Fact {
    let s = read.snapshot();
    let effects = s.effects;
    let epoch = |value| wire::EpochValue {
        epoch: nullable(value),
    };
    wire::Fact::Control(wire::ControlFact::LivePublication(wire::LivePublication {
        cut,
        snapshot: wire::PublicationSnapshot {
            control: id(s.control), frame: nullable(s.frame.map(id)), handler: nullable(s.handler.map(handler)), sealed: s.sealed,
            transport: match s.transport {
                actual::Transport::NotStarted => wire::AuthTransport::NotStarted(wire::Empty {}),
                actual::Transport::Recording => wire::AuthTransport::Recording(wire::Empty {}),
                actual::Transport::WriteEntered => wire::AuthTransport::WriteEntered(wire::Empty {}),
                actual::Transport::Written => wire::AuthTransport::Written(wire::Empty {}),
                actual::Transport::BoshExposureEntered { rid } => wire::AuthTransport::BoshExposureEntered(wire::RidValue { rid }),
                actual::Transport::BoshAccepted { rid } => wire::AuthTransport::BoshAccepted(wire::RidValue { rid }),
                actual::Transport::BoshRefused { rid } => wire::AuthTransport::BoshRefused(wire::RidValue { rid }),
            },
            publication: match s.publication {
                actual::Knowledge::NotStarted => wire::PublicationKnowledge::NotStarted(wire::Empty {}),
                actual::Knowledge::NotRequired => wire::PublicationKnowledge::NotRequired(wire::Empty {}),
                actual::Knowledge::BeforeCommit => wire::PublicationKnowledge::BeforeCommit(wire::Empty {}),
                actual::Knowledge::CommitCallEntered => wire::PublicationKnowledge::CommitCallEntered(wire::Empty {}),
                actual::Knowledge::ReceiptKnown(e) => wire::PublicationKnowledge::ReceiptKnown(epoch(e)),
            },
            service_started: s.service_started, repository_started: s.repository_started,
            rollback: same!(s.rollback, actual::Rollback => wire::PublicationRollback; NotRequested, CallEntered, Returned, Failed),
            returned: nullable(s.returned.map(|r| match r {
                actual::Returned::Authenticated(e) => wire::PublicationReturned::Authenticated(epoch(e)),
                actual::Returned::UnknownCredentials => wire::PublicationReturned::UnknownCredentials(wire::Empty {}),
                actual::Returned::Disabled => wire::PublicationReturned::Disabled(wire::Empty {}),
                actual::Returned::StaleGeneration => wire::PublicationReturned::StaleGeneration(wire::Empty {}),
                actual::Returned::ExpiredCredentials => wire::PublicationReturned::ExpiredCredentials(wire::Empty {}),
                actual::Returned::ReplayedCredentials => wire::PublicationReturned::ReplayedCredentials(wire::Empty {}),
                actual::Returned::IntegrityFailure => wire::PublicationReturned::IntegrityFailure(wire::Empty {}),
                actual::Returned::BackendFailure => wire::PublicationReturned::BackendFailure(wire::Empty {}),
            })),
            return_matches: s.return_matches,
            effects: wire::PublicationEffects { unbound: effects.unbound, epoch_applied: effects.epoch_applied, route_mapping: nullable(effects.route_mapping), route_activation: nullable(effects.route_activation), caps_entered: effects.caps_entered, caps_returned: effects.caps_returned, notification_entered: effects.notification_entered, notification_returned: nullable(effects.notification_returned) },
            terminal: nullable(s.terminal.map(|v| same!(v, actual::Terminal => wire::PublicationTerminal; Completed, DeferredNotification, Failed, Cancelled, Panicked, Abandoned, ExposedNotAttempted))),
        },
        joins: wire::Nullable::Value(publication_joins(read.joins())),
    }))
}
pub(crate) fn queue_item(
    item: &crate::outbound::OutboundItem,
    connection: Uuid,
    ordinal: u8,
) -> Result<wire::QueueItem<Id>> {
    let control = item
        .auth_publication()
        .and_then(|h| h.join_observation().snapshot().introduced)
        .map(|a| id(a.control));
    Ok(wire::QueueItem {
        item_ordinal: ordinal,
        connection_id: id(connection),
        source: nullable(item.durable_source.map(source)),
        stanza: wire::Text::new(item.stanza.clone())?,
        auth_control: nullable(control),
    })
}
