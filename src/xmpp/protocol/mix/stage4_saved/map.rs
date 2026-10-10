//! Factual, fallible copies. No expected-result fallback and no owner minting.
use crate::services::mix::outbox::core as c;
use crate::stage4_replay as w;
use anyhow::Result;
use northstar_room_application::mix as f;
use northstar_room_core::mix as m;
use std::sync::atomic::Ordering;
use uuid::Uuid;
pub(super) fn id(v: Uuid) -> w::EvidenceId {
    w::EvidenceId::observed(v)
}
pub(super) fn optional<T>(v: Option<T>) -> w::Nullable<T> {
    v.map_or(w::Nullable::Null(()), w::Nullable::Value)
}
fn one(v: Uuid) -> w::OneId<w::EvidenceId> {
    w::OneId { id: id(v) }
}
macro_rules! scalar {
    ($function:ident, $from:path, $to:path, $($v:ident),+ $(,)?) => {
        pub(super) fn $function(value: $from) -> $to { use $from as A; use $to as B; match value { $(A::$v => B::$v),+ } }
    };
}
scalar!(
    terminal,
    c::TerminalReason,
    w::OwnerTerminal,
    Completed,
    BackendFailure,
    Cancelled,
    TimedOut,
    Panicked
);
scalar!(
    fg_terminal,
    f::TerminalReason,
    w::OwnerTerminal,
    Completed,
    BackendFailure,
    Cancelled,
    TimedOut,
    Panicked
);
scalar!(
    phase,
    c::RoutePhase,
    w::RoutePhase,
    Unprepared,
    Prepared,
    Started,
    Returned
);
scalar!(
    route_result,
    c::RouteResult,
    w::RouteResult,
    CompletedByWorker,
    Transferred,
    Pending,
    Permanent,
    Retry,
    Cancelled
);
scalar!(
    retry,
    c::RetryResult,
    w::RetryResult,
    LeaseLost,
    Retried,
    RouteWokenAtAttemptLimit,
    DeadLettered
);
scalar!(wake, f::Wake, w::Wake, Unavailable, Ready, Invoked);
pub(super) fn source(v: crate::outbound::MixDelivery) -> w::MixSource<w::EvidenceId> {
    w::MixSource {
        delivery_id: id(v.delivery_id),
        lease_token: id(v.lease_token),
    }
}
pub(super) fn row(v: &c::Row) -> Result<w::DeliveryRow<w::EvidenceId>> {
    Ok(w::DeliveryRow {
        source: source(v.source),
        event_id: id(v.event_id),
        channel_id: id(v.channel_id),
        channel_jid: w::Text::new(&v.channel_jid)?,
        participant_id: id(v.participant_id),
        recipient_jid: w::Text::new(&v.recipient_jid)?,
        recipient_nick: optional(v.recipient_nick.as_ref().map(w::Text::new).transpose()?),
        stanza: w::Text::new(&v.stanza)?,
        authoritative_stanza_id: optional(v.authoritative_stanza_id.map(id)),
        archive: v.archive,
        encrypted: v.encrypted,
        attempt_count: v.attempt_count,
        route_wake_generation: v.route_wake_generation,
    })
}
fn rows(v: &c::Rows) -> Result<w::Rows<w::EvidenceId>> {
    Ok(w::Rows {
        rows: w::List::new(v.iter().map(|r| row(r)).collect::<Result<Vec<_>>>()?)?,
    })
}
pub(super) fn claim(v: &c::ClaimSnapshot) -> Result<w::ClaimSnapshot<w::EvidenceId>> {
    Ok(w::ClaimSnapshot {
        issued: v.issued,
        started: v.started,
        knowledge: match &v.knowledge {
            c::ClaimKnowledge::NoStatementEntered => {
                w::ClaimKnowledge::NoStatementEntered(w::Empty {})
            }
            c::ClaimKnowledge::ReadEmpty => w::ClaimKnowledge::ReadEmpty(w::Empty {}),
            c::ClaimKnowledge::AutocommitStatementEntered => {
                w::ClaimKnowledge::AutocommitStatementEntered(w::Empty {})
            }
            c::ClaimKnowledge::StatementReceipt(v) => w::ClaimKnowledge::StatementReceipt(rows(v)?),
        },
        returned: optional(
            v.returned
                .as_ref()
                .map(|r| -> Result<_> {
                    Ok(match r {
                        c::ClaimReturned::Accepted(n) => {
                            w::ClaimReturned::Accepted(w::CountValue {
                                count: u32::try_from(*n)?,
                            })
                        }
                        c::ClaimReturned::Rejected(r) => w::ClaimReturned::Rejected(rows(r)?),
                        c::ClaimReturned::Error => w::ClaimReturned::Error(w::Empty {}),
                    })
                })
                .transpose()?,
        ),
        terminal: optional(v.terminal.map(terminal)),
    })
}
fn archive_result(v: c::ArchiveResult) -> w::ArchiveResult<w::EvidenceId> {
    match v {
        c::ArchiveResult::Stored(v) => w::ArchiveResult::Stored(one(v)),
        c::ArchiveResult::Replay(v) => w::ArchiveResult::Replay(one(v)),
    }
}
pub(super) fn archive_returned(v: c::ArchiveReturned) -> w::ArchiveReturned<w::EvidenceId> {
    match v {
        c::ArchiveReturned::Outcome(v) => w::ArchiveReturned::Outcome(archive_result(v)),
        c::ArchiveReturned::Error => w::ArchiveReturned::Error(w::Empty {}),
    }
}
pub(super) fn archive_command(v: &c::ArchiveCommand) -> Result<w::ArchiveCommand<w::EvidenceId>> {
    Ok(w::ArchiveCommand {
        personal_archive_id: id(v.personal_archive_id),
        owner_id: id(v.owner_id),
        channel_jid: w::Text::new(&v.channel_jid)?,
        authoritative_stanza_id: id(v.authoritative_stanza_id),
        stanza: w::Text::new(v.stanza.as_ref())?,
        encrypted: v.encrypted,
        client_stanza_id: optional(v.client_stanza_id.as_ref().map(w::Text::new).transpose()?),
    })
}
pub(super) fn boundary(v: c::TransferBoundary) -> w::TransferBoundary<w::EvidenceId> {
    match v {
        c::TransferBoundary::SocketFenced(v) => w::TransferBoundary::SocketFenced(one(v)),
        c::TransferBoundary::SmPersisted(v) => w::TransferBoundary::SmPersisted(one(v)),
        c::TransferBoundary::BoshPersisted(v) => w::TransferBoundary::BoshPersisted(one(v)),
        c::TransferBoundary::ClusterSocketFenced => {
            w::TransferBoundary::ClusterSocketFenced(w::Empty {})
        }
        c::TransferBoundary::ClusterSmPersisted => {
            w::TransferBoundary::ClusterSmPersisted(w::Empty {})
        }
        c::TransferBoundary::ClusterBoshPersisted => {
            w::TransferBoundary::ClusterBoshPersisted(w::Empty {})
        }
    }
}
fn local(v: c::LocalResult) -> w::LocalResult<w::EvidenceId> {
    match v {
        c::LocalResult::QueueFull => w::LocalResult::QueueFull(w::Empty {}),
        c::LocalResult::QueueClosed => w::LocalResult::QueueClosed(w::Empty {}),
        c::LocalResult::HandoffClosed => w::LocalResult::HandoffClosed(w::Empty {}),
        c::LocalResult::Transferred(v) => w::LocalResult::Transferred(boundary(v)),
    }
}
scalar!(
    settlement_kind,
    c::SettlementKind,
    w::SettlementKind,
    Ack,
    Defer,
    Retry,
    DeadLetter
);
fn settlement_result(v: c::SettlementResult) -> w::SettlementResult {
    match v {
        c::SettlementResult::Ack(value) => w::SettlementResult::Ack(w::BoolValue { value }),
        c::SettlementResult::Defer(value) => w::SettlementResult::Defer(w::BoolValue { value }),
        c::SettlementResult::DeadLetter(value) => {
            w::SettlementResult::DeadLetter(w::BoolValue { value })
        }
        c::SettlementResult::Retry(value) => w::SettlementResult::Retry(w::RetryValue {
            value: retry(value),
        }),
    }
}
pub(super) fn settlement_returned(v: c::SettlementReturned) -> w::SettlementReturned {
    match v {
        c::SettlementReturned::Outcome(v) => w::SettlementReturned::Outcome(settlement_result(v)),
        c::SettlementReturned::Error => w::SettlementReturned::Error(w::Empty {}),
    }
}
pub(super) fn settlement_command(v: &c::SettlementCommand) -> Result<w::SettlementCommand> {
    Ok(match v {
        c::SettlementCommand::Ack => w::SettlementCommand::Ack(w::Empty {}),
        c::SettlementCommand::Defer { delay_seconds } => {
            w::SettlementCommand::Defer(w::DeferCommand {
                delay_seconds: *delay_seconds,
            })
        }
        c::SettlementCommand::Retry { error } => w::SettlementCommand::Retry(w::RetryCommand {
            error: w::Text::new(error)?,
        }),
        c::SettlementCommand::DeadLetter { reason, error } => {
            w::SettlementCommand::DeadLetter(w::DeadLetterCommand {
                reason: w::Text::new(reason)?,
                error: w::Text::new(error)?,
            })
        }
    })
}
pub(super) fn worker(v: &c::Snapshot) -> Result<w::WorkerSnapshot<w::EvidenceId>> {
    Ok(w::WorkerSnapshot {
        route: phase(v.route),
        route_returned: optional(v.route_returned.map(route_result)),
        archive: w::ArchiveSnapshot {
            issued: v.archive.issued,
            started: v.archive.started,
            knowledge: match v.archive.knowledge {
                c::ArchiveKnowledge::NoCommitEntered => {
                    w::ArchiveKnowledge::NoCommitEntered(w::Empty {})
                }
                c::ArchiveKnowledge::CommitCallEntered(v) => {
                    w::ArchiveKnowledge::CommitCallEntered(archive_result(v))
                }
                c::ArchiveKnowledge::ReceiptKnown(v) => {
                    w::ArchiveKnowledge::ReceiptKnown(archive_result(v))
                }
            },
            returned: optional(v.archive.returned.map(archive_returned)),
        },
        local: w::List::new(
            v.local
                .iter()
                .map(|v| -> Result<_> {
                    Ok(w::LocalPrefix {
                        target: w::Text::new(&v.target)?,
                        started: v.started,
                        enqueued: v.enqueued,
                        returned: optional(v.returned.map(local)),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        )?,
        cluster: w::List::new(
            v.cluster
                .iter()
                .map(|v| -> Result<_> {
                    Ok(w::ClusterPrefix {
                        node: w::Text::new(&v.node)?,
                        started: v.started,
                        returned: v.returned,
                        handoff: optional(v.handoff.map(boundary)),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        )?,
        transfer: optional(
            v.transfer
                .as_ref()
                .map(|v| -> Result<_> {
                    Ok(w::TransferFact {
                        target: w::Text::new(&v.target)?,
                        boundary: boundary(v.boundary),
                    })
                })
                .transpose()?,
        ),
        lease_lost: v.lease_lost,
        aborted: v.aborted,
        renewal_scope_closed: v.renewal_scope_closed,
        renewal: w::RenewalSnapshot {
            issued: v.renewal.issued,
            started: v.renewal.started,
            pending: v.renewal.pending,
            knowledge: match v.renewal.knowledge {
                c::RenewalKnowledge::NotEntered => w::RenewalKnowledge::NotEntered(w::Empty {}),
                c::RenewalKnowledge::AutocommitStatementEntered => {
                    w::RenewalKnowledge::AutocommitStatementEntered(w::Empty {})
                }
                c::RenewalKnowledge::StatementReceipt(value) => {
                    w::RenewalKnowledge::StatementReceipt(w::BoolValue { value })
                }
            },
            returned: optional(v.renewal.returned.map(|v| match v {
                c::RenewalReturned::Outcome(value) => {
                    w::RenewalReturned::Outcome(w::BoolValue { value })
                }
                c::RenewalReturned::Error => w::RenewalReturned::Error(w::Empty {}),
            })),
            last_receipt: optional(
                v.renewal
                    .last_receipt
                    .map(|(ordinal, value)| w::RenewalReceipt { ordinal, value }),
            ),
        },
        settlement: optional(v.settlement.as_ref().map(|v| w::SettlementSnapshot {
            kind: settlement_kind(v.kind),
            started: v.started,
            knowledge: match v.knowledge {
                c::SettlementKnowledge::NotEntered => {
                    w::SettlementKnowledge::NotEntered(w::Empty {})
                }
                c::SettlementKnowledge::CommitCallEntered(v) => {
                    w::SettlementKnowledge::CommitCallEntered(settlement_result(v))
                }
                c::SettlementKnowledge::AutocommitStatementEntered => {
                    w::SettlementKnowledge::AutocommitStatementEntered(w::Empty {})
                }
                c::SettlementKnowledge::ReceiptKnown(v) => {
                    w::SettlementKnowledge::ReceiptKnown(settlement_result(v))
                }
            },
            returned: optional(v.returned.map(settlement_returned)),
        })),
        terminal: optional(v.terminal.map(terminal)),
    })
}
pub(super) fn route_session(
    key: &str,
    v: &crate::state::OnlineSession,
) -> Result<w::RouteSession<w::EvidenceId>> {
    Ok(w::RouteSession {
        full_jid: w::Text::new(key)?,
        connection_id: id(v.connection_id),
        user_id: id(v.user_id),
        auth_generation: v.auth_generation,
        user_agent_epoch: optional(v.user_agent_epoch),
        caps_observation_generation: v.caps_observation_generation.load(Ordering::Acquire),
        routable: v.routable.load(Ordering::Acquire),
        disconnected: v.disconnect.is_cancelled(),
        lifecycle: v.lifecycle.load(Ordering::Acquire),
    })
}
pub(super) fn caps(
    v: &northstar_protocol_runtime::caps::CapsObservationSnapshot,
) -> Result<w::CapsObservation<w::EvidenceId>> {
    use northstar_protocol_runtime::caps::CapsObservationOwner;
    Ok(w::CapsObservation {
        owner: match v.owner {
            CapsObservationOwner::Local(v) => w::CapsOwner::Local(w::LocalCapsEpoch {
                connection_id: id(v.connection_id),
                generation: v.generation,
            }),
            CapsObservationOwner::Federated {
                connection_id,
                observation_id,
            } => w::CapsOwner::Federated(w::FederatedCapsOwner {
                connection_id: id(connection_id),
                observation_id: id(observation_id),
            }),
        },
        key: optional(
            v.key
                .as_ref()
                .map(|v| -> Result<_> {
                    Ok(w::CapsKey {
                        algorithm: w::Text::new(&v.algorithm)?,
                        node: w::Text::new(&v.node)?,
                        version: w::Text::new(&v.version)?,
                    })
                })
                .transpose()?,
        ),
        summary: optional(
            v.summary
                .as_ref()
                .map(|v| -> Result<_> {
                    Ok(w::VerifiedCapsSummary {
                        mix_core: v.mix_core,
                        mix_pam: v.mix_pam,
                        notify_storage: w::Text::new(&v.notify_storage)?,
                        notify_ranges: w::List::new(
                            v.notify_ranges
                                .iter()
                                .map(|&(start, end)| w::NotifyRange { start, end })
                                .collect(),
                        )?,
                    })
                })
                .transpose()?,
        ),
    })
}
fn participant(v: &m::Participant) -> Result<w::Participant<w::EvidenceId>> {
    Ok(w::Participant {
        participant_id: id(v.participant_id),
        jid: w::Text::new(&v.jid)?,
        nick: optional(v.nick.as_ref().map(w::Text::new).transpose()?),
    })
}
fn projection(v: &m::DeliveryProjection) -> Result<w::DeliveryProjection<w::EvidenceId>> {
    Ok(w::DeliveryProjection {
        event_id: id(v.event_id),
        channel_id: id(v.channel_id),
        channel_jid: w::Text::new(&v.channel_jid)?,
        stanza_template: w::Text::new(&v.stanza_template)?,
        authoritative_stanza_id: optional(v.authoritative_stanza_id.map(id)),
        archive: v.archive,
        encrypted: v.encrypted,
        recipients: w::List::new(
            v.recipients
                .iter()
                .map(|v| -> Result<_> {
                    Ok(w::RecipientProjection {
                        participant: participant(&v.participant)?,
                        delivery_id: id(v.delivery_id),
                        sequence: v.sequence,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        )?,
    })
}
fn stored(v: &m::Stored) -> Result<w::Stored<w::EvidenceId>> {
    Ok(w::Stored {
        authoritative_id: id(v.authoritative_id),
        storage_id: id(v.storage_id),
        channel_id: id(v.channel_id),
        channel_jid: w::Text::new(&v.channel_jid)?,
        projection: optional(v.projection.as_ref().map(projection).transpose()?),
    })
}
fn existing(v: &m::Existing) -> Result<w::Existing<w::EvidenceId>> {
    Ok(w::Existing {
        authoritative_id: id(v.authoritative_id),
        semantic_key_id: w::Text::new(&v.semantic_key_id)?,
        semantic_mac: w::Bytes::of(&v.semantic_mac)?,
        target_id: optional(v.target_id.map(id)),
    })
}
fn replay(v: m::Replay) -> w::MixReplay<w::EvidenceId> {
    match v {
        m::Replay::Miss => w::MixReplay::Miss(w::Empty {}),
        m::Replay::Conflict => w::MixReplay::Conflict(w::Empty {}),
        m::Replay::Replay(v) => w::MixReplay::Replay(one(v)),
    }
}
fn existing_knowledge(v: &f::ExistingKnowledge) -> Result<w::ExistingKnowledge<w::EvidenceId>> {
    Ok(w::ExistingKnowledge {
        raw: optional(v.raw.as_ref().map(|v| existing(v)).transpose()?),
        authenticated: optional(v.authenticated.map(replay)),
    })
}
fn outcome(v: m::Outcome) -> w::MixOutcome<w::EvidenceId> {
    match v {
        m::Outcome::Stored(v) => w::MixOutcome::Stored(one(v)),
        m::Outcome::Replay(v) => w::MixOutcome::Replay(one(v)),
        m::Outcome::NotParticipant => w::MixOutcome::NotParticipant(w::Empty {}),
        m::Outcome::Conflict => w::MixOutcome::Conflict(w::Empty {}),
        m::Outcome::TooLarge => w::MixOutcome::TooLarge(w::Empty {}),
    }
}
pub(super) fn foreground(v: &f::Snapshot) -> Result<w::ForegroundSnapshot<w::EvidenceId>> {
    Ok(w::ForegroundSnapshot {
        replay: w::ReadKnowledge {
            issued: v.replay.issued,
            started: v.replay.started,
            miss: v.replay.miss,
            existing: existing_knowledge(&v.replay.existing)?,
            returned: optional(v.replay.returned.map(|v| match v {
                f::ReadReturned::Outcome(v) => w::ReadReturned::Outcome(replay(v)),
                f::ReadReturned::Error => w::ReadReturned::Error(w::Empty {}),
            })),
        },
        request_issued: v.request_issued,
        repository_started: v.repository_started,
        existing: existing_knowledge(&v.existing)?,
        knowledge: match &v.knowledge {
            f::Knowledge::NoCommitRequested => {
                w::ForegroundKnowledge::NoCommitRequested(w::Empty {})
            }
            f::Knowledge::CommitCallEntered(v) => {
                w::ForegroundKnowledge::CommitCallEntered(stored(v)?)
            }
            f::Knowledge::ReceiptKnown(v) => w::ForegroundKnowledge::ReceiptKnown(stored(v)?),
        },
        returned: optional(
            v.returned
                .as_ref()
                .map(|v| -> Result<_> {
                    Ok(match v {
                        f::Returned::AcceptedStored(v) => {
                            w::ForegroundReturned::AcceptedStored(one(*v))
                        }
                        f::Returned::Error => w::ForegroundReturned::Error(w::Empty {}),
                        f::Returned::Admission(v) => {
                            w::ForegroundReturned::Admission(w::MixAdmission {
                                outcome: outcome(v.outcome),
                                recipients: w::List::new(
                                    v.recipients
                                        .iter()
                                        .map(participant)
                                        .collect::<Result<Vec<_>>>()?,
                                )?,
                            })
                        }
                    })
                })
                .transpose()?,
        ),
        wake: wake(v.wake),
        terminal: optional(v.terminal.map(fg_terminal)),
    })
}
pub(super) fn ingress(v: &m::Ingress) -> Result<w::MixIngress<w::EvidenceId>> {
    Ok(w::MixIngress {
        channel_id: id(v.channel_id),
        channel_jid: w::Text::new(&v.channel_jid)?,
        actor_bare: w::Text::new(&v.actor_bare)?,
        actor_full: w::Text::new(&v.actor_full)?,
        children: w::Text::new(&v.children)?,
        encrypted: v.encrypted,
        identity: optional(
            v.identity
                .as_ref()
                .map(|v| -> Result<_> {
                    Ok(w::ReplayIdentityInput {
                        client_id: w::Text::new(&v.client_id)?,
                        canonical_semantics: w::Bytes::of(&v.canonical_semantics)?,
                    })
                })
                .transpose()?,
        ),
    })
}
pub(super) fn command(v: &m::StoreCommand) -> Result<w::MixStoreCommand<w::EvidenceId>> {
    Ok(w::MixStoreCommand {
        channel_id: id(v.channel_id),
        actor: w::Text::new(&v.actor)?,
        item_id: id(v.item_id),
        payload: w::Text::new(&v.payload)?,
        identity: optional(
            v.identity
                .as_ref()
                .map(|v| -> Result<_> {
                    Ok(w::ReplayIdentityInput {
                        client_id: w::Text::new(&v.client_id)?,
                        canonical_semantics: w::Bytes::of(&v.canonical_semantics)?,
                    })
                })
                .transpose()?,
        ),
        delivery_payload: w::Text::new(&v.delivery_payload)?,
        visible_jid: optional(v.visible_jid.as_ref().map(w::Text::new).transpose()?),
        encrypted: v.encrypted,
    })
}
