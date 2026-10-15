//! Single ignored, bounded saved-input composition entry. Repository effects
//! and writer responses are controlled; production preparation and owners run.
//! Native, SM, BOSH and replacement paths use their actual private helpers.
//! Full fixed-profile execution and qualification remain separately gated.
use super::*;
use crate::direct_replay as wire;
use crate::services::message_admission::{
    self,
    witness::{self, AdmissionWitness},
    MessageAdmissionRepository, MessageAdmissionService,
};
use crate::services::messaging::{
    DirectMessageRoutePort, FullJidFallbackPort, OnlineRoutePort, OnlineRouteResult,
};
use crate::xmpp::outbound::{
    DurableDelivery, OutboundItem, OutboundSender, RouteEnqueue, RouteSendError,
    TransportOwnershipSource,
};
use anyhow::Context;
use northstar_abuse_policy::{
    admission_execution as admission, admission_transaction::FinalizeDecision,
};
use northstar_message_application::{
    direct_commit, direct_handoff, direct_lifecycle, MessageApplication,
    PersonalMessageCommitRepository,
};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use uuid::Uuid;

mod native;
mod ports;
mod runs;
mod sm;

use self::native::{
    fixture_item, native_state, ItemReceivers, NativeInput, NativeLog, NativePlan, NativePort,
    ReplacementControl, ScriptedWriter, SmMetadata,
};
use self::ports::{AdmissionPort, DirectPort, FrameLog, RoutePort};
use self::runs::{run_native, run_original, run_replacement};

type Sequence = Arc<Mutex<wire::Sequence>>;
fn next(sequence: &Sequence) -> u32 {
    sequence.lock().unwrap().next()
}
fn actual_mode(mode: DirectPostCommitMode) -> wire::Mode {
    match mode {
        DirectPostCommitMode::Live => wire::Mode::Live,
        DirectPostCommitMode::SpoolOnly => wire::Mode::SpoolOnly,
        DirectPostCommitMode::Rejected => panic!("unexpected rejected returned mode"),
    }
}
fn transaction(value: &direct_commit::TransactionOutcome) -> wire::Transaction {
    match value {
        direct_commit::TransactionOutcome::Stored {
            recipient_id,
            delivery_id,
            archive_ids,
            live_claim_id,
        } => wire::Transaction::Stored {
            recipient_id: wire::Id(*recipient_id),
            delivery_id: wire::Id(*delivery_id),
            archive_ids: archive_ids.iter().copied().map(wire::Id).collect(),
            live_claim_id: live_claim_id.map_or(wire::Nullable::Null(()), |id| {
                wire::Nullable::Value(wire::Id(id))
            }),
        },
        direct_commit::TransactionOutcome::Replay { archive_ids } => wire::Transaction::Replay {
            archive_ids: archive_ids.iter().copied().map(wire::Id).collect(),
        },
        direct_commit::TransactionOutcome::AccountUnavailable => {
            wire::Transaction::AccountUnavailable {}
        }
    }
}
fn direct_prepared(value: &direct_commit::PreparedCommit) -> wire::DirectPrepared {
    wire::DirectPrepared {
        correlation: value.correlation.into(),
        transaction: transaction(&value.outcome),
        admitted_mode: actual_mode(value.admitted_mode),
    }
}
fn admission_commit(
    correlation: admission::Correlation,
    scope: admission::TransactionScope,
    fact: &admission::CommitFact,
) -> wire::AdmissionCommit {
    let scope = match scope {
        admission::TransactionScope::RatedBegin(admission::BeginCommitPurpose::NewReservation) => {
            "RatedBeginNewReservation"
        }
        admission::TransactionScope::AdmissionFinalize => "AdmissionFinalize",
        _ => panic!("unexpected admission scope"),
    };
    let fact = match fact {
        admission::CommitFact::Reserved(fence) => wire::AdmissionFact::Reserved {
            fence: fence.into(),
        },
        admission::CommitFact::Finalized {
            fence,
            result: admission::FinalizeSuccess::PendingAccepted,
        } => wire::AdmissionFact::Finalized {
            fence: fence.into(),
            result: "PendingAccepted",
        },
        _ => panic!("unexpected admission fact"),
    };
    wire::AdmissionCommit {
        correlation: correlation.into(),
        scope,
        fact,
    }
}
fn admission_state(value: direct_lifecycle::AdmissionSnapshot) -> wire::AdmissionEvidence {
    let knowledge = match value.witness.knowledge() {
        admission::Knowledge::NoCommitRequested => wire::AdmissionKnowledge::NoCommitRequested,
        admission::Knowledge::CommitCallEntered(prepared) => {
            wire::AdmissionKnowledge::CommitCallEntered {
                prepared: admission_commit(prepared.correlation, prepared.scope, &prepared.fact),
            }
        }
        admission::Knowledge::ReceiptKnown(receipt) => wire::AdmissionKnowledge::ReceiptKnown {
            receipt: admission_commit(receipt.correlation, receipt.scope, &receipt.fact),
        },
    };
    let returned = match value.state {
        admission::ExecutionState::Waiting(_) => None,
        admission::ExecutionState::Finished(admission::ExecutionOutcome::Completed {
            result: admission::EffectResult::Begin(admission::BeginResult::Reserved(fence)),
            ..
        }) => Some(wire::AdmissionReturned::Proceed {
            fence: (&fence).into(),
        }),
        admission::ExecutionState::Finished(admission::ExecutionOutcome::Completed {
            result: admission::EffectResult::Finalize(FinalizeDecision::AcceptPending),
            ..
        }) => Some(wire::AdmissionReturned::AcceptPending),
        admission::ExecutionState::Finished(_) => Some(wire::AdmissionReturned::Error),
    };
    wire::AdmissionEvidence {
        correlation: value.witness.effect().correlation.into(),
        started: value.effect_started,
        knowledge,
        returned,
    }
}
fn handoff(value: direct_handoff::Snapshot) -> wire::Handoff {
    wire::Handoff {
        correlation: value.correlation.into(),
        source: TransportOwnershipSource::C2s(value.source).into(),
        local_call: match value.local_call {
            direct_handoff::LocalKnowledge::NotRequested => "NotRequested",
            direct_handoff::LocalKnowledge::CallEntered => "CallEntered",
            direct_handoff::LocalKnowledge::Refused => "Refused",
            direct_handoff::LocalKnowledge::Accepted => "Accepted",
        },
        local_accepted: value.local_accepted,
        last_local_refusal: value.last_local_refusal.map(|value| match value {
            direct_handoff::Refusal::Full => "Full",
            direct_handoff::Refusal::Closed => "Closed",
        }),
        remote: match value.remote {
            direct_handoff::RemoteKnowledge::NotRequested => "NotRequested",
            direct_handoff::RemoteKnowledge::CallEntered => "CallEntered",
            direct_handoff::RemoteKnowledge::NoPositiveReceipt => "NoPositiveReceipt",
            direct_handoff::RemoteKnowledge::AcceptanceReported => "AcceptanceReported",
        },
        prior_remote_uncertain: value.prior_remote_uncertain,
        rearm: match value.rearm {
            direct_handoff::RearmKnowledge::NotRequested => "NotRequested",
            direct_handoff::RearmKnowledge::CallEntered => "CallEntered",
            direct_handoff::RearmKnowledge::CallReturned => "CallReturned",
        },
        route_end: match value.route_end {
            direct_handoff::RouteEnd::NotStarted => "NotStarted",
            direct_handoff::RouteEnd::Running => "Running",
            direct_handoff::RouteEnd::Returned => "Returned",
            direct_handoff::RouteEnd::Dropped => "Dropped",
        },
        retired: value.retired,
    }
}
fn original_state(owner: &DirectOperationHandle) -> wire::OriginalState {
    let value = owner.snapshot();
    let direct = value.direct.map(|value| {
        let knowledge = match &value.knowledge {
            direct_commit::Knowledge::NoCommitRequested => wire::DirectKnowledge::NoCommitRequested,
            direct_commit::Knowledge::CommitCallEntered(prepared) => {
                wire::DirectKnowledge::CommitCallEntered {
                    prepared: direct_prepared(prepared),
                }
            }
            direct_commit::Knowledge::ReceiptKnown(receipt) => {
                wire::DirectKnowledge::ReceiptKnown {
                    receipt: wire::DirectReceipt {
                        prepared: direct_prepared(&receipt.prepared),
                    },
                }
            }
        };
        let returned = match &value.outcome {
            Some(direct_commit::ExecutionOutcome::Completed(returned)) => {
                Some(wire::DirectReturned {
                    commit: match &returned.commit {
                        northstar_message_core::MessageCommit::Stored {
                            archive_written,
                            post_commit:
                                MessagePostCommit::RouteLocalDelivery {
                                    recipient_id,
                                    delivery_id,
                                },
                        } => wire::CommitResult::Stored {
                            archive_written: *archive_written,
                            recipient_id: wire::Id(*recipient_id),
                            delivery_id: wire::Id(*delivery_id),
                        },
                        northstar_message_core::MessageCommit::Replay => wire::CommitResult::Replay,
                        northstar_message_core::MessageCommit::AccountUnavailable => {
                            wire::CommitResult::AccountUnavailable
                        }
                        _ => panic!("unexpected local direct result"),
                    },
                    mode: actual_mode(returned.mode),
                    live_claim_id: returned.live_claim_id.map(wire::Id),
                })
            }
            _ => None,
        };
        let preserved_transaction = match &value.outcome {
            Some(direct_commit::ExecutionOutcome::ReceiptPreserved(receipt)) => {
                Some(transaction(&receipt.prepared.outcome))
            }
            _ => None,
        };
        wire::DirectEvidence {
            correlation: value.effect.correlation().into(),
            started: value.started,
            knowledge,
            returned,
            preserved_transaction,
            application_error: value.outcome.is_some()
                && !matches!(
                    value.outcome,
                    Some(direct_commit::ExecutionOutcome::Completed(_))
                ),
        }
    });
    wire::OriginalState {
        begin: value.reservation.map(admission_state),
        finalize: value.finalization.map(admission_state),
        direct,
        handoff: value.handoff.map(handoff),
        terminal: value.terminal.map(|value| match value {
            direct_lifecycle::TerminalReason::Completed => "Completed",
            direct_lifecycle::TerminalReason::BackendFailure => "BackendFailure",
            direct_lifecycle::TerminalReason::TimedOut => "TimedOut",
            direct_lifecycle::TerminalReason::Cancelled => "Cancelled",
            direct_lifecycle::TerminalReason::Panicked => "Panicked",
        }),
    }
}

async fn run_case(case: &wire::Case, input: &[u8]) -> Result<wire::Envelope> {
    let sequence = Arc::new(Mutex::new(wire::Sequence::default()));
    let mut originals = Vec::new();
    let mut recipient = wire::RecipientEvidence::None;
    let mut cancelled = false;
    for index in 0..case.originals.len() {
        let mut run = run_original(case, index, sequence.clone()).await?;
        cancelled |= run.cancelled;
        match &case.recipient_owner {
            wire::RecipientOwner::Native { frame_id, native }
                if *frame_id == case.originals[index].frame_id =>
            {
                let item = run.target.take().ok_or_else(|| {
                    anyhow::anyhow!("declared native owner has no dequeued target")
                })?;
                anyhow::ensure!(
                    item.transport_receipt.is_none() && item.transport_write_receipt.is_none(),
                    "routed item acquired synthetic receipts"
                );
                let mut recorder =
                    sm::Recorder::new(native.connection_id.0, None, &[], sequence.clone())?;
                let mut receivers = ItemReceivers::default();
                let mut mix_handoffs = vec![];
                let (evidence, dropped, _failed) = run_native(
                    NativeInput {
                        case,
                        frame_id: *frame_id,
                        plan: NativePlan {
                            connection_id: native.connection_id,
                            native: Some(native),
                            write: &native.write,
                            replacement: None,
                        },
                        item,
                        row: run.row.clone(),
                        sequence: sequence.clone(),
                    },
                    &mut recorder,
                    &mut receivers,
                    &mut mix_handoffs,
                )
                .await?;
                anyhow::ensure!(mix_handoffs.is_empty(), "C2S target acquired MIX handoff");
                cancelled |= dropped;
                recipient = wire::RecipientEvidence::Native {
                    native: Box::new(evidence),
                };
            }
            wire::RecipientOwner::Sm {
                frame_id,
                connection_id,
                config,
                extra_items,
                record_replies,
                write,
                ack,
            } if *frame_id == case.originals[index].frame_id => {
                let target = run
                    .target
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("declared SM owner has no dequeued target"))?;
                anyhow::ensure!(
                    target.transport_receipt.is_none() && target.transport_write_receipt.is_none(),
                    "routed item acquired synthetic receipts"
                );
                let mut recorder = sm::Recorder::new(
                    connection_id.0,
                    Some(config),
                    record_replies,
                    sequence.clone(),
                )?;
                let mut items = VecDeque::from([(target, ItemReceivers::default())]);
                for item in extra_items {
                    items.push_back(fixture_item(item)?);
                }
                let mut native_writes = vec![];
                let mut mix_handoffs = vec![];
                let mut dropped = false;
                let mut failed = false;
                while let Some((item, mut receivers)) = items.pop_front() {
                    let (evidence, was_dropped, did_fail) = run_native(
                        NativeInput {
                            case,
                            frame_id: *frame_id,
                            plan: NativePlan {
                                connection_id: *connection_id,
                                native: None,
                                write,
                                replacement: None,
                            },
                            item,
                            row: run.row.clone(),
                            sequence: sequence.clone(),
                        },
                        &mut recorder,
                        &mut receivers,
                        &mut mix_handoffs,
                    )
                    .await?;
                    native_writes.push(evidence);
                    dropped = was_dropped;
                    failed = did_fail;
                    if dropped || failed {
                        break;
                    }
                }
                if !dropped && !failed {
                    anyhow::ensure!(recorder.replies_exhausted(), "unconsumed SM record replies");
                    if let Some(ack) = ack.get() {
                        recorder.acknowledge(ack).await?;
                    }
                }
                cancelled |= dropped;
                recipient = wire::RecipientEvidence::Sm {
                    native_writes,
                    sm_turns: recorder.evidence(),
                    fifo_after: recorder.fifo(),
                    outbound_h: recorder.sm.outbound_h,
                    acked_h: recorder.sm.acked_h,
                    mix_handoffs,
                };
            }
            wire::RecipientOwner::Bosh {
                frame_id,
                recording,
                governor,
                ..
            } if *frame_id == case.originals[index].frame_id => {
                let target = run
                    .target
                    .take()
                    .context("declared BOSH owner has no dequeued target")?;
                anyhow::ensure!(
                    target.transport_receipt.is_none() && target.transport_write_receipt.is_none(),
                    "routed item acquired synthetic receipts"
                );
                let (connection_id, config, replies) = match recording.as_ref() {
                    wire::BoshRecording::Disabled {} => (
                        case.identities
                            .connection_id
                            .get()
                            .context("BOSH route connection role")?
                            .0,
                        None,
                        &[][..],
                    ),
                    wire::BoshRecording::PersistedSm {
                        connection_id,
                        config,
                        record_replies,
                    } => (connection_id.0, Some(config), record_replies.as_slice()),
                };
                let mut recorder =
                    sm::Recorder::new(connection_id, config, replies, sequence.clone())?;
                // Preflight already checked all four declared limits. Keep the
                // real SM charge alive while BOSH uses this very same governor.
                let governor = match recorder.governor() {
                    Some(governor) => governor,
                    None => crate::services::sm_capacity::SmMemoryGovernor::new(
                        governor.max_bytes as usize,
                        governor.max_recovery_bytes as usize,
                        governor.max_recovery_jobs as usize,
                        governor.max_snapshot_bytes as usize,
                        Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default()),
                    )?,
                };
                let (evidence, dropped) = crate::bosh::run_saved_case(
                    case,
                    target,
                    &mut recorder,
                    &governor,
                    sequence.clone(),
                )
                .await?;
                recorder.capture_retired();
                anyhow::ensure!(
                    recorder.replies_exhausted(),
                    "unconsumed BOSH SM record replies"
                );
                cancelled |= dropped;
                recipient = wire::RecipientEvidence::Bosh {
                    bosh: Box::new(evidence),
                    sm_turns: recorder.evidence(),
                    sm_fifo_after: recorder.fifo(),
                    sm_outbound_h: config.map(|_| recorder.sm.outbound_h),
                    sm_acked_h: config.map(|_| recorder.sm.acked_h),
                };
            }
            wire::RecipientOwner::NativeReplacement { frame_id, .. }
                if *frame_id == case.originals[index].frame_id =>
            {
                let item = run
                    .target
                    .take()
                    .context("replacement owner has no original dequeued item")?;
                anyhow::ensure!(
                    item.transport_receipt.is_none() && item.transport_write_receipt.is_none(),
                    "routed item acquired synthetic receipts"
                );
                recipient =
                    run_replacement(case, *frame_id, item, run.row.clone(), sequence.clone())
                        .await?;
            }
            _ => {}
        }
        anyhow::ensure!(
            run.target.is_none(),
            "dequeued item has no declared receiving owner"
        );
        originals.push(run.evidence);
    }
    Ok(wire::Envelope {
        schema: wire::EVIDENCE_SCHEMA,
        entry: wire::ENTRY,
        input_sha256: wire::digest(input),
        rejection: None,
        execution: Some(if cancelled {
            wire::Execution::Cancelled
        } else {
            wire::Execution::Complete
        }),
        originals,
        recipient: Some(recipient),
    })
}

#[tokio::test]
#[ignore = "requires the separately reviewed fixed saved-case profile; reads one JSON input from fd0"]
async fn replay_saved_case() -> Result<()> {
    let input = wire::read_input()?;
    let evidence = match wire::decode(&input) {
        Ok(case) => run_case(&case, &input).await?,
        Err(reason) => wire::Envelope::rejected(&input, reason),
    };
    wire::emit(&evidence)
}

#[cfg(test)]
mod route_observation_tests;

#[cfg(test)]
mod replacement_gate_tests;
