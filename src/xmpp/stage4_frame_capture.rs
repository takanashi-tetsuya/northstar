//! Test-only projection of the actual, caller-quiescent frame observation.
//! No owner, task, clock, sequence, or authority is retained by this module.
#![cfg(test)]
use super::frame_execution::FrameExecution;
use crate::stage4_replay as wire;
pub(super) type Capture = wire::driver::Capture;

fn nullable<T>(value: Option<T>) -> wire::Nullable<T> {
    value.map_or(wire::Nullable::Null(()), wire::Nullable::Value)
}

fn frame_stage(raw: u8) -> Option<wire::FrameStage> {
    Some(match raw {
        0 => wire::FrameStage::Validation,
        1 => wire::FrameStage::Handler,
        2 => wire::FrameStage::SmCheckpoint,
        3 => wire::FrameStage::AuthPublication,
        4 => wire::FrameStage::CapsPublication,
        5 => wire::FrameStage::ReplacementNotification,
        6 => wire::FrameStage::MessagePolicy,
        7 => wire::FrameStage::MessageAdmission,
        8 => wire::FrameStage::MessageRouting,
        9 => wire::FrameStage::MessageFollowup,
        10 => wire::FrameStage::MucPolicy,
        11 => wire::FrameStage::MucGateWait,
        12 => wire::FrameStage::MucAuthority,
        13 => wire::FrameStage::MucAdmission,
        14 => wire::FrameStage::MucClusterFanout,
        15 => wire::FrameStage::MucLocalFanout,
        16 => wire::FrameStage::MixPolicy,
        17 => wire::FrameStage::MixAdmission,
        _ => return None,
    })
}
fn frame_outcome(raw: u8) -> Option<wire::FrameOutcome> {
    Some(match raw {
        0 => wire::FrameOutcome::Pending,
        1 => wire::FrameOutcome::Completed,
        2 => wire::FrameOutcome::BackendFailure,
        3 => wire::FrameOutcome::TimedOut,
        4 => wire::FrameOutcome::Cancelled,
        5 => wire::FrameOutcome::Panicked,
        6 => wire::FrameOutcome::IntegrityRejected,
        7 => wire::FrameOutcome::CredentialRejected,
        8 => wire::FrameOutcome::RouteRejected,
        9 => wire::FrameOutcome::CompletedWithDeferredNotification,
        _ => return None,
    })
}
/// The caller must prove that no other task, callback or retained clone can
/// mutate this frame during these reads. A returned manual poll alone does not
/// establish that condition. This function does not provide a linearizable
/// snapshot or a quiescence token. Admission values are separately observed
/// facts supplied by the caller; absence must mean no actual retained evidence,
/// never an inferred result. Pending publication may retain a prior Completed
/// frame outcome; publication readiness is determined by its own live owner.
pub(super) fn capture_frame(
    frame: &FrameExecution,
    cut: wire::Cut,
    admission_begin: Option<wire::AdmissionEvidence<wire::EvidenceId>>,
    admission_finalize: Option<wire::AdmissionEvidence<wire::EvidenceId>>,
    recorder: &Capture,
) {
    let raw = frame.observation_for_saved_case();
    let stage = frame_stage(raw.stage_raw);
    let outcome = frame_outcome(raw.outcome_raw);
    wire::driver::emit(
        recorder,
        wire::Fact::Frame(wire::FrameCapture {
            frame: wire::EvidenceId::observed(raw.operation_id),
            cut,
            stage: nullable(stage),
            outcome: nullable(outcome),
            admission_begin: nullable(admission_begin),
            admission_finalize: nullable(admission_finalize),
        }),
    );
    if stage.is_none() || outcome.is_none() {
        wire::driver::lost(recorder);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmpp::frame_execution::{PublicationResult, Stage};
    use crate::xmpp::protocol::ClientTransport;

    #[test]
    fn every_actual_stage_discriminant_has_its_exact_closed_projection() {
        let pairs = [
            (Stage::Validation, wire::FrameStage::Validation),
            (Stage::Handler, wire::FrameStage::Handler),
            (Stage::SmCheckpoint, wire::FrameStage::SmCheckpoint),
            (Stage::AuthPublication, wire::FrameStage::AuthPublication),
            (Stage::CapsPublication, wire::FrameStage::CapsPublication),
            (
                Stage::ReplacementNotification,
                wire::FrameStage::ReplacementNotification,
            ),
            (Stage::MessagePolicy, wire::FrameStage::MessagePolicy),
            (Stage::MessageAdmission, wire::FrameStage::MessageAdmission),
            (Stage::MessageRouting, wire::FrameStage::MessageRouting),
            (Stage::MessageFollowup, wire::FrameStage::MessageFollowup),
            (Stage::MucPolicy, wire::FrameStage::MucPolicy),
            (Stage::MucGateWait, wire::FrameStage::MucGateWait),
            (Stage::MucAuthority, wire::FrameStage::MucAuthority),
            (Stage::MucAdmission, wire::FrameStage::MucAdmission),
            (Stage::MucClusterFanout, wire::FrameStage::MucClusterFanout),
            (Stage::MucLocalFanout, wire::FrameStage::MucLocalFanout),
            (Stage::MixPolicy, wire::FrameStage::MixPolicy),
            (Stage::MixAdmission, wire::FrameStage::MixAdmission),
        ];
        for (actual, projected) in pairs {
            assert_eq!(frame_stage(actual as u8), Some(projected));
        }
        for raw in 18..=u8::MAX {
            assert_eq!(frame_stage(raw), None);
        }
    }

    #[test]
    fn outcome_mapping_is_closed_and_never_defaults_unknown_to_pending() {
        let expected = [
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
        for (raw, expected) in expected.into_iter().enumerate() {
            assert_eq!(frame_outcome(raw as u8), Some(expected));
        }
        for raw in 10..=u8::MAX {
            assert_eq!(frame_outcome(raw), None);
        }
    }

    #[tokio::test]
    async fn actual_publication_outcomes_project_without_boolean_collapse() {
        for (actual, expected) in [
            (PublicationResult::Completed, wire::FrameOutcome::Completed),
            (
                PublicationResult::BackendFailure,
                wire::FrameOutcome::BackendFailure,
            ),
            (
                PublicationResult::IntegrityRejected,
                wire::FrameOutcome::IntegrityRejected,
            ),
            (
                PublicationResult::CredentialRejected,
                wire::FrameOutcome::CredentialRejected,
            ),
            (
                PublicationResult::RouteRejected,
                wire::FrameOutcome::RouteRejected,
            ),
            (
                PublicationResult::CompletedWithDeferredNotification,
                wire::FrameOutcome::CompletedWithDeferredNotification,
            ),
        ] {
            let frame =
                FrameExecution::for_saved_case(ClientTransport::Tcp, "<iq/>", uuid::Uuid::nil());
            let returned = frame.observe_publication(async { actual }).await;
            let raw = frame.observation_for_saved_case();
            assert_eq!(
                frame_stage(raw.stage_raw),
                Some(wire::FrameStage::AuthPublication)
            );
            assert_eq!(frame_outcome(raw.outcome_raw), Some(expected));
            assert_eq!(returned, actual.transport_succeeded());
        }
    }
}
