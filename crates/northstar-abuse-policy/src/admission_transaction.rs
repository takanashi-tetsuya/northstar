//! Decisions evaluated against rows locked by the admission repository.
//! These snapshots are inputs, never substitutes for transaction authority.
use chrono::{DateTime, Utc};
use std::fmt;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_USER, MESSAGE_ADMISSION_ACCEPTED_TTL,
    MESSAGE_ADMISSION_LEASE, MESSAGE_ADMISSION_PENDING_TTL,
};

#[derive(Clone, PartialEq, Eq)]
pub struct AdmissionCandidate {
    pub key_id: String,
    pub admission_key: Vec<u8>,
    pub payload_mac: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AdmissionFence {
    pub admission_key: Vec<u8>,
    pub payload_mac: Vec<u8>,
    pub lease_token: Uuid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowState {
    Pending,
    Accepted,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AdmissionRow {
    pub admission_key: Vec<u8>,
    pub key_id: String,
    pub actor_id: Uuid,
    pub payload_mac: Vec<u8>,
    pub state: RowState,
    pub lease_token: Uuid,
    pub lease_expires_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

macro_rules! redacted_debug {
    ($($t:ty),+ $(,)?) => {$(impl fmt::Debug for $t {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(concat!(stringify!($t), " { authority: [redacted] }"))
        }
    })+};
}
redacted_debug!(AdmissionCandidate, AdmissionFence, AdmissionRow);

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RowIntegrityError {
    #[error("multiple admission rotation rows")]
    MultipleRows,
    #[error("missing primary admission candidate")]
    MissingCandidate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeginRowDecision {
    VerifyGuard,
    Conflict,
    ReplayAccepted,
    InProgress { retry_after_seconds: u64 },
    Reclaim,
}

/// Exact-key expiry cleanup has already run under the candidate locks.
pub fn decide_begin(
    actor_id: Uuid,
    candidates: &[AdmissionCandidate],
    rows: &[AdmissionRow],
    now: DateTime<Utc>,
) -> Result<BeginRowDecision, RowIntegrityError> {
    if candidates.is_empty() {
        return Err(RowIntegrityError::MissingCandidate);
    }
    if rows.len() > 1 {
        return Err(RowIntegrityError::MultipleRows);
    }
    let Some(row) = rows.first() else {
        return Ok(BeginRowDecision::VerifyGuard);
    };
    let exact = row.actor_id == actor_id
        && candidates.iter().any(|candidate| {
            candidate.key_id == row.key_id
                && bool::from(row.admission_key.as_slice().ct_eq(&candidate.admission_key))
                && bool::from(row.payload_mac.as_slice().ct_eq(&candidate.payload_mac))
        });
    if !exact {
        return Ok(BeginRowDecision::Conflict);
    }
    if row.state == RowState::Accepted {
        return Ok(BeginRowDecision::ReplayAccepted);
    }
    if row.lease_expires_at > now {
        // Preserve the repository's millisecond truncation before rounding.
        let retry_after_seconds = u64::try_from(
            row.lease_expires_at
                .signed_duration_since(now)
                .num_milliseconds()
                .saturating_add(999)
                / 1_000,
        )
        .unwrap_or(u64::MAX)
        .max(1);
        return Ok(BeginRowDecision::InProgress {
            retry_after_seconds,
        });
    }
    Ok(BeginRowDecision::Reclaim)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityDecision {
    Available,
    Limited,
}

pub fn decide_actor_capacity(active: i64) -> CapacityDecision {
    if active >= MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_USER {
        CapacityDecision::Limited
    } else {
        CapacityDecision::Available
    }
}

/// The input is the authoritative UPDATE ... RETURNING result, not a snapshot.
pub fn decide_shard_reservation(returned_count: Option<i32>) -> CapacityDecision {
    if returned_count.is_some() {
        CapacityDecision::Available
    } else {
        CapacityDecision::Limited
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalizeDecision {
    Missing,
    PayloadConflict,
    AlreadyAccepted,
    LostFence,
    AcceptPending,
}

/// Deliberately no expiry/capacity predicate. Accepted precedes token equality.
pub fn decide_finalize(row: Option<&AdmissionRow>, fence: &AdmissionFence) -> FinalizeDecision {
    let Some(row) = row else {
        return FinalizeDecision::Missing;
    };
    if !bool::from(row.admission_key.as_slice().ct_eq(&fence.admission_key))
        || !bool::from(row.payload_mac.as_slice().ct_eq(&fence.payload_mac))
    {
        return FinalizeDecision::PayloadConflict;
    }
    if row.state == RowState::Accepted {
        return FinalizeDecision::AlreadyAccepted;
    }
    if row.lease_token != fence.lease_token {
        return FinalizeDecision::LostFence;
    }
    FinalizeDecision::AcceptPending
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemporalValidity {
    Current,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileObservation {
    ExactPending {
        lease: TemporalValidity,
        retention: TemporalValidity,
    },
    ExactAccepted {
        retention: TemporalValidity,
    },
    Missing,
    Conflicting,
    Superseded,
}

/// The same instant used to classify this locked-row observation.
/// Its clock belongs to the adapter; this value is not a commit receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimedReconcileObservation {
    pub observed_at: DateTime<Utc>,
    pub observation: ReconcileObservation,
}

/// Positive current-row evidence is not historical attribution or retry authority.
pub fn reconcile(
    row: Option<&AdmissionRow>,
    fence: &AdmissionFence,
    now: DateTime<Utc>,
) -> TimedReconcileObservation {
    let observation = match decide_finalize(row, fence) {
        FinalizeDecision::Missing => ReconcileObservation::Missing,
        FinalizeDecision::PayloadConflict => ReconcileObservation::Conflicting,
        FinalizeDecision::AlreadyAccepted => ReconcileObservation::ExactAccepted {
            retention: validity(row.expect("decision requires a row").expires_at, now),
        },
        FinalizeDecision::LostFence => ReconcileObservation::Superseded,
        FinalizeDecision::AcceptPending => {
            let row = row.expect("decision requires a row");
            ReconcileObservation::ExactPending {
                lease: validity(row.lease_expires_at, now),
                retention: validity(row.expires_at, now),
            }
        }
    };
    TimedReconcileObservation {
        observed_at: now,
        observation,
    }
}

pub fn validity(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> TemporalValidity {
    if expires_at > now {
        TemporalValidity::Current
    } else {
        TemporalValidity::Expired
    }
}

fn after(now: DateTime<Utc>, duration: std::time::Duration) -> DateTime<Utc> {
    now + chrono::Duration::seconds(i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
}
pub fn pending_expiry(now: DateTime<Utc>) -> DateTime<Utc> {
    after(now, MESSAGE_ADMISSION_PENDING_TTL)
}
pub fn lease_expiry(now: DateTime<Utc>) -> DateTime<Utc> {
    after(now, MESSAGE_ADMISSION_LEASE)
}
pub fn accepted_expiry(now: DateTime<Utc>) -> DateTime<Utc> {
    after(now, MESSAGE_ADMISSION_ACCEPTED_TTL)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (
        DateTime<Utc>,
        AdmissionCandidate,
        AdmissionRow,
        AdmissionFence,
    ) {
        let now = DateTime::from_timestamp(1_000, 0).unwrap();
        let candidate = AdmissionCandidate {
            key_id: "test-key".into(),
            admission_key: vec![1; 32],
            payload_mac: vec![2; 32],
        };
        let fence = AdmissionFence {
            admission_key: candidate.admission_key.clone(),
            payload_mac: candidate.payload_mac.clone(),
            lease_token: Uuid::from_u128(3),
        };
        let row = AdmissionRow {
            admission_key: candidate.admission_key.clone(),
            key_id: candidate.key_id.clone(),
            actor_id: Uuid::from_u128(4),
            payload_mac: candidate.payload_mac.clone(),
            state: RowState::Pending,
            lease_token: fence.lease_token,
            lease_expires_at: lease_expiry(now),
            expires_at: pending_expiry(now),
        };
        (now, candidate, row, fence)
    }
    #[test]
    fn locked_begin_identity_rotation_and_retry_millisecond_semantics() {
        let (now, candidate, mut row, _) = fixture();
        assert_eq!(
            decide_begin(row.actor_id, std::slice::from_ref(&candidate), &[], now).unwrap(),
            BeginRowDecision::VerifyGuard
        );
        row.lease_expires_at = now + chrono::Duration::microseconds(1_000_999);
        assert_eq!(
            decide_begin(
                row.actor_id,
                std::slice::from_ref(&candidate),
                std::slice::from_ref(&row),
                now
            )
            .unwrap(),
            BeginRowDecision::InProgress {
                retry_after_seconds: 1
            }
        );
        row.lease_expires_at += chrono::Duration::microseconds(1);
        assert_eq!(
            decide_begin(
                row.actor_id,
                std::slice::from_ref(&candidate),
                std::slice::from_ref(&row),
                now
            )
            .unwrap(),
            BeginRowDecision::InProgress {
                retry_after_seconds: 2
            }
        );
        row.lease_expires_at = now;
        assert_eq!(
            decide_begin(
                row.actor_id,
                std::slice::from_ref(&candidate),
                std::slice::from_ref(&row),
                now
            )
            .unwrap(),
            BeginRowDecision::Reclaim
        );
        row.state = RowState::Accepted;
        assert_eq!(
            decide_begin(
                row.actor_id,
                std::slice::from_ref(&candidate),
                std::slice::from_ref(&row),
                now
            )
            .unwrap(),
            BeginRowDecision::ReplayAccepted
        );
        assert_eq!(
            decide_begin(
                Uuid::nil(),
                std::slice::from_ref(&candidate),
                std::slice::from_ref(&row),
                now
            )
            .unwrap(),
            BeginRowDecision::Conflict
        );
        assert_eq!(
            decide_begin(
                row.actor_id,
                std::slice::from_ref(&candidate),
                &[row.clone(), row.clone()],
                now
            ),
            Err(RowIntegrityError::MultipleRows)
        );
        row.payload_mac[0] ^= 1;
        assert_eq!(
            decide_begin(row.actor_id, &[candidate], std::slice::from_ref(&row), now).unwrap(),
            BeginRowDecision::Conflict
        );
    }
    #[test]
    fn admission_capacity_and_expiry_predicates_are_distinct() {
        let (now, _, _, _) = fixture();
        assert_eq!(decide_actor_capacity(4095), CapacityDecision::Available);
        assert_eq!(decide_actor_capacity(4096), CapacityDecision::Limited);
        assert_eq!(decide_actor_capacity(4097), CapacityDecision::Limited);
        assert_eq!(
            decide_shard_reservation(Some(32768)),
            CapacityDecision::Available
        );
        assert_eq!(decide_shard_reservation(None), CapacityDecision::Limited);
        for (offset, expected) in [
            (-1, TemporalValidity::Current),
            (0, TemporalValidity::Expired),
            (1, TemporalValidity::Expired),
        ] {
            assert_eq!(
                validity(now, now + chrono::Duration::microseconds(offset)),
                expected
            );
        }
        assert_eq!((pending_expiry(now) - now).num_seconds(), 1800);
        assert_eq!((accepted_expiry(now) - now).num_seconds(), 21600);
        assert_eq!((lease_expiry(now) - now).num_seconds(), 60);
    }
    #[test]
    fn finalize_preserves_accepted_before_token_and_late_pending() {
        let (_, _, mut row, mut fence) = fixture();
        assert_eq!(decide_finalize(None, &fence), FinalizeDecision::Missing);
        assert_eq!(
            decide_finalize(Some(&row), &fence),
            FinalizeDecision::AcceptPending
        );
        row.expires_at -= chrono::Duration::days(1);
        assert_eq!(
            decide_finalize(Some(&row), &fence),
            FinalizeDecision::AcceptPending
        );
        fence.lease_token = Uuid::from_u128(99);
        assert_eq!(
            decide_finalize(Some(&row), &fence),
            FinalizeDecision::LostFence
        );
        row.state = RowState::Accepted;
        assert_eq!(
            decide_finalize(Some(&row), &fence),
            FinalizeDecision::AlreadyAccepted
        );
        fence.payload_mac[0] ^= 1;
        assert_eq!(
            decide_finalize(Some(&row), &fence),
            FinalizeDecision::PayloadConflict
        );
    }
    #[test]
    fn every_reconcile_classification_retains_the_exact_sample() {
        let (_, _, row, fence) = fixture();
        let observed_at = DateTime::from_timestamp(1_001, 123_456_000).unwrap();
        let mut accepted = row.clone();
        accepted.state = RowState::Accepted;
        accepted.lease_token = Uuid::from_u128(88);
        let mut superseded = row.clone();
        superseded.lease_token = Uuid::from_u128(77);
        let mut conflicting = row.clone();
        conflicting.payload_mac[0] ^= 1;
        for (row, expected) in [
            (None, ReconcileObservation::Missing),
            (
                Some(row),
                ReconcileObservation::ExactPending {
                    lease: TemporalValidity::Current,
                    retention: TemporalValidity::Current,
                },
            ),
            (
                Some(accepted),
                ReconcileObservation::ExactAccepted {
                    retention: TemporalValidity::Current,
                },
            ),
            (Some(superseded), ReconcileObservation::Superseded),
            (Some(conflicting), ReconcileObservation::Conflicting),
        ] {
            assert_eq!(
                reconcile(row.as_ref(), &fence, observed_at),
                TimedReconcileObservation {
                    observed_at,
                    observation: expected,
                }
            );
        }
    }
    #[test]
    fn reconcile_keeps_independent_lease_and_retention_boundaries() {
        use TemporalValidity::{Current, Expired};
        let (_, _, row, fence) = fixture();
        let microsecond = chrono::Duration::microseconds(1);
        for (observed_at, lease, retention) in [
            (row.lease_expires_at - microsecond, Current, Current),
            (row.lease_expires_at, Expired, Current),
            (row.lease_expires_at + microsecond, Expired, Current),
            (row.expires_at - microsecond, Expired, Current),
            (row.expires_at, Expired, Expired),
            (row.expires_at + microsecond, Expired, Expired),
        ] {
            let observed = reconcile(Some(&row), &fence, observed_at);
            assert_eq!(observed.observed_at, observed_at);
            assert_eq!(
                observed.observation,
                ReconcileObservation::ExactPending { lease, retention }
            );
        }
    }
    #[test]
    fn reconcile_keeps_retention_boundary_for_both_states() {
        let (_, _, mut row, fence) = fixture();
        row.lease_expires_at = row.expires_at;
        for state in [RowState::Pending, RowState::Accepted] {
            row.state = state;
            for (offset, expected) in [
                (-1, TemporalValidity::Current),
                (0, TemporalValidity::Expired),
                (1, TemporalValidity::Expired),
            ] {
                let observed = reconcile(
                    Some(&row),
                    &fence,
                    row.expires_at + chrono::Duration::microseconds(offset),
                );
                let expected = match state {
                    RowState::Pending => ReconcileObservation::ExactPending {
                        lease: expected,
                        retention: expected,
                    },
                    RowState::Accepted => ReconcileObservation::ExactAccepted {
                        retention: expected,
                    },
                };
                assert_eq!(observed.observation, expected);
                assert_eq!(
                    observed.observed_at,
                    row.expires_at + chrono::Duration::microseconds(offset)
                );
            }
        }
    }
}
