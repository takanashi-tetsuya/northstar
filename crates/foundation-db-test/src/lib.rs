//! Deterministic database invariant and concurrency-model test primitives.
//!
//! The helpers are intentionally storage-neutral: integration suites execute
//! them against an isolated PostgreSQL instance, while unit tests use the
//! same models to prove that correctness does not depend on an application
//! mutex or a particular task schedule.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::hash::Hash;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq)]
pub enum InvariantError {
    #[error("duplicate authoritative key at index {index}")]
    DuplicateKey { index: usize },
    #[error("sequence regressed from {previous} to {current} at index {index}")]
    SequenceRegressed {
        previous: u64,
        current: u64,
        index: usize,
    },
    #[error("lease CAS expected epoch {expected}, observed {observed}")]
    LeaseCasMismatch { expected: u64, observed: u64 },
    #[error("foreign key crosses service ownership boundary: {from} -> {to}")]
    CrossServiceForeignKey { from: String, to: String },
    #[error("query plan cost {actual} exceeds baseline {baseline}")]
    QueryPlanRegression { actual: f64, baseline: f64 },
}

/// Proves that an authority key is unique in the returned rows.  Production
/// databases must still enforce the same property with a UNIQUE constraint;
/// this helper detects a missing/disabled constraint in integration tests.
pub fn assert_unique<I, T>(values: I) -> Result<(), InvariantError>
where
    I: IntoIterator<Item = T>,
    T: Eq + Hash,
{
    let mut seen = HashSet::new();
    for (index, value) in values.into_iter().enumerate() {
        if !seen.insert(value) {
            return Err(InvariantError::DuplicateKey { index });
        }
    }
    Ok(())
}

/// Proves that a persisted sequence never regresses. Equal values are allowed
/// because retries may observe the same committed version more than once.
pub fn assert_monotonic<I>(values: I) -> Result<(), InvariantError>
where
    I: IntoIterator<Item = u64>,
{
    let mut previous = None;
    for (index, current) in values.into_iter().enumerate() {
        if let Some(previous_value) = previous {
            if current < previous_value {
                return Err(InvariantError::SequenceRegressed {
                    previous: previous_value,
                    current,
                    index,
                });
            }
        }
        previous = Some(current);
    }
    Ok(())
}

/// Model of an epoch compare-and-swap used by lease/session authorities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseCas {
    pub epoch: u64,
}

impl LeaseCas {
    pub fn new(epoch: u64) -> Self {
        Self { epoch }
    }

    pub fn advance(self, expected: u64) -> Result<Self, InvariantError> {
        if self.epoch != expected {
            return Err(InvariantError::LeaseCasMismatch {
                expected,
                observed: self.epoch,
            });
        }
        Ok(Self {
            epoch: self.epoch.saturating_add(1),
        })
    }
}

pub fn assert_internal_foreign_key(from: &str, to: &str) -> Result<(), InvariantError> {
    let from_service = from.split('.').next().unwrap_or(from);
    let to_service = to.split('.').next().unwrap_or(to);
    if from_service != to_service {
        return Err(InvariantError::CrossServiceForeignKey {
            from: from.to_owned(),
            to: to.to_owned(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetrySafety {
    /// Safe to retry: the transaction has no committed visible side effect.
    Safe,
    /// Never retry automatically: a visible side effect may have committed.
    Unsafe,
}

/// SQLSTATE classification used by failure-injection tests.  Only transient
/// transaction failures are safe to retry; constraint and permission failures
/// must surface to the caller.
pub fn retry_safety(sqlstate: &str) -> RetrySafety {
    match sqlstate {
        "40001" | "40P01" | "55P03" | "57014" => RetrySafety::Safe,
        _ => RetrySafety::Unsafe,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueryPlanBaseline {
    pub query_id: String,
    pub plan_hash: String,
    pub max_total_cost: f64,
}

impl QueryPlanBaseline {
    pub fn verify(&self, actual_cost: f64) -> Result<(), InvariantError> {
        if !actual_cost.is_finite() || actual_cost < 0.0 || actual_cost > self.max_total_cost {
            return Err(InvariantError::QueryPlanRegression {
                actual: actual_cost,
                baseline: self.max_total_cost,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniqueness_and_sequence_invariants_are_deterministic() {
        assert!(assert_unique(["a", "b", "c"]).is_ok());
        assert_eq!(
            assert_unique(["a", "a"]),
            Err(InvariantError::DuplicateKey { index: 1 })
        );
        assert!(assert_monotonic([1, 1, 2, 3]).is_ok());
        assert!(matches!(
            assert_monotonic([1, 3, 2]),
            Err(InvariantError::SequenceRegressed { .. })
        ));
    }

    #[test]
    fn lease_cas_rejects_stale_workers() {
        let lease = LeaseCas::new(7);
        assert_eq!(lease.advance(7).unwrap().epoch, 8);
        assert!(matches!(
            lease.advance(6),
            Err(InvariantError::LeaseCasMismatch {
                expected: 6,
                observed: 7
            })
        ));
    }

    #[test]
    fn cross_service_foreign_keys_and_retry_policy_fail_closed() {
        assert!(assert_internal_foreign_key("identity.users", "identity.roles").is_ok());
        assert!(assert_internal_foreign_key("identity.users", "session.leases").is_err());
        assert_eq!(retry_safety("40001"), RetrySafety::Safe);
        assert_eq!(retry_safety("23505"), RetrySafety::Unsafe);
    }

    #[test]
    fn query_plan_baseline_rejects_nan_and_regressions() {
        let baseline = QueryPlanBaseline {
            query_id: "claim-outbox".into(),
            plan_hash: "sha256:test".into(),
            max_total_cost: 10.0,
        };
        assert!(baseline.verify(9.9).is_ok());
        assert!(baseline.verify(10.1).is_err());
        assert!(baseline.verify(f64::NAN).is_err());
    }
}
