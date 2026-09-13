//! Bounded internal-RPC client policy primitives.

use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl RetryPolicy {
    pub fn validate(self) -> Result<Self, ClientPolicyError> {
        if self.max_attempts == 0
            || self.max_attempts > 8
            || self.base_delay.is_zero()
            || self.max_delay < self.base_delay
        {
            return Err(ClientPolicyError::InvalidRetryPolicy);
        }
        Ok(self)
    }

    pub fn delay_for_attempt(self, attempt: u8) -> Duration {
        let exponent = u32::from(attempt.min(31));
        self.base_delay
            .saturating_mul(2u32.saturating_pow(exponent))
            .min(self.max_delay)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
}

#[derive(Debug)]
pub struct CircuitBreaker {
    failures: u32,
    failure_threshold: u32,
    open_until: Option<Instant>,
    cool_down: Duration,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, cool_down: Duration) -> Result<Self, ClientPolicyError> {
        if failure_threshold == 0 || cool_down.is_zero() {
            return Err(ClientPolicyError::InvalidCircuitPolicy);
        }
        Ok(Self {
            failures: 0,
            failure_threshold,
            open_until: None,
            cool_down,
        })
    }

    pub fn state(&mut self, now: Instant) -> CircuitState {
        if let Some(until) = self.open_until {
            if now < until {
                return CircuitState::Open;
            }
            self.open_until = None;
            self.failures = 0;
        }
        CircuitState::Closed
    }

    pub fn allow(&mut self, now: Instant) -> bool {
        self.state(now) == CircuitState::Closed
    }

    pub fn record_success(&mut self) {
        self.failures = 0;
        self.open_until = None;
    }

    pub fn record_failure(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= self.failure_threshold {
            self.open_until = Some(now + self.cool_down);
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ClientPolicyError {
    #[error("retry policy is invalid or unbounded")]
    InvalidRetryPolicy,
    #[error("circuit breaker policy is invalid")]
    InvalidCircuitPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_backoff_is_bounded() {
        let policy = RetryPolicy {
            max_attempts: 4,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(25),
        }
        .validate()
        .unwrap();
        assert_eq!(policy.delay_for_attempt(0), Duration::from_millis(10));
        assert_eq!(policy.delay_for_attempt(2), Duration::from_millis(25));
        assert!(RetryPolicy {
            max_attempts: 0,
            ..policy
        }
        .validate()
        .is_err());
    }

    #[test]
    fn circuit_breaker_opens_and_recovers() {
        let now = Instant::now();
        let mut breaker = CircuitBreaker::new(2, Duration::from_secs(1)).unwrap();
        breaker.record_failure(now);
        assert!(breaker.allow(now));
        breaker.record_failure(now);
        assert!(!breaker.allow(now));
        assert!(breaker.allow(now + Duration::from_secs(1)));
    }
}
