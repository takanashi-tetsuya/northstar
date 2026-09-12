//! Foundation telemetry and distributed tracing helpers.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 15, 19.1).

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use thiserror::Error;

/// W3C Trace Context propagator across microservice boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributedTraceContext {
    pub traceparent: String,
    pub tracestate: Option<String>,
    pub correlation_id: Option<String>,
    pub causation_id: Option<String>,
}

impl DistributedTraceContext {
    pub fn new(traceparent: impl Into<String>) -> Self {
        Self {
            traceparent: traceparent.into(),
            tracestate: None,
            correlation_id: None,
            causation_id: None,
        }
    }

    pub fn with_correlation(
        mut self,
        correlation_id: impl Into<String>,
        causation_id: Option<String>,
    ) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self.causation_id = causation_id;
        self
    }

    pub fn validate(&self) -> Result<(), TelemetryError> {
        let value = self.traceparent.as_bytes();
        if value.len() != 55
            || value[2] != b'-'
            || value[35] != b'-'
            || value[52] != b'-'
            || !value
                .iter()
                .enumerate()
                .filter(|(index, _)| !matches!(*index, 2 | 35 | 52))
                .all(|(_, byte)| byte.is_ascii_hexdigit())
            || self.traceparent[3..35].chars().all(|c| c == '0')
            || self.traceparent[36..52].chars().all(|c| c == '0')
        {
            return Err(TelemetryError::InvalidTraceparent);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricDimensions {
    pub service: String,
    pub rpc: Option<String>,
    pub event: Option<String>,
    pub db: Option<String>,
    pub kafka: Option<String>,
    pub stanza_kind: Option<String>,
}

impl MetricDimensions {
    pub fn new(service: impl Into<String>) -> Result<Self, TelemetryError> {
        let service = bounded_label(service.into())?;
        Ok(Self {
            service,
            rpc: None,
            event: None,
            db: None,
            kafka: None,
            stanza_kind: None,
        })
    }

    pub fn rpc(mut self, value: impl Into<String>) -> Result<Self, TelemetryError> {
        self.rpc = Some(bounded_label(value.into())?);
        Ok(self)
    }
    pub fn event(mut self, value: impl Into<String>) -> Result<Self, TelemetryError> {
        self.event = Some(bounded_label(value.into())?);
        Ok(self)
    }
    pub fn db(mut self, value: impl Into<String>) -> Result<Self, TelemetryError> {
        self.db = Some(bounded_label(value.into())?);
        Ok(self)
    }
    pub fn kafka(mut self, value: impl Into<String>) -> Result<Self, TelemetryError> {
        self.kafka = Some(bounded_label(value.into())?);
        Ok(self)
    }
    pub fn stanza_kind(mut self, value: impl Into<String>) -> Result<Self, TelemetryError> {
        self.stanza_kind = Some(bounded_label(value.into())?);
        Ok(self)
    }
}

fn bounded_label(value: String) -> Result<String, TelemetryError> {
    if value.is_empty()
        || value.len() > 64
        || !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(TelemetryError::InvalidMetricLabel);
    }
    Ok(value)
}

#[derive(Debug)]
pub struct BoundedTelemetryBuffer<T> {
    queue: Mutex<VecDeque<T>>,
    capacity: usize,
    dropped: AtomicU64,
}

impl<T> BoundedTelemetryBuffer<T> {
    pub fn new(capacity: usize) -> Result<Self, TelemetryError> {
        if capacity == 0 {
            return Err(TelemetryError::InvalidBufferCapacity);
        }
        Ok(Self {
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            dropped: AtomicU64::new(0),
        })
    }

    pub fn push(&self, value: T) {
        let mut queue = self.queue.lock().unwrap();
        if queue.len() == self.capacity {
            queue.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        queue.push_back(value);
    }

    pub fn pop(&self) -> Option<T> {
        self.queue.lock().unwrap().pop_front()
    }
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
    pub fn len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.lock().unwrap().is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplingPolicy {
    pub head_probability_percent: u8,
    pub tail_latency_ms: u64,
}

impl SamplingPolicy {
    pub fn validate(self) -> Result<Self, TelemetryError> {
        if self.head_probability_percent > 100 || self.tail_latency_ms == 0 {
            return Err(TelemetryError::InvalidSamplingPolicy);
        }
        Ok(self)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryError {
    #[error("traceparent is malformed or uses an all-zero identifier")]
    InvalidTraceparent,
    #[error("metric label is empty, oversized or non-ASCII")]
    InvalidMetricLabel,
    #[error("telemetry buffer capacity must be non-zero")]
    InvalidBufferCapacity,
    #[error("sampling policy is outside its bounded range")]
    InvalidSamplingPolicy,
}

/// Helper to sanitize metrics labels and avoid cardinality explosion or confidential leak.
pub fn sanitize_metric_label(label: &str) -> String {
    label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_label_sanitization() {
        assert_eq!(
            sanitize_metric_label("user@example.com/mobile"),
            "user_example_com_mobile"
        );
        assert_eq!(sanitize_metric_label("ok-status_1"), "ok-status_1");
    }

    #[test]
    fn trace_context_builder() {
        let ctx =
            DistributedTraceContext::new("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
                .with_correlation("corr-123", Some("caus-456".to_string()));
        assert_eq!(ctx.correlation_id.as_deref(), Some("corr-123"));
        assert_eq!(ctx.causation_id.as_deref(), Some("caus-456"));
        assert!(ctx.validate().is_ok());
    }

    #[test]
    fn metrics_are_low_cardinality_and_buffer_is_bounded() {
        let dims = MetricDimensions::new("message-ingress")
            .unwrap()
            .rpc("SubmitMessage")
            .unwrap();
        assert_eq!(dims.rpc.as_deref(), Some("SubmitMessage"));
        assert!(MetricDimensions::new("alice@example.com").is_err());
        assert!(MetricDimensions::new("a".repeat(65)).is_err());
        let buffer = BoundedTelemetryBuffer::new(2).unwrap();
        buffer.push(1);
        buffer.push(2);
        buffer.push(3);
        assert_eq!(buffer.pop(), Some(2));
        assert_eq!(buffer.dropped(), 1);
    }

    #[test]
    fn invalid_trace_and_sampling_inputs_fail_closed() {
        assert!(DistributedTraceContext::new(
            "00-00000000000000000000000000000000-0000000000000000-01"
        )
        .validate()
        .is_err());
        assert!(SamplingPolicy {
            head_probability_percent: 101,
            tail_latency_ms: 1
        }
        .validate()
        .is_err());
        assert!(SamplingPolicy {
            head_probability_percent: 5,
            tail_latency_ms: 10
        }
        .validate()
        .is_ok());
    }
}
