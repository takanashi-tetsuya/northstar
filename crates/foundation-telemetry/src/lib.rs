//! Foundation telemetry and distributed tracing helpers.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 15, 19.1).

use serde::{Deserialize, Serialize};

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
    }
}
